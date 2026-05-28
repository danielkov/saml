//! XML-DSig signature verification, including HTTP-Redirect detached signatures.
//!
//! See `docs/rfcs/RFC-002-xml-crypto-core.md` §3 and §3.3.
//!
//! The verification entry point [`verify_signature`] returns a
//! [`VerifiedSignature`] handle whose `signed_element` field is the **only**
//! supported way to extract the validated payload. Callers must always pass
//! that [`ElementId`] to `Document::element(...)` — never re-resolve by name
//! or by re-running `URI` lookup. This is the structural XSW defense described
//! in RFC-002 §3.2.

use subtle::ConstantTimeEq;

use crate::crypto::cert::X509Certificate;
use crate::crypto::verifier::{DefaultVerifier, KeyInfo, SignatureVerifier, VerifyMatch};
use crate::dsig::algorithms::{C14nAlgorithm, SignatureAlgorithm};
use crate::dsig::c14n::canonicalize;
use crate::dsig::reference::{
    DS_NS, ancestor_chain, compute_reference_digest, decode_base64_lenient, parse_reference,
};
use crate::error::Error;
use crate::xml::parse::{Document, Element, ElementId};

/// Verified-signature handle returned by [`verify_signature`]. Caller MUST use
/// `signed_element` (not name-lookup, not re-parse) to extract the validated
/// payload — that is the structural XSW defense. See RFC-002 §3.2.
#[derive(Debug, Clone)]
pub struct VerifiedSignature {
    /// The `ElementId` of the element whose canonical form was signed.
    pub signed_element: ElementId,
    /// SHA-256 fingerprint of the verifying certificate.
    pub verifying_cert_fingerprint: [u8; 32],
    /// Signature algorithm that verified.
    pub signature_algorithm: SignatureAlgorithm,
}

/// Verify an enveloped XML-DSig signature using the default in-process
/// verifier (`DefaultVerifier`).
pub(crate) fn verify_signature(
    document: &Document,
    signature_element: &Element,
    candidate_certs: &[X509Certificate],
    allowed_algorithms: &[SignatureAlgorithm],
) -> Result<VerifiedSignature, Error> {
    verify_signature_with(
        document,
        signature_element,
        candidate_certs,
        allowed_algorithms,
        &DefaultVerifier,
    )
}

/// Verify an enveloped XML-DSig signature with a custom [`SignatureVerifier`].
pub(crate) fn verify_signature_with(
    document: &Document,
    signature_element: &Element,
    candidate_certs: &[X509Certificate],
    allowed_algorithms: &[SignatureAlgorithm],
    verifier: &dyn SignatureVerifier,
) -> Result<VerifiedSignature, Error> {
    // ---- 1. Locate <ds:SignedInfo> -----------------------------------------
    let signed_info = signature_element
        .child_element(Some(DS_NS), "SignedInfo")
        .ok_or(Error::SignatureVerification {
            reason: "missing SignedInfo",
        })?;

    // ---- 2. CanonicalizationMethod / SignatureMethod -----------------------
    let c14n_alg = parse_c14n_method(signed_info)?;
    let sig_alg = parse_signature_method(signed_info, allowed_algorithms)?;

    // ---- 3. Exactly one Reference ------------------------------------------
    let reference_elem = single_reference(signed_info)?;
    let parsed = parse_reference(document, reference_elem)?;

    // ---- 4. Compute and compare digest -------------------------------------
    // Pass the enclosing <ds:Signature>'s ElementId so the enveloped-signature
    // transform strips *only that* signature from the signed subtree — not any
    // separately-signed inner element (e.g. an Assertion's own ds:Signature on
    // a double-signed Response).
    let computed_digest = compute_reference_digest(document, &parsed, signature_element.id())?;
    // Constant-time compare: the parsed digest is attacker-controlled (it
    // arrives in the signed XML) and the computed digest is derived from the
    // canonical bytes. A timing-leaky `==` could in principle reveal the
    // leading bytes of the expected digest to an attacker probing forged
    // payloads.
    if !bool::from(computed_digest.ct_eq(&parsed.digest_value)) {
        return Err(Error::SignatureVerification {
            reason: "digest mismatch",
        });
    }

    // ---- 5. Canonicalize <ds:SignedInfo> for the SignatureValue check ------
    let signed_info_id = signed_info.id();
    let signed_info_chain =
        ancestor_chain(document, signed_info_id).ok_or(Error::SignatureVerification {
            reason: "could not compute SignedInfo ancestor chain",
        })?;
    // Empty PrefixList for SignedInfo c14n — SAML signatures never use
    // InclusiveNamespaces on the SignedInfo c14n itself.
    let signed_info_bytes = canonicalize(document, signed_info, &signed_info_chain, c14n_alg, &[])?;

    // ---- 6. SignatureValue -------------------------------------------------
    let signature_value_elem = signature_element
        .child_element(Some(DS_NS), "SignatureValue")
        .ok_or(Error::SignatureVerification {
            reason: "missing SignatureValue",
        })?;
    let signature_bytes = decode_base64_lenient(&signature_value_elem.text_content())?;

    // ---- 7. KeyInfo (optional) ---------------------------------------------
    let key_info = extract_key_info(signature_element);

    // ---- 8. Hand off to the verifier ---------------------------------------
    let vmatch = verifier.verify(
        sig_alg,
        &signed_info_bytes,
        &signature_bytes,
        candidate_certs,
        allowed_algorithms,
        &key_info,
    )?;

    Ok(VerifiedSignature {
        signed_element: parsed.target,
        verifying_cert_fingerprint: vmatch.cert_fingerprint,
        signature_algorithm: vmatch.algorithm,
    })
}

/// Verify a detached HTTP-Redirect query-string signature per spec §3.4.4.1.
///
/// `signed_query_string` is the canonical-order, percent-encoded query string
/// the binding layer (`binding::redirect::decode`) returned in
/// `DecodedRedirect::signed_query_string`. It is the bytes the verifier
/// hashes — NOT the decoded XML.
pub(crate) fn verify_detached_signature(
    signed_query_string: &[u8],
    signature_bytes: &[u8],
    sig_alg: SignatureAlgorithm,
    candidate_certs: &[X509Certificate],
    allowed_algorithms: &[SignatureAlgorithm],
) -> Result<VerifyMatch, Error> {
    verify_detached_signature_with(
        signed_query_string,
        signature_bytes,
        sig_alg,
        candidate_certs,
        allowed_algorithms,
        &DefaultVerifier,
    )
}

pub(crate) fn verify_detached_signature_with(
    signed_query_string: &[u8],
    signature_bytes: &[u8],
    sig_alg: SignatureAlgorithm,
    candidate_certs: &[X509Certificate],
    allowed_algorithms: &[SignatureAlgorithm],
    verifier: &dyn SignatureVerifier,
) -> Result<VerifyMatch, Error> {
    // Algorithm-allow-list gate, identical to the XML-DSig path. We surface
    // the rejection here rather than waiting for the verifier so a non-default
    // `SignatureVerifier` implementation can't accidentally widen the policy
    // by skipping the check.
    if !allowed_algorithms.contains(&sig_alg) {
        return Err(Error::DisallowedAlgorithm {
            alg: sig_alg.uri().to_owned(),
        });
    }
    verifier.verify(
        sig_alg,
        signed_query_string,
        signature_bytes,
        candidate_certs,
        allowed_algorithms,
        &KeyInfo::default(),
    )
}

// =============================================================================
// SignedInfo parsing helpers
// =============================================================================

fn parse_c14n_method(signed_info: &Element) -> Result<C14nAlgorithm, Error> {
    let elem = signed_info
        .child_element(Some(DS_NS), "CanonicalizationMethod")
        .ok_or(Error::SignatureVerification {
            reason: "missing CanonicalizationMethod",
        })?;
    let uri = elem.attribute(None, "Algorithm").ok_or(
        Error::SignatureVerification {
            reason: "CanonicalizationMethod missing Algorithm",
        },
    )?;
    C14nAlgorithm::from_uri(uri)
}

fn parse_signature_method(
    signed_info: &Element,
    allowed_algorithms: &[SignatureAlgorithm],
) -> Result<SignatureAlgorithm, Error> {
    let elem = signed_info
        .child_element(Some(DS_NS), "SignatureMethod")
        .ok_or(Error::SignatureVerification {
            reason: "missing SignatureMethod",
        })?;
    let uri = elem
        .attribute(None, "Algorithm")
        .ok_or(Error::SignatureVerification {
            reason: "SignatureMethod missing Algorithm",
        })?;
    let alg = SignatureAlgorithm::from_uri(uri)?;
    // Per-call policy gate (RFC-002 §3.1 step 1): an algorithm that parses to
    // a known variant is still rejected if it isn't in the caller-supplied
    // allow-list. The verifier re-checks this — we duplicate the gate here so
    // a misconfigured custom verifier can't silently widen acceptance, and so
    // we fail fast before any key material is touched.
    if !allowed_algorithms.contains(&alg) {
        return Err(Error::DisallowedAlgorithm {
            alg: uri.to_owned(),
        });
    }
    Ok(alg)
}

/// Locate the single `<ds:Reference>` inside `<ds:SignedInfo>`. Multiple
/// references are an XSW vector (RFC-002 §3.2) and rejected by default.
fn single_reference(signed_info: &Element) -> Result<&Element, Error> {
    let mut iter = signed_info.all_child_elements(Some(DS_NS), "Reference");
    let first = iter.next().ok_or(Error::SignatureVerification {
        reason: "SignedInfo has no Reference",
    })?;
    if iter.next().is_some() {
        return Err(Error::SignatureVerification {
            reason: "multi-reference signature rejected (XSW vector)",
        });
    }
    Ok(first)
}

/// Extract `<ds:KeyInfo>` content into a [`KeyInfo`] struct. Missing
/// `<ds:KeyInfo>` is fine — the verifier will fall back to `candidate_certs`.
fn extract_key_info(signature_element: &Element) -> KeyInfo {
    let Some(key_info_elem) = signature_element.child_element(Some(DS_NS), "KeyInfo") else {
        return KeyInfo::default();
    };
    let mut out = KeyInfo::default();

    if let Some(name_elem) = key_info_elem.child_element(Some(DS_NS), "KeyName") {
        out.key_name = Some(name_elem.text_content());
    }

    for x509_data in key_info_elem.all_child_elements(Some(DS_NS), "X509Data") {
        for cert_elem in x509_data.all_child_elements(Some(DS_NS), "X509Certificate") {
            // Preserve the raw text (including any whitespace); `KeyInfo`'s
            // consumer (`trusted_inline_certs`) strips whitespace on decode.
            out.x509_certificates_base64.push(cert_elem.text_content());
        }
        for subject in x509_data.all_child_elements(Some(DS_NS), "X509SubjectName") {
            out.x509_subject_names.push(subject.text_content());
        }
        for serial in x509_data.all_child_elements(Some(DS_NS), "X509IssuerSerial") {
            let issuer = serial
                .child_element(Some(DS_NS), "X509IssuerName")
                .map(Element::text_content)
                .unwrap_or_default();
            let serial_number = serial
                .child_element(Some(DS_NS), "X509SerialNumber")
                .map(Element::text_content)
                .unwrap_or_default();
            out.x509_issuer_serials.push((issuer, serial_number));
        }
    }

    out
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

    use crate::crypto::cert::test_vectors::*;
    use crate::crypto::keypair::KeyPair;
    use crate::dsig::algorithms::DigestAlgorithm;
    use crate::xml::parse::Document;

    /// Construct a SAML-shaped XML payload, sign it (locally, with the test
    /// keypair), and return the serialized XML plus the verifying cert.
    ///
    /// We build the document by string concatenation rather than going through
    /// the (Wave-3B-owned) `sign_element` API, so this test module has no
    /// cross-wave dependencies. The shape mirrors a typical IdP `<Response>`:
    ///
    /// ```xml
    /// <Root ID="root">
    ///   <Inner>payload</Inner>
    ///   <ds:Signature>
    ///     <ds:SignedInfo>...</ds:SignedInfo>
    ///     <ds:SignatureValue>...</ds:SignatureValue>
    ///     <ds:KeyInfo>
    ///       <ds:X509Data><ds:X509Certificate>...</ds:X509Certificate></ds:X509Data>
    ///     </ds:KeyInfo>
    ///   </ds:Signature>
    /// </Root>
    /// ```
    fn sign_test_root(
        target_id: &str,
        body_xml: &str,
        sig_alg: SignatureAlgorithm,
        c14n_alg: C14nAlgorithm,
    ) -> (String, X509Certificate) {
        let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).unwrap();
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();

        // ---- Stage 1: build the *signable* outer element (no Signature yet).
        // We need its canonical form *with* the eventual <ds:Signature> child
        // stripped — i.e. the enveloped-signature transform output. Since we
        // haven't added the Signature yet, canonicalizing now yields exactly
        // that.
        let stage_1_xml = format!(
            r#"<Root xmlns="urn:p" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="{target_id}">{body_xml}</Root>"#
        );
        let stage_1_doc = Document::parse(stage_1_xml.as_bytes()).unwrap();
        let chain_1 = ancestor_chain(&stage_1_doc, stage_1_doc.root().id()).unwrap();
        let canonical_root =
            canonicalize(&stage_1_doc, stage_1_doc.root(), &chain_1, c14n_alg, &[]).unwrap();
        let reference_digest = DigestAlgorithm::Sha256.digest(&canonical_root);
        let reference_digest_b64 = BASE64_STANDARD.encode(&reference_digest);

        // ---- Stage 2: build <ds:SignedInfo>, canonicalize, sign.
        let signed_info_inner = format!(
            r##"<ds:CanonicalizationMethod Algorithm="{c14n}"/><ds:SignatureMethod Algorithm="{sig}"/><ds:Reference URI="#{id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="{c14n}"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference>"##,
            c14n = c14n_alg.uri(),
            sig = sig_alg.uri(),
            id = target_id,
            digest = reference_digest_b64,
        );
        // To canonicalize <ds:SignedInfo>, parse it inside a wrapping element
        // so it has its `ds:` namespace declaration in scope.
        let signed_info_xml = format!(
            r#"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{signed_info_inner}</ds:SignedInfo>"#
        );
        let signed_info_doc = Document::parse(signed_info_xml.as_bytes()).unwrap();
        let signed_info_chain =
            ancestor_chain(&signed_info_doc, signed_info_doc.root().id()).unwrap();
        let signed_info_canonical = canonicalize(
            &signed_info_doc,
            signed_info_doc.root(),
            &signed_info_chain,
            c14n_alg,
            &[],
        )
        .unwrap();
        let sig_bytes = kp.sign(sig_alg, &signed_info_canonical).unwrap();
        let sig_b64 = BASE64_STANDARD.encode(&sig_bytes);

        // ---- Stage 3: assemble the final document.
        let cert_b64 = cert.to_base64_x509();
        let body = body_xml;
        let si_inner = &signed_info_inner;
        let sig = &sig_b64;
        let cert_text = &cert_b64;
        let final_xml = format!(
            r#"<Root xmlns="urn:p" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="{target_id}">{body}<ds:Signature><ds:SignedInfo>{si_inner}</ds:SignedInfo><ds:SignatureValue>{sig}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_text}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></Root>"#
        );
        (final_xml, cert)
    }

    #[test]
    fn happy_path_verifies_rsa_sha256() {
        let (xml, cert) = sign_test_root(
            "root-1",
            "<Inner>payload</Inner>",
            SignatureAlgorithm::RsaSha256,
            C14nAlgorithm::ExclusiveCanonical,
        );
        let doc = Document::parse(xml.as_bytes()).unwrap();
        let sig_elem = doc
            .find_first(Some(DS_NS), "Signature")
            .expect("ds:Signature");

        let verified = verify_signature(
            &doc,
            sig_elem,
            std::slice::from_ref(&cert),
            &[SignatureAlgorithm::RsaSha256],
        )
        .expect("should verify");

        assert_eq!(verified.signed_element, doc.root().id());
        assert_eq!(verified.signature_algorithm, SignatureAlgorithm::RsaSha256);
        assert_eq!(
            verified.verifying_cert_fingerprint,
            cert.fingerprint_sha256()
        );
    }

    #[test]
    fn rejects_when_signature_algorithm_not_in_allow_list() {
        let (xml, cert) = sign_test_root(
            "root-1",
            "<Inner>payload</Inner>",
            SignatureAlgorithm::RsaSha256,
            C14nAlgorithm::ExclusiveCanonical,
        );
        let doc = Document::parse(xml.as_bytes()).unwrap();
        let sig_elem = doc.find_first(Some(DS_NS), "Signature").unwrap();

        let err = verify_signature(
            &doc,
            sig_elem,
            &[cert],
            // Allow only RsaSha512 — does not include the signed algorithm.
            &[SignatureAlgorithm::RsaSha512],
        )
        .expect_err("should reject disallowed algorithm");
        assert!(matches!(err, Error::DisallowedAlgorithm { .. }));
    }

    #[test]
    fn rejects_when_digest_mismatches_after_tampering() {
        // Sign with one body, then tamper with the body bytes. The reference
        // digest will no longer match.
        let (xml, cert) = sign_test_root(
            "root-1",
            "<Inner>payload</Inner>",
            SignatureAlgorithm::RsaSha256,
            C14nAlgorithm::ExclusiveCanonical,
        );
        let tampered = xml.replace("payload", "TAMPERED");
        let doc = Document::parse(tampered.as_bytes()).unwrap();
        let sig_elem = doc.find_first(Some(DS_NS), "Signature").unwrap();

        let err = verify_signature(
            &doc,
            sig_elem,
            &[cert],
            &[SignatureAlgorithm::RsaSha256],
        )
        .expect_err("should reject tampered digest");
        assert!(
            matches!(
                err,
                Error::SignatureVerification {
                    reason: "digest mismatch"
                }
            ),
            "got: {err:?}"
        );
    }

    #[test]
    fn rejects_multi_reference_signature() {
        // Hand-craft a SignedInfo with two References. The signed-info bytes
        // don't need to verify — multi-reference rejection happens before key
        // material is touched.
        let xml = r##"<Root xmlns="urn:p" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="root-1">
            <Inner ID="a">payload</Inner>
            <Inner2 ID="b">other</Inner2>
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                    <ds:Reference URI="#a">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AAAA</ds:DigestValue>
                    </ds:Reference>
                    <ds:Reference URI="#b">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AAAA</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AAAA</ds:SignatureValue>
            </ds:Signature>
        </Root>"##;
        let doc = Document::parse(xml.as_bytes()).unwrap();
        let sig_elem = doc.find_first(Some(DS_NS), "Signature").unwrap();
        let err = verify_signature(&doc, sig_elem, &[], &[SignatureAlgorithm::RsaSha256])
            .expect_err("multi-reference must be rejected");
        assert!(
            matches!(
                err,
                Error::SignatureVerification {
                    reason: "multi-reference signature rejected (XSW vector)"
                }
            ),
            "got: {err:?}"
        );
    }

    #[test]
    fn rejects_disallowed_transform_in_reference() {
        // SignedInfo declares an XSLT transform inside the Reference; the
        // transform whitelist rejects it before any crypto runs.
        let xml = r##"<Root xmlns="urn:p" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="root-1">
            <Inner>payload</Inner>
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                    <ds:Reference URI="#root-1">
                        <ds:Transforms>
                            <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116"/>
                        </ds:Transforms>
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AAAA</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AAAA</ds:SignatureValue>
            </ds:Signature>
        </Root>"##;
        let doc = Document::parse(xml.as_bytes()).unwrap();
        let sig_elem = doc.find_first(Some(DS_NS), "Signature").unwrap();
        let err = verify_signature(&doc, sig_elem, &[], &[SignatureAlgorithm::RsaSha256])
            .expect_err("XSLT transform must be rejected");
        assert!(matches!(err, Error::DisallowedTransform { .. }));
    }

    #[test]
    fn rejects_missing_signed_info() {
        let xml = r#"<Root xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Signature/></Root>"#;
        let doc = Document::parse(xml.as_bytes()).unwrap();
        let sig_elem = doc.find_first(Some(DS_NS), "Signature").unwrap();
        let err = verify_signature(&doc, sig_elem, &[], &[SignatureAlgorithm::RsaSha256])
            .expect_err("missing SignedInfo must be rejected");
        assert!(matches!(
            err,
            Error::SignatureVerification {
                reason: "missing SignedInfo"
            }
        ));
    }

    #[test]
    fn rejects_unknown_signature_method() {
        let xml = r#"<Root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    <ds:SignatureMethod Algorithm="http://example.com/unknown"/>
                    <ds:Reference><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AAAA</ds:SignatureValue>
            </ds:Signature>
        </Root>"#;
        let doc = Document::parse(xml.as_bytes()).unwrap();
        let sig_elem = doc.find_first(Some(DS_NS), "Signature").unwrap();
        let err = verify_signature(&doc, sig_elem, &[], &[SignatureAlgorithm::RsaSha256])
            .expect_err("unknown SignatureMethod must be rejected");
        assert!(matches!(err, Error::DisallowedAlgorithm { .. }));
    }

    #[test]
    fn verify_signature_extracts_inline_keyinfo() {
        // Confirm `extract_key_info` round-trips the X.509 cert blob into
        // `KeyInfo.x509_certificates_base64`. This is the data the verifier
        // pin-checks before honoring inline cert material (RFC-002 §3.1
        // step 6 / RFC-002 §8 "Cert chain confusion").
        let (xml, cert) = sign_test_root(
            "root-1",
            "<Inner>payload</Inner>",
            SignatureAlgorithm::RsaSha256,
            C14nAlgorithm::ExclusiveCanonical,
        );
        let doc = Document::parse(xml.as_bytes()).unwrap();
        let sig_elem = doc.find_first(Some(DS_NS), "Signature").unwrap();
        let key_info = extract_key_info(sig_elem);
        assert_eq!(key_info.x509_certificates_base64.len(), 1);
        // The fingerprint pin gates the inline cert before it can verify
        // anything — test that gate directly via `trusted_inline_certs`.
        let trusted = key_info.trusted_inline_certs(std::slice::from_ref(&cert));
        assert_eq!(trusted.len(), 1);
        assert_eq!(trusted[0], cert);
    }

    // ---- Detached HTTP-Redirect verification --------------------------------

    #[test]
    fn detached_signature_verifies_success() {
        let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).unwrap();
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        let qs = b"SAMLRequest=abc&RelayState=xyz&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256";
        let sig = kp.sign(SignatureAlgorithm::RsaSha256, qs).unwrap();

        let m = verify_detached_signature(
            qs,
            &sig,
            SignatureAlgorithm::RsaSha256,
            std::slice::from_ref(&cert),
            &[SignatureAlgorithm::RsaSha256],
        )
        .expect("detached signature should verify");
        assert_eq!(m.cert_fingerprint, cert.fingerprint_sha256());
        assert_eq!(m.algorithm, SignatureAlgorithm::RsaSha256);
    }

    #[test]
    fn detached_signature_rejects_bit_flip_in_signature() {
        let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).unwrap();
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        let qs = b"SAMLRequest=abc&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256";
        let mut sig = kp.sign(SignatureAlgorithm::RsaSha256, qs).unwrap();
        sig[0] ^= 0x01;

        let err = verify_detached_signature(
            qs,
            &sig,
            SignatureAlgorithm::RsaSha256,
            &[cert],
            &[SignatureAlgorithm::RsaSha256],
        )
        .expect_err("tampered signature must be rejected");
        assert!(matches!(
            err,
            Error::SignatureVerification {
                reason: "no candidate cert matched"
            }
        ));
    }

    #[test]
    fn detached_signature_rejects_when_alg_not_in_allow_list() {
        let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).unwrap();
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        let qs = b"SAMLRequest=abc";
        let sig = kp.sign(SignatureAlgorithm::RsaSha256, qs).unwrap();

        let err = verify_detached_signature(
            qs,
            &sig,
            SignatureAlgorithm::RsaSha256,
            &[cert],
            // Allow only RsaSha512 — signing alg not allowed.
            &[SignatureAlgorithm::RsaSha512],
        )
        .expect_err("disallowed algorithm must be rejected");
        assert!(matches!(err, Error::DisallowedAlgorithm { .. }));
    }

    #[test]
    fn detached_signature_rejects_query_string_tampering() {
        let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).unwrap();
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        let qs_signed = b"SAMLRequest=abc&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256";
        let qs_tampered = b"SAMLRequest=XYZ&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256";
        let sig = kp.sign(SignatureAlgorithm::RsaSha256, qs_signed).unwrap();
        let err = verify_detached_signature(
            qs_tampered,
            &sig,
            SignatureAlgorithm::RsaSha256,
            &[cert],
            &[SignatureAlgorithm::RsaSha256],
        )
        .expect_err("query string tampering must be rejected");
        assert!(matches!(
            err,
            Error::SignatureVerification {
                reason: "no candidate cert matched"
            }
        ));
    }

    // ---- Structural XSW property: verified payload extraction --------------

    #[test]
    fn verified_signed_element_routes_through_element_id() {
        // The verified handle's `signed_element` MUST resolve to the same
        // element the signature covered, irrespective of any subsequent
        // name-based lookups. (We exercise this end-to-end: the verified ID
        // resolves to the same element we built and signed.)
        let (xml, cert) = sign_test_root(
            "root-1",
            "<Inner>payload</Inner>",
            SignatureAlgorithm::RsaSha256,
            C14nAlgorithm::ExclusiveCanonical,
        );
        let doc = Document::parse(xml.as_bytes()).unwrap();
        let sig_elem = doc.find_first(Some(DS_NS), "Signature").unwrap();
        let verified = verify_signature(
            &doc,
            sig_elem,
            &[cert],
            &[SignatureAlgorithm::RsaSha256],
        )
        .expect("should verify");

        let resolved = doc.element(verified.signed_element).expect("element by id");
        assert_eq!(resolved.qname().local(), "Root");
        // The Root carries ID="root-1"; the id_index points to the same
        // element, confirming there's a single resolution path.
        let by_id = doc.element_by_id_attr("root-1").unwrap();
        assert_eq!(verified.signed_element, by_id);
    }
}
