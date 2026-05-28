//! XML-DSig signing (outbound).
//!
//! See `docs/rfcs/RFC-002-xml-crypto-core.md` §6.
//!
//! Two entry points:
//!
//! - `sign_element` — embeds an enveloped `<ds:Signature>` inside a SAML
//!   protocol element (typically `<samlp:Response>`, `<saml:Assertion>`,
//!   `<samlp:AuthnRequest>`, or `<samlp:LogoutRequest>`).
//! - `sign_detached_query` — computes the raw signature bytes for the
//!   HTTP-Redirect binding (SAML 2.0 §3.4.4.1); the caller is responsible for
//!   base64-encoding the result into the `Signature=` query parameter.
//!
//! ## Where the signature lives in the tree
//!
//! Per SAML 2.0 §1.5 + the XSD, `<ds:Signature>` MUST appear in the
//! `signaturePosition` slot of the signed element: immediately *after* the
//! `<saml:Issuer>` child when present, otherwise as the very first child. We
//! enforce that by walking the target element's children and splicing the
//! `<ds:Signature>` at the schema-correct index.
//!
//! ## Reference URI
//!
//! Every SAML signable element carries an `ID` attribute (unqualified — XML
//! Schema `xs:ID` typing means no namespace). The `<ds:Reference URI="#…">`
//! is always `#<ID>`. If the target element has no `ID` we refuse to sign:
//! the resulting signature would be unverifiable (no anchor for the
//! reference) and would surface as XSW-prone if force-emitted with an empty
//! URI.
//!
//! ## Digest path
//!
//! The transform chain on the `<ds:Reference>` is fixed by spec to
//! `enveloped-signature` followed by the chosen C14N. Because the signature
//! is added *after* digest computation here, the enveloped-signature
//! transform is a no-op at sign time — the target element does not yet
//! contain a `<ds:Signature>` to strip. We canonicalize the target as-is and
//! digest that. On the verifier's side the inverse holds: the verifier
//! strips the signature element before canonicalizing, recovering the same
//! bytes.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

use crate::crypto::keypair::KeyPair;
use crate::dsig::algorithms::{C14nAlgorithm, DigestAlgorithm, SignatureAlgorithm};
use crate::dsig::c14n::canonicalize;
use crate::dsig::reference::{DS_NS as DSIG_NS, EC_NS, ENVELOPED_SIGNATURE_URI};
use crate::error::Error;
use crate::xml::parse::{Document, Element, Node, QName};

/// SAML 2.0 assertion namespace URI; `<saml:Issuer>` lives here.
const SAML_ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

/// Embed an enveloped XML-DSig signature inside `element` (which must carry
/// an `ID` attribute — SAML 2.0 §1.5 mandates `ID` on every signable
/// element).
///
/// Per RFC-002 §6, the signature is positioned *after* the `<saml:Issuer>`
/// child element (or as the first child if there is no `<saml:Issuer>`) to
/// satisfy the SAML 2.0 schema's `signaturePosition` constraint.
///
/// Steps:
/// 1. Canonicalize the target element (no signature present yet) per
///    `c14n`.
/// 2. Compute digest of canonical bytes per `digest`.
/// 3. Build `<ds:SignedInfo>` with CanonicalizationMethod, SignatureMethod,
///    and one `<ds:Reference URI="#<element-ID>">` carrying the digest.
/// 4. Canonicalize `<ds:SignedInfo>` per `c14n`.
/// 5. Sign the canonical `<ds:SignedInfo>` bytes with `signing_key` using
///    `signature_algorithm`.
/// 6. Build `<ds:Signature>` with the SignedInfo, the base64-encoded
///    SignatureValue, and (if `include_x509_cert`) a `<ds:KeyInfo>/
///    <ds:X509Data>/<ds:X509Certificate>` carrying the signing cert.
/// 7. Splice `<ds:Signature>` into the target element's children at the
///    schema-correct position.
///
/// Returns the modified `element` with the signature embedded. The
/// element's `ID` is preserved; no other content is altered. Callers that
/// need a fresh `ElementId` index should re-wrap the returned element with
/// `Document::new`.
///
/// Cryptographic and serialization options are bundled into [`SignOptions`]
/// so the call signature stays focused on the two structural inputs (target
/// element, document context). See [`SignOptions`] for the field-level
/// documentation.
pub(crate) fn sign_element(
    element: Element,
    document_context: &Document,
    opts: SignOptions<'_>,
) -> Result<Element, Error> {
    let SignOptions {
        signing_key,
        sig_alg,
        digest_alg,
        c14n_alg,
        inclusive_namespaces,
        include_x509_cert,
    } = opts;

    // ---- Step 0: locate the element's ID attribute. -----------------------
    let id_value = element
        .attribute(None, "ID")
        .ok_or(Error::InvalidConfiguration {
            reason: "signing target requires ID attribute",
        })?
        .to_owned();

    // ---- Step 1: canonicalize the target element (no signature yet). ------
    // The element lives somewhere inside `document_context`, but we don't
    // require the caller to give us its ancestor chain. Exclusive C14N's
    // namespace-rendering rules only depend on the ancestor *in-scope*
    // namespace set; for the SAML signing path the element is always either
    // the document root (no ancestors) or a top-level child where the
    // ancestor namespace decls don't visibly affect the canonical output of
    // the element itself (Exclusive C14N drops namespaces that aren't
    // visibly utilized by the apex). Passing an empty ancestor chain
    // matches `canonicalize`'s use of "apex" mode: it renders the
    // namespaces visibly utilized by the element + descendants, which is
    // exactly the inclusive-namespace-prefixes-honoring set the verifier
    // recomputes. This is the same convention `dsig::c14n`'s own tests use.
    let target_canonical = canonicalize(
        document_context,
        &element,
        &[],
        c14n_alg,
        inclusive_namespaces,
    )?;
    let digest_bytes = digest_alg.digest(&target_canonical);
    let digest_b64 = BASE64_STANDARD.encode(&digest_bytes);

    // ---- Step 2/3: build the <ds:SignedInfo> subtree. ---------------------
    // We declare the `ds` prefix on the `<ds:Signature>` element (step 6
    // below). `<ds:SignedInfo>` inherits the binding by ancestor scope, so
    // we don't re-declare it here. For the standalone canonicalization of
    // SignedInfo in step 4 we synthesize a transient document whose root
    // *does* declare `xmlns:ds`, so the c14n pass sees an in-scope binding.
    let signed_info = build_signed_info(
        sig_alg,
        digest_alg,
        c14n_alg,
        &id_value,
        &digest_b64,
        inclusive_namespaces,
    );

    // ---- Step 4: canonicalize <ds:SignedInfo>. ----------------------------
    // Build a fresh document whose root *is* the SignedInfo, with the `ds`
    // namespace declared on it. This satisfies the c14n pass's requirement
    // that every visibly-utilized prefix have an in-scope declaration.
    let signed_info_root = clone_with_namespace(
        &signed_info,
        Some("ds".to_owned()),
        DSIG_NS.to_owned(),
    );
    let signed_info_doc = Document::new(signed_info_root)?;
    let signed_info_canonical = canonicalize(
        &signed_info_doc,
        signed_info_doc.root(),
        &[],
        c14n_alg,
        inclusive_namespaces,
    )?;

    // ---- Step 5: produce the signature bytes. -----------------------------
    let signature_bytes = signing_key.sign(sig_alg, &signed_info_canonical)?;
    let signature_b64 = BASE64_STANDARD.encode(&signature_bytes);

    // ---- Step 6: assemble the <ds:Signature> element. ---------------------
    let signature_element = build_signature_element(
        signed_info,
        &signature_b64,
        include_x509_cert,
        signing_key,
    )?;

    // ---- Step 7: splice the <ds:Signature> into `element`. ----------------
    let position = signature_insertion_index(&element);
    let mut element = element;
    element.insert_child(position, Node::Element(signature_element));
    Ok(element)
}

/// Bundle of cryptographic + canonicalization options consumed by
/// [`sign_element`].
///
/// Grouping these into a single struct keeps the call signature focused on
/// the two structural inputs (target element + document context). Every
/// field is load-bearing — there are intentionally no defaults — so callers
/// must spell out exactly which algorithms the signature uses.
pub(crate) struct SignOptions<'a> {
    /// Private key (with optional certificate) used to produce the signature
    /// bytes over `<ds:SignedInfo>`.
    pub signing_key: &'a KeyPair,
    /// Signature algorithm advertised in `<ds:SignatureMethod Algorithm="…">`
    /// and used for the actual sign operation.
    pub sig_alg: SignatureAlgorithm,
    /// Digest algorithm advertised in `<ds:DigestMethod Algorithm="…">` and
    /// used to hash the canonicalized target element.
    pub digest_alg: DigestAlgorithm,
    /// C14N algorithm applied both to the target element (for the digest)
    /// and to `<ds:SignedInfo>` (for the signature input).
    pub c14n_alg: C14nAlgorithm,
    /// PrefixList for `<ec:InclusiveNamespaces>` when `c14n_alg` is
    /// Exclusive. Empty means no `<ec:InclusiveNamespaces>` child is
    /// attached to the C14N transform.
    pub inclusive_namespaces: &'a [&'a str],
    /// When true, attach `<ds:KeyInfo>/<ds:X509Data>/<ds:X509Certificate>`
    /// carrying `signing_key`'s certificate. Errors if the key has no cert.
    pub include_x509_cert: bool,
}

/// Sign a detached query-string payload per HTTP-Redirect binding spec
/// §3.4.4.1. Returns the raw signature bytes (caller base64-encodes them
/// for the `Signature=` query parameter).
pub(crate) fn sign_detached_query(
    canonical_query_string: &[u8],
    signing_key: &KeyPair,
    signature_algorithm: SignatureAlgorithm,
) -> Result<Vec<u8>, Error> {
    signing_key.sign(signature_algorithm, canonical_query_string)
}

// =============================================================================
// Helpers
// =============================================================================

/// QName under the XML-DSig namespace.
fn ds(local: &str) -> QName {
    QName::new(Some(DSIG_NS.to_owned()), local)
}

/// QName under the Exclusive-C14N namespace (`<ec:InclusiveNamespaces>`).
fn ec(local: &str) -> QName {
    QName::new(Some(EC_NS.to_owned()), local)
}

/// Build the `<ds:SignedInfo>` subtree. The `ds` namespace prefix is
/// expected to be in scope from the enclosing `<ds:Signature>` element
/// (`build_signature_element` declares it there).
fn build_signed_info(
    signature_algorithm: SignatureAlgorithm,
    digest: DigestAlgorithm,
    c14n: C14nAlgorithm,
    id_value: &str,
    digest_b64: &str,
    inclusive_namespace_prefixes: &[&str],
) -> Element {
    let canonicalization_method = Element::build(ds("CanonicalizationMethod"))
        .with_attribute(QName::new(None, "Algorithm"), c14n.uri())
        .finish();

    let signature_method = Element::build(ds("SignatureMethod"))
        .with_attribute(QName::new(None, "Algorithm"), signature_algorithm.uri())
        .finish();

    // Transforms: always enveloped-signature, then the chosen C14N.
    // If a non-empty PrefixList was supplied AND the c14n is Exclusive, we
    // attach `<ec:InclusiveNamespaces PrefixList="...">` as a child of the
    // C14N transform per Exclusive-C14N §3.1.
    let enveloped_transform = Element::build(ds("Transform"))
        .with_attribute(QName::new(None, "Algorithm"), ENVELOPED_SIGNATURE_URI)
        .finish();

    let mut c14n_transform_builder = Element::build(ds("Transform"))
        .with_attribute(QName::new(None, "Algorithm"), c14n.uri());
    if c14n.is_exclusive() && !inclusive_namespace_prefixes.is_empty() {
        let prefix_list = inclusive_namespace_prefixes.join(" ");
        let inclusive = Element::build(ec("InclusiveNamespaces"))
            .with_namespace(Some("ec".to_owned()), EC_NS)
            .with_attribute(QName::new(None, "PrefixList"), prefix_list)
            .finish();
        c14n_transform_builder =
            c14n_transform_builder.with_child(Node::Element(inclusive));
    }
    let c14n_transform = c14n_transform_builder.finish();

    let transforms = Element::build(ds("Transforms"))
        .with_child(Node::Element(enveloped_transform))
        .with_child(Node::Element(c14n_transform))
        .finish();

    let digest_method = Element::build(ds("DigestMethod"))
        .with_attribute(QName::new(None, "Algorithm"), digest.uri())
        .finish();

    let digest_value = Element::build(ds("DigestValue"))
        .with_text(digest_b64.to_owned())
        .finish();

    let reference = Element::build(ds("Reference"))
        .with_attribute(QName::new(None, "URI"), format!("#{id_value}"))
        .with_child(Node::Element(transforms))
        .with_child(Node::Element(digest_method))
        .with_child(Node::Element(digest_value))
        .finish();

    Element::build(ds("SignedInfo"))
        .with_child(Node::Element(canonicalization_method))
        .with_child(Node::Element(signature_method))
        .with_child(Node::Element(reference))
        .finish()
}

/// Assemble the `<ds:Signature>` element. The `ds` prefix is declared on
/// this element (the root of the signature subtree) and inherited by all
/// descendants via ancestor namespace scope.
fn build_signature_element(
    signed_info: Element,
    signature_b64: &str,
    include_x509_cert: bool,
    signing_key: &KeyPair,
) -> Result<Element, Error> {
    let signature_value = Element::build(ds("SignatureValue"))
        .with_text(signature_b64.to_owned())
        .finish();

    let mut signature_builder = Element::build(ds("Signature"))
        .with_namespace(Some("ds".to_owned()), DSIG_NS)
        .with_child(Node::Element(signed_info))
        .with_child(Node::Element(signature_value));

    if include_x509_cert {
        let cert = signing_key
            .certificate()
            .ok_or(Error::InvalidConfiguration {
                reason: "include_x509_cert requested but signing key has no certificate",
            })?;
        let x509_certificate = Element::build(ds("X509Certificate"))
            .with_text(cert.to_base64_x509())
            .finish();
        let x509_data = Element::build(ds("X509Data"))
            .with_child(Node::Element(x509_certificate))
            .finish();
        let key_info = Element::build(ds("KeyInfo"))
            .with_child(Node::Element(x509_data))
            .finish();
        signature_builder = signature_builder.with_child(Node::Element(key_info));
    }

    Ok(signature_builder.finish())
}

/// Clone `element` and prepend a namespace declaration to its
/// `namespaces_declared_here`. Used so the standalone canonicalization of
/// `<ds:SignedInfo>` (which normally inherits `xmlns:ds` from its
/// `<ds:Signature>` parent) sees an in-scope binding.
fn clone_with_namespace(element: &Element, prefix: Option<String>, uri: String) -> Element {
    let mut cloned = element.clone();
    // Prepend so the new declaration is visible at the top of the in-scope
    // set; later entries with the same prefix would shadow it. SignedInfo
    // does not itself re-declare `ds`, so there is no collision here.
    cloned.namespaces_declared_here.insert(0, (prefix, uri));
    cloned
}

/// Choose the child-index at which to splice `<ds:Signature>`. Schema rule:
/// after `<saml:Issuer>` if present (the first such occurrence in document
/// order), otherwise as the first child (`0`).
fn signature_insertion_index(element: &Element) -> usize {
    for (idx, child) in element.children().enumerate() {
        if let Node::Element(child_elem) = child
            && child_elem.qname().local() == "Issuer"
            && child_elem.qname().namespace() == Some(SAML_ASSERTION_NS)
        {
            // `enumerate` yields a usize bounded by the child count and never
            // overflows in practice; the checked add satisfies the
            // `arithmetic_side_effects` restriction. Falling back to `idx`
            // would still place the signature inside the element (just at the
            // Issuer's index instead of after it) on the impossible-in-practice
            // overflow path.
            return idx.checked_add(1).unwrap_or(idx);
        }
    }
    0
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cert::X509Certificate;
    use crate::crypto::cert::test_vectors::{
        EC_P256_CERT_PEM, EC_P256_KEY_PKCS8_PEM, RSA_CERT_PEM, RSA_KEY_PKCS8_PEM,
    };

    /// Build `<samlp:Response ID="..."><saml:Issuer>...</saml:Issuer>...</samlp:Response>`.
    fn build_response_with_issuer(id: &str, with_issuer: bool) -> Element {
        let samlp_ns = "urn:oasis:names:tc:SAML:2.0:protocol";
        let mut builder = Element::build(QName::new(Some(samlp_ns.to_owned()), "Response"))
            .with_namespace(Some("samlp".to_owned()), samlp_ns)
            .with_namespace(Some("saml".to_owned()), SAML_ASSERTION_NS)
            .with_attribute(QName::new(None, "ID"), id)
            .with_attribute(QName::new(None, "Version"), "2.0")
            .with_attribute(
                QName::new(None, "IssueInstant"),
                "2024-01-01T00:00:00Z",
            );

        if with_issuer {
            let issuer = Element::build(QName::new(
                Some(SAML_ASSERTION_NS.to_owned()),
                "Issuer",
            ))
            .with_text("https://idp.example.com")
            .finish();
            builder = builder.with_child(Node::Element(issuer));
        }

        let status = Element::build(QName::new(Some(samlp_ns.to_owned()), "Status"))
            .with_child(Node::Element(
                Element::build(QName::new(Some(samlp_ns.to_owned()), "StatusCode"))
                    .with_attribute(
                        QName::new(None, "Value"),
                        "urn:oasis:names:tc:SAML:2.0:status:Success",
                    )
                    .finish(),
            ))
            .finish();
        builder = builder.with_child(Node::Element(status));

        builder.finish()
    }

    fn rsa_key_with_cert() -> KeyPair {
        let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).unwrap();
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        kp.with_certificate(cert)
    }

    fn ecdsa_key_with_cert() -> KeyPair {
        let kp = KeyPair::from_pkcs8_pem(EC_P256_KEY_PKCS8_PEM).unwrap();
        let cert = X509Certificate::from_pem(EC_P256_CERT_PEM).unwrap();
        kp.with_certificate(cert)
    }

    /// Locate the first `<ds:Signature>` child of `element`.
    fn find_signature(element: &Element) -> Option<&Element> {
        element.child_element(Some(DSIG_NS), "Signature")
    }

    /// Locate `<ds:SignedInfo>` inside `<ds:Signature>`.
    fn signed_info_of(signature: &Element) -> &Element {
        signature
            .child_element(Some(DSIG_NS), "SignedInfo")
            .expect("SignedInfo present")
    }

    /// Locate the lone `<ds:Reference>` and extract DigestValue text.
    fn digest_value_of(signed_info: &Element) -> String {
        let reference = signed_info
            .child_element(Some(DSIG_NS), "Reference")
            .expect("Reference present");
        let dv = reference
            .child_element(Some(DSIG_NS), "DigestValue")
            .expect("DigestValue present");
        dv.text_content()
    }

    #[test]
    fn signs_rsa_sha256_and_digest_recomputes() {
        let response = build_response_with_issuer("resp-1", true);
        let doc = Document::new(response).unwrap();
        let target = doc.root().clone();

        let kp = rsa_key_with_cert();
        let signed = sign_element(
            target,
            &doc,
            SignOptions {
                signing_key: &kp,
                sig_alg: SignatureAlgorithm::RsaSha256,
                digest_alg: DigestAlgorithm::Sha256,
                c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                inclusive_namespaces: &[],
                include_x509_cert: true,
            },
        )
        .expect("sign");

        // The Signature element must be present, right after <saml:Issuer>.
        let signature = find_signature(&signed).expect("signature embedded");
        // Issuer should still be the first child; Signature second.
        let mut iter = signed.child_elements();
        let first = iter.next().expect("first child");
        assert_eq!(first.qname().local(), "Issuer");
        let second = iter.next().expect("second child");
        assert_eq!(second.qname().local(), "Signature");

        // Recompute the digest from the canonical bytes of the target element
        // with the signature stripped, and confirm it matches the embedded
        // DigestValue (which is what the verifier will do).
        let mut sans_signature = signed.clone();
        sans_signature.children.retain(|n| match n {
            Node::Element(e) => !(e.qname().local() == "Signature"
                && e.qname().namespace() == Some(DSIG_NS)),
            _ => true,
        });
        // Rewrap into a doc so canonicalize has a context.
        let stripped_doc = Document::new(sans_signature).unwrap();
        let recomputed_canonical = canonicalize(
            &stripped_doc,
            stripped_doc.root(),
            &[],
            C14nAlgorithm::ExclusiveCanonical,
            &[],
        )
        .unwrap();
        let recomputed = DigestAlgorithm::Sha256.digest(&recomputed_canonical);
        let recomputed_b64 = BASE64_STANDARD.encode(&recomputed);
        let signed_info = signed_info_of(signature);
        assert_eq!(digest_value_of(signed_info), recomputed_b64);

        // <ds:KeyInfo>/<ds:X509Data>/<ds:X509Certificate> populated.
        let key_info = signature
            .child_element(Some(DSIG_NS), "KeyInfo")
            .expect("KeyInfo present");
        let x509_data = key_info
            .child_element(Some(DSIG_NS), "X509Data")
            .expect("X509Data present");
        let x509_cert = x509_data
            .child_element(Some(DSIG_NS), "X509Certificate")
            .expect("X509Certificate present");
        assert!(!x509_cert.text_content().is_empty());
    }

    #[test]
    fn signs_with_ecdsa_p256_sha256() {
        let response = build_response_with_issuer("resp-2", true);
        let doc = Document::new(response).unwrap();
        let target = doc.root().clone();

        let kp = ecdsa_key_with_cert();
        let signed = sign_element(
            target,
            &doc,
            SignOptions {
                signing_key: &kp,
                sig_alg: SignatureAlgorithm::EcdsaSha256,
                digest_alg: DigestAlgorithm::Sha256,
                c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                inclusive_namespaces: &[],
                include_x509_cert: false,
            },
        )
        .expect("sign");

        let signature = find_signature(&signed).expect("signature embedded");
        // No KeyInfo when include_x509_cert is false.
        assert!(
            signature
                .child_element(Some(DSIG_NS), "KeyInfo")
                .is_none(),
            "KeyInfo should be absent when include_x509_cert=false"
        );

        // SignatureValue length: base64-decoded length must be 64 (P-256
        // IEEE P1363).
        let sig_value = signature
            .child_element(Some(DSIG_NS), "SignatureValue")
            .expect("SignatureValue present");
        let raw = BASE64_STANDARD
            .decode(sig_value.text_content().trim().as_bytes())
            .expect("base64");
        assert_eq!(raw.len(), 64);

        // SignedInfo algorithm URI is ECDSA-SHA256.
        let signed_info = signed_info_of(signature);
        let method = signed_info
            .child_element(Some(DSIG_NS), "SignatureMethod")
            .unwrap();
        assert_eq!(
            method.attribute(None, "Algorithm"),
            Some(SignatureAlgorithm::EcdsaSha256.uri())
        );
    }

    #[test]
    fn places_signature_after_issuer_when_present() {
        let response = build_response_with_issuer("resp-3", true);
        let doc = Document::new(response).unwrap();
        let target = doc.root().clone();

        let kp = rsa_key_with_cert();
        let signed = sign_element(
            target,
            &doc,
            SignOptions {
                signing_key: &kp,
                sig_alg: SignatureAlgorithm::RsaSha256,
                digest_alg: DigestAlgorithm::Sha256,
                c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                inclusive_namespaces: &[],
                include_x509_cert: false,
            },
        )
        .unwrap();

        // Walk children: first non-text element should be Issuer, then Signature.
        let elements: Vec<&Element> = signed.child_elements().collect();
        assert!(elements.len() >= 2);
        assert_eq!(elements[0].qname().local(), "Issuer");
        assert_eq!(elements[1].qname().local(), "Signature");
    }

    #[test]
    fn places_signature_first_when_no_issuer() {
        let response = build_response_with_issuer("resp-4", false);
        let doc = Document::new(response).unwrap();
        let target = doc.root().clone();

        let kp = rsa_key_with_cert();
        let signed = sign_element(
            target,
            &doc,
            SignOptions {
                signing_key: &kp,
                sig_alg: SignatureAlgorithm::RsaSha256,
                digest_alg: DigestAlgorithm::Sha256,
                c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                inclusive_namespaces: &[],
                include_x509_cert: false,
            },
        )
        .unwrap();

        let elements: Vec<&Element> = signed.child_elements().collect();
        assert!(!elements.is_empty());
        assert_eq!(elements[0].qname().local(), "Signature");
    }

    #[test]
    fn rejects_target_without_id_attribute() {
        let samlp_ns = "urn:oasis:names:tc:SAML:2.0:protocol";
        let response = Element::build(QName::new(Some(samlp_ns.to_owned()), "Response"))
            .with_namespace(Some("samlp".to_owned()), samlp_ns)
            // No ID attribute!
            .with_attribute(QName::new(None, "Version"), "2.0")
            .finish();
        let doc = Document::new(response).unwrap();
        let target = doc.root().clone();

        let kp = rsa_key_with_cert();
        let err = sign_element(
            target,
            &doc,
            SignOptions {
                signing_key: &kp,
                sig_alg: SignatureAlgorithm::RsaSha256,
                digest_alg: DigestAlgorithm::Sha256,
                c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                inclusive_namespaces: &[],
                include_x509_cert: false,
            },
        )
        .unwrap_err();
        match err {
            Error::InvalidConfiguration { reason } => {
                assert!(reason.contains("ID"), "got: {reason}");
            }
            other => panic!("expected InvalidConfiguration, got {other:?}"),
        }
    }

    #[test]
    fn rejects_include_x509_without_certificate() {
        let response = build_response_with_issuer("resp-5", true);
        let doc = Document::new(response).unwrap();
        let target = doc.root().clone();

        // KeyPair without certificate attached.
        let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).unwrap();
        let err = sign_element(
            target,
            &doc,
            SignOptions {
                signing_key: &kp,
                sig_alg: SignatureAlgorithm::RsaSha256,
                digest_alg: DigestAlgorithm::Sha256,
                c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                inclusive_namespaces: &[],
                include_x509_cert: true,
            },
        )
        .unwrap_err();
        match err {
            Error::InvalidConfiguration { reason } => {
                assert!(reason.contains("certificate"), "got: {reason}");
            }
            other => panic!("expected InvalidConfiguration, got {other:?}"),
        }
    }

    #[test]
    fn detached_query_rsa_signature_length() {
        let kp = rsa_key_with_cert();
        let query = b"SAMLRequest=AAA&RelayState=state&SigAlg=foo";
        let sig =
            sign_detached_query(query, &kp, SignatureAlgorithm::RsaSha256).expect("sign");
        // RSA-2048 signature: 256 bytes.
        assert_eq!(sig.len(), 256);
    }

    #[test]
    fn detached_query_ecdsa_signature_length() {
        let kp = ecdsa_key_with_cert();
        let query = b"SAMLRequest=AAA&RelayState=state&SigAlg=foo";
        let sig = sign_detached_query(query, &kp, SignatureAlgorithm::EcdsaSha256)
            .expect("sign");
        // ECDSA P-256 IEEE P1363: 64 bytes.
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn signature_method_uri_matches_algorithm() {
        let response = build_response_with_issuer("resp-6", true);
        let doc = Document::new(response).unwrap();
        let target = doc.root().clone();

        let kp = rsa_key_with_cert();
        let signed = sign_element(
            target,
            &doc,
            SignOptions {
                signing_key: &kp,
                sig_alg: SignatureAlgorithm::RsaSha512,
                digest_alg: DigestAlgorithm::Sha512,
                c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                inclusive_namespaces: &[],
                include_x509_cert: false,
            },
        )
        .unwrap();
        let signature = find_signature(&signed).unwrap();
        let signed_info = signed_info_of(signature);
        let method = signed_info
            .child_element(Some(DSIG_NS), "SignatureMethod")
            .unwrap();
        assert_eq!(
            method.attribute(None, "Algorithm"),
            Some(SignatureAlgorithm::RsaSha512.uri())
        );
        let digest_method = signed_info
            .child_element(Some(DSIG_NS), "Reference")
            .unwrap()
            .child_element(Some(DSIG_NS), "DigestMethod")
            .unwrap();
        assert_eq!(
            digest_method.attribute(None, "Algorithm"),
            Some(DigestAlgorithm::Sha512.uri())
        );
    }

    #[test]
    fn reference_uri_is_hash_of_id() {
        let response = build_response_with_issuer("my-special-id", true);
        let doc = Document::new(response).unwrap();
        let target = doc.root().clone();

        let kp = rsa_key_with_cert();
        let signed = sign_element(
            target,
            &doc,
            SignOptions {
                signing_key: &kp,
                sig_alg: SignatureAlgorithm::RsaSha256,
                digest_alg: DigestAlgorithm::Sha256,
                c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                inclusive_namespaces: &[],
                include_x509_cert: false,
            },
        )
        .unwrap();
        let signature = find_signature(&signed).unwrap();
        let signed_info = signed_info_of(signature);
        let reference = signed_info
            .child_element(Some(DSIG_NS), "Reference")
            .unwrap();
        assert_eq!(reference.attribute(None, "URI"), Some("#my-special-id"));
    }

    #[test]
    fn enveloped_signature_transform_emitted() {
        let response = build_response_with_issuer("resp-7", true);
        let doc = Document::new(response).unwrap();
        let target = doc.root().clone();

        let kp = rsa_key_with_cert();
        let signed = sign_element(
            target,
            &doc,
            SignOptions {
                signing_key: &kp,
                sig_alg: SignatureAlgorithm::RsaSha256,
                digest_alg: DigestAlgorithm::Sha256,
                c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                inclusive_namespaces: &[],
                include_x509_cert: false,
            },
        )
        .unwrap();
        let signature = find_signature(&signed).unwrap();
        let signed_info = signed_info_of(signature);
        let transforms = signed_info
            .child_element(Some(DSIG_NS), "Reference")
            .unwrap()
            .child_element(Some(DSIG_NS), "Transforms")
            .unwrap();
        // First transform: enveloped-signature.
        let xforms: Vec<&Element> = transforms
            .all_child_elements(Some(DSIG_NS), "Transform")
            .collect();
        assert_eq!(xforms.len(), 2);
        assert_eq!(
            xforms[0].attribute(None, "Algorithm"),
            Some(ENVELOPED_SIGNATURE_URI)
        );
        assert_eq!(
            xforms[1].attribute(None, "Algorithm"),
            Some(C14nAlgorithm::ExclusiveCanonical.uri())
        );
    }

    #[test]
    fn inclusive_namespaces_prefix_list_attached_to_c14n_transform() {
        let response = build_response_with_issuer("resp-8", true);
        let doc = Document::new(response).unwrap();
        let target = doc.root().clone();

        let kp = rsa_key_with_cert();
        let signed = sign_element(
            target,
            &doc,
            SignOptions {
                signing_key: &kp,
                sig_alg: SignatureAlgorithm::RsaSha256,
                digest_alg: DigestAlgorithm::Sha256,
                c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                inclusive_namespaces: &["samlp", "saml"],
                include_x509_cert: false,
            },
        )
        .unwrap();
        let signature = find_signature(&signed).unwrap();
        let signed_info = signed_info_of(signature);
        let transforms = signed_info
            .child_element(Some(DSIG_NS), "Reference")
            .unwrap()
            .child_element(Some(DSIG_NS), "Transforms")
            .unwrap();
        let xforms: Vec<&Element> = transforms
            .all_child_elements(Some(DSIG_NS), "Transform")
            .collect();
        let c14n_transform = xforms
            .iter()
            .find(|t| t.attribute(None, "Algorithm") == Some(C14nAlgorithm::ExclusiveCanonical.uri()))
            .expect("c14n transform");
        let inclusive = c14n_transform
            .child_element(Some(EC_NS), "InclusiveNamespaces")
            .expect("InclusiveNamespaces present");
        assert_eq!(
            inclusive.attribute(None, "PrefixList"),
            Some("samlp saml")
        );
    }
}
