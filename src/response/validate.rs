//! Validate parsed Response per RFC-003 §4.1. Returns `Identity` on success.
//!
//! This is the security-critical SP-side pipeline: signature verification,
//! optional `EncryptedAssertion` unwrap, audience / subject-confirmation /
//! time-window checks, optional `RequestedAuthnContext` non-downgrade. The
//! validated payload is *always* re-extracted via
//! `document.element(verified.signed_element)` (the structural XSW defense per
//! RFC-002 §3.2) — name-based lookup of the assertion is never used after
//! signature verification.

use std::time::{Duration, SystemTime};

use crate::authn_context::{
    AuthnContextClassRef, AuthnContextComparison, RequestedAuthnContext,
};
use crate::crypto::keypair::KeyPair;
use crate::descriptor::IdpDescriptor;
use crate::dsig::algorithms::PeerCryptoPolicy;
use crate::dsig::reference::DS_NS;
use crate::dsig::verify::{VerifiedSignature, verify_signature};
use crate::error::Error;
use crate::response::identity::Identity;
use crate::response::parse::{
    AssertionWrapper, ParsedAssertion, ParsedResponse, STATUS_SUCCESS,
    SUBJECT_CONFIRMATION_BEARER, SubjectConfirmation, parse_assertion,
};
use crate::xml::parse::{Document, Element, ElementId};

pub(crate) struct ValidateResponse<'a> {
    pub document: &'a Document,
    pub parsed: ParsedResponse,
    pub idp: &'a IdpDescriptor,
    pub peer_crypto_policy: &'a PeerCryptoPolicy,
    /// SP's signing/decryption keypair(s) (for EncryptedAssertion unwrap).
    pub decryption_keys: &'a [&'a KeyPair],
    /// SP entity ID (for AudienceRestriction).
    pub sp_entity_id: &'a str,
    /// SP ACS URL that received this Response (for Destination + Recipient).
    pub expected_destination: &'a str,
    /// Tracker request ID (for InResponseTo), or None for unsolicited.
    pub tracker_request_id: Option<&'a str>,
    /// True if the SP allows unsolicited responses.
    pub allow_unsolicited: bool,
    /// True if Response root signature is required.
    pub want_response_signed: bool,
    /// True if Assertion signature is required.
    pub want_assertions_signed: bool,
    pub now: SystemTime,
    pub clock_skew: Duration,
    /// Optional requested AuthnContext for downgrade-prevention check.
    pub requested_authn_context: Option<&'a RequestedAuthnContext>,
}

/// Validate a parsed Response and return the extracted `Identity` on success.
pub(crate) fn validate_response(input: ValidateResponse<'_>) -> Result<Identity, Error> {
    let ValidateResponse {
        document,
        parsed,
        idp,
        peer_crypto_policy,
        decryption_keys,
        sp_entity_id,
        expected_destination,
        tracker_request_id,
        allow_unsolicited,
        want_response_signed,
        want_assertions_signed,
        now,
        clock_skew,
        requested_authn_context,
    } = input;

    // --- Step 3: Destination cross-check when present. -----------------------
    if let Some(dest) = parsed.destination.as_deref()
        && dest != expected_destination
    {
        return Err(Error::DestinationMismatch);
    }

    // --- Step 4: Issuer mismatch ----------------------------------------------
    let response_issuer = parsed.issuer.as_deref();
    if response_issuer != Some(idp.entity_id.as_str()) {
        return Err(Error::IssuerMismatch {
            expected: idp.entity_id.clone(),
            got: parsed.issuer.clone(),
        });
    }

    // --- Step 5: Status must be Success ---------------------------------------
    if parsed.status_code != STATUS_SUCCESS {
        return Err(Error::StatusNotSuccess {
            code: parsed.status_code,
            message: parsed.status_message,
        });
    }

    // --- Step 6: InResponseTo binding (strict) --------------------------------
    match (tracker_request_id, parsed.in_response_to.as_deref()) {
        (Some(tracker), Some(in_resp)) if tracker == in_resp => {}
        (Some(_), _) => return Err(Error::InResponseToMismatch),
        (None, None) => {
            if !allow_unsolicited {
                return Err(Error::UnsolicitedNotAllowed);
            }
        }
        (None, Some(_)) => return Err(Error::UnsolicitedNotAllowed),
    }

    // --- Steps 9/10: Decrypt (if needed), find the assertion + signatures ----
    // The Response root element id is what `verify_signature` will produce in
    // `signed_element` when the Response root signature verifies — using it for
    // strict equality after verification is the XSW defense (RFC-002 §3.2).
    let response_root_element_id = document.root().id();

    // --- Step 7: exactly one assertion (already enforced as ≤1 at parse) ----
    let assertion_wrapper = parsed
        .assertion
        .as_ref()
        .ok_or_else(|| Error::XmlParse("Response contains no Assertion".to_string()))?;

    // ---- Step 9: handle encryption ----
    let (verified_cert_fingerprint, assertion_element, _decrypted_doc) = match assertion_wrapper {
        AssertionWrapper::Cleartext(assertion_id) => {
            let (verified, assertion_id) = verify_response_and_or_assertion(
                document,
                response_root_element_id,
                *assertion_id,
                idp,
                peer_crypto_policy,
                want_response_signed,
                want_assertions_signed,
            )?;
            let assertion_elem = document
                .element(assertion_id)
                .ok_or(Error::SignatureVerification {
                    reason: "verified assertion element id not resolvable",
                })?
                .clone();
            (verified.verifying_cert_fingerprint, assertion_elem, None)
        }
        AssertionWrapper::Encrypted(enc_id) => {
            handle_encrypted(
                document,
                response_root_element_id,
                *enc_id,
                idp,
                peer_crypto_policy,
                decryption_keys,
                want_response_signed,
                want_assertions_signed,
            )?
        }
    };

    // --- Step 11: re-parse the verified assertion ----------------------------
    let assertion = parse_assertion(&assertion_element)?;
    if assertion.issuer != idp.entity_id {
        return Err(Error::IssuerMismatch {
            expected: idp.entity_id.clone(),
            got: Some(assertion.issuer.clone()),
        });
    }

    // --- Steps 12/13: time windows on Conditions -----------------------------
    if let Some(nb) = assertion.conditions.not_before {
        // Reject if NotBefore is in the future beyond clock_skew.
        if nb > now + clock_skew {
            return Err(Error::NotYetValid);
        }
    }
    let conditions_not_on_or_after = assertion.conditions.not_on_or_after.ok_or(
        Error::XmlParse("Conditions missing NotOnOrAfter".to_string()),
    )?;
    if conditions_not_on_or_after <= now - clock_skew {
        return Err(Error::Expired);
    }

    // --- Step 14: AudienceRestriction MUST contain SP entity ID ---------------
    // Per spec: empty audiences == AudienceMismatch (we treat it as strict).
    if assertion.conditions.audiences.is_empty() {
        return Err(Error::AudienceMismatch);
    }
    if !assertion
        .conditions
        .audiences
        .iter()
        .any(|a| a == sp_entity_id)
    {
        return Err(Error::AudienceMismatch);
    }

    // --- Steps 15/16: locate a bearer SubjectConfirmation that passes --------
    // The helper returns the satisfying confirmation, but no data from it
    // flows into Identity — its only role here is to validate-or-reject.
    find_valid_bearer_subject_confirmation(
        &assertion,
        expected_destination,
        tracker_request_id,
        now,
        clock_skew,
    )?;

    // --- Step 17: AuthnContext non-downgrade ---------------------------------
    if let Some(req) = requested_authn_context {
        let first = assertion.authn_statements.first().ok_or(
            Error::AuthnContextDowngrade,
        )?;
        let actual_uri = first
            .authn_context_class_ref
            .as_deref()
            .ok_or(Error::AuthnContextDowngrade)?;
        check_authn_context(req, actual_uri)?;
    }

    // --- Step 18: extract Identity -------------------------------------------
    let (session_index, authn_instant, session_not_on_or_after, authn_context_class_ref) =
        match assertion.authn_statements.first() {
            Some(s) => (
                s.session_index.clone(),
                s.authn_instant,
                s.session_not_on_or_after,
                s.authn_context_class_ref.clone(),
            ),
            None => (None, assertion.issue_instant, None, None),
        };

    Ok(Identity {
        name_id: assertion.subject_name_id,
        session_index,
        authn_instant,
        session_not_on_or_after,
        authn_context_class_ref,
        attributes: assertion.attributes,
        assertion_id: assertion.id,
        not_on_or_after: conditions_not_on_or_after,
        verifying_cert_fingerprint: verified_cert_fingerprint,
    })
}

// =============================================================================
// Signature verification (cleartext path)
// =============================================================================

/// Run the signature gate for the cleartext Response/Assertion case. Returns
/// the `VerifiedSignature` from whichever signature was checked and the
/// `ElementId` of the assertion to validate further.
///
/// The returned assertion id is ALWAYS sourced from
/// `verified.signed_element` when the assertion signature was the one
/// verified — never via name lookup. That is the structural XSW defense
/// (RFC-002 §3.2).
fn verify_response_and_or_assertion(
    document: &Document,
    response_root_id: ElementId,
    assertion_name_lookup_id: ElementId,
    idp: &IdpDescriptor,
    policy: &PeerCryptoPolicy,
    want_response_signed: bool,
    want_assertions_signed: bool,
) -> Result<(VerifiedSignature, ElementId), Error> {
    let root = document.root();
    let response_signature = root.child_element(Some(DS_NS), "Signature");

    let assertion_elem = document
        .element(assertion_name_lookup_id)
        .ok_or(Error::SignatureVerification {
            reason: "assertion element id not resolvable",
        })?;
    let assertion_signature = assertion_elem.child_element(Some(DS_NS), "Signature");

    let verify_response = |sig: &Element| -> Result<VerifiedSignature, Error> {
        let verified = verify_signature(
            document,
            sig,
            &idp.signing_certs,
            &policy.allowed_signature_algorithms,
        )?;
        if verified.signed_element != response_root_id {
            return Err(Error::SignatureVerification {
                reason: "signature does not cover Response root",
            });
        }
        Ok(verified)
    };
    let verify_assertion = |sig: &Element| -> Result<VerifiedSignature, Error> {
        let verified = verify_signature(
            document,
            sig,
            &idp.signing_certs,
            &policy.allowed_signature_algorithms,
        )?;
        if verified.signed_element != assertion_name_lookup_id {
            return Err(Error::SignatureVerification {
                reason: "signature does not cover Assertion",
            });
        }
        Ok(verified)
    };

    // ---- Required: Response root signature ----
    if want_response_signed {
        let verified = verify_response(response_signature.ok_or(Error::SignatureMissing)?)?;
        // If the assertion is *also* required signed, re-verify that here and
        // prefer its fingerprint for the downstream Identity (the assertion
        // signature is the one that vouches for the user attributes).
        if want_assertions_signed {
            let averified =
                verify_assertion(assertion_signature.ok_or(Error::SignatureMissing)?)?;
            return Ok((averified, assertion_name_lookup_id));
        }
        // Response-only signature: the Response root covers the assertion as
        // a descendant.
        return Ok((verified, assertion_name_lookup_id));
    }

    // ---- Required: Assertion signature ----
    if want_assertions_signed {
        let verified = verify_assertion(assertion_signature.ok_or(Error::SignatureMissing)?)?;
        return Ok((verified, assertion_name_lookup_id));
    }

    // ---- Neither required: at least one signature must be present + valid ----
    if let Some(sig) = response_signature {
        let verified = verify_response(sig)?;
        return Ok((verified, assertion_name_lookup_id));
    }
    if let Some(sig) = assertion_signature {
        let verified = verify_assertion(sig)?;
        return Ok((verified, assertion_name_lookup_id));
    }

    Err(Error::SignatureMissing)
}

// =============================================================================
// Encrypted assertion handling
// =============================================================================

#[cfg(feature = "xmlenc")]
#[allow(clippy::too_many_arguments)]
fn handle_encrypted(
    document: &Document,
    response_root_id: ElementId,
    encrypted_assertion_id: ElementId,
    idp: &IdpDescriptor,
    policy: &PeerCryptoPolicy,
    decryption_keys: &[&KeyPair],
    want_response_signed: bool,
    want_assertions_signed: bool,
) -> Result<([u8; 32], Element, Option<Document>), Error> {
    use crate::xmlenc::decrypt::decrypt_encrypted_assertion;

    // ---- Optional: verify the Response root signature first ----------------
    // The Response root signature, if present, covers the EncryptedAssertion as
    // a descendant; that's how a "want_response_signed" IdP authenticates the
    // assertion when it's encrypted (the assertion itself can't be signed inside
    // the ciphertext envelope and have a verifier read the signature without
    // first decrypting).
    let root = document.root();
    let response_signature = root.child_element(Some(DS_NS), "Signature");

    let mut response_verified_fingerprint: Option<[u8; 32]> = None;
    if let Some(sig) = response_signature {
        let verified = verify_signature(
            document,
            sig,
            &idp.signing_certs,
            &policy.allowed_signature_algorithms,
        )?;
        if verified.signed_element != response_root_id {
            return Err(Error::SignatureVerification {
                reason: "signature does not cover Response root",
            });
        }
        response_verified_fingerprint = Some(verified.verifying_cert_fingerprint);
    } else if want_response_signed {
        return Err(Error::SignatureMissing);
    }

    // ---- Decrypt the EncryptedAssertion ------------------------------------
    let enc_elem = document
        .element(encrypted_assertion_id)
        .ok_or(Error::DecryptFailed {
            reason: "EncryptedAssertion element id not resolvable",
        })?;
    let cleartext_assertion = decrypt_encrypted_assertion(
        enc_elem,
        decryption_keys,
        &policy.allowed_data_encryption_algorithms,
        &policy.allowed_key_transport_algorithms,
    )?;

    // ---- Re-wrap into a fresh Document so we can verify the inner signature
    // ---- via its own ElementId index. Mutating the parent document would
    // ---- invalidate the existing ElementId arena, so we build a separate
    // ---- one and walk into it.
    let decrypted_doc = Document::new(cleartext_assertion)?;
    let assertion_root = decrypted_doc.root();
    let inner_signature = assertion_root.child_element(Some(DS_NS), "Signature");

    // The "required" and "optional-but-present" inner-signature branches do
    // the same verify-and-resolve dance; differ only on what to do when the
    // signature is absent.
    let verify_inner = |sig: &Element| -> Result<([u8; 32], Element), Error> {
        let verified = verify_signature(
            &decrypted_doc,
            sig,
            &idp.signing_certs,
            &policy.allowed_signature_algorithms,
        )?;
        if verified.signed_element != assertion_root.id() {
            return Err(Error::SignatureVerification {
                reason: "signature does not cover Assertion",
            });
        }
        let resolved = decrypted_doc
            .element(verified.signed_element)
            .ok_or(Error::SignatureVerification {
                reason: "verified assertion element id not resolvable",
            })?
            .clone();
        Ok((verified.verifying_cert_fingerprint, resolved))
    };

    if want_assertions_signed {
        let (fp, resolved) = verify_inner(inner_signature.ok_or(Error::SignatureMissing)?)?;
        return Ok((fp, resolved, Some(decrypted_doc)));
    }

    // No required inner signature. We must still have *some* successful
    // signature — either the outer Response signature (above) or an optional
    // inner one. Reject if neither.
    if let Some(sig) = inner_signature {
        let (fp, resolved) = verify_inner(sig)?;
        return Ok((fp, resolved, Some(decrypted_doc)));
    }

    if let Some(fp) = response_verified_fingerprint {
        return Ok((fp, assertion_root.clone(), Some(decrypted_doc)));
    }

    Err(Error::SignatureMissing)
}

#[cfg(not(feature = "xmlenc"))]
#[allow(clippy::too_many_arguments)]
fn handle_encrypted(
    _document: &Document,
    _response_root_id: ElementId,
    _encrypted_assertion_id: ElementId,
    _idp: &IdpDescriptor,
    _policy: &PeerCryptoPolicy,
    _decryption_keys: &[&KeyPair],
    _want_response_signed: bool,
    _want_assertions_signed: bool,
) -> Result<([u8; 32], Element, Option<Document>), Error> {
    Err(Error::InvalidConfiguration {
        reason: "EncryptedAssertion requires the `xmlenc` feature",
    })
}

// =============================================================================
// SubjectConfirmation + AuthnContext checks
// =============================================================================

fn find_valid_bearer_subject_confirmation<'a>(
    assertion: &'a ParsedAssertion,
    expected_destination: &str,
    tracker_request_id: Option<&str>,
    now: SystemTime,
    clock_skew: Duration,
) -> Result<&'a SubjectConfirmation, Error> {
    // Collect bearer-method confirmations.
    let bearers: Vec<&SubjectConfirmation> = assertion
        .subject_confirmations
        .iter()
        .filter(|sc| sc.method == SUBJECT_CONFIRMATION_BEARER)
        .collect();

    if bearers.is_empty() {
        return Err(Error::SignatureVerification {
            reason: "no bearer SubjectConfirmation",
        });
    }

    // First pick a candidate whose recipient matches. The spec allows
    // multiple SubjectConfirmation elements, only one needs to satisfy ALL
    // the bearer constraints — but errors are surfaced for the FIRST bearer
    // that mismatches on a non-recipient axis so the caller's error code is
    // informative.
    let mut last_err: Option<Error> = None;
    for sc in &bearers {
        // Recipient must match the expected destination.
        match sc.recipient.as_deref() {
            Some(r) if r == expected_destination => {}
            _ => {
                last_err = Some(Error::RecipientMismatch);
                continue;
            }
        }
        // NotOnOrAfter must be present and in the future (within clock_skew).
        match sc.not_on_or_after {
            Some(nooa) if nooa > now - clock_skew => {}
            _ => {
                last_err = Some(Error::Expired);
                continue;
            }
        }
        // NotBefore: tolerated if absent; if present, must be ≤ now+skew.
        if let Some(nb) = sc.not_before
            && nb > now + clock_skew
        {
            last_err = Some(Error::NotYetValid);
            continue;
        }
        // InResponseTo mirrors response-level rule.
        match (tracker_request_id, sc.in_response_to.as_deref()) {
            (Some(tracker), Some(in_resp)) if tracker == in_resp => {}
            (Some(_), _) => {
                last_err = Some(Error::InResponseToMismatch);
                continue;
            }
            (None, None) => {}
            (None, Some(_)) => {
                last_err = Some(Error::UnsolicitedNotAllowed);
                continue;
            }
        }
        return Ok(sc);
    }

    Err(last_err.unwrap_or(Error::RecipientMismatch))
}

fn check_authn_context(
    requested: &RequestedAuthnContext,
    actual_uri: &str,
) -> Result<(), Error> {
    let actual = AuthnContextClassRef::from_uri(actual_uri);

    // For Exact comparison we don't need strength ordering — URI equality is
    // authoritative and works for `Custom` refs too.
    if matches!(requested.comparison, AuthnContextComparison::Exact) {
        return requested
            .class_refs
            .iter()
            .any(|c| c.as_uri() == actual.as_uri())
            .then_some(())
            .ok_or(Error::AuthnContextDowngrade);
    }

    // Strength-ordered comparisons: both sides must be rankable.
    let actual_strength = strength_of(&actual).ok_or(Error::AuthnContextDowngrade)?;
    let requested_strengths = requested.class_refs.iter().filter_map(strength_of);
    let ok = match requested.comparison {
        AuthnContextComparison::Exact => unreachable!("handled above"),
        AuthnContextComparison::Minimum => {
            let weakest = requested_strengths.min().ok_or(Error::AuthnContextDowngrade)?;
            actual_strength >= weakest
        }
        AuthnContextComparison::Maximum => {
            let strongest = requested_strengths.max().ok_or(Error::AuthnContextDowngrade)?;
            actual_strength <= strongest
        }
        AuthnContextComparison::Better => {
            let strongest = requested_strengths.max().ok_or(Error::AuthnContextDowngrade)?;
            actual_strength > strongest
        }
    };
    ok.then_some(()).ok_or(Error::AuthnContextDowngrade)
}

/// Coarse strength ranking of the standard AuthnContextClassRefs. Returns
/// `None` for `Custom`/`Unspecified` — the caller can't meaningfully order
/// those, so any comparison other than exact-by-URI degrades to "downgrade".
fn strength_of(cr: &AuthnContextClassRef) -> Option<u8> {
    match cr {
        AuthnContextClassRef::Unspecified => Some(0),
        AuthnContextClassRef::PreviousSession => Some(1),
        AuthnContextClassRef::Password => Some(2),
        AuthnContextClassRef::PasswordProtectedTransport => Some(3),
        AuthnContextClassRef::TimeSyncToken => Some(4),
        AuthnContextClassRef::Kerberos => Some(5),
        AuthnContextClassRef::TlsClient => Some(5),
        AuthnContextClassRef::Smartcard => Some(6),
        AuthnContextClassRef::SmartcardPki => Some(7),
        AuthnContextClassRef::MultiFactorAuth => Some(8),
        AuthnContextClassRef::Custom(_) => None,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::Endpoint;
    use crate::crypto::cert::X509Certificate;
    use crate::crypto::cert::test_vectors::{RSA_CERT_PEM, RSA_KEY_PKCS8_PEM};
    use crate::dsig::algorithms::{
        C14nAlgorithm, DigestAlgorithm, SignatureAlgorithm,
    };
    use crate::dsig::sign::sign_element;
    use crate::nameid::NameIdFormat;
    use crate::response::parse::parse_response;
    use crate::response::{SAML_NS, SAMLP_NS, saml_qname, samlp_qname};
    use crate::xml::emit::emit_document;
    use crate::xml::parse::{Document, Node, QName};
    use std::time::{Duration, UNIX_EPOCH};

    // ---------- Test fixtures ----------

    fn fixed_now() -> SystemTime {
        // 2026-05-26T12:00:30Z
        UNIX_EPOCH + Duration::from_secs(1_779_796_830)
    }

    fn fixture_idp() -> IdpDescriptor {
        IdpDescriptor {
            entity_id: "https://idp.example.com".to_owned(),
            sso_endpoints: vec![Endpoint::post("https://idp.example.com/sso", 0, true)],
            slo_endpoints: vec![],
            artifact_resolution_endpoints: vec![],
            signing_certs: vec![X509Certificate::from_pem(RSA_CERT_PEM).unwrap()],
            encryption_certs: vec![],
            supported_name_id_formats: vec![],
            want_authn_requests_signed: false,
            valid_until: None,
            cache_duration: None,
        }
    }

    fn rsa_signing_key() -> KeyPair {
        let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).unwrap();
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        kp.with_certificate(cert)
    }

    fn strong_policy() -> PeerCryptoPolicy {
        PeerCryptoPolicy::strong_defaults()
    }

    /// Build a complete `<saml:Assertion>` Element parameterized by the
    /// most-commonly-tweaked fields.
    fn build_assertion(
        id: &str,
        issuer: &str,
        recipient: &str,
        in_response_to: Option<&str>,
        audience: &str,
        not_before: &str,
        not_on_or_after: &str,
        sc_not_on_or_after: &str,
        authn_context: &str,
        name_id_value: &str,
        name_id_format_uri: &str,
    ) -> Element {
        let name_id = Element::build(saml_qname("NameID"))
            .with_attribute(QName::new(None, "Format"), name_id_format_uri.to_owned())
            .with_text(name_id_value.to_owned())
            .finish();

        let mut scd_builder = Element::build(saml_qname("SubjectConfirmationData"))
            .with_attribute(QName::new(None, "Recipient"), recipient.to_owned())
            .with_attribute(
                QName::new(None, "NotOnOrAfter"),
                sc_not_on_or_after.to_owned(),
            );
        if let Some(irt) = in_response_to {
            scd_builder = scd_builder
                .with_attribute(QName::new(None, "InResponseTo"), irt.to_owned());
        }
        let scd = scd_builder.finish();

        let sc = Element::build(saml_qname("SubjectConfirmation"))
            .with_attribute(
                QName::new(None, "Method"),
                SUBJECT_CONFIRMATION_BEARER.to_owned(),
            )
            .with_child(Node::Element(scd))
            .finish();

        let subject = Element::build(saml_qname("Subject"))
            .with_child(Node::Element(name_id))
            .with_child(Node::Element(sc))
            .finish();

        let audience_elem = Element::build(saml_qname("Audience"))
            .with_text(audience.to_owned())
            .finish();
        let restriction = Element::build(saml_qname("AudienceRestriction"))
            .with_child(Node::Element(audience_elem))
            .finish();
        let conditions = Element::build(saml_qname("Conditions"))
            .with_attribute(QName::new(None, "NotBefore"), not_before.to_owned())
            .with_attribute(
                QName::new(None, "NotOnOrAfter"),
                not_on_or_after.to_owned(),
            )
            .with_child(Node::Element(restriction))
            .finish();

        let class_ref = Element::build(saml_qname("AuthnContextClassRef"))
            .with_text(authn_context.to_owned())
            .finish();
        let authn_context = Element::build(saml_qname("AuthnContext"))
            .with_child(Node::Element(class_ref))
            .finish();
        let authn_stmt = Element::build(saml_qname("AuthnStatement"))
            .with_attribute(
                QName::new(None, "AuthnInstant"),
                "2026-05-26T11:59:30Z".to_owned(),
            )
            .with_attribute(QName::new(None, "SessionIndex"), "sess-1")
            .with_child(Node::Element(authn_context))
            .finish();

        let issuer_elem = Element::build(saml_qname("Issuer"))
            .with_text(issuer.to_owned())
            .finish();

        Element::build(saml_qname("Assertion"))
            .with_namespace(Some("saml".to_owned()), SAML_NS)
            .with_attribute(QName::new(None, "ID"), id.to_owned())
            .with_attribute(QName::new(None, "Version"), "2.0")
            .with_attribute(
                QName::new(None, "IssueInstant"),
                "2026-05-26T12:00:00Z".to_owned(),
            )
            .with_child(Node::Element(issuer_elem))
            .with_child(Node::Element(subject))
            .with_child(Node::Element(conditions))
            .with_child(Node::Element(authn_stmt))
            .finish()
    }

    fn build_response_with_assertion(
        response_id: &str,
        in_response_to: Option<&str>,
        destination: &str,
        issuer: &str,
        assertion: Element,
        status_code: &str,
    ) -> Element {
        let status_code_elem = Element::build(samlp_qname("StatusCode"))
            .with_attribute(QName::new(None, "Value"), status_code.to_owned())
            .finish();
        let status = Element::build(samlp_qname("Status"))
            .with_child(Node::Element(status_code_elem))
            .finish();

        let issuer_elem = Element::build(saml_qname("Issuer"))
            .with_text(issuer.to_owned())
            .finish();

        let mut builder = Element::build(samlp_qname("Response"))
            .with_namespace(Some("samlp".to_owned()), SAMLP_NS)
            .with_namespace(Some("saml".to_owned()), SAML_NS)
            .with_attribute(QName::new(None, "ID"), response_id.to_owned())
            .with_attribute(QName::new(None, "Version"), "2.0")
            .with_attribute(
                QName::new(None, "IssueInstant"),
                "2026-05-26T12:00:00Z".to_owned(),
            )
            .with_attribute(QName::new(None, "Destination"), destination.to_owned());
        if let Some(irt) = in_response_to {
            builder = builder.with_attribute(QName::new(None, "InResponseTo"), irt.to_owned());
        }
        builder
            .with_child(Node::Element(issuer_elem))
            .with_child(Node::Element(status))
            .with_child(Node::Element(assertion))
            .finish()
    }

    /// Build a typical `<samlp:Response>` with an assertion signed by the test
    /// IdP key. Returns the assembled XML bytes.
    fn build_and_sign_response(
        kp: &KeyPair,
        sign_response: bool,
        sign_assertion: bool,
        in_response_to: Option<&str>,
        audience: &str,
        recipient: &str,
        not_before: &str,
        not_on_or_after: &str,
    ) -> Vec<u8> {
        let mut assertion = build_assertion(
            "_a1",
            "https://idp.example.com",
            recipient,
            in_response_to,
            audience,
            not_before,
            not_on_or_after,
            "2026-05-26T12:05:00Z",
            "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
            "alice@example.com",
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        );

        if sign_assertion {
            let stash_doc = Document::new(assertion.clone()).unwrap();
            assertion = sign_element(
                stash_doc.root().clone(),
                &stash_doc,
                kp,
                SignatureAlgorithm::RsaSha256,
                DigestAlgorithm::Sha256,
                C14nAlgorithm::ExclusiveCanonical,
                &[],
                true,
            )
            .unwrap();
        }

        let mut response = build_response_with_assertion(
            "_resp1",
            in_response_to,
            recipient,
            "https://idp.example.com",
            assertion,
            STATUS_SUCCESS,
        );

        if sign_response {
            let stash_doc = Document::new(response.clone()).unwrap();
            response = sign_element(
                stash_doc.root().clone(),
                &stash_doc,
                kp,
                SignatureAlgorithm::RsaSha256,
                DigestAlgorithm::Sha256,
                C14nAlgorithm::ExclusiveCanonical,
                &[],
                true,
            )
            .unwrap();
        }

        let doc = Document::new(response).unwrap();
        emit_document(&doc).unwrap().into_bytes()
    }

    fn default_input<'a>(
        document: &'a Document,
        parsed: ParsedResponse,
        idp: &'a IdpDescriptor,
        policy: &'a PeerCryptoPolicy,
    ) -> ValidateResponse<'a> {
        ValidateResponse {
            document,
            parsed,
            idp,
            peer_crypto_policy: policy,
            decryption_keys: &[],
            sp_entity_id: "https://sp.example.com",
            expected_destination: "https://sp.example.com/acs",
            tracker_request_id: Some("_req1"),
            allow_unsolicited: false,
            want_response_signed: false,
            want_assertions_signed: true,
            now: fixed_now(),
            clock_skew: Duration::from_secs(30),
            requested_authn_context: None,
        }
    }

    // ---------- Tests ----------

    #[test]
    fn happy_path_validates_signed_assertion() {
        let kp = rsa_signing_key();
        let xml = build_and_sign_response(
            &kp,
            false,
            true,
            Some("_req1"),
            "https://sp.example.com",
            "https://sp.example.com/acs",
            "2026-05-26T11:59:00Z",
            "2026-05-26T12:10:00Z",
        );
        let doc = Document::parse(&xml).expect("re-parse");
        let (parsed, _) = parse_response(&doc).expect("parse");
        let idp = fixture_idp();
        let policy = strong_policy();
        let identity = validate_response(default_input(&doc, parsed, &idp, &policy))
            .expect("validate");

        assert_eq!(identity.assertion_id, "_a1");
        assert_eq!(identity.name_id.value, "alice@example.com");
        assert_eq!(identity.name_id.format, NameIdFormat::EmailAddress);
        assert_eq!(identity.session_index.as_deref(), Some("sess-1"));
        assert_eq!(
            identity.authn_context_class_ref.as_deref(),
            Some("urn:oasis:names:tc:SAML:2.0:ac:classes:Password")
        );
        // Fingerprint matches the test cert.
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        assert_eq!(identity.verifying_cert_fingerprint, cert.fingerprint_sha256());
    }

    #[test]
    fn rejects_issuer_mismatch() {
        let kp = rsa_signing_key();
        let xml = build_and_sign_response(
            &kp,
            false,
            true,
            Some("_req1"),
            "https://sp.example.com",
            "https://sp.example.com/acs",
            "2026-05-26T11:59:00Z",
            "2026-05-26T12:10:00Z",
        );
        let doc = Document::parse(&xml).unwrap();
        let (parsed, _) = parse_response(&doc).unwrap();
        let mut idp = fixture_idp();
        idp.entity_id = "https://other-idp.example.com".to_owned();
        let policy = strong_policy();
        let err = validate_response(default_input(&doc, parsed, &idp, &policy)).unwrap_err();
        assert!(matches!(err, Error::IssuerMismatch { .. }));
    }

    #[test]
    fn rejects_status_not_success() {
        // Build a Response whose StatusCode is Responder.
        let assertion = build_assertion(
            "_a1",
            "https://idp.example.com",
            "https://sp.example.com/acs",
            Some("_req1"),
            "https://sp.example.com",
            "2026-05-26T11:59:00Z",
            "2026-05-26T12:10:00Z",
            "2026-05-26T12:05:00Z",
            "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
            "alice@example.com",
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        );
        let response = build_response_with_assertion(
            "_r",
            Some("_req1"),
            "https://sp.example.com/acs",
            "https://idp.example.com",
            assertion,
            "urn:oasis:names:tc:SAML:2.0:status:Responder",
        );
        let doc = Document::new(response).unwrap();
        let (parsed, _) = parse_response(&doc).unwrap();
        let idp = fixture_idp();
        let policy = strong_policy();
        let err = validate_response(default_input(&doc, parsed, &idp, &policy)).unwrap_err();
        match err {
            Error::StatusNotSuccess { code, .. } => {
                assert_eq!(code, "urn:oasis:names:tc:SAML:2.0:status:Responder");
            }
            other => panic!("expected StatusNotSuccess, got {other:?}"),
        }
    }

    #[test]
    fn rejects_in_response_to_mismatch() {
        let kp = rsa_signing_key();
        let xml = build_and_sign_response(
            &kp,
            false,
            true,
            Some("_wrong-id"),
            "https://sp.example.com",
            "https://sp.example.com/acs",
            "2026-05-26T11:59:00Z",
            "2026-05-26T12:10:00Z",
        );
        let doc = Document::parse(&xml).unwrap();
        let (parsed, _) = parse_response(&doc).unwrap();
        let idp = fixture_idp();
        let policy = strong_policy();
        let err = validate_response(default_input(&doc, parsed, &idp, &policy)).unwrap_err();
        assert!(matches!(err, Error::InResponseToMismatch));
    }

    #[test]
    fn unsolicited_response_requires_allow_flag() {
        // Build a response with no InResponseTo. With tracker=None and
        // allow_unsolicited=false, this rejects.
        let kp = rsa_signing_key();
        let xml = build_and_sign_response(
            &kp,
            false,
            true,
            None,
            "https://sp.example.com",
            "https://sp.example.com/acs",
            "2026-05-26T11:59:00Z",
            "2026-05-26T12:10:00Z",
        );
        let doc = Document::parse(&xml).unwrap();
        let (parsed, _) = parse_response(&doc).unwrap();
        let idp = fixture_idp();
        let policy = strong_policy();
        let mut input = default_input(&doc, parsed, &idp, &policy);
        input.tracker_request_id = None;
        input.allow_unsolicited = false;
        let err = validate_response(input).unwrap_err();
        assert!(matches!(err, Error::UnsolicitedNotAllowed));
    }

    #[test]
    fn unsolicited_response_accepted_when_allow_flag_set() {
        let kp = rsa_signing_key();
        let xml = build_and_sign_response(
            &kp,
            false,
            true,
            None,
            "https://sp.example.com",
            "https://sp.example.com/acs",
            "2026-05-26T11:59:00Z",
            "2026-05-26T12:10:00Z",
        );
        let doc = Document::parse(&xml).unwrap();
        let (parsed, _) = parse_response(&doc).unwrap();
        let idp = fixture_idp();
        let policy = strong_policy();
        let mut input = default_input(&doc, parsed, &idp, &policy);
        input.tracker_request_id = None;
        input.allow_unsolicited = true;
        let identity = validate_response(input).expect("validate");
        assert_eq!(identity.assertion_id, "_a1");
    }

    #[test]
    fn rejects_audience_mismatch() {
        let kp = rsa_signing_key();
        let xml = build_and_sign_response(
            &kp,
            false,
            true,
            Some("_req1"),
            "https://other.example.com",
            "https://sp.example.com/acs",
            "2026-05-26T11:59:00Z",
            "2026-05-26T12:10:00Z",
        );
        let doc = Document::parse(&xml).unwrap();
        let (parsed, _) = parse_response(&doc).unwrap();
        let idp = fixture_idp();
        let policy = strong_policy();
        let err = validate_response(default_input(&doc, parsed, &idp, &policy)).unwrap_err();
        assert!(matches!(err, Error::AudienceMismatch));
    }

    #[test]
    fn rejects_recipient_mismatch() {
        let kp = rsa_signing_key();
        // Compose a Response whose root Destination matches the SP's ACS, but
        // whose inner SubjectConfirmationData/Recipient does not. This
        // exercises step 16's recipient check independently of step 3's
        // destination check.
        let assertion = build_assertion(
            "_a1",
            "https://idp.example.com",
            "https://wrong.example.com/acs",
            Some("_req1"),
            "https://sp.example.com",
            "2026-05-26T11:59:00Z",
            "2026-05-26T12:10:00Z",
            "2026-05-26T12:05:00Z",
            "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
            "alice@example.com",
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        );
        let signed_assertion = {
            let d = Document::new(assertion).unwrap();
            sign_element(
                d.root().clone(),
                &d,
                &kp,
                SignatureAlgorithm::RsaSha256,
                DigestAlgorithm::Sha256,
                C14nAlgorithm::ExclusiveCanonical,
                &[],
                true,
            )
            .unwrap()
        };
        let response = build_response_with_assertion(
            "_resp1",
            Some("_req1"),
            "https://sp.example.com/acs",
            "https://idp.example.com",
            signed_assertion,
            STATUS_SUCCESS,
        );
        let doc = Document::new(response).unwrap();
        let (parsed, _) = parse_response(&doc).unwrap();
        let idp = fixture_idp();
        let policy = strong_policy();
        let err = validate_response(default_input(&doc, parsed, &idp, &policy)).unwrap_err();
        assert!(matches!(err, Error::RecipientMismatch));
    }

    #[test]
    fn rejects_not_yet_valid() {
        let kp = rsa_signing_key();
        let xml = build_and_sign_response(
            &kp,
            false,
            true,
            Some("_req1"),
            "https://sp.example.com",
            "https://sp.example.com/acs",
            "2026-05-26T13:00:00Z", // NotBefore far in the future
            "2026-05-26T14:00:00Z",
        );
        let doc = Document::parse(&xml).unwrap();
        let (parsed, _) = parse_response(&doc).unwrap();
        let idp = fixture_idp();
        let policy = strong_policy();
        let err = validate_response(default_input(&doc, parsed, &idp, &policy)).unwrap_err();
        assert!(matches!(err, Error::NotYetValid));
    }

    #[test]
    fn rejects_expired() {
        let kp = rsa_signing_key();
        let xml = build_and_sign_response(
            &kp,
            false,
            true,
            Some("_req1"),
            "https://sp.example.com",
            "https://sp.example.com/acs",
            "2025-01-01T00:00:00Z",
            "2025-12-31T23:59:59Z",
        );
        let doc = Document::parse(&xml).unwrap();
        let (parsed, _) = parse_response(&doc).unwrap();
        let idp = fixture_idp();
        let policy = strong_policy();
        let err = validate_response(default_input(&doc, parsed, &idp, &policy)).unwrap_err();
        assert!(matches!(err, Error::Expired));
    }

    #[test]
    fn rejects_when_no_signature_present() {
        // Build a response with no signatures, want_response_signed=true.
        let assertion = build_assertion(
            "_a1",
            "https://idp.example.com",
            "https://sp.example.com/acs",
            Some("_req1"),
            "https://sp.example.com",
            "2026-05-26T11:59:00Z",
            "2026-05-26T12:10:00Z",
            "2026-05-26T12:05:00Z",
            "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
            "alice@example.com",
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        );
        let response = build_response_with_assertion(
            "_resp1",
            Some("_req1"),
            "https://sp.example.com/acs",
            "https://idp.example.com",
            assertion,
            STATUS_SUCCESS,
        );
        let doc = Document::new(response).unwrap();
        let (parsed, _) = parse_response(&doc).unwrap();
        let idp = fixture_idp();
        let policy = strong_policy();
        let mut input = default_input(&doc, parsed, &idp, &policy);
        input.want_response_signed = true;
        input.want_assertions_signed = false;
        let err = validate_response(input).unwrap_err();
        assert!(matches!(err, Error::SignatureMissing));
    }

    #[test]
    fn rejects_no_bearer_subject_confirmation() {
        // Build an assertion whose SC method is NOT bearer.
        let name_id = Element::build(saml_qname("NameID"))
            .with_attribute(
                QName::new(None, "Format"),
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_owned(),
            )
            .with_text("alice@example.com")
            .finish();
        let scd = Element::build(saml_qname("SubjectConfirmationData"))
            .with_attribute(
                QName::new(None, "Recipient"),
                "https://sp.example.com/acs".to_owned(),
            )
            .with_attribute(
                QName::new(None, "NotOnOrAfter"),
                "2026-05-26T12:05:00Z".to_owned(),
            )
            .with_attribute(QName::new(None, "InResponseTo"), "_req1".to_owned())
            .finish();
        let sc = Element::build(saml_qname("SubjectConfirmation"))
            .with_attribute(
                QName::new(None, "Method"),
                "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key".to_owned(),
            )
            .with_child(Node::Element(scd))
            .finish();
        let subject = Element::build(saml_qname("Subject"))
            .with_child(Node::Element(name_id))
            .with_child(Node::Element(sc))
            .finish();
        let audience = Element::build(saml_qname("Audience"))
            .with_text("https://sp.example.com")
            .finish();
        let restriction = Element::build(saml_qname("AudienceRestriction"))
            .with_child(Node::Element(audience))
            .finish();
        let conditions = Element::build(saml_qname("Conditions"))
            .with_attribute(QName::new(None, "NotBefore"), "2026-05-26T11:59:00Z")
            .with_attribute(QName::new(None, "NotOnOrAfter"), "2026-05-26T12:10:00Z")
            .with_child(Node::Element(restriction))
            .finish();
        let class_ref = Element::build(saml_qname("AuthnContextClassRef"))
            .with_text("urn:oasis:names:tc:SAML:2.0:ac:classes:Password")
            .finish();
        let actx = Element::build(saml_qname("AuthnContext"))
            .with_child(Node::Element(class_ref))
            .finish();
        let astmt = Element::build(saml_qname("AuthnStatement"))
            .with_attribute(QName::new(None, "AuthnInstant"), "2026-05-26T12:00:00Z")
            .with_child(Node::Element(actx))
            .finish();
        let issuer = Element::build(saml_qname("Issuer"))
            .with_text("https://idp.example.com")
            .finish();
        let assertion = Element::build(saml_qname("Assertion"))
            .with_namespace(Some("saml".to_owned()), SAML_NS)
            .with_attribute(QName::new(None, "ID"), "_a1")
            .with_attribute(QName::new(None, "Version"), "2.0")
            .with_attribute(QName::new(None, "IssueInstant"), "2026-05-26T12:00:00Z")
            .with_child(Node::Element(issuer))
            .with_child(Node::Element(subject))
            .with_child(Node::Element(conditions))
            .with_child(Node::Element(astmt))
            .finish();

        let kp = rsa_signing_key();
        let d = Document::new(assertion).unwrap();
        let signed_assertion = sign_element(
            d.root().clone(),
            &d,
            &kp,
            SignatureAlgorithm::RsaSha256,
            DigestAlgorithm::Sha256,
            C14nAlgorithm::ExclusiveCanonical,
            &[],
            true,
        )
        .unwrap();
        let response = build_response_with_assertion(
            "_r",
            Some("_req1"),
            "https://sp.example.com/acs",
            "https://idp.example.com",
            signed_assertion,
            STATUS_SUCCESS,
        );
        let doc = Document::new(response).unwrap();
        let (parsed, _) = parse_response(&doc).unwrap();
        let idp = fixture_idp();
        let policy = strong_policy();
        let err = validate_response(default_input(&doc, parsed, &idp, &policy)).unwrap_err();
        match err {
            Error::SignatureVerification { reason } => {
                assert!(reason.contains("bearer"), "got: {reason}");
            }
            other => panic!("expected SignatureVerification, got {other:?}"),
        }
    }

    #[test]
    fn rejects_authn_context_downgrade() {
        let kp = rsa_signing_key();
        let xml = build_and_sign_response(
            &kp,
            false,
            true,
            Some("_req1"),
            "https://sp.example.com",
            "https://sp.example.com/acs",
            "2026-05-26T11:59:00Z",
            "2026-05-26T12:10:00Z",
        );
        let doc = Document::parse(&xml).unwrap();
        let (parsed, _) = parse_response(&doc).unwrap();
        let idp = fixture_idp();
        let policy = strong_policy();
        let mut input = default_input(&doc, parsed, &idp, &policy);
        let req = RequestedAuthnContext {
            class_refs: vec![AuthnContextClassRef::MultiFactorAuth],
            comparison: AuthnContextComparison::Exact,
        };
        input.requested_authn_context = Some(&req);
        let err = validate_response(input).unwrap_err();
        assert!(matches!(err, Error::AuthnContextDowngrade));
    }

    #[test]
    fn accepts_authn_context_minimum_when_actual_is_stronger() {
        // Default fixture emits Password (strength 2). Minimum-of-Password
        // should pass.
        let kp = rsa_signing_key();
        let xml = build_and_sign_response(
            &kp,
            false,
            true,
            Some("_req1"),
            "https://sp.example.com",
            "https://sp.example.com/acs",
            "2026-05-26T11:59:00Z",
            "2026-05-26T12:10:00Z",
        );
        let doc = Document::parse(&xml).unwrap();
        let (parsed, _) = parse_response(&doc).unwrap();
        let idp = fixture_idp();
        let policy = strong_policy();
        let mut input = default_input(&doc, parsed, &idp, &policy);
        let req = RequestedAuthnContext {
            class_refs: vec![AuthnContextClassRef::Password],
            comparison: AuthnContextComparison::Minimum,
        };
        input.requested_authn_context = Some(&req);
        let identity = validate_response(input).expect("validate");
        assert_eq!(identity.assertion_id, "_a1");
    }
}
