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
    ComparatorOutcome, RequestedAuthnContext, StandardComparator,
};
#[cfg(test)]
use crate::authn_context::{AuthnContextClassRef, AuthnContextComparison};
#[cfg(any(test, feature = "xmlenc"))]
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
    #[cfg(feature = "xmlenc")]
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
        #[cfg(feature = "xmlenc")]
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

    // --- Structural XSW defense: reject `<ds:Signature>` in unexpected places.
    //
    // The SAML 2.0 profile only places `<ds:Signature>` as a direct child of
    // `<samlp:Response>` or `<saml:Assertion>` (and `<saml:EncryptedAssertion>`
    // for the encrypted path). A `<ds:Signature>` anywhere else — e.g. buried
    // inside `<samlp:Status>` so that name-based lookup at the canonical
    // position returns `None` — is a signature-wrapping attempt: the attacker
    // moved a valid signature to a location the SP doesn't inspect, so the SP
    // sees no signature at the canonical position while a cryptographically
    // valid signature exists elsewhere. We refuse to consume any Response
    // whose tree carries a `<ds:Signature>` outside the allowed positions,
    // regardless of whether `want_*_signed` is set.
    enforce_signature_positions(document)?;

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
            (verified.verifying_cert_fingerprint, assertion_elem, None::<Document>)
        }
        #[cfg(feature = "xmlenc")]
        AssertionWrapper::Encrypted(enc_id) => {
            handle_encrypted(HandleEncryptedParams {
                document,
                response_root_id: response_root_element_id,
                encrypted_assertion_id: *enc_id,
                idp,
                policy: peer_crypto_policy,
                decryption_keys,
                want_response_signed,
                want_assertions_signed,
            })?
        }
        #[cfg(not(feature = "xmlenc"))]
        AssertionWrapper::Encrypted(_enc_id) => {
            return Err(Error::InvalidConfiguration {
                reason: "EncryptedAssertion requires the `xmlenc` feature",
            });
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
        let now_plus_skew = now.checked_add(clock_skew).ok_or_else(|| {
            Error::XmlParse("now + clock_skew overflows SystemTime".to_string())
        })?;
        if nb > now_plus_skew {
            return Err(Error::NotYetValid);
        }
    }
    let conditions_not_on_or_after = assertion.conditions.not_on_or_after.ok_or(
        Error::XmlParse("Conditions missing NotOnOrAfter".to_string()),
    )?;
    let now_minus_skew = now.checked_sub(clock_skew).ok_or_else(|| {
        Error::XmlParse("now - clock_skew underflows SystemTime".to_string())
    })?;
    if conditions_not_on_or_after <= now_minus_skew {
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

    // `<saml:OneTimeUse>` (SAML 2.0 Core §2.5.1.5) is a deduplication
    // directive, not a time bound — distinct from `NotOnOrAfter`. The library
    // surfaces the parsed flag here and leaves enforcement (replay cache
    // keyed on `assertion_id`) to the caller. See `Identity::is_one_time_use`
    // for the contract.
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
        is_one_time_use: assertion.conditions.one_time_use,
    })
}

// =============================================================================
// Structural defense: `<ds:Signature>` must only appear in profile-allowed
// positions.
// =============================================================================

/// SAML protocol namespace URI (`samlp:`).
const SAMLP_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
/// SAML assertion namespace URI (`saml:`).
const SAML_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

/// Recursively scan the document for `<ds:Signature>` elements. Each one MUST
/// be a direct child of either `<samlp:Response>`, `<saml:Assertion>`, or
/// `<saml:EncryptedAssertion>`. Any other location is treated as a signature-
/// wrapping attempt and rejected.
///
/// The check runs before any signature verification so that a maliciously
/// placed signature cannot influence the outcome — not even by being silently
/// ignored.
fn enforce_signature_positions(document: &Document) -> Result<(), Error> {
    fn walk(
        element: &Element,
        parent: Option<&Element>,
    ) -> Result<(), Error> {
        if element.qname().namespace() == Some(DS_NS) && element.qname().local() == "Signature" {
            // The implicit `<ds:Signature>` inside another `<ds:Signature>`'s
            // `<ds:KeyInfo>` is not legal SAML; we forbid it too by requiring
            // an explicit allowed parent.
            let allowed = parent.is_some_and(|p| {
                let ns = p.qname().namespace();
                let local = p.qname().local();
                matches!(
                    (ns, local),
                    (Some(SAMLP_NS), "Response")
                        | (Some(SAML_NS), "Assertion" | "EncryptedAssertion")
                )
            });
            if !allowed {
                return Err(Error::SignatureVerification {
                    reason: "ds:Signature in disallowed position",
                });
            }
            // Do NOT descend into a (validly placed) Signature's own subtree:
            // `<ds:KeyInfo>` may legitimately contain further `<ds:Signature>`
            // descendants in exotic shapes (e.g. countersignatures), but our
            // SAML profile never relies on them — and we don't want to
            // double-count a Signature element as both signature and target.
            return Ok(());
        }
        for child in element.child_elements() {
            walk(child, Some(element))?;
        }
        Ok(())
    }
    walk(document.root(), None)
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

/// Inputs for [`handle_encrypted`]. Only exists under `xmlenc`: when the
/// feature is off the encrypted-assertion code path collapses to a single
/// `Error::InvalidConfiguration` at the call site, with no need for a
/// per-field params struct.
#[cfg(feature = "xmlenc")]
struct HandleEncryptedParams<'a> {
    document: &'a Document,
    response_root_id: ElementId,
    encrypted_assertion_id: ElementId,
    idp: &'a IdpDescriptor,
    policy: &'a PeerCryptoPolicy,
    decryption_keys: &'a [&'a KeyPair],
    want_response_signed: bool,
    want_assertions_signed: bool,
}

#[cfg(feature = "xmlenc")]
fn handle_encrypted(
    params: HandleEncryptedParams<'_>,
) -> Result<([u8; 32], Element, Option<Document>), Error> {
    let HandleEncryptedParams {
        document,
        response_root_id,
        encrypted_assertion_id,
        idp,
        policy,
        decryption_keys,
        want_response_signed,
        want_assertions_signed,
    } = params;
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
    let now_minus_skew = now.checked_sub(clock_skew).ok_or_else(|| {
        Error::XmlParse("now - clock_skew underflows SystemTime".to_string())
    })?;
    let now_plus_skew = now.checked_add(clock_skew).ok_or_else(|| {
        Error::XmlParse("now + clock_skew overflows SystemTime".to_string())
    })?;
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
            Some(nooa) if nooa > now_minus_skew => {}
            _ => {
                last_err = Some(Error::Expired);
                continue;
            }
        }
        // NotBefore: tolerated if absent; if present, must be ≤ now+skew.
        if let Some(nb) = sc.not_before
            && nb > now_plus_skew
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

/// Enforce non-downgrade against the requested AuthnContext per SAML 2.0
/// §3.3.2.2.1 (`exact` / `minimum` / `maximum` / `better`). All comparator
/// semantics — including the set-aggregating "stronger than each" rule for
/// `Better` — live in
/// [`crate::authn_context::StandardComparator`]; this function adapts its
/// tri-valued [`ComparatorOutcome`] onto the SP pipeline's binary
/// `Result<(), Error>` surface by collapsing both `NotSatisfied` and
/// `NotComparable` to [`Error::AuthnContextDowngrade`] (fail-closed).
fn check_authn_context(
    requested: &RequestedAuthnContext,
    actual_uri: &str,
) -> Result<(), Error> {
    match StandardComparator.evaluate(requested, actual_uri) {
        ComparatorOutcome::Satisfied => Ok(()),
        ComparatorOutcome::NotSatisfied | ComparatorOutcome::NotComparable => {
            Err(Error::AuthnContextDowngrade)
        }
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
    use crate::dsig::sign::{SignOptions, sign_element};
    use crate::nameid::NameIdFormat;
    use crate::response::parse::parse_response;
    use crate::response::{SAML_NS, SAMLP_NS, saml_qname, samlp_qname};
    use crate::xml::emit::emit_document;
    use crate::xml::parse::{Document, Node, QName};
    use std::time::{Duration, UNIX_EPOCH};

    // ---------- Test fixtures ----------

    fn fixed_now() -> SystemTime {
        // 2026-05-26T12:00:30Z
        UNIX_EPOCH
            .checked_add(Duration::from_secs(1_779_796_830))
            .expect("UNIX_EPOCH + small duration fits in SystemTime")
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

    /// Inputs for [`build_assertion`] test fixture.
    struct BuildAssertionFixture<'a> {
        id: &'a str,
        issuer: &'a str,
        recipient: &'a str,
        in_response_to: Option<&'a str>,
        audience: &'a str,
        not_before: &'a str,
        not_on_or_after: &'a str,
        sc_not_on_or_after: &'a str,
        authn_context: &'a str,
        name_id_value: &'a str,
        name_id_format_uri: &'a str,
    }

    /// Build a complete `<saml:Assertion>` Element parameterized by the
    /// most-commonly-tweaked fields.
    fn build_assertion(p: &BuildAssertionFixture<'_>) -> Element {
        let &BuildAssertionFixture {
            id,
            issuer,
            recipient,
            in_response_to,
            audience,
            not_before,
            not_on_or_after,
            sc_not_on_or_after,
            authn_context,
            name_id_value,
            name_id_format_uri,
        } = p;
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

    /// Inputs for [`build_and_sign_response`] test fixture.
    struct BuildAndSignResponseFixture<'a> {
        kp: &'a KeyPair,
        sign_response: bool,
        sign_assertion: bool,
        in_response_to: Option<&'a str>,
        audience: &'a str,
        recipient: &'a str,
        not_before: &'a str,
        not_on_or_after: &'a str,
    }

    /// Build a typical `<samlp:Response>` with an assertion signed by the test
    /// IdP key. Returns the assembled XML bytes.
    fn build_and_sign_response(p: &BuildAndSignResponseFixture<'_>) -> Vec<u8> {
        let &BuildAndSignResponseFixture {
            kp,
            sign_response,
            sign_assertion,
            in_response_to,
            audience,
            recipient,
            not_before,
            not_on_or_after,
        } = p;
        let mut assertion = build_assertion(&BuildAssertionFixture {
            id: "_a1",
            issuer: "https://idp.example.com",
            recipient,
            in_response_to,
            audience,
            not_before,
            not_on_or_after,
            sc_not_on_or_after: "2026-05-26T12:05:00Z",
            authn_context: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
            name_id_value: "alice@example.com",
            name_id_format_uri: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        });

        if sign_assertion {
            let stash_doc = Document::new(assertion.clone()).unwrap();
            assertion = sign_element(
                stash_doc.root().clone(),
                &stash_doc,
                SignOptions {
                    signing_key: kp,
                    sig_alg: SignatureAlgorithm::RsaSha256,
                    digest_alg: DigestAlgorithm::Sha256,
                    c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                    inclusive_namespaces: &[],
                    include_x509_cert: true,
                },
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
                SignOptions {
                    signing_key: kp,
                    sig_alg: SignatureAlgorithm::RsaSha256,
                    digest_alg: DigestAlgorithm::Sha256,
                    c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                    inclusive_namespaces: &[],
                    include_x509_cert: true,
                },
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
            #[cfg(feature = "xmlenc")]
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
        let xml = build_and_sign_response(&BuildAndSignResponseFixture {
            kp: &kp,
            sign_response: false,
            sign_assertion: true,
            in_response_to: Some("_req1"),
            audience: "https://sp.example.com",
            recipient: "https://sp.example.com/acs",
            not_before: "2026-05-26T11:59:00Z",
            not_on_or_after: "2026-05-26T12:10:00Z",
        });
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
        let xml = build_and_sign_response(&BuildAndSignResponseFixture {
            kp: &kp,
            sign_response: false,
            sign_assertion: true,
            in_response_to: Some("_req1"),
            audience: "https://sp.example.com",
            recipient: "https://sp.example.com/acs",
            not_before: "2026-05-26T11:59:00Z",
            not_on_or_after: "2026-05-26T12:10:00Z",
        });
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
        let assertion = build_assertion(&BuildAssertionFixture {
            id: "_a1",
            issuer: "https://idp.example.com",
            recipient: "https://sp.example.com/acs",
            in_response_to: Some("_req1"),
            audience: "https://sp.example.com",
            not_before: "2026-05-26T11:59:00Z",
            not_on_or_after: "2026-05-26T12:10:00Z",
            sc_not_on_or_after: "2026-05-26T12:05:00Z",
            authn_context: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
            name_id_value: "alice@example.com",
            name_id_format_uri: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        });
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
        let xml = build_and_sign_response(&BuildAndSignResponseFixture {
            kp: &kp,
            sign_response: false,
            sign_assertion: true,
            in_response_to: Some("_wrong-id"),
            audience: "https://sp.example.com",
            recipient: "https://sp.example.com/acs",
            not_before: "2026-05-26T11:59:00Z",
            not_on_or_after: "2026-05-26T12:10:00Z",
        });
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
        let xml = build_and_sign_response(&BuildAndSignResponseFixture {
            kp: &kp,
            sign_response: false,
            sign_assertion: true,
            in_response_to: None,
            audience: "https://sp.example.com",
            recipient: "https://sp.example.com/acs",
            not_before: "2026-05-26T11:59:00Z",
            not_on_or_after: "2026-05-26T12:10:00Z",
        });
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
        let xml = build_and_sign_response(&BuildAndSignResponseFixture {
            kp: &kp,
            sign_response: false,
            sign_assertion: true,
            in_response_to: None,
            audience: "https://sp.example.com",
            recipient: "https://sp.example.com/acs",
            not_before: "2026-05-26T11:59:00Z",
            not_on_or_after: "2026-05-26T12:10:00Z",
        });
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
        let xml = build_and_sign_response(&BuildAndSignResponseFixture {
            kp: &kp,
            sign_response: false,
            sign_assertion: true,
            in_response_to: Some("_req1"),
            audience: "https://other.example.com",
            recipient: "https://sp.example.com/acs",
            not_before: "2026-05-26T11:59:00Z",
            not_on_or_after: "2026-05-26T12:10:00Z",
        });
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
        let assertion = build_assertion(&BuildAssertionFixture {
            id: "_a1",
            issuer: "https://idp.example.com",
            recipient: "https://wrong.example.com/acs",
            in_response_to: Some("_req1"),
            audience: "https://sp.example.com",
            not_before: "2026-05-26T11:59:00Z",
            not_on_or_after: "2026-05-26T12:10:00Z",
            sc_not_on_or_after: "2026-05-26T12:05:00Z",
            authn_context: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
            name_id_value: "alice@example.com",
            name_id_format_uri: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        });
        let signed_assertion = {
            let d = Document::new(assertion).unwrap();
            sign_element(
                d.root().clone(),
                &d,
                SignOptions {
                    signing_key: &kp,
                    sig_alg: SignatureAlgorithm::RsaSha256,
                    digest_alg: DigestAlgorithm::Sha256,
                    c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                    inclusive_namespaces: &[],
                    include_x509_cert: true,
                },
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
        let xml = build_and_sign_response(&BuildAndSignResponseFixture {
            kp: &kp,
            sign_response: false,
            sign_assertion: true,
            in_response_to: Some("_req1"),
            audience: "https://sp.example.com",
            recipient: "https://sp.example.com/acs",
            not_before: "2026-05-26T13:00:00Z", // NotBefore far in the future
            not_on_or_after: "2026-05-26T14:00:00Z",
        });
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
        let xml = build_and_sign_response(&BuildAndSignResponseFixture {
            kp: &kp,
            sign_response: false,
            sign_assertion: true,
            in_response_to: Some("_req1"),
            audience: "https://sp.example.com",
            recipient: "https://sp.example.com/acs",
            not_before: "2025-01-01T00:00:00Z",
            not_on_or_after: "2025-12-31T23:59:59Z",
        });
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
        let assertion = build_assertion(&BuildAssertionFixture {
            id: "_a1",
            issuer: "https://idp.example.com",
            recipient: "https://sp.example.com/acs",
            in_response_to: Some("_req1"),
            audience: "https://sp.example.com",
            not_before: "2026-05-26T11:59:00Z",
            not_on_or_after: "2026-05-26T12:10:00Z",
            sc_not_on_or_after: "2026-05-26T12:05:00Z",
            authn_context: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
            name_id_value: "alice@example.com",
            name_id_format_uri: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        });
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
            SignOptions {
                signing_key: &kp,
                sig_alg: SignatureAlgorithm::RsaSha256,
                digest_alg: DigestAlgorithm::Sha256,
                c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                inclusive_namespaces: &[],
                include_x509_cert: true,
            },
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
        let xml = build_and_sign_response(&BuildAndSignResponseFixture {
            kp: &kp,
            sign_response: false,
            sign_assertion: true,
            in_response_to: Some("_req1"),
            audience: "https://sp.example.com",
            recipient: "https://sp.example.com/acs",
            not_before: "2026-05-26T11:59:00Z",
            not_on_or_after: "2026-05-26T12:10:00Z",
        });
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

    /// SAML 2.0 Core §2.5.1.5: when `<saml:OneTimeUse>` is present inside
    /// `<saml:Conditions>`, the relying party MUST refuse to consume the
    /// assertion more than once. The library itself does not implement the
    /// replay cache — that's the caller's responsibility — but the parsed
    /// flag MUST surface on `Identity` so the caller can act on it.
    /// Enforcement (rejecting a repeat) is exercised by the replay-cache
    /// layer; this test only nails down the flag-plumbing contract.
    #[test]
    fn one_time_use_flag_surfaces_on_identity() {
        // Build a standard assertion, then splice <saml:OneTimeUse/> into its
        // <saml:Conditions> child before signing. Doing the splice pre-signing
        // is important: the assertion signature MUST cover the OneTimeUse
        // element, otherwise an attacker could strip it (RFC-002 §3.2 XSW
        // family).
        let kp = rsa_signing_key();
        let mut assertion = build_assertion(&BuildAssertionFixture {
            id: "_a-one-time",
            issuer: "https://idp.example.com",
            recipient: "https://sp.example.com/acs",
            in_response_to: Some("_req1"),
            audience: "https://sp.example.com",
            not_before: "2026-05-26T11:59:00Z",
            not_on_or_after: "2026-05-26T12:10:00Z",
            sc_not_on_or_after: "2026-05-26T12:05:00Z",
            authn_context: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
            name_id_value: "alice@example.com",
            name_id_format_uri: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        });
        // Locate <saml:Conditions> and append <saml:OneTimeUse/>.
        let conditions_idx = assertion
            .children
            .iter()
            .position(|n| match n {
                Node::Element(e) => {
                    e.qname().namespace() == Some(SAML_NS)
                        && e.qname().local() == "Conditions"
                }
                _ => false,
            })
            .expect("assertion has <saml:Conditions>");
        let Node::Element(conditions) = &mut assertion.children[conditions_idx] else {
            panic!("expected Conditions element node");
        };
        let one_time_use = Element::build(saml_qname("OneTimeUse")).finish();
        conditions.children.push(Node::Element(one_time_use));

        // Now sign the modified assertion so the signature covers OneTimeUse.
        let stash_doc = Document::new(assertion).unwrap();
        let signed_assertion = sign_element(
            stash_doc.root().clone(),
            &stash_doc,
            SignOptions {
                signing_key: &kp,
                sig_alg: SignatureAlgorithm::RsaSha256,
                digest_alg: DigestAlgorithm::Sha256,
                c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                inclusive_namespaces: &[],
                include_x509_cert: true,
            },
        )
        .unwrap();

        let response = build_response_with_assertion(
            "_resp-one-time",
            Some("_req1"),
            "https://sp.example.com/acs",
            "https://idp.example.com",
            signed_assertion,
            STATUS_SUCCESS,
        );
        let doc = Document::new(response).unwrap();
        let xml = emit_document(&doc).unwrap().into_bytes();
        let doc = Document::parse(&xml).expect("re-parse");
        let (parsed, _) = parse_response(&doc).expect("parse_response");
        let idp = fixture_idp();
        let policy = strong_policy();
        let identity =
            validate_response(default_input(&doc, parsed, &idp, &policy)).expect("validate");

        assert_eq!(identity.assertion_id, "_a-one-time");
        assert!(
            identity.is_one_time_use,
            "Identity.is_one_time_use must surface when <saml:OneTimeUse/> is present in Conditions"
        );

        // Sanity: when the flag is absent, the default fixture leaves it
        // false. Guards against accidental "always true" plumbing.
        let xml2 = build_and_sign_response(&BuildAndSignResponseFixture {
            kp: &kp,
            sign_response: false,
            sign_assertion: true,
            in_response_to: Some("_req1"),
            audience: "https://sp.example.com",
            recipient: "https://sp.example.com/acs",
            not_before: "2026-05-26T11:59:00Z",
            not_on_or_after: "2026-05-26T12:10:00Z",
        });
        let doc2 = Document::parse(&xml2).expect("re-parse");
        let (parsed2, _) = parse_response(&doc2).expect("parse");
        let identity2 =
            validate_response(default_input(&doc2, parsed2, &idp, &policy)).expect("validate");
        assert!(
            !identity2.is_one_time_use,
            "Identity.is_one_time_use must be false when <saml:OneTimeUse/> is absent"
        );
    }

    #[test]
    fn accepts_authn_context_minimum_when_actual_is_stronger() {
        // Default fixture emits Password (strength 2). Minimum-of-Password
        // should pass.
        let kp = rsa_signing_key();
        let xml = build_and_sign_response(&BuildAndSignResponseFixture {
            kp: &kp,
            sign_response: false,
            sign_assertion: true,
            in_response_to: Some("_req1"),
            audience: "https://sp.example.com",
            recipient: "https://sp.example.com/acs",
            not_before: "2026-05-26T11:59:00Z",
            not_on_or_after: "2026-05-26T12:10:00Z",
        });
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

    // -------------------------------------------------------------------------
    // RequestedAuthnContext comparator wiring — full SAML 2.0 §3.3.2.2.1
    // matrix exercised through the validate_response pipeline.
    //
    // The shared assertion fixture emits AuthnContext = Password (strength 2).
    // We hold the assertion constant and vary the RequestedAuthnContext to
    // confirm each comparator branch is reached from the SP-side validator.
    //
    // The unit-level coverage of comparator logic lives in
    // `crate::authn_context::tests::*`; this block proves the wiring (the
    // `check_authn_context` adapter and the Step-17 call site).
    // -------------------------------------------------------------------------

    /// Build, sign, parse, and return `(doc, parsed)` for an assertion whose
    /// `AuthnContextClassRef` is `Password`. All comparator tests below share
    /// this fixture so the only variable is the comparator side.
    fn signed_password_response_doc() -> (Document, ParsedResponse) {
        let kp = rsa_signing_key();
        let xml = build_and_sign_response(&BuildAndSignResponseFixture {
            kp: &kp,
            sign_response: false,
            sign_assertion: true,
            in_response_to: Some("_req1"),
            audience: "https://sp.example.com",
            recipient: "https://sp.example.com/acs",
            not_before: "2026-05-26T11:59:00Z",
            not_on_or_after: "2026-05-26T12:10:00Z",
        });
        let doc = Document::parse(&xml).unwrap();
        let (parsed, _) = parse_response(&doc).unwrap();
        (doc, parsed)
    }

    /// Run `validate_response` against the shared Password fixture under
    /// `req`. Returns the validation outcome so callers can pattern-match.
    fn validate_with_requested(
        req: &RequestedAuthnContext,
    ) -> Result<crate::response::Identity, Error> {
        let (doc, parsed) = signed_password_response_doc();
        let idp = fixture_idp();
        let policy = strong_policy();
        let mut input = default_input(&doc, parsed, &idp, &policy);
        input.requested_authn_context = Some(req);
        validate_response(input)
    }

    // ---- Exact ----

    #[test]
    fn comparator_exact_accepts_matching_class_ref() {
        // Actual = Password; requested = {Password} Exact → satisfied.
        let req = RequestedAuthnContext {
            class_refs: vec![AuthnContextClassRef::Password],
            comparison: AuthnContextComparison::Exact,
        };
        let identity = validate_with_requested(&req).expect("validate");
        assert_eq!(identity.assertion_id, "_a1");
    }

    #[test]
    fn comparator_exact_accepts_when_actual_is_any_of_requested() {
        // Multi-ref Exact: passes if actual matches ANY listed URI.
        let req = RequestedAuthnContext {
            class_refs: vec![
                AuthnContextClassRef::Password,
                AuthnContextClassRef::MultiFactorAuth,
            ],
            comparison: AuthnContextComparison::Exact,
        };
        validate_with_requested(&req).expect("validate");
    }

    #[test]
    fn comparator_exact_rejects_when_actual_is_not_in_set() {
        let req = RequestedAuthnContext {
            class_refs: vec![AuthnContextClassRef::MultiFactorAuth],
            comparison: AuthnContextComparison::Exact,
        };
        let err = validate_with_requested(&req).unwrap_err();
        assert!(matches!(err, Error::AuthnContextDowngrade));
    }

    // ---- Minimum ----

    #[test]
    fn comparator_minimum_accepts_when_actual_equals_floor() {
        // Actual Password(2), requested Password(2) Minimum → satisfied.
        let req = RequestedAuthnContext {
            class_refs: vec![AuthnContextClassRef::Password],
            comparison: AuthnContextComparison::Minimum,
        };
        validate_with_requested(&req).expect("validate");
    }

    #[test]
    fn comparator_minimum_rejects_weaker_actual() {
        // Actual Password(2), requested PPT(3) Minimum → downgrade.
        let req = RequestedAuthnContext {
            class_refs: vec![AuthnContextClassRef::PasswordProtectedTransport],
            comparison: AuthnContextComparison::Minimum,
        };
        let err = validate_with_requested(&req).unwrap_err();
        assert!(matches!(err, Error::AuthnContextDowngrade));
    }

    #[test]
    fn comparator_minimum_uses_weakest_among_multiple_requested() {
        // Floor is the *weakest* requested ref. With {PreviousSession(1),
        // MultiFactorAuth(8)} the floor is 1, so Password(2) passes.
        let req = RequestedAuthnContext {
            class_refs: vec![
                AuthnContextClassRef::PreviousSession,
                AuthnContextClassRef::MultiFactorAuth,
            ],
            comparison: AuthnContextComparison::Minimum,
        };
        validate_with_requested(&req).expect("validate");
    }

    // ---- Maximum ----

    #[test]
    fn comparator_maximum_accepts_when_actual_is_weaker_or_equal() {
        // Ceiling Smartcard(6); actual Password(2) → 2 ≤ 6 → satisfied.
        let req = RequestedAuthnContext {
            class_refs: vec![AuthnContextClassRef::Smartcard],
            comparison: AuthnContextComparison::Maximum,
        };
        validate_with_requested(&req).expect("validate");
    }

    #[test]
    fn comparator_maximum_rejects_stronger_actual() {
        // Ceiling PreviousSession(1); actual Password(2) → 2 > 1 → reject.
        let req = RequestedAuthnContext {
            class_refs: vec![AuthnContextClassRef::PreviousSession],
            comparison: AuthnContextComparison::Maximum,
        };
        let err = validate_with_requested(&req).unwrap_err();
        assert!(matches!(err, Error::AuthnContextDowngrade));
    }

    #[test]
    fn comparator_maximum_uses_strongest_among_multiple_requested() {
        // Ceiling = max(Password(2), Smartcard(6)) = 6. Password(2) ≤ 6 → pass.
        let req = RequestedAuthnContext {
            class_refs: vec![
                AuthnContextClassRef::Password,
                AuthnContextClassRef::Smartcard,
            ],
            comparison: AuthnContextComparison::Maximum,
        };
        validate_with_requested(&req).expect("validate");
    }

    // ---- Better ----

    #[test]
    fn comparator_better_rejects_equal_strength() {
        // Better requires strict >. Equal Password(2) vs Password(2) → reject.
        let req = RequestedAuthnContext {
            class_refs: vec![AuthnContextClassRef::Password],
            comparison: AuthnContextComparison::Better,
        };
        let err = validate_with_requested(&req).unwrap_err();
        assert!(matches!(err, Error::AuthnContextDowngrade));
    }

    #[test]
    fn comparator_better_accepts_strictly_stronger_actual() {
        // Actual Password(2) > PreviousSession(1) → satisfied.
        let req = RequestedAuthnContext {
            class_refs: vec![AuthnContextClassRef::PreviousSession],
            comparison: AuthnContextComparison::Better,
        };
        validate_with_requested(&req).expect("validate");
    }

    #[test]
    fn comparator_better_requires_exceeding_every_requested() {
        // Spec §3.3.2.2.1: "better than the specified authentication
        // contexts" — i.e. strictly stronger than EACH. With
        // requested = {PreviousSession(1), Smartcard(6)}, ceiling = 6;
        // Password(2) is only > PreviousSession, not > Smartcard, so the
        // request MUST be rejected.
        let req = RequestedAuthnContext {
            class_refs: vec![
                AuthnContextClassRef::PreviousSession,
                AuthnContextClassRef::Smartcard,
            ],
            comparison: AuthnContextComparison::Better,
        };
        let err = validate_with_requested(&req).unwrap_err();
        assert!(matches!(err, Error::AuthnContextDowngrade));
    }

    // ---- Non-rankable Custom URIs ----

    #[test]
    fn comparator_minimum_with_unknown_requested_uri_fails_closed() {
        // All requested refs are Custom (non-rankable) → comparator returns
        // NotComparable, which the SP path collapses to AuthnContextDowngrade.
        let req = RequestedAuthnContext {
            class_refs: vec![AuthnContextClassRef::Custom(
                "urn:example:vendor:strong".into(),
            )],
            comparison: AuthnContextComparison::Minimum,
        };
        let err = validate_with_requested(&req).unwrap_err();
        assert!(matches!(err, Error::AuthnContextDowngrade));
    }

    #[test]
    fn comparator_exact_works_with_custom_uri_match() {
        // Build an assertion that emits a Custom URI; Exact match should pass.
        let kp = rsa_signing_key();
        let custom = "urn:example:vendor:strong";
        let assertion = build_assertion(&BuildAssertionFixture {
            id: "_a1",
            issuer: "https://idp.example.com",
            recipient: "https://sp.example.com/acs",
            in_response_to: Some("_req1"),
            audience: "https://sp.example.com",
            not_before: "2026-05-26T11:59:00Z",
            not_on_or_after: "2026-05-26T12:10:00Z",
            sc_not_on_or_after: "2026-05-26T12:05:00Z",
            authn_context: custom,
            name_id_value: "alice@example.com",
            name_id_format_uri: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        });
        let stash_doc = Document::new(assertion).unwrap();
        let signed = sign_element(
            stash_doc.root().clone(),
            &stash_doc,
            SignOptions {
                signing_key: &kp,
                sig_alg: SignatureAlgorithm::RsaSha256,
                digest_alg: DigestAlgorithm::Sha256,
                c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                inclusive_namespaces: &[],
                include_x509_cert: true,
            },
        )
        .unwrap();
        let response = build_response_with_assertion(
            "_resp1",
            Some("_req1"),
            "https://sp.example.com/acs",
            "https://idp.example.com",
            signed,
            STATUS_SUCCESS,
        );
        let doc = Document::new(response).unwrap();
        let xml = emit_document(&doc).unwrap().into_bytes();
        let doc = Document::parse(&xml).unwrap();
        let (parsed, _) = parse_response(&doc).unwrap();
        let idp = fixture_idp();
        let policy = strong_policy();
        let mut input = default_input(&doc, parsed, &idp, &policy);
        let req = RequestedAuthnContext {
            class_refs: vec![AuthnContextClassRef::Custom(custom.into())],
            comparison: AuthnContextComparison::Exact,
        };
        input.requested_authn_context = Some(&req);
        validate_response(input).expect("validate");
    }

    #[test]
    fn comparator_rejects_when_actual_authn_context_class_ref_missing() {
        // If the AuthnStatement has no ClassRef but the SP supplied a
        // RequestedAuthnContext, validation must fail (per RFC-003 §4.1 step
        // 17). This is enforced by validate_response before
        // check_authn_context is even called.
        //
        // The OASIS XSD requires `<saml:AuthnContext>` as a child of
        // `<saml:AuthnStatement>` (minOccurs=1), so we cannot just strip the
        // whole AuthnContext — the structural schema gate (RFC-002 §0,
        // `crate::schema`) would reject the message before validate_response
        // ever ran. Instead we keep an empty `<saml:AuthnContext/>` (no
        // ClassRef child) — schema-valid per OASIS (all children of
        // AuthnContext are minOccurs=0), but the parser yields
        // `authn_context_class_ref = None`, which is the condition the
        // downgrade check is designed to surface.
        let kp = rsa_signing_key();
        let mut assertion = build_assertion(&BuildAssertionFixture {
            id: "_a1",
            issuer: "https://idp.example.com",
            recipient: "https://sp.example.com/acs",
            in_response_to: Some("_req1"),
            audience: "https://sp.example.com",
            not_before: "2026-05-26T11:59:00Z",
            not_on_or_after: "2026-05-26T12:10:00Z",
            sc_not_on_or_after: "2026-05-26T12:05:00Z",
            authn_context: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
            name_id_value: "alice@example.com",
            name_id_format_uri: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        });
        // Locate the <saml:AuthnStatement> and strip every child element of
        // its inner <saml:AuthnContext> so the parser's lookup for
        // <AuthnContextClassRef> yields None.
        let astmt_idx = assertion
            .children
            .iter()
            .position(|n| match n {
                Node::Element(e) => {
                    e.qname().namespace() == Some(SAML_NS)
                        && e.qname().local() == "AuthnStatement"
                }
                _ => false,
            })
            .expect("assertion has <saml:AuthnStatement>");
        let Node::Element(astmt) = &mut assertion.children[astmt_idx] else {
            panic!("expected AuthnStatement element node");
        };
        let actx_idx = astmt
            .children
            .iter()
            .position(|n| match n {
                Node::Element(e) => {
                    e.qname().namespace() == Some(SAML_NS)
                        && e.qname().local() == "AuthnContext"
                }
                _ => false,
            })
            .expect("AuthnStatement has <saml:AuthnContext>");
        let Node::Element(actx) = &mut astmt.children[actx_idx] else {
            panic!("expected AuthnContext element node");
        };
        actx.children.clear();
        let stash_doc = Document::new(assertion).unwrap();
        let signed = sign_element(
            stash_doc.root().clone(),
            &stash_doc,
            SignOptions {
                signing_key: &kp,
                sig_alg: SignatureAlgorithm::RsaSha256,
                digest_alg: DigestAlgorithm::Sha256,
                c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                inclusive_namespaces: &[],
                include_x509_cert: true,
            },
        )
        .unwrap();
        let response = build_response_with_assertion(
            "_resp1",
            Some("_req1"),
            "https://sp.example.com/acs",
            "https://idp.example.com",
            signed,
            STATUS_SUCCESS,
        );
        let doc = Document::new(response).unwrap();
        let xml = emit_document(&doc).unwrap().into_bytes();
        let doc = Document::parse(&xml).unwrap();
        let (parsed, _) = parse_response(&doc).unwrap();
        let idp = fixture_idp();
        let policy = strong_policy();
        let mut input = default_input(&doc, parsed, &idp, &policy);
        let req = RequestedAuthnContext {
            class_refs: vec![AuthnContextClassRef::Password],
            comparison: AuthnContextComparison::Exact,
        };
        input.requested_authn_context = Some(&req);
        let err = validate_response(input).unwrap_err();
        assert!(matches!(err, Error::AuthnContextDowngrade));
    }
}
