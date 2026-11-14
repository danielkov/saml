//! `IdentityProvider::verify_issued_assertion` (RFC-004 §3.3).
//!
//! Each test issues a real Response, lifts the signed `<saml:Assertion>` out
//! of it the way a presenter would, and hands the standalone assertion back to
//! the IdP.

#[path = "common/mod.rs"]
mod common;

use std::io::Read;
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use flate2::read::DeflateDecoder;

use saml::authn_context::AuthnContextClassRef;
use saml::binding::{Binding, Dispatch, SsoResponseBinding, SsoResponseDispatch};
use saml::idp::{ConsumeAuthnRequest, IssueResponse, IssueUnsolicited, VerifyIssuedAssertion};
use saml::nameid::{NameId, NameIdFormat};
use saml::sp::StartLogin;
use saml::{Error, IdentityProvider, KeyPair, SpDescriptor, X509Certificate};

const SP_ENTITY_ID: &str = "https://sp.example.com/issued";
const SP_ACS_URL: &str = "https://sp.example.com/issued/acs";
const IDP_ENTITY_ID: &str = "https://idp.example.com/issued";
const IDP_SSO_URL: &str = "https://idp.example.com/issued/sso";

const SECOND_RSA_CERT_PEM: &[u8] = include_bytes!("../examples/demo/keys/sp.crt");
const SECOND_RSA_KEY_PEM: &[u8] = include_bytes!("../examples/demo/keys/sp.key");

const SKEW: Duration = Duration::from_mins(2);

struct Fixture {
    idp: IdentityProvider,
    sp: SpDescriptor,
    now: SystemTime,
}

fn fixture() -> Fixture {
    let sp = common::make_sp(SP_ENTITY_ID, SP_ACS_URL, false).expect("sp builds");
    Fixture {
        idp: common::make_idp(IDP_ENTITY_ID, IDP_SSO_URL).expect("idp builds"),
        sp: common::sp_descriptor(&sp).expect("sp descriptor"),
        now: common::fixed_now().expect("fixed now"),
    }
}

/// Cut the `<saml:Assertion>` element out of a base64 `SAMLResponse`. The
/// issuer declares `xmlns:saml` on the assertion itself, so the slice is a
/// self-contained document and its signature still verifies.
fn assertion_from_post_form(dispatch: SsoResponseDispatch) -> String {
    let SsoResponseDispatch::Post(form) = dispatch else {
        panic!("expected POST dispatch");
    };
    let response = String::from_utf8(
        BASE64
            .decode(form.saml_response.as_bytes())
            .expect("SAMLResponse base64"),
    )
    .expect("SAMLResponse utf-8");
    let start = response.find("<saml:Assertion").expect("assertion start");
    let close = "</saml:Assertion>";
    let end = response
        .find(close)
        .expect("assertion end")
        .checked_add(close.len())
        .expect("offset fits");
    response
        .get(start..end)
        .expect("assertion slice on char boundaries")
        .to_owned()
}

/// An unsolicited (IdP-initiated) bearer assertion for `alice@example.com`.
fn issue_assertion(f: &Fixture) -> String {
    issue_assertion_confirmed_by(f, None)
}

/// As [`issue_assertion`], with a Holder-of-Key confirmation when
/// `holder_of_key_cert` is `Some`.
fn issue_assertion_confirmed_by(
    f: &Fixture,
    holder_of_key_cert: Option<&X509Certificate>,
) -> String {
    let dispatch = f
        .idp
        .issue_unsolicited(IssueUnsolicited {
            sp: &f.sp,
            acs_url: SP_ACS_URL,
            name_id: NameId::email("alice@example.com"),
            attributes: vec![],
            authn_instant: f.now,
            session_index: "sess-issued-1".to_owned(),
            session_not_on_or_after: None,
            authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
            requested_name_id_format: None,
            relay_state: None,
            force_encrypt_assertion: Some(false),
            now: f.now,
            assertion_lifetime: Duration::from_mins(10),
            subject_confirmation_lifetime: Duration::from_mins(5),
            holder_of_key_cert,
        })
        .expect("issue_unsolicited");
    assertion_from_post_form(dispatch)
}

fn verify(
    idp: &IdentityProvider,
    sp: &SpDescriptor,
    assertion: &str,
    now: SystemTime,
) -> Result<saml::Identity, Error> {
    idp.verify_issued_assertion(VerifyIssuedAssertion {
        sp,
        crypto_policy: None,
        assertion: assertion.as_bytes(),
        retired_signing_certs: &[],
        now,
        clock_skew: SKEW,
    })
}

/// The same IdP config with one field changed.
fn idp_with(
    base: &IdentityProvider,
    change: impl FnOnce(&mut saml::IdentityProviderConfig),
) -> IdentityProvider {
    let mut config = base.config().clone();
    change(&mut config);
    IdentityProvider::new(config).expect("idp config valid")
}

fn second_keypair() -> KeyPair {
    KeyPair::from_pkcs8_pem(SECOND_RSA_KEY_PEM)
        .expect("second RSA key")
        .with_certificate(X509Certificate::from_pem(SECOND_RSA_CERT_PEM).expect("second RSA cert"))
        .expect("matching second RSA certificate")
}

#[test]
fn accepts_an_assertion_the_idp_issued_to_the_sp() {
    let f = fixture();
    let assertion = issue_assertion(&f);

    let identity = verify(&f.idp, &f.sp, &assertion, f.now).expect("issued assertion verifies");

    assert_eq!(identity.name_id().value, "alice@example.com");
    assert_eq!(identity.session_index(), Some("sess-issued-1"));
    assert!(
        assertion.contains(&format!(r#"ID="{}""#, identity.assertion_id())),
        "the identity must describe the presented assertion",
    );
    assert_eq!(
        identity.verifying_cert_fingerprint(),
        common::rsa_cert().expect("cert").fingerprint_sha256(),
    );
}

/// A solicited assertion carries `InResponseTo` on its subject confirmation.
/// The IdP holds no request tracker, so the value must not block verification.
#[test]
fn accepts_a_solicited_assertion_without_a_request_tracker() {
    let f = fixture();
    let sp = common::make_sp(SP_ENTITY_ID, SP_ACS_URL, false).expect("sp builds");
    let idp_descriptor = common::idp_descriptor(&f.idp).expect("idp descriptor");
    // `start_login` stamps the request from the real clock, so the whole
    // flow has to run on it.
    let now = SystemTime::now();

    let start = sp
        .start_login(
            &idp_descriptor,
            StartLogin {
                relay_state: None,
                binding: Binding::HttpRedirect,
                force_authn: false,
                is_passive: false,
                requested_name_id_format: Some(NameIdFormat::EmailAddress),
                requested_authn_context: None,
                acs_index: None,
                acs_url: None,
                response_binding: Some(SsoResponseBinding::HttpPost),
            },
        )
        .expect("start_login");
    let Dispatch::Redirect(redirect_url) = start.dispatch else {
        panic!("expected Redirect dispatch");
    };
    let saml_request = redirect_url
        .query_pairs()
        .find(|(k, _)| k == "SAMLRequest")
        .map(|(_, v)| v.into_owned())
        .expect("SAMLRequest present");
    let deflated = BASE64.decode(saml_request.as_bytes()).expect("base64");
    let mut authn_request_xml = Vec::new();
    DeflateDecoder::new(deflated.as_slice())
        .read_to_end(&mut authn_request_xml)
        .expect("inflate");

    let parsed = f
        .idp
        .consume_authn_request(ConsumeAuthnRequest {
            sp: &f.sp,
            peer_crypto_policy: None,
            max_authn_request_age: None,
            saml_request: &authn_request_xml,
            binding: Binding::HttpRedirect,
            relay_state: None,
            detached_signature: None,
            expected_destination: IDP_SSO_URL,
            now,
            clock_skew: SKEW,
        })
        .expect("consume_authn_request");
    let dispatch = f
        .idp
        .issue_response(IssueResponse {
            sp: &f.sp,
            in_response_to: &parsed,
            name_id: NameId::email("alice@example.com"),
            attributes: vec![],
            authn_instant: now,
            session_index: "sess-issued-2".to_owned(),
            session_not_on_or_after: None,
            authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
            force_encrypt_assertion: Some(false),
            now,
            assertion_lifetime: Duration::from_mins(10),
            subject_confirmation_lifetime: Duration::from_mins(5),
            holder_of_key_cert: None,
        })
        .expect("issue_response");
    let assertion = assertion_from_post_form(dispatch);
    assert!(
        assertion.contains("InResponseTo="),
        "fixture must exercise a solicited confirmation",
    );

    let identity = verify(&f.idp, &f.sp, &assertion, now).expect("solicited assertion verifies");
    assert_eq!(identity.name_id().value, "alice@example.com");
}

#[test]
fn rejects_a_response_document() {
    let f = fixture();
    let assertion = issue_assertion(&f);
    let wrapped = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">{assertion}</samlp:Response>"#
    );

    let err = verify(&f.idp, &f.sp, &wrapped, f.now).expect_err("root must be the assertion");
    assert!(matches!(err, Error::XmlParse(_)), "{err:?}");
}

#[test]
fn rejects_an_assertion_issued_to_another_sp() {
    let f = fixture();
    let assertion = issue_assertion(&f);
    let mut other = f.sp.clone();
    other.entity_id = "https://other-sp.example.com".to_owned();

    let err = verify(&f.idp, &other, &assertion, f.now).expect_err("audience must match");
    assert!(matches!(err, Error::AudienceMismatch), "{err:?}");
}

#[test]
fn rejects_a_recipient_that_is_not_a_registered_acs() {
    let f = fixture();
    let assertion = issue_assertion(&f);
    let mut moved = f.sp.clone();
    for acs in &mut moved.assertion_consumer_services {
        acs.url = "https://sp.example.com/issued/other-acs".to_owned();
    }

    let err = verify(&f.idp, &moved, &assertion, f.now).expect_err("recipient must be registered");
    assert!(matches!(err, Error::RecipientMismatch), "{err:?}");
}

#[test]
fn rejects_an_assertion_from_another_issuer() {
    let f = fixture();
    let assertion = issue_assertion(&f);
    // Same key, different entity ID: the signature verifies, the Issuer does not match.
    let other_idp = idp_with(&f.idp, |config| {
        config.entity_id = "https://other-idp.example.com".to_owned();
    });

    let err = verify(&other_idp, &f.sp, &assertion, f.now).expect_err("issuer must match");
    assert!(matches!(err, Error::IssuerMismatch { .. }), "{err:?}");
}

#[test]
fn rejects_an_expired_assertion() {
    let f = fixture();
    let assertion = issue_assertion(&f);
    let later = f
        .now
        .checked_add(Duration::from_hours(1))
        .expect("later fits");

    let err = verify(&f.idp, &f.sp, &assertion, later).expect_err("assertion expired");
    assert!(matches!(err, Error::Expired), "{err:?}");
}

/// The subject confirmation window (5 minutes) closes before the Conditions
/// window (10 minutes). The shorter one still binds.
#[test]
fn rejects_an_expired_subject_confirmation_inside_a_live_conditions_window() {
    let f = fixture();
    let assertion = issue_assertion(&f);
    let later = f
        .now
        .checked_add(Duration::from_mins(8))
        .expect("later fits");

    let err = verify(&f.idp, &f.sp, &assertion, later).expect_err("confirmation expired");
    assert!(matches!(err, Error::Expired), "{err:?}");
}

#[test]
fn rejects_a_tampered_assertion() {
    let f = fixture();
    let assertion = issue_assertion(&f).replace("alice@example.com", "mallory@example.com");

    verify(&f.idp, &f.sp, &assertion, f.now).expect_err("digest no longer matches");
}

#[test]
fn rejects_an_unsigned_assertion() {
    let f = fixture();
    let assertion = issue_assertion(&f);
    let start = assertion.find("<ds:Signature").expect("signature start");
    let close = "</ds:Signature>";
    let end = assertion
        .find(close)
        .expect("signature end")
        .checked_add(close.len())
        .expect("offset fits");
    let mut unsigned = assertion.clone();
    unsigned.replace_range(start..end, "");

    let err = verify(&f.idp, &f.sp, &unsigned, f.now).expect_err("signature is required");
    assert!(matches!(err, Error::SignatureMissing), "{err:?}");
}

/// A second `<ds:Signature>` anywhere but the assertion root is refused on
/// position alone, before any signature is evaluated.
#[test]
fn rejects_a_signature_outside_the_assertion_root() {
    let f = fixture();
    let assertion = issue_assertion(&f);
    let start = assertion.find("<ds:Signature").expect("signature start");
    let close = "</ds:Signature>";
    let end = assertion
        .find(close)
        .expect("signature end")
        .checked_add(close.len())
        .expect("offset fits");
    let signature = assertion.get(start..end).expect("signature slice");
    let wrapped = assertion.replacen("</saml:Subject>", &format!("{signature}</saml:Subject>"), 1);

    let err = verify(&f.idp, &f.sp, &wrapped, f.now).expect_err("misplaced signature");
    assert!(
        matches!(
            err,
            Error::SignatureVerification {
                reason: "ds:Signature in disallowed position"
            }
        ),
        "{err:?}",
    );
}

/// Holder-of-Key needs the presenter's TLS certificate, which this call does
/// not take. An assertion with no bearer confirmation is therefore unusable.
#[test]
fn rejects_a_holder_of_key_only_assertion() {
    let f = fixture();
    let subject_cert = common::rsa_cert().expect("subject cert");
    let assertion = issue_assertion_confirmed_by(&f, Some(&subject_cert));

    let err = verify(&f.idp, &f.sp, &assertion, f.now).expect_err("no bearer confirmation");
    assert!(
        matches!(err, Error::HolderOfKeyConfirmation { .. }),
        "{err:?}"
    );
}

#[test]
fn accepts_a_retired_signing_cert_only_when_listed() {
    let f = fixture();
    let assertion = issue_assertion(&f);
    // The IdP has rotated to a new key since issuing the assertion.
    let rotated = idp_with(&f.idp, |config| config.signing_key = second_keypair());
    let retired = [common::rsa_cert().expect("retired cert")];

    verify(&rotated, &f.sp, &assertion, f.now)
        .expect_err("the old key is not trusted unless the caller lists it");

    let identity = rotated
        .verify_issued_assertion(VerifyIssuedAssertion {
            sp: &f.sp,
            crypto_policy: None,
            assertion: assertion.as_bytes(),
            retired_signing_certs: &retired,
            now: f.now,
            clock_skew: SKEW,
        })
        .expect("retired cert verifies");
    assert_eq!(
        identity.verifying_cert_fingerprint(),
        retired
            .first()
            .expect("one retired cert")
            .fingerprint_sha256(),
    );
}

#[test]
fn needs_a_certificate_to_verify_against() {
    let f = fixture();
    let assertion = issue_assertion(&f);
    let bare_key = KeyPair::from_pkcs8_pem(common::RSA_KEY_PKCS8_PEM).expect("key without cert");
    let certless = idp_with(&f.idp, |config| config.signing_key = bare_key);

    let err = verify(&certless, &f.sp, &assertion, f.now).expect_err("no candidate certificate");
    assert!(matches!(err, Error::InvalidConfiguration { .. }), "{err:?}");
}
