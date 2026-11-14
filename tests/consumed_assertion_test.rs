//! `ServiceProvider::consume_response_with_assertion` (RFC-003 §4.3).
//!
//! The SP consumes a Response and gets the verified assertion back as a
//! standalone document. Where the assertion can stand alone, the tests present
//! it to the issuing IdP through `verify_issued_assertion` (RFC-004 §3.3),
//! which is the round trip this API exists for.

#[path = "common/mod.rs"]
mod common;

use std::time::{Duration, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use saml::authn_context::AuthnContextClassRef;
use saml::binding::{SsoResponseBinding, SsoResponseDispatch};
use saml::idp::{IssueUnsolicited, VerifyIssuedAssertion};
use saml::nameid::NameId;
use saml::sp::{ConsumeResponse, ConsumedResponse};
use saml::{
    IdentityProvider, IdentityProviderConfig, IdpDescriptor, ReplayMode, ServiceProvider,
    ServiceProviderConfig, SpDescriptor,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/consumed";
const SP_ACS_URL: &str = "https://sp.example.com/consumed/acs";
const IDP_ENTITY_ID: &str = "https://idp.example.com/consumed";
const IDP_SSO_URL: &str = "https://idp.example.com/consumed/sso";

const SKEW: Duration = Duration::from_mins(2);

struct Fixture {
    sp: ServiceProvider,
    sp_descriptor: SpDescriptor,
    idp: IdentityProvider,
    idp_descriptor: IdpDescriptor,
    now: SystemTime,
}

/// An SP that accepts IdP-initiated Responses and its IdP, each adjusted by
/// the given closure.
fn fixture(
    change_sp: impl FnOnce(&mut ServiceProviderConfig),
    change_idp: impl FnOnce(&mut IdentityProviderConfig),
) -> Fixture {
    let mut sp_config = common::make_sp(SP_ENTITY_ID, SP_ACS_URL, false)
        .expect("sp builds")
        .config()
        .clone();
    sp_config.allow_unsolicited = true;
    change_sp(&mut sp_config);
    let sp = ServiceProvider::new(sp_config).expect("sp config valid");

    let mut idp_config = common::make_idp(IDP_ENTITY_ID, IDP_SSO_URL)
        .expect("idp builds")
        .config()
        .clone();
    change_idp(&mut idp_config);
    let idp = IdentityProvider::new(idp_config).expect("idp config valid");

    Fixture {
        sp_descriptor: common::sp_descriptor(&sp).expect("sp descriptor"),
        idp_descriptor: common::idp_descriptor(&idp).expect("idp descriptor"),
        sp,
        idp,
        now: common::fixed_now().expect("fixed now"),
    }
}

/// Decoded `<samlp:Response>` XML for an IdP-initiated sign-on of
/// `alice@example.com`.
fn issue_response(f: &Fixture, encrypt: bool) -> Vec<u8> {
    let dispatch = f
        .idp
        .issue_unsolicited(IssueUnsolicited {
            sp: &f.sp_descriptor,
            acs_url: SP_ACS_URL,
            name_id: NameId::email("alice@example.com"),
            attributes: vec![],
            authn_instant: f.now,
            session_index: "sess-consumed-1".to_owned(),
            session_not_on_or_after: None,
            authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
            requested_name_id_format: None,
            relay_state: None,
            force_encrypt_assertion: Some(encrypt),
            now: f.now,
            assertion_lifetime: Duration::from_mins(10),
            subject_confirmation_lifetime: Duration::from_mins(5),
            holder_of_key_cert: None,
        })
        .expect("issue_unsolicited");
    let SsoResponseDispatch::Post(form) = dispatch else {
        panic!("expected POST dispatch");
    };
    BASE64
        .decode(form.saml_response.as_bytes())
        .expect("SAMLResponse base64")
}

fn consume_input<'a>(f: &'a Fixture, saml_response: &'a [u8]) -> ConsumeResponse<'a> {
    ConsumeResponse {
        idp: &f.idp_descriptor,
        peer_crypto_policy: None,
        saml_response,
        binding: SsoResponseBinding::HttpPost,
        relay_state: None,
        tracker: None,
        expected_destination: SP_ACS_URL,
        now: f.now,
        clock_skew: SKEW,
        replay_cache: None,
        replay_mode: ReplayMode::All,
        holder_of_key_cert: None,
    }
}

fn consume(f: &Fixture, saml_response: &[u8]) -> ConsumedResponse {
    f.sp.consume_response_with_assertion(consume_input(f, saml_response))
        .expect("response is valid")
}

/// Present `assertion_xml` to the IdP that issued it.
fn verify_at_idp(f: &Fixture, assertion_xml: &str) -> saml::Identity {
    f.idp
        .verify_issued_assertion(VerifyIssuedAssertion {
            sp: &f.sp_descriptor,
            crypto_policy: None,
            assertion: assertion_xml.as_bytes(),
            retired_signing_certs: &[],
            now: f.now,
            clock_skew: SKEW,
        })
        .expect("the issuer accepts its own assertion")
}

#[test]
fn returns_the_signed_assertion_and_the_issuer_accepts_it() {
    let f = fixture(|_| {}, |_| {});
    let response = issue_response(&f, false);

    let consumed = consume(&f, &response);
    let assertion = consumed.assertion.expect("assertion is signed");

    assert!(assertion.as_xml().starts_with("<saml:Assertion"));
    let at_idp = verify_at_idp(&f, assertion.as_xml());
    assert_eq!(at_idp.assertion_id(), consumed.identity.assertion_id());
    assert_eq!(at_idp.name_id().value, "alice@example.com");
}

#[test]
fn identity_matches_consume_response() {
    let f = fixture(|_| {}, |_| {});
    let response = issue_response(&f, false);

    let plain =
        f.sp.consume_response(consume_input(&f, &response))
            .expect("response is valid");
    let consumed = consume(&f, &response);

    assert_eq!(consumed.identity.assertion_id(), plain.assertion_id());
    assert_eq!(consumed.identity.name_id().value, plain.name_id().value);
    assert_eq!(consumed.identity.not_on_or_after(), plain.not_on_or_after());
    assert_eq!(
        consumed.identity.verifying_cert_fingerprint(),
        plain.verifying_cert_fingerprint(),
    );
}

/// With only the Response signed, the assertion has no signature of its own.
/// The login is still valid; there is just nothing that can stand alone.
#[test]
fn returns_no_assertion_when_only_the_response_is_signed() {
    let f = fixture(
        |sp| {
            sp.want_signed.response = true;
            sp.want_signed.assertions = false;
        },
        |idp| {
            idp.assertion_signing.sign_responses = true;
            idp.assertion_signing.sign_assertions = false;
        },
    );
    let response = issue_response(&f, false);

    let consumed = consume(&f, &response);

    assert_eq!(consumed.identity.name_id().value, "alice@example.com");
    assert!(consumed.assertion.is_none());
}

/// An encrypted assertion comes back decrypted, with its inner signature
/// intact, so the issuer can still verify it.
#[cfg(feature = "xmlenc")]
#[test]
fn returns_an_encrypted_assertion_decrypted() {
    let f = fixture(
        |sp| sp.decryption_key = Some(common::rsa_keypair_with_cert().expect("key")),
        |_| {},
    );
    let response = issue_response(&f, true);
    assert!(
        String::from_utf8_lossy(&response).contains("EncryptedAssertion"),
        "fixture must exercise the encrypted path",
    );

    let consumed = consume(&f, &response);
    let assertion = consumed.assertion.expect("inner assertion is signed");

    assert!(assertion.as_xml().contains("alice@example.com"));
    let at_idp = verify_at_idp(&f, assertion.as_xml());
    assert_eq!(at_idp.assertion_id(), consumed.identity.assertion_id());
}

/// The assertion is a bearer credential, so `Debug` must not print it.
#[test]
fn debug_does_not_print_the_assertion() {
    let f = fixture(|_| {}, |_| {});
    let response = issue_response(&f, false);

    let assertion = consume(&f, &response)
        .assertion
        .expect("assertion is signed");
    let printed = format!("{assertion:?}");

    assert!(!printed.contains("alice@example.com"), "{printed}");
    assert!(!printed.contains("SignatureValue"), "{printed}");
}
