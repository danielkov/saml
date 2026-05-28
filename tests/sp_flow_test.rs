//! SP-role end-to-end cross-role flow test.
//!
//! Builds an SP + a real IdP, drives `start_login`, lets the IdP issue a real
//! Response, extracts the SAMLResponse from the POST dispatch, and consumes
//! it back through the SP. Also exercises the negative path: a single-byte
//! mutation of the signed Response must trip the signature verifier.

#[path = "common/mod.rs"]
mod common;

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use saml::attribute::Attribute;
use saml::authn_context::AuthnContextClassRef;
use saml::binding::{Binding, Dispatch, SsoResponseBinding, SsoResponseDispatch};
use saml::error::Error;
use saml::idp::{ConsumeAuthnRequest, IssueResponse};
use saml::nameid::{NameId, NameIdFormat};
use saml::sp::{ConsumeResponse, StartLogin};

const SP_ENTITY_ID: &str = "https://sp.example.com/sp-flow";
const SP_ACS_URL: &str = "https://sp.example.com/sp-flow/acs";
const IDP_ENTITY_ID: &str = "https://idp.example.com/sp-flow";
const IDP_SSO_URL: &str = "https://idp.example.com/sp-flow/sso";

const USER_EMAIL: &str = "alice@example.com";
const USER_DISPLAY_NAME: &str = "Alice Example";

/// Walk an SP through a full IdP-issued Response and assert the identity.
#[test]
fn sp_consumes_real_idp_response() {
    let sp = common::make_sp(SP_ENTITY_ID, SP_ACS_URL, false).expect("sp builds");
    let idp = common::make_idp(IDP_ENTITY_ID, IDP_SSO_URL).expect("idp builds");
    let idp_descriptor = common::idp_descriptor(&idp).expect("idp descriptor");
    let sp_descriptor = common::sp_descriptor(&sp).expect("sp descriptor");
    let now = common::fixed_now().expect("fixed_now");

    // 1. Kick off SP-side login.
    let start = sp
        .start_login(
            &idp_descriptor,
            StartLogin {
                relay_state: Some("sp-flow-relay"),
                binding: Binding::HttpPost,
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

    // 2. Extract the AuthnRequest XML out of the POST dispatch.
    let authn_request_xml = match start.dispatch {
        Dispatch::Post(form) => {
            let b64 = form
                .saml_request
                .expect("POST dispatch carries SAMLRequest");
            BASE64.decode(b64.as_bytes()).expect("base64 valid")
        }
        Dispatch::Redirect(_) => panic!("expected POST dispatch"),
    };

    // 3. IdP consumes the AuthnRequest.
    let parsed = idp
        .consume_authn_request(ConsumeAuthnRequest {
            sp: &sp_descriptor,
            peer_crypto_policy: None,
            saml_request: &authn_request_xml,
            binding: Binding::HttpPost,
            relay_state: Some("sp-flow-relay"),
            detached_signature: None,
            expected_destination: IDP_SSO_URL,
            now,
            clock_skew: Duration::from_mins(2),
        })
        .expect("idp consume_authn_request");

    // 4. IdP issues a Response.
    let dispatch = idp
        .issue_response(IssueResponse {
            sp: &sp_descriptor,
            in_response_to: &parsed,
            name_id: NameId::email(USER_EMAIL),
            attributes: vec![
                Attribute::email(USER_EMAIL),
                Attribute::display_name(USER_DISPLAY_NAME),
            ],
            authn_instant: now,
            session_index: "sess-sp-flow-1".to_owned(),
            session_not_on_or_after: Some(
                now.checked_add(Duration::from_hours(1))
                    .expect("session_not_on_or_after fits"),
            ),
            authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
            force_encrypt_assertion: None,
            now,
            assertion_lifetime: Duration::from_mins(10),
            subject_confirmation_lifetime: Duration::from_mins(5),
        })
        .expect("idp issue_response");

    // 5. Extract the SAMLResponse XML from the POST dispatch.
    let response_xml = extract_response_xml(dispatch).expect("extract response xml");

    // 6. SP consumes the Response.
    let identity = sp
        .consume_response(ConsumeResponse {
            idp: &idp_descriptor,
            peer_crypto_policy: None,
            saml_response: &response_xml,
            binding: SsoResponseBinding::HttpPost,
            relay_state: Some("sp-flow-relay"),
            tracker: Some(&start.tracker),
            expected_destination: SP_ACS_URL,
            now,
            clock_skew: Duration::from_mins(2),
            replay_cache: None,
        })
        .expect("sp consume_response");

    // 7. Assertions on the recovered Identity.
    assert_eq!(identity.name_id.format, NameIdFormat::EmailAddress);
    assert_eq!(identity.name_id.value, USER_EMAIL);
    assert_eq!(identity.session_index.as_deref(), Some("sess-sp-flow-1"));

    let email_attr = identity
        .attributes
        .iter()
        .find(|a| a.friendly_name.as_deref() == Some("mail"))
        .expect("mail attribute present");
    assert_eq!(email_attr.values, vec![USER_EMAIL.to_owned()]);

    let display_attr = identity
        .attributes
        .iter()
        .find(|a| a.friendly_name.as_deref() == Some("displayName"))
        .expect("displayName attribute present");
    assert_eq!(display_attr.values, vec![USER_DISPLAY_NAME.to_owned()]);
}

/// A single-byte mutation of the signed assertion MUST trip the signature
/// verifier. This is the SP-side XSW-style negative path.
#[test]
fn sp_rejects_tampered_response() {
    let sp = common::make_sp(SP_ENTITY_ID, SP_ACS_URL, false).expect("sp builds");
    let idp = common::make_idp(IDP_ENTITY_ID, IDP_SSO_URL).expect("idp builds");
    let idp_descriptor = common::idp_descriptor(&idp).expect("idp descriptor");
    let sp_descriptor = common::sp_descriptor(&sp).expect("sp descriptor");
    let now = common::fixed_now().expect("fixed_now");

    let start = sp
        .start_login(
            &idp_descriptor,
            StartLogin {
                relay_state: None,
                binding: Binding::HttpPost,
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

    let authn_request_xml = match start.dispatch {
        Dispatch::Post(form) => BASE64
            .decode(form.saml_request.unwrap().as_bytes())
            .unwrap(),
        Dispatch::Redirect(_) => panic!("expected POST dispatch"),
    };

    let parsed = idp
        .consume_authn_request(ConsumeAuthnRequest {
            sp: &sp_descriptor,
            peer_crypto_policy: None,
            saml_request: &authn_request_xml,
            binding: Binding::HttpPost,
            relay_state: None,
            detached_signature: None,
            expected_destination: IDP_SSO_URL,
            now,
            clock_skew: Duration::from_mins(2),
        })
        .expect("idp consume_authn_request");

    let dispatch = idp
        .issue_response(IssueResponse {
            sp: &sp_descriptor,
            in_response_to: &parsed,
            name_id: NameId::email(USER_EMAIL),
            attributes: vec![Attribute::email(USER_EMAIL)],
            authn_instant: now,
            session_index: "sess-tamper".to_owned(),
            session_not_on_or_after: Some(
                now.checked_add(Duration::from_hours(1))
                    .expect("session_not_on_or_after fits"),
            ),
            authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
            force_encrypt_assertion: None,
            now,
            assertion_lifetime: Duration::from_mins(10),
            subject_confirmation_lifetime: Duration::from_mins(5),
        })
        .expect("idp issue_response");

    let mut response_xml = extract_response_xml(dispatch).expect("extract response xml");

    // Flip a byte inside the signed assertion content. We target the email
    // attribute value (`alice@example.com`) so the mutation lands in
    // signed-over content but does not break XML well-formedness.
    let needle = b"alice@example.com";
    let pos = response_xml
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("found alice@ in the Response XML");
    // Replace 'a' with 'A' — same length, valid UTF-8, breaks the digest.
    response_xml[pos] = b'A';

    let err = sp
        .consume_response(ConsumeResponse {
            idp: &idp_descriptor,
            peer_crypto_policy: None,
            saml_response: &response_xml,
            binding: SsoResponseBinding::HttpPost,
            relay_state: None,
            tracker: Some(&start.tracker),
            expected_destination: SP_ACS_URL,
            now,
            clock_skew: Duration::from_mins(2),
            replay_cache: None,
        })
        .expect_err("tampered response must fail");

    match err {
        Error::SignatureVerification { .. } => {}
        other => panic!("expected SignatureVerification, got {other:?}"),
    }
}

/// Pull the base64-decoded SAML XML out of a POST SsoResponseDispatch.
fn extract_response_xml(dispatch: SsoResponseDispatch) -> Result<Vec<u8>, String> {
    match dispatch {
        SsoResponseDispatch::Post(form) => BASE64
            .decode(form.saml_response.as_bytes())
            .map_err(|e| format!("base64 decode failed: {e}")),
        SsoResponseDispatch::Artifact(_) => {
            Err("expected POST dispatch for SSO Response, got Artifact".to_owned())
        }
    }
}
