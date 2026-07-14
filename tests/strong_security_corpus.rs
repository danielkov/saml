//! Always-on XML-DSig security corpus built with the repository's test IdP.
//!
//! The imported ruby-saml/python3-saml attack fixtures are valuable, but most
//! were captured with RSA-SHA1 and a SHA-1 reference digest. These cases mint
//! a known-good RSA-SHA256/SHA-256 assertion first, prove the baseline is
//! accepted, and only then apply one narrowly-scoped attack mutation. Exact
//! error assertions ensure a test cannot pass merely because a weak algorithm
//! was rejected before the intended defense ran.

#[path = "common/mod.rs"]
mod common;

use std::time::{Duration, SystemTime};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    std::io::Error::other(message.into()).into()
}

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use saml::attribute::Attribute;
use saml::authn_context::AuthnContextClassRef;
use saml::binding::{Binding, Dispatch, SsoResponseBinding, SsoResponseDispatch};
use saml::descriptor::IdpDescriptor;
use saml::error::Error;
use saml::idp::{ConsumeAuthnRequest, IssueResponse};
use saml::nameid::{NameId, NameIdFormat};
use saml::replay::ReplayMode;
use saml::sp::{ConsumeResponse, LoginTracker, ServiceProvider, StartLogin};

const SP_ENTITY_ID: &str = "https://sp.example.com/strong-security-corpus";
const SP_ACS_URL: &str = "https://sp.example.com/strong-security-corpus/acs";
const IDP_ENTITY_ID: &str = "https://idp.example.com/strong-security-corpus";
const IDP_SSO_URL: &str = "https://idp.example.com/strong-security-corpus/sso";
const USER_EMAIL: &str = "alice@example.com";

const RSA_SHA256_URI: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SHA256_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const RSA_SHA1_URI: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const SHA1_URI: &str = "http://www.w3.org/2000/09/xmldsig#sha1";

struct StrongResponse {
    sp: ServiceProvider,
    idp: IdpDescriptor,
    tracker: LoginTracker,
    response_xml: Vec<u8>,
    now: SystemTime,
}

/// Mint one valid assertion through the public SP -> IdP -> SP request path.
/// `common::make_idp` pins both outbound algorithms to SHA-256.
fn issue_strong_response() -> TestResult<StrongResponse> {
    let sp = common::make_sp(SP_ENTITY_ID, SP_ACS_URL, false)?;
    let idp = common::make_idp(IDP_ENTITY_ID, IDP_SSO_URL)?;
    let idp_descriptor = common::idp_descriptor(&idp)?;
    let sp_descriptor = common::sp_descriptor(&sp)?;
    let now = common::fixed_now()?;

    let start = sp.start_login(
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
    )?;

    let authn_request_xml = match start.dispatch {
        Dispatch::Post(form) => {
            let encoded = form
                .saml_request
                .ok_or_else(|| test_error("POST did not carry SAMLRequest"))?;
            BASE64.decode(encoded.as_bytes())?
        }
        Dispatch::Redirect(_) => return Err(test_error("expected POST AuthnRequest")),
    };

    let parsed = idp.consume_authn_request(ConsumeAuthnRequest {
        sp: &sp_descriptor,
        peer_crypto_policy: None,
        saml_request: &authn_request_xml,
        binding: Binding::HttpPost,
        relay_state: None,
        detached_signature: None,
        expected_destination: IDP_SSO_URL,
        now,
        clock_skew: Duration::from_mins(2),
    })?;

    let dispatch = idp.issue_response(IssueResponse {
        sp: &sp_descriptor,
        in_response_to: &parsed,
        name_id: NameId::email(USER_EMAIL),
        attributes: vec![Attribute::email(USER_EMAIL)],
        authn_instant: now,
        session_index: "strong-security-session".to_owned(),
        session_not_on_or_after: now.checked_add(Duration::from_hours(1)),
        authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
        force_encrypt_assertion: None,
        now,
        assertion_lifetime: Duration::from_mins(10),
        subject_confirmation_lifetime: Duration::from_mins(5),
        holder_of_key_cert: None,
    })?;

    let response_xml = match dispatch {
        SsoResponseDispatch::Post(form) => BASE64.decode(form.saml_response.as_bytes())?,
        SsoResponseDispatch::Artifact(_) => return Err(test_error("expected POST SAMLResponse")),
    };

    let wire = std::str::from_utf8(&response_xml)?;
    if !wire.contains(RSA_SHA256_URI) {
        return Err(test_error(
            "fixture precondition failed: missing RSA-SHA256 SignatureMethod",
        ));
    }
    if !wire.contains(SHA256_URI) {
        return Err(test_error(
            "fixture precondition failed: missing SHA-256 DigestMethod",
        ));
    }
    if wire.contains(RSA_SHA1_URI) || wire.contains(SHA1_URI) {
        return Err(test_error(
            "fixture precondition failed: found a SHA-1 algorithm URI",
        ));
    }

    Ok(StrongResponse {
        sp,
        idp: idp_descriptor,
        tracker: start.tracker,
        response_xml,
        now,
    })
}

fn consume(
    fixture: &StrongResponse,
    response_xml: &[u8],
) -> Result<saml::response::Identity, Error> {
    fixture.sp.consume_response(ConsumeResponse {
        idp: &fixture.idp,
        peer_crypto_policy: None,
        saml_response: response_xml,
        binding: SsoResponseBinding::HttpPost,
        relay_state: None,
        tracker: Some(&fixture.tracker),
        expected_destination: SP_ACS_URL,
        now: fixture.now,
        clock_skew: Duration::from_mins(2),
        replay_cache: None,
        replay_mode: ReplayMode::All,
        holder_of_key_cert: None,
    })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[test]
fn strong_rsa_sha256_baseline_is_accepted() -> TestResult {
    let fixture = issue_strong_response()?;
    let identity = consume(&fixture, &fixture.response_xml)?;
    if identity.name_id.value != USER_EMAIL {
        return Err(test_error(format!(
            "expected NameID {USER_EMAIL}, got {}",
            identity.name_id.value
        )));
    }
    Ok(())
}

#[test]
fn strong_rsa_sha256_content_tamper_is_digest_mismatch() -> TestResult {
    let fixture = issue_strong_response()?;
    let mut attack = fixture.response_xml.clone();
    let offset = find_bytes(&attack, USER_EMAIL.as_bytes())
        .ok_or_else(|| test_error("signed email is absent"))?;
    let email_byte = attack
        .get_mut(offset)
        .ok_or_else(|| test_error("email offset is outside Response"))?;
    *email_byte = b'A';

    let result = consume(&fixture, &attack);
    if !matches!(
        &result,
        Err(Error::SignatureVerification {
            reason: "digest mismatch"
        })
    ) {
        return Err(test_error(format!(
            "expected digest mismatch, got {result:?}"
        )));
    }
    Ok(())
}

#[test]
fn strong_rsa_sha256_reference_to_missing_id_is_rejected() -> TestResult {
    let fixture = issue_strong_response()?;
    let mut attack = fixture.response_xml.clone();
    let marker = b"<ds:Reference URI=\"#";
    let marker_offset =
        find_bytes(&attack, marker).ok_or_else(|| test_error("Reference URI is absent"))?;
    let id_offset = marker_offset
        .checked_add(marker.len())
        .ok_or_else(|| test_error("Reference offset overflowed usize"))?;
    let first_id_byte = attack
        .get_mut(id_offset)
        .ok_or_else(|| test_error("Reference URI does not contain a target ID"))?;
    *first_id_byte = if *first_id_byte == b'X' { b'Y' } else { b'X' };

    let result = consume(&fixture, &attack);
    if !matches!(&result, Err(Error::ReferenceResolution)) {
        return Err(test_error(format!(
            "expected ReferenceResolution, got {result:?}"
        )));
    }
    Ok(())
}

#[test]
fn strong_rsa_sha256_duplicate_id_xsw_is_rejected() -> TestResult {
    let fixture = issue_strong_response()?;
    let assertion_open = b"<saml:Assertion";
    let assertion_close = b"</saml:Assertion>";
    let response_close = b"</samlp:Response>";

    let assertion_start = find_bytes(&fixture.response_xml, assertion_open)
        .ok_or_else(|| test_error("Assertion start is absent"))?;
    let assertion_tail = fixture
        .response_xml
        .get(assertion_start..)
        .ok_or_else(|| test_error("Assertion start is outside Response"))?;
    let relative_end = find_bytes(assertion_tail, assertion_close)
        .ok_or_else(|| test_error("Assertion end is absent"))?;
    let assertion_end = assertion_start
        .checked_add(relative_end)
        .and_then(|offset| offset.checked_add(assertion_close.len()))
        .ok_or_else(|| test_error("Assertion range overflowed usize"))?;
    let duplicate = fixture
        .response_xml
        .get(assertion_start..assertion_end)
        .ok_or_else(|| test_error("Assertion range is outside Response"))?
        .to_vec();

    let insertion = find_bytes(&fixture.response_xml, response_close)
        .ok_or_else(|| test_error("Response end is absent"))?;
    let mut attack = fixture.response_xml.clone();
    attack.splice(insertion..insertion, duplicate);

    let result = consume(&fixture, &attack);
    if !matches!(&result, Err(Error::XmlParse(reason)) if reason.contains("duplicate ID")) {
        return Err(test_error(format!(
            "expected duplicate-ID XmlParse rejection, got {result:?}"
        )));
    }
    Ok(())
}
