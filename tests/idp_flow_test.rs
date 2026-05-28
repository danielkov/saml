//! IdP-role end-to-end cross-role flow test.
//!
//! Builds an IdP + a real SP, lets the SP build a real AuthnRequest (over
//! HTTP-Redirect), pulls the DEFLATE-encoded XML out of the redirect URL,
//! consumes it through the IdP, mints a Response, and checks that the
//! resulting dispatch re-parses cleanly.

#[path = "common/mod.rs"]
mod common;

use std::io::Read;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use flate2::read::DeflateDecoder;

use saml::attribute::Attribute;
use saml::authn_context::AuthnContextClassRef;
use saml::binding::{Binding, Dispatch, SsoResponseBinding, SsoResponseDispatch};
use saml::idp::{ConsumeAuthnRequest, IssueResponse};
use saml::nameid::{NameId, NameIdFormat};
use saml::sp::StartLogin;

const SP_ENTITY_ID: &str = "https://sp.example.com/idp-flow";
const SP_ACS_URL: &str = "https://sp.example.com/idp-flow/acs";
const IDP_ENTITY_ID: &str = "https://idp.example.com/idp-flow";
const IDP_SSO_URL: &str = "https://idp.example.com/idp-flow/sso";

/// End-to-end IdP flow: SP-built Redirect AuthnRequest → IdP consumes → IdP
/// issues Response → response re-parses.
#[test]
fn idp_consumes_redirect_authn_request_and_emits_response() {
    let sp = common::make_sp(SP_ENTITY_ID, SP_ACS_URL, false).expect("sp builds");
    let idp = common::make_idp(IDP_ENTITY_ID, IDP_SSO_URL).expect("idp builds");
    let idp_descriptor = common::idp_descriptor(&idp).expect("idp descriptor");
    let sp_descriptor = common::sp_descriptor(&sp).expect("sp descriptor");
    let now = common::fixed_now().expect("fixed_now");

    // 1. SP builds an AuthnRequest dispatched over HTTP-Redirect.
    let start = sp
        .start_login(
            &idp_descriptor,
            StartLogin {
                relay_state: Some("idp-flow-relay"),
                binding: Binding::HttpRedirect,
                force_authn: false,
                is_passive: false,
                requested_name_id_format: Some(NameIdFormat::Persistent),
                requested_authn_context: None,
                acs_index: None,
                acs_url: None,
                response_binding: Some(SsoResponseBinding::HttpPost),
            },
        )
        .expect("start_login");

    // 2. Decode the SAMLRequest out of the redirect URL: base64 → DEFLATE.
    let redirect_url = match start.dispatch {
        Dispatch::Redirect(u) => u,
        Dispatch::Post(_) => panic!("expected Redirect dispatch from start_login"),
    };
    let saml_request_param = redirect_url
        .query_pairs()
        .find(|(k, _)| k == "SAMLRequest")
        .map(|(_, v)| v.into_owned())
        .expect("SAMLRequest query parameter present");

    let deflated = BASE64
        .decode(saml_request_param.as_bytes())
        .expect("SAMLRequest base64 valid");
    let mut decoder = DeflateDecoder::new(deflated.as_slice());
    let mut authn_request_xml = Vec::new();
    decoder
        .read_to_end(&mut authn_request_xml)
        .expect("DEFLATE inflate");

    // RelayState should survive the round-trip on the wire.
    let relay_state_on_wire = redirect_url
        .query_pairs()
        .find(|(k, _)| k == "RelayState")
        .map(|(_, v)| v.into_owned())
        .expect("RelayState present in redirect URL");
    assert_eq!(relay_state_on_wire, "idp-flow-relay");

    // 3. IdP consumes the AuthnRequest.
    let parsed = idp
        .consume_authn_request(ConsumeAuthnRequest {
            sp: &sp_descriptor,
            peer_crypto_policy: None,
            saml_request: &authn_request_xml,
            binding: Binding::HttpRedirect,
            relay_state: Some(&relay_state_on_wire),
            // SP is unsigned in this fixture; no detached signature.
            detached_signature: None,
            expected_destination: IDP_SSO_URL,
            now,
            clock_skew: Duration::from_mins(2),
        })
        .expect("idp consume_authn_request");

    // Sanity-check the parsed view before issuing the Response.
    assert_eq!(parsed.issuer, SP_ENTITY_ID);
    assert_eq!(parsed.assertion_consumer_service.url, SP_ACS_URL);
    assert_eq!(parsed.relay_state.as_deref(), Some("idp-flow-relay"));
    assert_eq!(
        parsed.requested_name_id_format,
        Some(NameIdFormat::Persistent),
    );

    // 4. IdP issues a Response.
    let dispatch = idp
        .issue_response(IssueResponse {
            sp: &sp_descriptor,
            in_response_to: &parsed,
            name_id: NameId::persistent_for_sp("opaque-user-42", SP_ENTITY_ID),
            attributes: vec![Attribute::display_name("Idp Flow User")],
            authn_instant: now,
            session_index: "sess-idp-flow-1".to_owned(),
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

    // 5. The returned dispatch is a POST form targeted at the SP's ACS.
    let form = match dispatch {
        SsoResponseDispatch::Post(f) => f,
        SsoResponseDispatch::Artifact(_) => {
            panic!("expected POST dispatch for SSO Response")
        }
    };
    assert_eq!(form.action.as_str(), SP_ACS_URL);
    assert_eq!(form.relay_state.as_deref(), Some("idp-flow-relay"));

    // 6. The base64-decoded payload re-parses cleanly as UTF-8 XML carrying
    //    the elements we'd expect at minimum. The cheapest "well-formed"
    //    proof we have without reaching into `pub(crate)` XML internals is
    //    to round-trip the bytes through `from_utf8` and look for the
    //    structural markers, then hand the same XML to the SP role to
    //    confirm the full validator accepts it.
    let response_xml = BASE64
        .decode(form.saml_response.as_bytes())
        .expect("Response base64 valid");
    let as_str = std::str::from_utf8(&response_xml).expect("UTF-8");
    assert!(as_str.contains(":Response"), "carries Response element");
    assert!(as_str.contains(":Assertion"), "carries Assertion element");
    assert!(
        as_str.contains(SP_ENTITY_ID),
        "Audience includes SP entityID"
    );

    // Strongest "well-formed" check we have available from the integration
    // surface: hand the freshly-emitted Response back to the SP role and
    // confirm a full consume succeeds.
    let identity = sp
        .consume_response(saml::sp::ConsumeResponse {
            idp: &idp_descriptor,
            peer_crypto_policy: None,
            saml_response: &response_xml,
            binding: SsoResponseBinding::HttpPost,
            relay_state: Some("idp-flow-relay"),
            tracker: Some(&start.tracker),
            expected_destination: SP_ACS_URL,
            now,
            clock_skew: Duration::from_mins(2),
            replay_cache: None,
        })
        .expect("SP round-trips the IdP-issued Response");
    assert_eq!(identity.name_id.value, "opaque-user-42");
}
