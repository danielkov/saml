//! Interop corpus: Auth0-style `<samlp:Response>`.
//!
//! Vendor quirks pinned:
//! - Standard exclusive XML canonicalization (`xml-exc-c14n#`).
//! - Assertion-only signing.
//! - `EmailAddress` NameID Format.

#[path = "common/mod.rs"]
mod common;
#[path = "common/fixtures.rs"]
mod fixtures;

#[test]
fn consumes_auth0_style_response() {
    let (sp, idp_descriptor, response_xml, tracker, expected_destination) =
        fixtures::auth0_style();
    let identity = sp
        .consume_response(saml::sp::ConsumeResponse {
            idp: &idp_descriptor,
            peer_crypto_policy: None,
            saml_response: &response_xml,
            binding: saml::binding::SsoResponseBinding::HttpPost,
            relay_state: None,
            tracker: Some(&tracker),
            expected_destination: &expected_destination,
            now: common::fixed_now(),
            clock_skew: std::time::Duration::from_secs(120),
        })
        .expect("consume");
    assert_eq!(identity.name_id.format, saml::nameid::NameIdFormat::EmailAddress);
    assert_eq!(identity.name_id.value, "alice@example.com");
}
