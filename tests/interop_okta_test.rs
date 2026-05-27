//! Interop corpus: Okta-style `<samlp:Response>`.
//!
//! Vendor quirks pinned:
//! - `ds:` prefix on `<ds:Signature>` (library default, matches Okta emit).
//! - Assertion-only signing; the Response root carries no signature.
//! - `Persistent` NameID Format.

#[path = "common/mod.rs"]
mod common;
#[path = "common/fixtures.rs"]
mod fixtures;

#[test]
fn consumes_okta_style_response() {
    let (sp, idp_descriptor, response_xml, tracker, expected_destination) =
        fixtures::okta_style();
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
    assert_eq!(identity.name_id.format, saml::nameid::NameIdFormat::Persistent);
}
