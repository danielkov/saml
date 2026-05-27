//! Interop corpus: OneLogin-style `<samlp:Response>`.
//!
//! Vendor quirks pinned:
//! - The wire-format payload carries leading whitespace before the
//!   `<samlp:Response>` root (the fixture prepends `\n \t` bytes to the
//!   emitted XML). The parser must tolerate this — `xml::parse::push_text`
//!   silently drops whitespace outside the root.
//! - Otherwise standard assertion-only signing.

#[path = "common/mod.rs"]
mod common;
#[path = "common/fixtures.rs"]
mod fixtures;

#[test]
fn consumes_onelogin_style_response() {
    let (sp, idp_descriptor, response_xml, tracker, expected_destination) =
        fixtures::onelogin_style();

    // Sanity: the fixture should have prepended whitespace.
    assert!(
        response_xml.starts_with(b"\n \t"),
        "OneLogin fixture should carry leading whitespace"
    );

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
}
