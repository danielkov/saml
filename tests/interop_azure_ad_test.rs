//! Interop corpus: Azure AD-style `<samlp:Response>`.
//!
//! Vendor quirks pinned:
//! - Both the `<samlp:Response>` root AND the inner `<saml:Assertion>` are
//!   signed (defense in depth — XSW would have to bypass two signatures).
//! - `Persistent` NameID Format.
//! - Multiple namespace declarations (`saml`, `samlp`, `ds`) interleave on
//!   the emitted tree; consume rejecting on any of them would surface here.

#[path = "common/mod.rs"]
mod common;
#[path = "common/fixtures.rs"]
mod fixtures;

#[test]
fn consumes_azure_ad_style_response() {
    let (sp, idp_descriptor, response_xml, tracker, expected_destination) =
        fixtures::azure_ad_style();
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
