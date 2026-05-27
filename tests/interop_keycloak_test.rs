//! Interop corpus: Keycloak-style `<samlp:Response>` carrying a
//! `<saml:EncryptedAssertion>`.
//!
//! Vendor quirks pinned:
//! - The Assertion is encrypted with AES-256-GCM. The SP advertises an
//!   encryption cert in its metadata; the IdP picks it up off the
//!   `SpDescriptor` and emits `<saml:EncryptedAssertion>` instead of a
//!   cleartext `<saml:Assertion>`.
//! - Assertion-level signing applies to the *cleartext* assertion before
//!   encryption — the SP decrypts, then verifies.
//! - `Persistent` NameID Format.
//!
//! Gated behind `xmlenc` because xml-encryption isn't compiled into builds
//! that don't request it.

#![cfg(feature = "xmlenc")]

#[path = "common/mod.rs"]
mod common;
#[path = "common/fixtures.rs"]
mod fixtures;

#[test]
fn consumes_keycloak_style_response_with_encrypted_assertion() {
    let (sp, idp_descriptor, response_xml, tracker, expected_destination) =
        fixtures::keycloak_style();
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
