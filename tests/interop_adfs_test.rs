//! Interop corpus: ADFS-style `<samlp:Response>`.
//!
//! Vendor quirks pinned:
//! - Legacy `RSA-SHA1` signature on the Assertion. The SP-side default
//!   `PeerCryptoPolicy` would reject this; the fixture widens
//!   `allowed_signature_algorithms` to include `RsaSha1` so the consume
//!   succeeds (real-world ADFS deployments without algorithm overrides need
//!   this same opt-in).
//! - `EmailAddress` NameID Format.
//!
//! Gated behind `weak-algos` — `SignatureAlgorithm::RsaSha1` doesn't even
//! compile without it.

#![cfg(feature = "weak-algos")]

#[path = "common/mod.rs"]
mod common;
#[path = "common/fixtures.rs"]
mod fixtures;

#[test]
fn consumes_adfs_style_response_with_rsa_sha1() {
    let (sp, idp_descriptor, response_xml, tracker, expected_destination) =
        fixtures::adfs_style();
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
