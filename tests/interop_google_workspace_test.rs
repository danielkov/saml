//! Interop corpus: Google Workspace-style `<samlp:Response>`.
//!
//! Google Workspace's real-world quirk is that the emitted XML sometimes
//! carries comments inside the canonicalized region; the c14n layer must drop
//! them. Wave 5 already covers comment handling at the `c14n.rs` level, so the
//! interop test here just pins the *baseline* shape — assertion-only signing,
//! `EmailAddress` NameID — and ensures consume_response succeeds end-to-end.

#[path = "common/mod.rs"]
mod common;
#[path = "common/fixtures.rs"]
mod fixtures;

#[test]
fn consumes_google_workspace_style_response() {
    let (sp, idp_descriptor, response_xml, tracker, expected_destination) =
        fixtures::google_workspace_style();
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
