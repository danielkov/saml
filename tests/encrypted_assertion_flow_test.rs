//! Encrypted-assertion end-to-end cross-role flow test.
//!
//! Proves the `<saml:EncryptedAssertion>` round-trip the example apps wire up:
//! the SP advertises an encryption certificate in its metadata, the IdP picks
//! it up out of the parsed `SpDescriptor` and encrypts the assertion to it,
//! and the SP decrypts with its `decryption_key` and recovers the identity.
//!
//! This is the in-process proof that Item 3 demands — no live servers, no
//! `SAML_DEMO_E2E_RUST_IDP` gate.

#![cfg(feature = "xmlenc")]

#[path = "common/mod.rs"]
mod common;

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use saml::attribute::Attribute;
use saml::authn_context::AuthnContextClassRef;
use saml::binding::{Binding, SsoResponseBinding, SsoResponseDispatch, SsoResponseEndpoint};
use saml::descriptor::{IdpDescriptor, SpDescriptor};
use saml::dsig::algorithms::{
    C14nAlgorithm, DigestAlgorithm, PeerCryptoPolicy, SignatureAlgorithm,
};
use saml::idp::{ConsumeAuthnRequest, IdentityProvider, IdentityProviderConfig, IssueResponse};
use saml::nameid::{NameId, NameIdFormat};
use saml::sp::{ServiceProvider, ServiceProviderConfig, StartLogin};
use saml::xmlenc::algorithms::{DataEncryptionAlgorithm, KeyTransportAlgorithm};

const SP_ENTITY_ID: &str = "https://sp.example.com/enc-flow";
const SP_ACS_URL: &str = "https://sp.example.com/enc-flow/acs";
const IDP_ENTITY_ID: &str = "https://idp.example.com/enc-flow";
const IDP_SSO_URL: &str = "https://idp.example.com/enc-flow/sso";

/// SP with a `decryption_key` so its emitted metadata advertises an encryption
/// `KeyDescriptor`. Signs its AuthnRequests so the IdP fixture is exercised the
/// same way the demo apps drive it.
fn make_decrypting_sp() -> common::TestResult<ServiceProvider> {
    let key = common::rsa_keypair_with_cert()?;
    Ok(ServiceProvider::new(ServiceProviderConfig {
        entity_id: SP_ENTITY_ID.to_owned(),
        acs: vec![SsoResponseEndpoint::post(SP_ACS_URL, 0, true)],
        slo: vec![],
        name_id_formats: vec![NameIdFormat::Persistent, NameIdFormat::EmailAddress],
        signing_key: Some(key.clone()),
        decryption_key: Some(key),
        sign_authn_requests: true,
        want_signed: saml::SpWantSigned {
            response: false,
            assertions: true,
        },
        allow_unsolicited: false,
        #[cfg(feature = "slo")]
        logout_signing: saml::SpLogoutSigning::default(),
        #[cfg(feature = "slo")]
        logout_want_signed: saml::SpLogoutWantSigned::default(),
        default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
        outbound_digest_algorithm: DigestAlgorithm::Sha256,
    })?)
}

/// IdP that encrypts assertions when the SP can receive them.
fn make_encrypting_idp() -> common::TestResult<IdentityProvider> {
    let signing_key = common::rsa_keypair_with_cert()?;
    Ok(IdentityProvider::new(IdentityProviderConfig {
        entity_id: IDP_ENTITY_ID.to_owned(),
        sso: vec![saml::Endpoint::post(IDP_SSO_URL, 0, true)],
        slo: vec![],
        artifact_resolution: vec![],
        supported_name_id_formats: vec![NameIdFormat::Persistent, NameIdFormat::EmailAddress],
        default_name_id_format: NameIdFormat::EmailAddress,
        signing_key,
        decryption_key: None,
        want_authn_requests_signed: false,
        assertion_signing: saml::IdpAssertionSigning {
            sign_responses: false,
            sign_assertions: true,
        },
        encrypt_assertions_when_possible: false,
        #[cfg(feature = "slo")]
        logout_signing: saml::IdpLogoutSigning::default(),
        #[cfg(feature = "slo")]
        logout_want_signed: saml::IdpLogoutWantSigned::default(),
        default_session_duration: Duration::from_hours(1),
        default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
        outbound_digest_algorithm: DigestAlgorithm::Sha256,
        outbound_c14n: C14nAlgorithm::ExclusiveCanonical,
        outbound_data_encryption_algorithm: DataEncryptionAlgorithm::Aes256Gcm,
        outbound_key_transport_algorithm: KeyTransportAlgorithm::RsaOaep,
    })?)
}

/// Full encrypted round-trip: the SP-advertised encryption cert drives the
/// IdP to emit an `<saml:EncryptedAssertion>` on the wire, and the SP decrypts
/// it back into the expected identity.
#[test]
fn idp_encrypts_assertion_and_sp_decrypts_it() {
    let sp = make_decrypting_sp().expect("sp builds");
    let idp = make_encrypting_idp().expect("idp builds");

    // Round-trip both descriptors through metadata emit + parse, exactly as a
    // peer relying party would obtain them.
    let idp_descriptor = {
        let xml = idp.metadata_xml(false).expect("idp metadata");
        IdpDescriptor::from_metadata_xml(xml.as_bytes()).expect("idp descriptor")
    };
    let sp_descriptor = {
        let xml = sp.metadata_xml(false).expect("sp metadata");
        SpDescriptor::from_metadata_xml(xml.as_bytes()).expect("sp descriptor")
    };
    let now = common::fixed_now().expect("fixed_now");

    // Precondition: the SP's parsed descriptor exposes an encryption cert. This
    // is what the IdP example keys off of (`sp.encryption_cert().is_some()`).
    assert!(
        sp_descriptor.encryption_cert().is_some(),
        "SP metadata must advertise an encryption KeyDescriptor",
    );

    // 1. SP builds a POST AuthnRequest.
    let start = sp
        .start_login(
            &idp_descriptor,
            StartLogin {
                relay_state: Some("enc-flow-relay"),
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

    let form = match start.dispatch {
        saml::binding::Dispatch::Post(f) => f,
        saml::binding::Dispatch::Redirect(_) => panic!("expected POST dispatch"),
    };
    let saml_request_b64 = form.saml_request.expect("POST form carries SAMLRequest");
    let authn_request_xml = BASE64
        .decode(saml_request_b64.as_bytes())
        .expect("AuthnRequest base64 valid");

    // 2. IdP consumes it.
    let parsed = idp
        .consume_authn_request(ConsumeAuthnRequest {
            sp: &sp_descriptor,
            peer_crypto_policy: None,
            saml_request: &authn_request_xml,
            binding: Binding::HttpPost,
            relay_state: form.relay_state.as_deref(),
            detached_signature: None,
            expected_destination: IDP_SSO_URL,
            now,
            clock_skew: Duration::from_mins(2),
        })
        .expect("idp consume_authn_request");

    // 3. IdP issues a Response, forcing assertion encryption — the path the
    //    demo IdP takes when SAML_IDP_FORCE_ENCRYPT is set and the SP advertises
    //    an encryption cert.
    let dispatch = idp
        .issue_response(IssueResponse {
            sp: &sp_descriptor,
            in_response_to: &parsed,
            name_id: NameId::new("encrypted-user@example.com", NameIdFormat::EmailAddress),
            attributes: vec![Attribute::display_name("Encrypted Flow User")],
            authn_instant: now,
            session_index: "sess-enc-flow-1".to_owned(),
            session_not_on_or_after: Some(
                now.checked_add(Duration::from_hours(1))
                    .expect("session_not_on_or_after fits"),
            ),
            authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
            force_encrypt_assertion: Some(true),
            now,
            assertion_lifetime: Duration::from_mins(10),
            subject_confirmation_lifetime: Duration::from_mins(5),
        })
        .expect("idp issue_response");

    // 4. The wire must actually carry an EncryptedAssertion (not a cleartext
    //    Assertion). This is the load-bearing assertion of the whole item.
    let response_form = match dispatch {
        SsoResponseDispatch::Post(f) => f,
        SsoResponseDispatch::Artifact(_) => panic!("expected POST dispatch for SSO Response"),
    };
    let response_xml = BASE64
        .decode(response_form.saml_response.as_bytes())
        .expect("Response base64 valid");
    let as_str = std::str::from_utf8(&response_xml).expect("UTF-8");
    assert!(
        as_str.contains("EncryptedAssertion"),
        "wire must carry <saml:EncryptedAssertion>, got:\n{as_str}",
    );
    assert!(
        !as_str.contains("encrypted-user@example.com"),
        "NameID must not appear in cleartext when the assertion is encrypted",
    );

    // 5. SP decrypts and recovers the identity.
    let identity = sp
        .consume_response(saml::sp::ConsumeResponse {
            idp: &idp_descriptor,
            peer_crypto_policy: None,
            saml_response: &response_xml,
            binding: SsoResponseBinding::HttpPost,
            relay_state: Some("enc-flow-relay"),
            tracker: Some(&start.tracker),
            expected_destination: SP_ACS_URL,
            now,
            clock_skew: Duration::from_mins(2),
            replay_cache: None,
            replay_mode: saml::replay::ReplayMode::All,
        })
        .expect("SP decrypts and consumes the encrypted Response");

    assert_eq!(identity.name_id.value, "encrypted-user@example.com");
}
