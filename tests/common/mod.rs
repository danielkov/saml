//! Shared test helpers for the SAML integration tests.
//!
//! These helpers re-publish the static RSA test cert + key bundle pinned in
//! `src/crypto/cert.rs::test_vectors` (which is `pub(crate)` and therefore
//! unreachable from the `tests/` integration target) and build IdP, SP,
//! `IdpDescriptor`, and `SpDescriptor` fixtures by going through each role's
//! `metadata_xml` emit + `from_metadata_xml` parse.

#![expect(
    dead_code,
    reason = "helpers are shared across multiple integration-test binaries; \
              each binary only references a subset, so the unused-code lint \
              would otherwise fire spuriously per-binary."
)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use saml::crypto::cert::X509Certificate;
use saml::crypto::keypair::KeyPair;
use saml::dsig::algorithms::{
    C14nAlgorithm, DigestAlgorithm, PeerCryptoPolicy, SignatureAlgorithm,
};

use saml::binding::{Endpoint, SsoResponseEndpoint};
use saml::descriptor::{IdpDescriptor, SpDescriptor};
use saml::idp::{IdentityProvider, IdentityProviderConfig};
use saml::nameid::NameIdFormat;
use saml::sp::{ServiceProvider, ServiceProviderConfig};

pub mod mock_http_client;

/// Shorthand for fallible helper return types — every builder funnels its
/// constructor failures through a single boxed error so call sites can just
/// `?`-propagate or `.expect(...)` inside a `#[test]` function.
pub type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

// =============================================================================
// Static test cert + key bundle
// =============================================================================
//
// These are copied verbatim from `src/crypto/cert.rs::test_vectors` so that
// integration tests can build a `KeyPair` with a usable signing cert without
// reaching into a `pub(crate)` module.

/// Self-signed RSA-2048 certificate, CN=saml-test, valid 100 years.
pub const RSA_CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIUMOn0qquTgAJJwHbKm2N1V464CDIwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJc2FtbC10ZXN0MCAXDTI2MDUyNjIxMzcwMVoYDzIxMjYw
NTAyMjEzNzAxWjAUMRIwEAYDVQQDDAlzYW1sLXRlc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDaqL2wBXPWOtBqKErO58ddEa8L9r7OlI1Gh+SseXo1
ZYYH/cISplLMqch8SWk0rH4Aeg1/dcGYATVHYisToko785FphNiAVN3Mz4sL99lU
G7kogP88Beoe0N0s5o8Q53OXD2mHiLwkds0SoH5p8ghlM+Spw1gSq70+MJGKnaBS
O1XocupxARVb1MYhGnDDbJYAip2P2/eg0M7TPi4Kwe6yRndRbcTzKltTOECKaUBU
RbdE6fkwegMNOZ7vivQYsNUkrrgDYjEIKh8bmSsI61vNNhYJpdgja0UHnfguKinX
vF0GlFdtAWn9N8i+d7BfHyaj4TWjqRL8xM5ThM7Cts7BAgMBAAGjUzBRMB0GA1Ud
DgQWBBSyw8b031HFXwOSpE0SzavfT1RHxjAfBgNVHSMEGDAWgBSyw8b031HFXwOS
pE0SzavfT1RHxjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDG
Tn/w5sMK7ceNJa1jAwJKdhumlwknBP3ifozKX3ikmdU+yAs4W1iiGXtaZaL9tv6/
Pg9YXJBJaEO5tyH/xwEjH7+QDqrCIZ77ljZk0Qf0Rl3jdUnnR6TGF4+ToKtN+uG0
gZwXRBtjo+B/hL5mxP72/AHqvowVGblTzuefruuEUs/2bOD11XjW7wKl7kzYLZ65
kj8IXjzTetBlAqqhmQrEmIwVAtcURS+lfLvl7QZVvRwuKadvIa63kJSybV51oahN
08amDJRd0NXHBYHpPlCCUwujcTw2aBGzRgR+Pkx/kJSTOcx4+QZiYBB3BCvYhzg5
UkTEs4+5J1kgDIklDumS
-----END CERTIFICATE-----
";

/// PKCS#8 PEM of the RSA-2048 private key matching `RSA_CERT_PEM`.
pub const RSA_KEY_PKCS8_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDaqL2wBXPWOtBq
KErO58ddEa8L9r7OlI1Gh+SseXo1ZYYH/cISplLMqch8SWk0rH4Aeg1/dcGYATVH
YisToko785FphNiAVN3Mz4sL99lUG7kogP88Beoe0N0s5o8Q53OXD2mHiLwkds0S
oH5p8ghlM+Spw1gSq70+MJGKnaBSO1XocupxARVb1MYhGnDDbJYAip2P2/eg0M7T
Pi4Kwe6yRndRbcTzKltTOECKaUBURbdE6fkwegMNOZ7vivQYsNUkrrgDYjEIKh8b
mSsI61vNNhYJpdgja0UHnfguKinXvF0GlFdtAWn9N8i+d7BfHyaj4TWjqRL8xM5T
hM7Cts7BAgMBAAECggEABncvn7czjwm/bKorFx3lqF/73PbTesyL9mJRjdOMPGy3
d0BGxzIll+Fr2Rf7HUh989HoGQUgf7gGbSlPFIYrm4T232fDFp1bzyDyb7zJD3p/
4b2Zvnq+yuE6bwfUwmdTpMt6/3vYs1vTccnu3v9eBe8QQ4BQGAI9xutc/Fwvl8rV
FZ+/Ze07Mbbxk9f+PROFI/xCopwup1/rMBuN5CEgaL1uZmZPl9snVADjMkn2TluV
XeS01xq7ahpJxjr/tIl5XgFC/214DpLLUxgxGPvKnvPOaUsSwnWZ0S2Se8VJsa7p
i/jM4R/VXa5j52kIDOf8gojg+7BxoRxCqxTzSJl9CQKBgQD/cO2rbHA/bj81xebh
Th5DzJHFdDQJEjPqg8E2jBKrUKli0LsH0WmtNozVjv2RrB4VU5dJmGINJu26i5p/
rbkhtoCfZqoCyWnz1pbHPHoe2OSQhIUv2Srd/VhbvqNTjAMdebnFH+s/ewrxlh9S
kpY8leANhIRJfYzkHylkHocNSQKBgQDbIzYMFd7oywEj3IE+LCLQXHEbwxrPfR23
rC0gfR0RseupxNosMTnHNRjF7bXg+qKO6AQ8MZaYgfyUjELDgpLrKhBOc84HgAvD
HuUz3xVlWIdOQS3LcReHjN7tyFjR+SUYywuRiPNskyZOfWlt8LnvjPy2Xx/bcHht
Vooqe2WNuQKBgBUmEmdo+PondJBNLEpnH1ZZr4/7iPtfSHEYK30Kp9kLOpr10SZa
jjdLFunvhsryxyLY4uOy/Bs+p9wUBtyfU36ZD5ki9Nx6NI19rMoeFbZMGtBkSGqn
vkbW3OPrqrYWF4PvOhQ6Ck4dL9DErx81B79IYV59JD65aFrSwaiKZoARAoGBANmE
DfXZD7ZLKwqJqdAoxzXDTJKeC1LBgmn6gaCqD9ysmpudRmJvSkauMbTly49RuWHY
c7u8DRu8ixZ4Uxz10xeSXTVCRdO0CfjYBfKDER3TzhqjH+28h/qIng+wullR0LzX
btg69EVlmrR2T9xNAoMBkycDLQAIl8EQEX0xlxAhAoGAWNKS/mkM7OTHp1sOzcZ+
3qNoH4s30zdYQAmSwdgZDe+LcCnvZn8IsxsR5aaJYbYFeziAeB+PVMfTdcW89/Qn
72b0KDgBZ9FpLMzYg86nuAZ0moDgg2hY49e+XD6VYVwiPWO5VL4CE+HGyfOsqgDx
K0dYsJzrrDnL23ajO1yzAak=
-----END PRIVATE KEY-----
";

// =============================================================================
// Builders
// =============================================================================

/// Deterministic test timestamp — 2026-05-26T12:00:30Z. Keeps NotBefore /
/// NotOnOrAfter checks stable when callers thread `fixed_now()` everywhere.
pub fn fixed_now() -> TestResult<SystemTime> {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(1_779_796_830))
        .ok_or_else(|| "fixed_now timestamp overflowed SystemTime".into())
}

/// Build an RSA `KeyPair` with the static test cert attached. The same cert is
/// used for both IdP and SP fixtures by design — these are integration tests,
/// not key-rotation tests.
pub fn rsa_keypair_with_cert() -> TestResult<KeyPair> {
    let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM)?;
    let cert = X509Certificate::from_pem(RSA_CERT_PEM)?;
    Ok(kp.with_certificate(cert))
}

/// Build a fresh `X509Certificate` from the static PEM bundle.
pub fn rsa_cert() -> TestResult<X509Certificate> {
    Ok(X509Certificate::from_pem(RSA_CERT_PEM)?)
}

/// Build an IdP role with the static signing key and the supplied entityID +
/// SSO POST endpoint.
pub fn make_idp(entity_id: &str, sso_url: &str) -> TestResult<IdentityProvider> {
    let signing_key = rsa_keypair_with_cert()?;
    Ok(IdentityProvider::new(IdentityProviderConfig {
        entity_id: entity_id.to_owned(),
        sso: vec![
            Endpoint::post(sso_url, 0, true),
            Endpoint::redirect(sso_url, 1, false),
        ],
        slo: vec![],
        artifact_resolution: vec![],
        supported_name_id_formats: vec![
            NameIdFormat::Persistent,
            NameIdFormat::EmailAddress,
        ],
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
        #[cfg(feature = "xmlenc")]
        outbound_data_encryption_algorithm:
            saml::xmlenc::algorithms::DataEncryptionAlgorithm::Aes256Gcm,
        #[cfg(feature = "xmlenc")]
        outbound_key_transport_algorithm:
            saml::xmlenc::algorithms::KeyTransportAlgorithm::RsaOaep,
    })?)
}

/// Build an SP role. When `signing` is true the SP carries the static signing
/// key and emits signed AuthnRequests; otherwise it issues unsigned requests
/// and carries no key.
pub fn make_sp(entity_id: &str, acs_url: &str, signing: bool) -> TestResult<ServiceProvider> {
    let signing_key = if signing {
        Some(rsa_keypair_with_cert()?)
    } else {
        None
    };
    Ok(ServiceProvider::new(ServiceProviderConfig {
        entity_id: entity_id.to_owned(),
        acs: vec![SsoResponseEndpoint::post(acs_url, 0, true)],
        slo: vec![],
        name_id_formats: vec![NameIdFormat::Persistent, NameIdFormat::EmailAddress],
        signing_key,
        decryption_key: None,
        sign_authn_requests: signing,
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

/// Round-trip an IdP through metadata emit + parse so tests can hand the SP a
/// real `IdpDescriptor` (the same code path a peer relying party would use).
pub fn idp_descriptor(idp: &IdentityProvider) -> TestResult<IdpDescriptor> {
    let xml = idp.metadata_xml(false)?;
    Ok(IdpDescriptor::from_metadata_xml(xml.as_bytes())?)
}

/// Round-trip an SP through metadata emit + parse so the IdP gets a real
/// `SpDescriptor`.
pub fn sp_descriptor(sp: &ServiceProvider) -> TestResult<SpDescriptor> {
    let xml = sp.metadata_xml(false)?;
    Ok(SpDescriptor::from_metadata_xml(xml.as_bytes())?)
}
