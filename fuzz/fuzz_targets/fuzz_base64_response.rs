//! Fuzz the SP ACS receive path with attacker-controlled base64 bytes.
//!
//! Mirrors what a hostile peer can post to `/acs`: a base64-encoded SAML
//! Response. The decoded bytes are fed straight into
//! `ServiceProvider::consume_response`, which exercises:
//!
//! 1. base64 normalization (handled here so we can also feed raw XML through
//!    a `=`-padded encoding of the fuzz input — see `decode_lenient`),
//! 2. XML parsing,
//! 3. structural schema validation (under the `xsd-validate` default feature),
//! 4. signature reference resolution + c14n + digest checks,
//! 5. assertion-level spec checks (Issuer, Audience, NotBefore, NotOnOrAfter,
//!    SubjectConfirmation, …).
//!
//! Inputs that fail signature verification are by far the common case; the
//! goal isn't to find a forgery (libfuzzer can't break RSA-SHA256) but to
//! shake out panics, infinite loops, and quadratic blowups in steps 2-4 along
//! the path *before* the signature check rejects the response.
//!
//! The SP/IdP fixtures are built once and shared across iterations via
//! `OnceLock`. Construction failure aborts the harness — there is no useful
//! way to fuzz against a half-built SP.

#![cfg_attr(fuzzing, no_main)]

use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
#[cfg(fuzzing)]
use libfuzzer_sys::fuzz_target;

use saml::binding::{Endpoint, SsoResponseEndpoint};
use saml::descriptor::IdpDescriptor;
use saml::dsig::algorithms::{
    C14nAlgorithm, DigestAlgorithm, PeerCryptoPolicy, SignatureAlgorithm,
};
use saml::idp::{IdentityProvider, IdentityProviderConfig};
use saml::nameid::NameIdFormat;
use saml::sp::{ServiceProvider, ServiceProviderConfig, SpWantSigned};
use saml::{IdpAssertionSigning, KeyPair};
#[cfg(feature = "slo")]
use saml::{IdpLogoutSigning, IdpLogoutWantSigned, SpLogoutSigning, SpLogoutWantSigned};

// Self-signed RSA-2048 cert + key, lifted verbatim from
// `tests/common/mod.rs`. Baking the bundle into the harness lets each fuzz
// iteration skip key generation entirely.
const RSA_CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
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

const RSA_KEY_PKCS8_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
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

const SP_ENTITY_ID: &str = "https://sp.fuzz.test/saml";
const SP_ACS_URL: &str = "https://sp.fuzz.test/saml/acs";
const IDP_ENTITY_ID: &str = "https://idp.fuzz.test/saml";
const IDP_SSO_URL: &str = "https://idp.fuzz.test/saml/sso";

struct Fixture {
    sp: ServiceProvider,
    idp_descriptor: IdpDescriptor,
}

fn build_fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let keypair = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM)?
        .with_certificate(saml::crypto::cert::X509Certificate::from_pem(RSA_CERT_PEM)?);

    // The IdP fixture only exists to emit a metadata document containing the
    // signing cert + SSO endpoint; we then re-parse that document into an
    // `IdpDescriptor` exactly the way a real SP would. This keeps the fuzzer
    // honest about which code paths are reachable from public APIs.
    let idp = IdentityProvider::new(IdentityProviderConfig {
        entity_id: IDP_ENTITY_ID.to_owned(),
        sso: vec![
            Endpoint::post(IDP_SSO_URL, 0, true),
            Endpoint::redirect(IDP_SSO_URL, 1, false),
        ],
        slo: vec![],
        artifact_resolution: vec![],
        supported_name_id_formats: vec![NameIdFormat::EmailAddress, NameIdFormat::Persistent],
        default_name_id_format: NameIdFormat::EmailAddress,
        signing_key: keypair.clone(),
        decryption_key: None,
        want_authn_requests_signed: false,
        assertion_signing: IdpAssertionSigning {
            sign_responses: false,
            sign_assertions: true,
        },
        encrypt_assertions_when_possible: false,
        #[cfg(feature = "slo")]
        logout_signing: IdpLogoutSigning::default(),
        #[cfg(feature = "slo")]
        logout_want_signed: IdpLogoutWantSigned::default(),
        default_session_duration: Duration::from_secs(3600),
        default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
        outbound_digest_algorithm: DigestAlgorithm::Sha256,
        outbound_c14n: C14nAlgorithm::ExclusiveCanonical,
        #[cfg(feature = "xmlenc")]
        outbound_data_encryption_algorithm:
            saml::xmlenc::algorithms::DataEncryptionAlgorithm::Aes256Gcm,
        #[cfg(feature = "xmlenc")]
        outbound_key_transport_algorithm: saml::xmlenc::algorithms::KeyTransportAlgorithm::RsaOaep,
    })?;
    let idp_metadata = idp.metadata_xml(false)?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml(idp_metadata.as_bytes())?;

    let sp = ServiceProvider::new(ServiceProviderConfig {
        entity_id: SP_ENTITY_ID.to_owned(),
        acs: vec![SsoResponseEndpoint::post(SP_ACS_URL, 0, true)],
        slo: vec![],
        name_id_formats: vec![NameIdFormat::EmailAddress, NameIdFormat::Persistent],
        signing_key: None,
        decryption_key: None,
        sign_authn_requests: false,
        want_signed: SpWantSigned {
            response: false,
            assertions: true,
        },
        allow_unsolicited: true,
        #[cfg(feature = "slo")]
        logout_signing: SpLogoutSigning::default(),
        #[cfg(feature = "slo")]
        logout_want_signed: SpLogoutWantSigned::default(),
        default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
        outbound_digest_algorithm: DigestAlgorithm::Sha256,
    })?;

    Ok(Fixture { sp, idp_descriptor })
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| match build_fixture() {
        Ok(f) => f,
        Err(e) => {
            // Failure here is unrecoverable — the harness has no useful state
            // to fuzz against. Use the process abort path libfuzzer is
            // already wired into rather than swallowing the error silently.
            eprintln!("fuzz fixture build failed: {e}");
            std::process::abort();
        }
    })
}

/// Treat the input as base64 first, then fall back to raw XML. Real attackers
/// hand the ACS handler arbitrary bytes through the `SAMLResponse` form field
/// — the binding layer does the base64 decode, and we want the fuzzer to
/// explore both the well-formed-base64 and the looks-like-XML branches.
fn decode_lenient(data: &[u8]) -> Vec<u8> {
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(data) {
        return decoded;
    }
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD_NO_PAD.decode(data) {
        return decoded;
    }
    data.to_vec()
}

// Stable timestamp roughly matching the test cert's NotBefore so signing-cert
// validity checks don't immediately fast-fail the fuzzer before XML / DSig
// code has a chance to run. The cert is valid 2026-05 → 2126-05.
fn fixed_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_779_796_830)
}

#[cfg(fuzzing)]
fuzz_target!(|data: &[u8]| {
    let fixture = fixture();
    let saml_response = decode_lenient(data);
    let _ = fixture.sp.consume_response(saml::sp::ConsumeResponse {
        idp: &fixture.idp_descriptor,
        peer_crypto_policy: None,
        saml_response: &saml_response,
        binding: saml::binding::SsoResponseBinding::HttpPost,
        relay_state: None,
        tracker: None,
        expected_destination: SP_ACS_URL,
        now: fixed_now(),
        clock_skew: Duration::from_secs(60),
        replay_cache: None,
    });
});

// Provide a real `main` for non-fuzz builds (e.g. `cargo check --all`).
// `cargo fuzz build` always sets `--cfg fuzzing`, which selects the
// `#![no_main]` + `fuzz_target!`-generated entry point above instead.
#[cfg(not(fuzzing))]
fn main() {
    // Reference each helper as a function pointer so the unused-code lint
    // stays quiet under `cargo check --all`. The values are never invoked —
    // the real entry point is the libfuzzer-generated `LLVMFuzzerTestOneInput`
    // shim under `cfg(fuzzing)`.
    let _: fn() -> &'static Fixture = fixture;
    let _: fn(&[u8]) -> Vec<u8> = decode_lenient;
    let _: fn() -> SystemTime = fixed_now;
    // Touch the Fixture fields so the dead_code lint stays quiet.
    let probe = |f: &Fixture| {
        let _ = &f.sp;
        let _ = &f.idp_descriptor;
    };
    let _: fn(&Fixture) = probe;
}
