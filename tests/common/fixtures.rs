//! Vendor-flavored synthetic interop fixtures.
//!
//! Each `*_style()` function spins up a complete in-memory SAML flow:
//!
//! 1. Build an `IdentityProvider` configured to mimic the vendor's emit
//!    quirks (signing scope, NameID format default, encryption, weak
//!    algorithms).
//! 2. Build a matching `ServiceProvider` and drive a `start_login`.
//! 3. Hand the resulting AuthnRequest XML to the IdP via
//!    `consume_authn_request`, mint a `<samlp:Response>` via
//!    `issue_response`, and pull the base64-decoded XML out of the resulting
//!    `SsoResponseDispatch::Post` form.
//! 4. Return everything the test needs to call `sp.consume_response(...)`:
//!    the SP, an `IdpDescriptor` parsed from the IdP's own metadata, the raw
//!    Response XML bytes (with optional wire-level post-processing), the
//!    `LoginTracker`, and the expected ACS destination URL.
//!
//! Fixtures are built programmatically — *not* hand-crafted XML strings —
//! because the entire point of the interop corpus is to guard against
//! emit-time differentiation, and hand-rolled XML would silently drift away
//! from what the library actually produces.
//!
//! Module owner: Wave 8B. See `docs/rfcs/RFC-001-architecture.md` §10 for
//! the vendor enumeration.

#![allow(dead_code)]

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use saml::attribute::Attribute;
use saml::authn_context::AuthnContextClassRef;
use saml::binding::{
    Binding, Endpoint, SsoResponseBinding, SsoResponseDispatch, SsoResponseEndpoint,
};
use saml::crypto::keypair::KeyPair;
use saml::descriptor::IdpDescriptor;
use saml::dsig::algorithms::{
    C14nAlgorithm, DigestAlgorithm, PeerCryptoPolicy, SignatureAlgorithm,
};
use saml::idp::{
    ConsumeAuthnRequest, IdentityProvider, IdentityProviderConfig, IssueResponse,
};
use saml::nameid::{NameId, NameIdFormat};
use saml::sp::{
    LoginTracker, ServiceProvider, ServiceProviderConfig, StartLogin, StartLoginResult,
};

use super::common::{RSA_CERT_PEM, RSA_KEY_PKCS8_PEM, fixed_now};

// =============================================================================
// Public bundle type
// =============================================================================

/// One synthetic vendor flow. Tuple shape — destructured into named bindings
/// by each `tests/interop_*_test.rs` file.
pub type InteropBundle = (
    ServiceProvider,
    IdpDescriptor,
    Vec<u8>,    // Response XML bytes (already base64-decoded; ready for consume_response).
    LoginTracker,
    String, // expected ACS destination URL.
);

// =============================================================================
// Vendor-specific builders
// =============================================================================

/// Okta-style: `ds:` prefix on `<ds:Signature>` (library default), Assertion-
/// only signing (no Response-level signature), `Persistent` NameID.
pub fn okta_style() -> InteropBundle {
    build_bundle(VendorConfig {
        sign_responses: false,
        sign_assertions: true,
        name_id_format: NameIdFormat::Persistent,
        name_id_value: "okta-user-7a4f1e9c".to_owned(),
        encrypt_assertion: false,
        encryption_cert_on_sp: false,
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
        wire_post_processor: WirePostProcessor::None,
        sp_entity_id: "https://sp.example.com/okta",
        idp_entity_id: "https://idp.okta.com/exk1abc",
    })
}

/// Azure AD-style: signs BOTH the `<samlp:Response>` root AND the inner
/// `<saml:Assertion>` (defense-in-depth against XSW). Persistent NameID with
/// SP qualifier.
pub fn azure_ad_style() -> InteropBundle {
    build_bundle(VendorConfig {
        sign_responses: true,
        sign_assertions: true,
        name_id_format: NameIdFormat::Persistent,
        name_id_value: "azure-objectid-c1d4e5f6".to_owned(),
        encrypt_assertion: false,
        encryption_cert_on_sp: false,
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
        wire_post_processor: WirePostProcessor::None,
        sp_entity_id: "https://sp.example.com/azure",
        idp_entity_id: "https://sts.windows.net/tenant-id/",
    })
}

/// Auth0-style: standard exclusive canonicalization, Assertion-only signing,
/// `EmailAddress` NameID.
pub fn auth0_style() -> InteropBundle {
    build_bundle(VendorConfig {
        sign_responses: false,
        sign_assertions: true,
        name_id_format: NameIdFormat::EmailAddress,
        name_id_value: "alice@example.com".to_owned(),
        encrypt_assertion: false,
        encryption_cert_on_sp: false,
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
        wire_post_processor: WirePostProcessor::None,
        sp_entity_id: "https://sp.example.com/auth0",
        idp_entity_id: "urn:example.auth0.com",
    })
}

/// Google Workspace-style: standard exc-c14n + assertion-only signing. Wave 5
/// has already covered comment-in-c14n behavior at the c14n layer; this
/// fixture just confirms the standard Google emit shape consumes cleanly
/// end-to-end.
pub fn google_workspace_style() -> InteropBundle {
    build_bundle(VendorConfig {
        sign_responses: false,
        sign_assertions: true,
        name_id_format: NameIdFormat::EmailAddress,
        name_id_value: "alice@example.com".to_owned(),
        encrypt_assertion: false,
        encryption_cert_on_sp: false,
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
        wire_post_processor: WirePostProcessor::None,
        sp_entity_id: "https://sp.example.com/google",
        idp_entity_id: "https://accounts.google.com/o/saml2?idpid=C01abc",
    })
}

/// OneLogin-style: same emit shape as the standard Assertion-only signer, but
/// the wire-format payload carries leading whitespace before `<samlp:Response>`
/// (a quirk we've seen in real-world captures). The parser tolerates this
/// silently — see `xml::parse::push_text` — and the test pins that property.
pub fn onelogin_style() -> InteropBundle {
    build_bundle(VendorConfig {
        sign_responses: false,
        sign_assertions: true,
        name_id_format: NameIdFormat::EmailAddress,
        name_id_value: "alice@example.com".to_owned(),
        encrypt_assertion: false,
        encryption_cert_on_sp: false,
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
        // Inject leading whitespace bytes ahead of the `<samlp:Response>` element
        // to exercise the wire-tolerance path described in RFC-001 §10.
        wire_post_processor: WirePostProcessor::PrependWhitespace,
        sp_entity_id: "https://sp.example.com/onelogin",
        idp_entity_id: "https://app.onelogin.com/saml/metadata/12345",
    })
}

/// Keycloak-style: `<saml:EncryptedAssertion>` with AES-GCM data encryption.
/// Tests the xmlenc round-trip. The SP advertises an encryption cert in its
/// metadata (so the IdP can encrypt to it) and holds the matching private key
/// on the consume side.
#[cfg(feature = "xmlenc")]
pub fn keycloak_style() -> InteropBundle {
    build_bundle(VendorConfig {
        sign_responses: false,
        sign_assertions: true,
        name_id_format: NameIdFormat::Persistent,
        name_id_value: "keycloak-subject-9f1a".to_owned(),
        encrypt_assertion: true,
        encryption_cert_on_sp: true,
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
        wire_post_processor: WirePostProcessor::None,
        sp_entity_id: "https://sp.example.com/keycloak",
        idp_entity_id: "https://keycloak.example.com/realms/test",
    })
}

/// ADFS-style: legacy `RSA-SHA1` signatures. Available only with the
/// `weak-algos` feature compiled in; the test sets a permissive
/// `PeerCryptoPolicy` so the SP-side validator allows the SHA-1 signature.
#[cfg(feature = "weak-algos")]
pub fn adfs_style() -> InteropBundle {
    build_bundle(VendorConfig {
        sign_responses: false,
        sign_assertions: true,
        name_id_format: NameIdFormat::EmailAddress,
        name_id_value: "alice@example.com".to_owned(),
        encrypt_assertion: false,
        encryption_cert_on_sp: false,
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha1,
        wire_post_processor: WirePostProcessor::None,
        sp_entity_id: "https://sp.example.com/adfs",
        idp_entity_id: "http://adfs.example.com/adfs/services/trust",
    })
}

// =============================================================================
// Internals
// =============================================================================

/// Knobs the vendor builders thread into the shared `build_bundle` routine.
struct VendorConfig {
    sign_responses: bool,
    sign_assertions: bool,
    name_id_format: NameIdFormat,
    name_id_value: String,
    encrypt_assertion: bool,
    /// Whether the SP advertises an encryption cert in metadata (and holds the
    /// matching `decryption_key` for consume).
    encryption_cert_on_sp: bool,
    outbound_signature_algorithm: SignatureAlgorithm,
    wire_post_processor: WirePostProcessor,
    sp_entity_id: &'static str,
    idp_entity_id: &'static str,
}

/// Optional wire-format mutation applied after the IdP serializes the
/// Response but before the SP consumes it. Used to simulate vendor quirks
/// that exist below the SAML element layer (whitespace, comments, etc.).
#[derive(Debug, Clone, Copy)]
enum WirePostProcessor {
    None,
    /// Prepend `\n \t` bytes to the XML payload. Real-world OneLogin captures
    /// occasionally carry leading whitespace; the parser must tolerate it.
    PrependWhitespace,
}

/// Drive the full IdP→SP flow and return the consume-ready bundle.
fn build_bundle(cfg: VendorConfig) -> InteropBundle {
    let idp_sso_url = format!("{}/sso", cfg.idp_entity_id);
    let sp_acs_url = format!("{}/acs", cfg.sp_entity_id);

    // ---- Build IdP -------------------------------------------------------
    let idp = make_idp(&cfg);

    // ---- Build SP --------------------------------------------------------
    let sp = make_sp(&cfg, &sp_acs_url);

    // ---- Build descriptors via metadata round-trip ------------------------
    // The IdP descriptor the SP will validate against is the one parsed from
    // the IdP's emitted metadata — same code path a deployment would use.
    let idp_xml = idp.metadata_xml(false).expect("idp metadata emits");
    let idp_descriptor =
        IdpDescriptor::from_metadata_xml(idp_xml.as_bytes()).expect("idp metadata parses");

    // The IdP's view of the SP also goes through metadata round-trip so the
    // encryption cert on the SP side (Keycloak) is visible.
    let sp_descriptor_xml = sp.metadata_xml(false).expect("sp metadata emits");
    let sp_descriptor =
        saml::descriptor::SpDescriptor::from_metadata_xml(sp_descriptor_xml.as_bytes())
            .expect("sp metadata parses");

    // ---- 1. Drive start_login (SP → AuthnRequest) -------------------------
    // We pick HTTP-POST as the request binding so the assertion flow is
    // POST-bound end-to-end (the only realistic shape for SSO Responses).
    let StartLoginResult { tracker, dispatch } = sp
        .start_login(
            &idp_descriptor,
            StartLogin {
                relay_state: None,
                binding: Binding::HttpPost,
                force_authn: false,
                is_passive: false,
                requested_name_id_format: Some(cfg.name_id_format.clone()),
                requested_authn_context: None,
                acs_index: None,
                acs_url: None,
                response_binding: Some(SsoResponseBinding::HttpPost),
            },
        )
        .expect("start_login");

    // Pull the base64-encoded SAMLRequest XML out of the POST form. The
    // crate's binding::post::decode is pub(crate); we just base64-decode
    // directly here.
    let authn_request_xml = match dispatch {
        saml::binding::Dispatch::Post(form) => {
            let b64 = form.saml_request.expect("AuthnRequest dispatch has SAMLRequest");
            BASE64.decode(b64.as_bytes()).expect("base64 valid")
        }
        other => panic!("expected POST dispatch from start_login, got {other:?}"),
    };

    // ---- 2. IdP consumes the AuthnRequest --------------------------------
    let parsed_request = idp
        .consume_authn_request(ConsumeAuthnRequest {
            sp: &sp_descriptor,
            peer_crypto_policy: None,
            saml_request: &authn_request_xml,
            binding: Binding::HttpPost,
            relay_state: None,
            detached_signature: None,
            expected_destination: &idp_sso_url,
            now: fixed_now(),
            clock_skew: Duration::from_secs(120),
        })
        .expect("idp consume_authn_request");

    // ---- 3. IdP issues a success Response --------------------------------
    let name_id = NameId::new(cfg.name_id_value.clone(), cfg.name_id_format.clone());
    let response_dispatch = idp
        .issue_response(IssueResponse {
            sp: &sp_descriptor,
            in_response_to: &parsed_request,
            name_id,
            attributes: vec![Attribute::email("alice@example.com")],
            authn_instant: fixed_now(),
            session_index: "sess-interop-1".to_owned(),
            session_not_on_or_after: Some(fixed_now() + Duration::from_secs(3600)),
            authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
            force_encrypt_assertion: Some(cfg.encrypt_assertion),
            now: fixed_now(),
            assertion_lifetime: Duration::from_secs(600),
            subject_confirmation_lifetime: Duration::from_secs(300),
        })
        .expect("idp issue_response");

    // ---- 4. Extract the base64-decoded Response XML ----------------------
    let response_xml = match response_dispatch {
        SsoResponseDispatch::Post(form) => BASE64
            .decode(form.saml_response.as_bytes())
            .expect("response base64 valid"),
        SsoResponseDispatch::Artifact(_) => {
            panic!("unexpected Artifact dispatch from POST-bound interop flow")
        }
    };

    // ---- 5. Apply any wire-format post-processing ------------------------
    let response_xml = match cfg.wire_post_processor {
        WirePostProcessor::None => response_xml,
        WirePostProcessor::PrependWhitespace => {
            let mut out = b"\n \t".to_vec();
            out.extend_from_slice(&response_xml);
            out
        }
    };

    (sp, idp_descriptor, response_xml, tracker, sp_acs_url)
}

/// Build a fresh RSA `KeyPair` with the static test cert attached. Kept here
/// (not in `common::mod`) so each call site gets an owned, independent key —
/// `KeyPair` is not `Copy`, and several builders need more than one instance.
fn keypair_with_cert() -> KeyPair {
    let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).expect("PKCS#8 PEM parses");
    let cert = saml::crypto::cert::X509Certificate::from_pem(RSA_CERT_PEM)
        .expect("cert PEM parses");
    kp.with_certificate(cert)
}

/// Construct a vendor-flavored `IdentityProvider`.
fn make_idp(cfg: &VendorConfig) -> IdentityProvider {
    let idp_sso_url = format!("{}/sso", cfg.idp_entity_id);

    // For RSA-SHA1 we need a digest algorithm matching the signature
    // algorithm's hash. `RsaSha256` defaults to SHA-256 digest.
    let outbound_digest = digest_for_signature(cfg.outbound_signature_algorithm);

    IdentityProvider::new(IdentityProviderConfig {
        entity_id: cfg.idp_entity_id.to_owned(),
        sso: vec![Endpoint::post(idp_sso_url, 0, true)],
        slo: vec![],
        artifact_resolution: vec![],
        supported_name_id_formats: vec![
            NameIdFormat::EmailAddress,
            NameIdFormat::Persistent,
        ],
        default_name_id_format: cfg.name_id_format.clone(),
        signing_key: keypair_with_cert(),
        decryption_key: None,
        want_authn_requests_signed: false,
        sign_responses: cfg.sign_responses,
        sign_assertions: cfg.sign_assertions,
        encrypt_assertions_when_possible: cfg.encrypt_assertion,
        sign_logout_requests: false,
        sign_logout_responses: false,
        want_logout_requests_signed: false,
        want_logout_responses_signed: false,
        default_session_duration: Duration::from_secs(3600),
        default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
        outbound_signature_algorithm: cfg.outbound_signature_algorithm,
        outbound_digest_algorithm: outbound_digest,
        outbound_c14n: C14nAlgorithm::ExclusiveCanonical,
        #[cfg(feature = "xmlenc")]
        outbound_data_encryption_algorithm:
            saml::xmlenc::algorithms::DataEncryptionAlgorithm::Aes256Gcm,
        #[cfg(feature = "xmlenc")]
        outbound_key_transport_algorithm:
            saml::xmlenc::algorithms::KeyTransportAlgorithm::RsaOaep,
    })
    .expect("idp config valid")
}

/// Construct the matching `ServiceProvider`. When `cfg.encryption_cert_on_sp`
/// is set, the SP carries a `decryption_key` so its emitted metadata includes
/// an encryption-use `<md:KeyDescriptor>` the IdP can target.
fn make_sp(cfg: &VendorConfig, acs_url: &str) -> ServiceProvider {
    // Per-peer policy widening: when the IdP signs with a weak algorithm the
    // SP's default policy would reject it, so we plumb the matching policy
    // through `default_peer_crypto_policy`. Strong vendors keep the default.
    let peer_policy = policy_for_signature(cfg.outbound_signature_algorithm);

    ServiceProvider::new(ServiceProviderConfig {
        entity_id: cfg.sp_entity_id.to_owned(),
        acs: vec![SsoResponseEndpoint::post(acs_url, 0, true)],
        slo: vec![],
        name_id_formats: vec![NameIdFormat::EmailAddress, NameIdFormat::Persistent],
        signing_key: None,
        decryption_key: cfg.encryption_cert_on_sp.then(keypair_with_cert),
        sign_authn_requests: false,
        want_response_signed: false,
        want_assertions_signed: true,
        allow_unsolicited: false,
        sign_logout_requests: false,
        sign_logout_responses: false,
        want_logout_requests_signed: false,
        want_logout_responses_signed: false,
        default_peer_crypto_policy: peer_policy,
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
        outbound_digest_algorithm: DigestAlgorithm::Sha256,
    })
    .expect("sp config valid")
}

/// The matching digest algorithm for a given signature algorithm. Used to keep
/// the IdP's outbound digest in sync with its signature hash.
fn digest_for_signature(sig: SignatureAlgorithm) -> DigestAlgorithm {
    match sig {
        SignatureAlgorithm::RsaSha256 | SignatureAlgorithm::EcdsaSha256 => {
            DigestAlgorithm::Sha256
        }
        SignatureAlgorithm::RsaSha384 | SignatureAlgorithm::EcdsaSha384 => {
            DigestAlgorithm::Sha384
        }
        SignatureAlgorithm::RsaSha512 | SignatureAlgorithm::EcdsaSha512 => {
            DigestAlgorithm::Sha512
        }
        #[cfg(feature = "weak-algos")]
        SignatureAlgorithm::RsaSha1 | SignatureAlgorithm::DsaSha1 => DigestAlgorithm::Sha1,
        // `SignatureAlgorithm` is `#[non_exhaustive]`; pin SHA-256 as the
        // safe default for any future variant that lands without an explicit
        // mapping here.
        _ => DigestAlgorithm::Sha256,
    }
}

/// Build a `PeerCryptoPolicy` that allows the supplied signature algorithm. For
/// strong algorithms we use the library default; for weak algorithms we widen
/// to include the specific weak variant.
fn policy_for_signature(sig: SignatureAlgorithm) -> PeerCryptoPolicy {
    let mut policy = PeerCryptoPolicy::strong_defaults();
    if !policy.allowed_signature_algorithms.contains(&sig) {
        policy.allowed_signature_algorithms.push(sig);
    }
    policy
}
