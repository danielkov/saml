//! `saml` — stateless, async-native SAML 2.0 toolkit.
//!
//! # Features
//!
//! - SAML 2.0 Service Provider, Identity Provider, and proxy composition.
//! - Pure-Rust XML / XML-DSig / XML-Canonicalization / XML-Encryption.
//! - No libxml2 / xmlsec / openssl C build chain.
//! - Async-runtime-agnostic backchannel HTTP via the [`HttpClient`] trait
//!   (bring-your-own; optional [`reqwest`] feature inherits whatever
//!   transitive deps the caller's reqwest configuration brings).
//! - Stateless API: caller owns clock, persistence, replay storage.
//! - XSW-resistant by structure: validated payload extraction is bound to
//!   the signature's resolved element via [`VerifiedSignature`].
//! - Weak algorithms (SHA-1 / RSA-PKCS#1-v1.5 / DSA-SHA1) feature-gated
//!   behind `weak-algos`, off by default.
//!
//! # Quickstart — Service Provider
//!
//! ```no_run
//! use std::time::{Duration, SystemTime};
//! # #[cfg(feature = "slo")]
//! use saml::{
//!     Binding, ConsumeResponse, Dispatch, Endpoint, IdpDescriptor, KeyPair,
//!     LoginTracker, NameIdFormat, PeerCryptoPolicy, DigestAlgorithm, ReplayMode,
//!     ServiceProvider, ServiceProviderConfig, SignatureAlgorithm, SpLogoutSigning,
//!     SpLogoutWantSigned, SpWantSigned, SsoResponseBinding, SsoResponseEndpoint,
//!     StartLogin,
//! };
//!
//! # #[cfg(feature = "slo")]
//! # fn run(
//! #     sp_priv: &[u8],
//! #     sp_enc_priv: &[u8],
//! #     idp_metadata_xml: &[u8],
//! #     saml_response: &[u8],
//! #     relay_state: Option<&str>,
//! #     tracker: LoginTracker,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! let sp = ServiceProvider::new(ServiceProviderConfig {
//!     entity_id: "https://app.example.com/saml".into(),
//!     acs: vec![SsoResponseEndpoint::post(
//!         "https://app.example.com/saml/acs", 0, true,
//!     )],
//!     slo: vec![Endpoint::post(
//!         "https://app.example.com/saml/slo", 0, true,
//!     )],
//!     name_id_formats: vec![NameIdFormat::EmailAddress, NameIdFormat::Persistent],
//!     signing_key: Some(KeyPair::from_pkcs8_pem(sp_priv)?),
//!     decryption_key: Some(KeyPair::from_pkcs8_pem(sp_enc_priv)?),
//!     sign_authn_requests: true,
//!     want_signed: SpWantSigned { response: false, assertions: true },
//!     allow_unsolicited: false,
//!     logout_signing: SpLogoutSigning { sign_requests: true, sign_responses: true },
//!     logout_want_signed: SpLogoutWantSigned { requests: true, responses: true },
//!     default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
//!     outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
//!     outbound_digest_algorithm: DigestAlgorithm::Sha256,
//! })?;
//!
//! let idp = IdpDescriptor::from_metadata_xml(idp_metadata_xml)?;
//!
//! // --- /auth/login handler ---
//! let start = sp.start_login(&idp, StartLogin {
//!     relay_state,
//!     binding: Binding::HttpRedirect,
//!     force_authn: false,
//!     is_passive: false,
//!     requested_name_id_format: None,
//!     requested_authn_context: None,
//!     acs_index: None,
//!     acs_url: None,
//!     response_binding: None,
//! })?;
//! match start.dispatch {
//!     Dispatch::Redirect(_url) => { /* redirect user agent */ }
//!     Dispatch::Post(_form) => { /* render autosubmit form */ }
//! }
//!
//! // --- /saml/acs handler ---
//! let _identity = sp.consume_response(ConsumeResponse {
//!     idp: &idp,
//!     peer_crypto_policy: None,
//!     saml_response,
//!     binding: SsoResponseBinding::HttpPost,
//!     relay_state,
//!     tracker: Some(&tracker),
//!     expected_destination: "https://app.example.com/saml/acs",
//!     now: SystemTime::now(),
//!     clock_skew: Duration::from_secs(60),
//!     replay_cache: None,
//!     replay_mode: ReplayMode::All,
//! })?;
//! // Dedupe identity.assertion_id against your replay store, or pass
//! // `Some(&InMemoryReplayCache::default())` in the field above.
//! // Create app session keyed off identity.name_id + identity.session_index.
//! # Ok(())
//! # }
//! ```
//!
//! # Quickstart — Identity Provider
//!
//! ```no_run
//! use std::time::{Duration, SystemTime};
//! # #[cfg(all(feature = "xmlenc", feature = "slo"))]
//! use saml::{
//!     Attribute, AuthnContextClassRef, Binding, C14nAlgorithm, ConsumeAuthnRequest,
//!     DataEncryptionAlgorithm, DetachedSignature, DigestAlgorithm, Endpoint, IdentityProvider,
//!     IdentityProviderConfig, IdpAssertionSigning, IdpLogoutSigning, IdpLogoutWantSigned,
//!     IssueResponse, KeyPair, KeyTransportAlgorithm, NameId, NameIdFormat, PeerCryptoPolicy,
//!     SignatureAlgorithm, SpDescriptor,
//! };
//!
//! # #[cfg(all(feature = "xmlenc", feature = "slo"))]
//! # fn run(
//! #     idp_priv: &[u8],
//! #     sp: SpDescriptor,
//! #     saml_request: &[u8],
//! #     relay_state: Option<&str>,
//! #     signature: &[u8],
//! #     sig_alg: &str,
//! #     raw_query: &str,
//! #     user_opaque_id: &str,
//! #     user_email: &str,
//! #     user_display_name: &str,
//! #     user_session_id: &str,
//! #     user_authenticated_at: SystemTime,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! let idp = IdentityProvider::new(IdentityProviderConfig {
//!     entity_id: "https://idp.example.com/saml".into(),
//!     sso: vec![
//!         Endpoint::redirect("https://idp.example.com/saml/sso", 0, true),
//!         Endpoint::post("https://idp.example.com/saml/sso", 1, false),
//!     ],
//!     slo: vec![Endpoint::post("https://idp.example.com/saml/slo", 0, true)],
//!     artifact_resolution: vec![],
//!     supported_name_id_formats: vec![NameIdFormat::Persistent, NameIdFormat::EmailAddress],
//!     default_name_id_format: NameIdFormat::Persistent,
//!     signing_key: KeyPair::from_pkcs8_pem(idp_priv)?,
//!     decryption_key: None,
//!     want_authn_requests_signed: true,
//!     assertion_signing: IdpAssertionSigning { sign_responses: false, sign_assertions: true },
//!     encrypt_assertions_when_possible: true,
//!     logout_signing: IdpLogoutSigning { sign_requests: true, sign_responses: true },
//!     logout_want_signed: IdpLogoutWantSigned { requests: true, responses: true },
//!     default_session_duration: Duration::from_secs(3600),
//!     default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
//!     outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
//!     outbound_digest_algorithm: DigestAlgorithm::Sha256,
//!     outbound_c14n: C14nAlgorithm::ExclusiveCanonical,
//!     outbound_data_encryption_algorithm: DataEncryptionAlgorithm::Aes256Gcm,
//!     outbound_key_transport_algorithm: KeyTransportAlgorithm::RsaOaep,
//! })?;
//!
//! // --- /saml/sso handler ---
//! let parsed = idp.consume_authn_request(ConsumeAuthnRequest {
//!     sp: &sp,
//!     peer_crypto_policy: None,
//!     saml_request,
//!     binding: Binding::HttpRedirect,
//!     relay_state,
//!     detached_signature: Some(DetachedSignature {
//!         signature,
//!         sig_alg,
//!         raw_query_string: raw_query,
//!     }),
//!     expected_destination: "https://idp.example.com/saml/sso",
//!     now: SystemTime::now(),
//!     clock_skew: Duration::from_secs(60),
//! })?;
//!
//! // Authenticate the user out of band, then issue the Response.
//! let _dispatch = idp.issue_response(IssueResponse {
//!     sp: &sp,
//!     in_response_to: &parsed,
//!     name_id: NameId::persistent_for_sp(user_opaque_id, &sp.entity_id),
//!     attributes: vec![
//!         Attribute::email(user_email),
//!         Attribute::display_name(user_display_name),
//!     ],
//!     authn_instant: user_authenticated_at,
//!     session_index: format!("sess-{}", user_session_id),
//!     session_not_on_or_after: Some(SystemTime::now() + Duration::from_secs(3600)),
//!     authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
//!     force_encrypt_assertion: None,
//!     now: SystemTime::now(),
//!     assertion_lifetime: Duration::from_secs(300),
//!     subject_confirmation_lifetime: Duration::from_secs(300),
//! })?;
//! # Ok(())
//! # }
//! ```
//!
//! # Quickstart — Proxy
//!
//! ```no_run
//! use std::time::{Duration, SystemTime};
//! use saml::{
//!     Binding, BounceToUpstream, ConsumeAuthnRequest, ConsumeResponse, IdpDescriptor,
//!     IdentityProvider, NameIdFormat, OpaqueHandleCodec, PersistentPerSpHmac, Proxy,
//!     ProxyContext, ProxyContextStore, RelayToDownstream, ReleaseAllowList, ReplayMode,
//!     ServiceProvider, SpDescriptor, SsoResponseBinding,
//! };
//!
//! # fn run<S: ProxyContextStore + 'static>(
//! #     sp: ServiceProvider,
//! #     idp: IdentityProvider,
//! #     downstream_sp: SpDescriptor,
//! #     upstream_idp: IdpDescriptor,
//! #     redis_store: S,
//! #     saml_request: &[u8],
//! #     downstream_relay_state: Option<&str>,
//! #     saml_response: &[u8],
//! #     upstream_relay_state: String,
//! #     name_id_hmac_key: [u8; 32],
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! let proxy = Proxy::new(
//!     &sp,
//!     &idp,
//!     Box::new(OpaqueHandleCodec {
//!         store: redis_store,
//!         handle_byte_len: 24,
//!         ttl: Duration::from_secs(600),
//!     }),
//! );
//!
//! // --- /saml/sso handler (downstream SP → proxy) ---
//! let parsed = idp.consume_authn_request(ConsumeAuthnRequest {
//!     sp: &downstream_sp,
//!     peer_crypto_policy: None,
//!     saml_request,
//!     binding: Binding::HttpPost,
//!     relay_state: downstream_relay_state,
//!     detached_signature: None,
//!     expected_destination: "https://hub.example.com/saml/sso",
//!     now: SystemTime::now(),
//!     clock_skew: Duration::from_secs(60),
//! })?;
//!
//! let bounce = proxy.bounce_to_upstream(BounceToUpstream {
//!     upstream_idp: &upstream_idp,
//!     downstream_request: &parsed,
//!     propagate_request_flags: true,
//!     propagate_authn_context: true,
//!     propagate_name_id_policy: true,
//!     upstream_binding: Binding::HttpRedirect,
//!     now: SystemTime::now(),
//! })?;
//! // Dispatch to upstream IdP with `bounce.upstream_relay_state` carrying context.
//! let _ = bounce;
//!
//! // --- /saml/acs handler (upstream IdP → proxy) ---
//! let context: ProxyContext = proxy.context_codec().decode(&upstream_relay_state)?;
//! let upstream_identity = sp.consume_response(ConsumeResponse {
//!     idp: &upstream_idp,
//!     peer_crypto_policy: None,
//!     saml_response,
//!     binding: SsoResponseBinding::HttpPost,
//!     relay_state: Some(&upstream_relay_state),
//!     tracker: Some(&context.upstream_tracker),
//!     expected_destination: "https://hub.example.com/saml/acs",
//!     now: SystemTime::now(),
//!     clock_skew: Duration::from_secs(60),
//!     replay_cache: None,
//!     replay_mode: ReplayMode::All,
//! })?;
//!
//! let _dispatch = proxy.relay_to_downstream(RelayToDownstream {
//!     context: &context,
//!     upstream_identity: &upstream_identity,
//!     downstream_sp: &downstream_sp,
//!     attribute_release: &ReleaseAllowList {
//!         names: vec!["email".into(), "displayName".into(), "groups".into()],
//!     },
//!     name_id_transform: &PersistentPerSpHmac {
//!         key: name_id_hmac_key,
//!         format: NameIdFormat::Persistent,
//!     },
//!     passthrough_authn_context: true,
//!     now: SystemTime::now(),
//!     session_lifetime: Duration::from_secs(3600),
//!     subject_confirmation_lifetime: Duration::from_secs(300),
//! })?;
//! # Ok(())
//! # }
//! ```
//!
//! # Feature flags
//!
//! - `reqwest-client` (default) — optional [`ReqwestClient`] adapter.
//! - `rsa-sha` (default) — RSA-SHA256/384/512 signature algorithms.
//! - `ecdsa-sha` (default) — ECDSA-SHA256/384/512 signature algorithms.
//! - `xmlenc` (default) — XML Encryption (EncryptedAssertion).
//! - `slo` (default) — Single Logout.
//! - `metadata-emit` (default) — `metadata_xml` / `metadata_xml_with_extras`.
//! - `artifact-binding` — HTTP-Artifact binding (requires `weak-algos`).
//! - `weak-algos` — SHA-1 / RSA-PKCS#1-v1.5 / DSA-SHA1 (off by default).
//!
//! See `docs/rfcs/RFC-001-architecture.md` for the full design discussion.

#![forbid(unsafe_code)]

pub mod error;
pub mod http;
pub mod replay;
pub mod time;

pub mod attribute;
pub mod authn_context;
pub mod conditions;
pub mod nameid;

pub mod binding;
pub mod crypto;
pub mod descriptor;
pub mod dsig;
pub mod metadata;
pub mod xml;

#[cfg(feature = "xmlenc")]
pub mod xmlenc;

pub mod authn;
pub mod response;

#[cfg(feature = "xsd-validate")]
pub(crate) mod schema;

#[cfg(feature = "slo")]
pub mod logout;

pub mod idp;
pub mod proxy;
pub mod sp;

// === User-facing re-exports ===

pub use crate::error::Error;
pub use crate::http::{HttpClient, HttpRequest, HttpResponse};
pub use crate::replay::{InMemoryReplayCache, ReplayCache, ReplayMode};
pub use crate::time::{format_xs_datetime, parse_xs_datetime};

pub use crate::attribute::Attribute;
pub use crate::authn_context::{
    AuthnContextClassRef, AuthnContextComparison, RequestedAuthnContext,
};
pub use crate::conditions::Conditions;
pub use crate::nameid::{NameId, NameIdFormat};

pub use crate::binding::{
    ArtifactRedirect, Binding, DecodedWire, Dispatch, Endpoint, PostForm, SsoResponseBinding,
    SsoResponseDispatch, SsoResponseEndpoint, SsoResponsePostForm, WireDirection, decode_wire,
};

pub use crate::crypto::cert::{PublicKey, PublicKeyAlgorithm, X509Certificate};
pub use crate::crypto::keypair::KeyPair;
#[cfg(feature = "xmlenc")]
pub use crate::crypto::keypair::OaepDigest;
pub use crate::crypto::verifier::{DefaultVerifier, KeyInfo, SignatureVerifier, VerifyMatch};

pub use crate::descriptor::{IdpDescriptor, SpDescriptor};

pub use crate::dsig::algorithms::{
    C14nAlgorithm, DigestAlgorithm, PeerCryptoPolicy, SignatureAlgorithm,
};
pub use crate::dsig::verify::VerifiedSignature;

pub use crate::metadata::{
    MetadataContact, MetadataContactType, MetadataExtras, MetadataOrganization,
};
pub use crate::metadata::parse::{
    EntitiesDescriptor, MetadataEntry, VerifyMetadata, parse_signed_entities_descriptor,
    parse_signed_idp_descriptor, parse_signed_sp_descriptor, verify_metadata_signature,
};

pub use crate::response::Identity;
pub use crate::response::issue::SamlStatusCode;

pub use crate::sp::{
    ConsumeResponse, LoginTracker, ServiceProvider, ServiceProviderConfig, SpWantSigned,
    StartLogin, StartLoginResult,
};
#[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
pub use crate::sp::ConsumeArtifactResponse;
#[cfg(feature = "slo")]
pub use crate::sp::{SpLogoutSigning, SpLogoutWantSigned};

#[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
pub use crate::binding::artifact::ArtifactResolveRequest;

pub use crate::idp::{
    AcsSelection, ConsumeAuthnRequest, ConsumeAuthnRequestWire, DetachedSignature,
    IdentityProvider, IdentityProviderConfig, IdpAssertionSigning, IssueErrorResponse,
    IssueResponse, ParsedAuthnRequest,
};
#[cfg(feature = "slo")]
pub use crate::idp::{
    ConsumeLogoutRequestWire, ConsumeLogoutResponseWire, IdpLogoutSigning, IdpLogoutWantSigned,
};

pub use crate::proxy::{
    Aes256GcmCodec, AttributeReleasePolicy, AuthnContextComparator, BounceResult,
    BounceToUpstream, NameIdFromAttribute, NameIdTransform, OpaqueHandleCodec, PassThroughNameId,
    PerSpFormat, PersistentPerSpHmac, Proxy, ProxyContext, ProxyContextCodec, ProxyContextStore,
    RelayToDownstream, ReleaseAll, ReleaseAllowList, ReleaseNone, ReleasePerSp,
    StandardComparator,
};
#[cfg(feature = "slo")]
pub use crate::proxy::{FrontChannelChain, FrontChannelState, FrontChannelTarget};

#[cfg(feature = "xmlenc")]
pub use crate::xmlenc::algorithms::{DataEncryptionAlgorithm, KeyTransportAlgorithm};

#[cfg(feature = "slo")]
pub use crate::logout::{
    ConsumeLogoutRequest, ConsumeLogoutResponse, LogoutDispatch, LogoutOutcome, LogoutStatus,
    LogoutTracker, ParsedLogoutRequest, StartLogout,
};

#[cfg(feature = "reqwest-client")]
pub use crate::http::ReqwestClient;

// === Fuzzing hooks ===
//
// cargo-fuzz sets `--cfg fuzzing` when building any fuzz target. The targets
// under `fuzz/` link against this crate as a regular dependency and therefore
// only see `pub` items; the parser and canonicalizer they need to exercise are
// otherwise `pub(crate)`. This module hands the fuzzer thin shims into those
// internals without widening the stable public surface — the items below are
// invisible to ordinary builds, doctests, and downstream callers.
#[cfg(fuzzing)]
pub mod __fuzz {
    use crate::dsig::algorithms::C14nAlgorithm;
    use crate::dsig::c14n;
    use crate::error::Error;
    use crate::xml::parse::Document;

    /// Parse `bytes` as XML through the production parser. Errors are
    /// surfaced verbatim so the fuzzer can distinguish parse failures from
    /// panics / aborts.
    pub fn parse_document(bytes: &[u8]) -> Result<(), Error> {
        Document::parse(bytes).map(drop)
    }

    /// Parse `bytes` then canonicalize the document root with `algorithm`.
    /// Returns the canonical byte sequence on success.
    pub fn canonicalize_root(bytes: &[u8], algorithm: C14nAlgorithm) -> Result<Vec<u8>, Error> {
        let doc = Document::parse(bytes)?;
        c14n::canonicalize(&doc, doc.root(), &[], algorithm, &[])
    }
}
