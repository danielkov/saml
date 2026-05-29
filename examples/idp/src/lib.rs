//! Standalone SAML 2.0 Identity Provider built on the `saml` crate.
//!
//! Architecture (closes the loop with `examples/demo`'s SP):
//!
//! - Startup: load `config/users.toml` (seed users → argon2id hashes) and
//!   `config/sps.toml` (known SPs). For each SP entry, fetch the SP's
//!   metadata over HTTP and parse it into a [`SpDescriptor`]; the signing
//!   cert lives inside, so inbound AuthnRequest/LogoutRequest signatures
//!   verify against the SP's public key. Failures here are warned and
//!   skipped, matching the demo SP's graceful degradation when an IdP
//!   metadata fetch fails.
//! - `GET /metadata` — serves the IdP's `<EntityDescriptor>` so the SP
//!   can wire us in.
//! - `GET | POST /saml/sso` — accepts the inbound `<samlp:AuthnRequest>`
//!   (DEFLATE+base64 over Redirect, base64 over POST). If the user
//!   already has a session cookie, [`IdentityProvider::issue_response`]
//!   mints the Assertion immediately. Otherwise we stash the parsed
//!   request keyed by `request_id` and redirect to the login form.
//! - `POST /login` — verifies the password, sets the session cookie,
//!   then redirects to `/saml/sso/continue?request_id=...` which pulls
//!   the stashed AuthnRequest and finishes the round trip.
//! - `GET | POST /saml/slo` — IdP-side SLO: parse the SP's
//!   `<samlp:LogoutRequest>`, clear the session, echo a
//!   `<samlp:LogoutResponse>` back to the SP's SLO endpoint.

pub mod auth;
pub mod session;
pub mod sso;
pub mod templates;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    Router,
    routing::{get, post},
};
use serde::Deserialize;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use saml::dsig::algorithms::{C14nAlgorithm, DigestAlgorithm, PeerCryptoPolicy};
use saml::{
    DataEncryptionAlgorithm, Endpoint, IdentityProvider, IdentityProviderConfig,
    IdpAssertionSigning, IdpLogoutSigning, IdpLogoutWantSigned, KeyPair, KeyTransportAlgorithm,
    NameIdFormat, ParsedAuthnRequest, SignatureAlgorithm, SpDescriptor,
};

use crate::auth::{UserStore, UsersFile};
use crate::session::Session;

// =============================================================================
// Baked-in keys, defaults
// =============================================================================

/// IdP signing keypair. Self-signed RSA-2048, generated once with
/// `openssl req -x509 -newkey rsa:2048 -nodes`. Test only — DO NOT reuse.
pub const IDP_KEY_PEM: &[u8] = include_bytes!("../keys/idp.key");
pub const IDP_CERT_PEM: &[u8] = include_bytes!("../keys/idp.crt");

pub const DEFAULT_USERS_TOML: &str = include_str!("../config/users.toml");
pub const DEFAULT_SPS_TOML: &str = include_str!("../config/sps.toml");

// =============================================================================
// Config
// =============================================================================

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub bind_addr: SocketAddr,
    pub idp_entity_id: String,
    pub idp_base_url: String,
    pub session_signing_key: [u8; 32],
    pub users_toml_path: Option<PathBuf>,
    pub sps_toml_path: Option<PathBuf>,
}

impl AppConfig {
    pub fn from_env() -> Self {
        let port: u16 = std::env::var("SAML_IDP_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3001);
        let bind_addr = SocketAddr::from(([127, 0, 0, 1], port));
        let idp_base_url = std::env::var("SAML_IDP_BASE_URL")
            .unwrap_or_else(|_| format!("http://localhost:{port}"));
        let idp_entity_id = std::env::var("SAML_IDP_ENTITY_ID")
            .unwrap_or_else(|_| format!("{idp_base_url}/saml/idp"));
        let users_toml_path = std::env::var("SAML_IDP_USERS_TOML").ok().map(PathBuf::from);
        let sps_toml_path = std::env::var("SAML_IDP_SPS_TOML").ok().map(PathBuf::from);
        let session_signing_key = derive_session_key(&idp_entity_id);
        Self {
            bind_addr,
            idp_entity_id,
            idp_base_url,
            session_signing_key,
            users_toml_path,
            sps_toml_path,
        }
    }
}

fn derive_session_key(entity_id: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"saml-idp-example:session-key:v1:");
    hasher.update(entity_id.as_bytes());
    hasher.update(IDP_KEY_PEM);
    hasher.finalize().into()
}

// =============================================================================
// SP registry
// =============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct SpsFile {
    #[serde(default)]
    pub sp: Vec<SpEntryConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SpEntryConfig {
    pub entity_id: String,
    pub acs_url: String,
    #[serde(default = "default_post_binding")]
    pub acs_binding: String,
    pub slo_url: Option<String>,
    #[serde(default = "default_post_binding")]
    pub slo_binding: String,
    pub metadata_url: String,
    /// Optional override of the entity ID to advertise back to this SP.
    /// Useful in tests where the SP's metadata uses a fixed
    /// `saml-axum-demo` but we want a per-test isolated IdP entity ID.
    #[serde(default)]
    pub idp_entity_id_override: Option<String>,
}

fn default_post_binding() -> String {
    "HTTP-POST".to_owned()
}

impl SpsFile {
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// Apply environment-variable overrides of the form
    /// `SAML_IDP_SP_<UPPER_ENTITY_ID>_METADATA_URL`. Used by the e2e test
    /// to point at a free-port demo SP without rewriting sps.toml.
    pub fn apply_env_overrides(&mut self) {
        for sp in &mut self.sp {
            let key = format!(
                "SAML_IDP_SP_{}_METADATA_URL",
                sanitize_env_key(&sp.entity_id),
            );
            if let Ok(v) = std::env::var(&key)
                && !v.is_empty()
            {
                tracing::info!(sp = %sp.entity_id, env = %key, "overriding metadata_url via env");
                sp.metadata_url = v;
            }
            let acs_key = format!("SAML_IDP_SP_{}_ACS_URL", sanitize_env_key(&sp.entity_id),);
            if let Ok(v) = std::env::var(&acs_key)
                && !v.is_empty()
            {
                tracing::info!(sp = %sp.entity_id, env = %acs_key, "overriding acs_url via env");
                sp.acs_url = v;
            }
            let slo_key = format!("SAML_IDP_SP_{}_SLO_URL", sanitize_env_key(&sp.entity_id),);
            if let Ok(v) = std::env::var(&slo_key)
                && !v.is_empty()
            {
                tracing::info!(sp = %sp.entity_id, env = %slo_key, "overriding slo_url via env");
                sp.slo_url = Some(v);
            }
        }
    }
}

fn sanitize_env_key(raw: &str) -> String {
    raw.to_uppercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// One ready-to-use SP entry: config from `sps.toml` plus the parsed
/// SP descriptor pulled from the metadata URL at startup.
#[derive(Clone)]
pub struct SpEntry {
    pub config: SpEntryConfig,
    pub sp: Arc<SpDescriptor>,
    /// Human-readable label rendered on the login screen.
    pub label: String,
}

impl SpEntry {
    pub fn label(&self) -> &str {
        &self.label
    }
}

// =============================================================================
// In-flight request store
// =============================================================================

/// One in-flight AuthnRequest plus the SP it came from. Stashed keyed by
/// the request's `ID` across the "redirect to login form" detour, then
/// pulled back out by `/saml/sso/continue` once the user logs in.
#[derive(Clone)]
pub struct PendingRequest {
    pub parsed: Arc<ParsedAuthnRequest>,
    pub sp_entity_id: String,
    pub created_at: SystemTime,
}

/// Bounded in-memory map of in-flight requests, keyed by the AuthnRequest
/// `ID`. Mirrors the demo SP's `TrackerStore` shape; a hostile actor can
/// hammer `/saml/sso` to fill memory, so we cap and evict.
#[derive(Debug, Default)]
pub struct PendingStore {
    map: HashMap<String, PendingRequestEntry>,
}

#[derive(Clone)]
pub struct PendingRequestEntry {
    request: PendingRequest,
}

impl std::fmt::Debug for PendingRequestEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingRequestEntry")
            .field("sp_entity_id", &self.request.sp_entity_id)
            .field("created_at", &self.request.created_at)
            .finish()
    }
}

impl PendingStore {
    const MAX_PENDING: usize = 4096;
    const STALE_AFTER: Duration = Duration::from_mins(5);

    fn insert(&mut self, key: String, request: PendingRequest) {
        let now = SystemTime::now();
        self.map.retain(|_, e| {
            now.duration_since(e.request.created_at)
                .map_or(true, |age| age < Self::STALE_AFTER)
        });
        if self.map.len() >= Self::MAX_PENDING
            && let Some(oldest) = self
                .map
                .iter()
                .min_by_key(|(_, e)| e.request.created_at)
                .map(|(k, _)| k.clone())
        {
            self.map.remove(&oldest);
        }
        self.map.insert(key, PendingRequestEntry { request });
    }

    fn take(&mut self, key: &str) -> Option<PendingRequest> {
        self.map.remove(key).map(|e| e.request)
    }

    fn get(&self, key: &str) -> Option<&PendingRequest> {
        self.map.get(key).map(|e| &e.request)
    }
}

// =============================================================================
// AppState
// =============================================================================

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub idp: Arc<IdentityProvider>,
    pub users: Arc<UserStore>,
    /// SP registry keyed by SP `entity_id`. The SSO handler uses the
    /// inbound Issuer to look up which SP descriptor to validate against.
    /// Wrapped in a [`Mutex`] so the e2e test can hot-swap the registry
    /// after the SP comes up (the SP-↔-IdP boot order is bidirectional;
    /// neither side can do its metadata fetch before the other is
    /// listening).
    pub by_entity_id: Arc<Mutex<HashMap<String, SpEntry>>>,
    pub all_sp_configs: Arc<Vec<SpEntryConfig>>,
    pub pending: Arc<Mutex<PendingStore>>,
}

impl AppState {
    pub fn new(
        config: AppConfig,
        idp: IdentityProvider,
        users: UserStore,
        entries: Vec<SpEntry>,
        all_sp_configs: Vec<SpEntryConfig>,
    ) -> Self {
        let mut by_entity_id: HashMap<String, SpEntry> = HashMap::new();
        for entry in entries {
            by_entity_id.insert(entry.sp.entity_id.clone(), entry);
        }
        Self {
            config: Arc::new(config),
            idp: Arc::new(idp),
            users: Arc::new(users),
            by_entity_id: Arc::new(Mutex::new(by_entity_id)),
            all_sp_configs: Arc::new(all_sp_configs),
            pending: Arc::new(Mutex::new(PendingStore::default())),
        }
    }

    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    pub fn sp_by_entity_id(&self, id: &str) -> Option<SpEntry> {
        self.by_entity_id
            .lock()
            .ok()
            .and_then(|m| m.get(id).cloned())
    }

    pub fn sp_count(&self) -> usize {
        self.by_entity_id.lock().map_or(0, |m| m.len())
    }

    /// Replace the registry's contents wholesale. Used by the e2e test to
    /// populate the SP set once the SP listener is up.
    pub fn replace_sps(&self, entries: Vec<SpEntry>) {
        let mut by_entity_id: HashMap<String, SpEntry> = HashMap::new();
        for entry in entries {
            by_entity_id.insert(entry.sp.entity_id.clone(), entry);
        }
        if let Ok(mut guard) = self.by_entity_id.lock() {
            *guard = by_entity_id;
        }
    }

    pub fn insert_pending(&self, key: String, request: PendingRequest) -> Result<(), String> {
        let mut store = self
            .pending
            .lock()
            .map_err(|e| format!("pending store poisoned: {e}"))?;
        store.insert(key, request);
        Ok(())
    }

    pub fn take_pending(&self, key: &str) -> Result<Option<PendingRequest>, String> {
        let mut store = self
            .pending
            .lock()
            .map_err(|e| format!("pending store poisoned: {e}"))?;
        Ok(store.take(key))
    }

    pub fn peek_pending(&self, key: &str) -> Result<Option<PendingRequest>, String> {
        let store = self
            .pending
            .lock()
            .map_err(|e| format!("pending store poisoned: {e}"))?;
        Ok(store.get(key).cloned())
    }
}

// =============================================================================
// Loaders
// =============================================================================

pub fn load_users(path: Option<&std::path::Path>) -> Result<UsersFile, String> {
    let raw = read_config_or_default(
        path,
        &["config/users.toml", "examples/idp/config/users.toml"],
        DEFAULT_USERS_TOML,
        "users.toml",
    )?;
    UsersFile::from_toml(&raw).map_err(|e| format!("parse users.toml: {e}"))
}

pub fn load_sps(path: Option<&std::path::Path>) -> Result<SpsFile, String> {
    let raw = read_config_or_default(
        path,
        &["config/sps.toml", "examples/idp/config/sps.toml"],
        DEFAULT_SPS_TOML,
        "sps.toml",
    )?;
    let mut file = SpsFile::from_toml(&raw).map_err(|e| format!("parse sps.toml: {e}"))?;
    file.apply_env_overrides();
    Ok(file)
}

fn read_config_or_default(
    path: Option<&std::path::Path>,
    candidates: &[&str],
    baked: &str,
    label: &str,
) -> Result<String, String> {
    if let Some(p) = path {
        return std::fs::read_to_string(p).map_err(|e| format!("read {}: {e}", p.display()));
    }
    for c in candidates {
        if let Ok(s) = std::fs::read_to_string(c) {
            info!(path = c, label, "loaded config file");
            return Ok(s);
        }
    }
    info!(label, "falling back to baked-in config");
    Ok(baked.to_owned())
}

// =============================================================================
// IdP construction
// =============================================================================

pub fn build_identity_provider(config: &AppConfig) -> Result<IdentityProvider, saml::Error> {
    let kp = KeyPair::from_pkcs8_pem(IDP_KEY_PEM)?;
    let cert = saml::X509Certificate::from_pem(IDP_CERT_PEM)?;
    let signing_key = kp.with_certificate(cert);

    let sso_endpoint_url = format!("{}/saml/sso", config.idp_base_url);
    let logout_endpoint_url = format!("{}/saml/slo", config.idp_base_url);

    IdentityProvider::new(IdentityProviderConfig {
        entity_id: config.idp_entity_id.clone(),
        sso: vec![
            Endpoint::redirect(sso_endpoint_url.clone(), 0, true),
            Endpoint::post(sso_endpoint_url, 1, false),
        ],
        slo: vec![
            Endpoint::post(logout_endpoint_url.clone(), 0, true),
            Endpoint::redirect(logout_endpoint_url, 1, false),
        ],
        artifact_resolution: vec![],
        supported_name_id_formats: vec![
            NameIdFormat::EmailAddress,
            NameIdFormat::Persistent,
            NameIdFormat::Unspecified,
        ],
        default_name_id_format: NameIdFormat::EmailAddress,
        signing_key: signing_key.clone(),
        decryption_key: Some(signing_key),
        // The SP demo signs its outbound AuthnRequests; the IdP requires
        // signed inbound requests so we exercise the verify path.
        want_authn_requests_signed: true,
        assertion_signing: IdpAssertionSigning {
            // Sign the Assertion, not the Response envelope, matching what
            // the SP's `SpWantSigned { response: false, assertions: true }`
            // expects.
            sign_responses: false,
            sign_assertions: true,
        },
        encrypt_assertions_when_possible: false,
        logout_signing: IdpLogoutSigning {
            sign_requests: true,
            sign_responses: true,
        },
        // The SP demo signs every outbound LogoutRequest; require it.
        logout_want_signed: IdpLogoutWantSigned {
            requests: true,
            responses: false,
        },
        default_session_duration: Duration::from_hours(8),
        default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
        outbound_digest_algorithm: DigestAlgorithm::Sha256,
        outbound_c14n: C14nAlgorithm::ExclusiveCanonical,
        outbound_data_encryption_algorithm: DataEncryptionAlgorithm::Aes256Gcm,
        outbound_key_transport_algorithm: KeyTransportAlgorithm::RsaOaep,
    })
}

pub async fn fetch_one_sp_descriptor(
    metadata_url: &str,
) -> Result<SpDescriptor, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let mut attempts: u32 = 0;
    loop {
        attempts = attempts.saturating_add(1);
        match client.get(metadata_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let xml = resp.bytes().await?;
                return Ok(SpDescriptor::from_metadata_xml(&xml)?);
            }
            Ok(resp) => {
                warn!(status = %resp.status(), metadata_url, "SP metadata fetch returned non-success");
            }
            Err(e) => {
                warn!(error = %e, metadata_url, "SP metadata fetch failed");
            }
        }
        if attempts >= 5 {
            return Err(format!(
                "gave up after {attempts} attempts to fetch SP metadata from {metadata_url}"
            )
            .into());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

pub async fn fetch_all_sps(file: &SpsFile) -> Vec<SpEntry> {
    let handles: Vec<_> = file
        .sp
        .iter()
        .cloned()
        .map(|cfg| {
            tokio::spawn(async move {
                let label = labelize(&cfg.entity_id);
                match fetch_one_sp_descriptor(&cfg.metadata_url).await {
                    Ok(sp) => Some(SpEntry {
                        config: cfg,
                        sp: Arc::new(sp),
                        label,
                    }),
                    Err(e) => {
                        warn!(
                            sp = %cfg.entity_id,
                            metadata_url = %cfg.metadata_url,
                            error = %e,
                            "skipping SP - metadata unreachable at startup"
                        );
                        None
                    }
                }
            })
        })
        .collect();

    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        match h.await {
            Ok(Some(entry)) => out.push(entry),
            Ok(None) => {}
            Err(e) => warn!(error = %e, "SP metadata fetch task panicked"),
        }
    }
    out
}

/// Best-effort humanization of an SP entity ID for the login screen.
fn labelize(entity_id: &str) -> String {
    let trimmed = entity_id
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let head = trimmed.split('/').next().unwrap_or(trimmed);
    let parts: Vec<&str> = head.split(['-', '_', '.']).collect();
    let mut out = String::new();
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let mut chars = p.chars();
        if let Some(c) = chars.next() {
            out.extend(c.to_uppercase());
        }
        out.push_str(chars.as_str());
    }
    if out.is_empty() {
        entity_id.to_owned()
    } else {
        out
    }
}

// =============================================================================
// Router
// =============================================================================

pub fn build_router(state: AppState) -> Router {
    let static_dir = if std::path::Path::new("examples/idp/static").is_dir() {
        "examples/idp/static"
    } else {
        "static"
    };

    let router = Router::new()
        .route("/", get(sso::handle_index))
        .route("/healthz", get(|| async { "ok" }))
        .route("/metadata", get(sso::handle_metadata))
        .route(
            "/saml/sso",
            get(sso::handle_sso_get).post(sso::handle_sso_post),
        )
        .route("/saml/sso/login", get(sso::handle_login_get))
        .route(
            "/saml/sso/continue",
            get(sso::handle_sso_continue_get).post(sso::handle_sso_continue),
        )
        .route("/login", post(sso::handle_login))
        .route("/logout", post(sso::handle_logout_self))
        .route(
            "/saml/slo",
            get(sso::handle_slo_get).post(sso::handle_slo_post),
        );

    let router = attach_artifact_route(router);

    router
        .nest_service("/static", ServeDir::new(static_dir))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[cfg(feature = "artifact-binding")]
fn attach_artifact_route(router: Router<AppState>) -> Router<AppState> {
    router.route("/saml/artifact", post(sso::handle_artifact))
}

#[cfg(not(feature = "artifact-binding"))]
fn attach_artifact_route(router: Router<AppState>) -> Router<AppState> {
    router
}

// =============================================================================
// Helpers used by the sso module
// =============================================================================

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub fn extract_session_from_headers(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Option<Session> {
    let cookie_header = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())?;
    let value = session::extract_cookie_value(cookie_header)?;
    match session::decode(value, &state.config.session_signing_key, unix_now()) {
        Ok(s) => Some(s),
        Err(e) => {
            warn!(error = %e, "session cookie present but invalid");
            None
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_identity_provider_succeeds_with_default_config() {
        let cfg = AppConfig {
            bind_addr: "127.0.0.1:3001".parse().unwrap(),
            idp_entity_id: "http://test/idp".into(),
            idp_base_url: "http://test".into(),
            session_signing_key: [0u8; 32],
            users_toml_path: None,
            sps_toml_path: None,
        };
        let idp = build_identity_provider(&cfg).expect("idp builds");
        assert_eq!(idp.entity_id(), "http://test/idp");
    }

    #[test]
    fn idp_metadata_xml_round_trips_via_descriptor() {
        let cfg = AppConfig {
            bind_addr: "127.0.0.1:3001".parse().unwrap(),
            idp_entity_id: "http://test/idp".into(),
            idp_base_url: "http://test".into(),
            session_signing_key: [0u8; 32],
            users_toml_path: None,
            sps_toml_path: None,
        };
        let idp = build_identity_provider(&cfg).expect("idp builds");
        let xml = idp.metadata_xml(true).expect("metadata emits");
        let parsed =
            saml::IdpDescriptor::from_metadata_xml(xml.as_bytes()).expect("metadata parses");
        assert_eq!(parsed.entity_id, "http://test/idp");
        assert!(!parsed.sso_endpoints.is_empty());
        assert!(!parsed.slo_endpoints.is_empty());
        assert!(!parsed.signing_certs.is_empty());
    }

    #[test]
    fn load_users_falls_back_to_baked_default() {
        let users = load_users(None).expect("loads");
        assert!(users.user.iter().any(|u| u.id == "alice"));
    }

    #[test]
    fn load_sps_falls_back_to_baked_default() {
        let sps = load_sps(None).expect("loads");
        assert!(sps.sp.iter().any(|s| s.entity_id == "saml-axum-demo"));
    }

    #[test]
    fn labelize_handles_known_shapes() {
        assert_eq!(labelize("saml-axum-demo"), "Saml Axum Demo");
        assert_eq!(labelize("https://app.example.com/saml"), "App Example Com");
        assert_eq!(labelize(""), "");
    }

    #[test]
    fn env_key_sanitizer_replaces_punctuation() {
        assert_eq!(sanitize_env_key("saml-axum-demo"), "SAML_AXUM_DEMO");
        assert_eq!(
            sanitize_env_key("https://app.example.com/saml"),
            "HTTPS___APP_EXAMPLE_COM_SAML",
        );
    }

    #[test]
    fn pending_store_inserts_and_takes() {
        let mut store = PendingStore::default();
        let parsed_req = synthetic_parsed_authn_request();
        let pending = PendingRequest {
            parsed: Arc::new(parsed_req),
            sp_entity_id: "sp".into(),
            created_at: SystemTime::now(),
        };
        store.insert("_req-1".into(), pending);
        let pulled = store.take("_req-1").expect("present");
        assert_eq!(pulled.sp_entity_id, "sp");
        assert!(store.take("_req-1").is_none());
    }

    fn synthetic_parsed_authn_request() -> ParsedAuthnRequest {
        use saml::{AcsSelection, SsoResponseEndpoint};
        ParsedAuthnRequest {
            id: "_req-1".into(),
            issuer: "sp".into(),
            destination: Some("http://test/saml/sso".into()),
            issue_instant: SystemTime::UNIX_EPOCH,
            force_authn: false,
            is_passive: false,
            requested_name_id_format: None,
            requested_authn_context: None,
            assertion_consumer_service: SsoResponseEndpoint::post("http://sp/acs", 0, true),
            assertion_consumer_service_selection: AcsSelection::Default,
            relay_state: None,
            protocol_binding: None,
        }
    }
}
