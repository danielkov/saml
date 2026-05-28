//! Consolidated end-to-end Axum Service Provider that drives SAML 2.0 SSO
//! against any one of seven IdPs (Keycloak, Authentik, FusionAuth running
//! locally; Zitadel, Auth0, Descope, Asgardeo running in the cloud). One
//! ACS endpoint, one cookie, one dashboard - per-provider quirks live in
//! `config/providers.toml`.
//!
//! Architecture:
//!
//! - Startup: load `config/providers.toml`, fetch each IdP's metadata in
//!   parallel, build a `HashMap<idp_entity_id, ProviderEntry>` so the ACS
//!   handler can resolve a Response's Issuer back to a provider in O(1).
//! - `GET /login/:provider_id` builds an AuthnRequest for that provider
//!   and stashes the matching `LoginTracker` keyed by request ID. The
//!   provider's `id` is the `RelayState` value.
//! - `POST /saml/acs` re-derives the provider from the Issuer, asserts
//!   that the RelayState matches (cross-provider replay defense),
//!   validates the assertion against that provider's IdP descriptor, and
//!   sets the session cookie.

pub mod providers;
pub mod session;
pub mod templates;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    Router,
    extract::{Form, Path, RawQuery, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use serde::Deserialize;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use saml::dsig::algorithms::DigestAlgorithm;
use saml::{
    Attribute, Binding, ConsumeLogoutRequest, ConsumeLogoutResponse, ConsumeResponse, Dispatch,
    Endpoint, IdpDescriptor, InMemoryReplayCache, KeyPair, LoginTracker, LogoutOutcome,
    LogoutStatus, LogoutTracker, NameId, NameIdFormat, ParsedLogoutRequest, PeerCryptoPolicy,
    ReplayMode, ServiceProvider, ServiceProviderConfig, SignatureAlgorithm, SpLogoutSigning,
    SpLogoutWantSigned, SpWantSigned, SsoResponseBinding, SsoResponseEndpoint, StartLogin,
    StartLogout, X509Certificate,
};

use crate::providers::{ProviderConfig, ProviderIndex, ProvidersFile};
use crate::session::{Session, SessionAttribute};

// =============================================================================
// Config
// =============================================================================

/// SP signing keypair, baked into the binary. These are test keys - DO NOT
/// reuse outside the demo. The matching public cert is pinned on the cloud
/// IdPs and on the local realm/blueprint/kickstart files; do not regenerate.
pub const SP_KEY_PEM: &[u8] = include_bytes!("../keys/sp.key");
pub const SP_CERT_PEM: &[u8] = include_bytes!("../keys/sp.crt");

const DEFAULT_PROVIDERS_TOML: &str = include_str!("../config/providers.toml");

/// Top-level app config, threaded through every handler.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub bind_addr: SocketAddr,
    pub sp_entity_id: String,
    pub sp_base_url: String,
    /// 32-byte HMAC-SHA256 key used to sign the session cookie.
    pub session_signing_key: [u8; 32],
    /// Path to providers.toml. Defaults to `config/providers.toml`
    /// relative to whichever directory the binary is run from; falls back
    /// to a baked-in copy if the file is missing.
    pub providers_toml_path: Option<PathBuf>,
}

impl AppConfig {
    pub fn from_env() -> Self {
        let port: u16 = std::env::var("SAML_DEMO_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3000);
        let bind_addr = SocketAddr::from(([127, 0, 0, 1], port));
        let sp_base_url = std::env::var("SAML_DEMO_BASE_URL")
            .unwrap_or_else(|_| format!("http://localhost:{port}"));
        let sp_entity_id = std::env::var("SAML_DEMO_SP_ENTITY_ID")
            .unwrap_or_else(|_| "saml-axum-demo".to_owned());

        let providers_toml_path = std::env::var("SAML_DEMO_PROVIDERS_TOML")
            .ok()
            .map(PathBuf::from);

        let session_signing_key = derive_session_key(&sp_entity_id);

        Self {
            bind_addr,
            sp_entity_id,
            sp_base_url,
            session_signing_key,
            providers_toml_path,
        }
    }
}

fn derive_session_key(entity_id: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"saml-axum-demo:session-key:v1:");
    hasher.update(entity_id.as_bytes());
    hasher.update(SP_KEY_PEM);
    hasher.finalize().into()
}

/// Load providers.toml from disk (preferred) or fall back to the baked-in
/// copy so the binary still boots inside `cargo test`.
pub fn load_providers(path: Option<&std::path::Path>) -> Result<ProvidersFile, String> {
    let raw = if let Some(p) = path {
        std::fs::read_to_string(p).map_err(|e| format!("read {}: {e}", p.display()))?
    } else {
        let candidates = ["config/providers.toml", "examples/demo/config/providers.toml"];
        let mut found = None;
        for c in candidates {
            if let Ok(s) = std::fs::read_to_string(c) {
                info!(path = c, "loaded providers.toml");
                found = Some(s);
                break;
            }
        }
        if let Some(s) = found {
            s
        } else {
            info!("falling back to baked-in providers.toml");
            DEFAULT_PROVIDERS_TOML.to_owned()
        }
    };
    let mut file = ProvidersFile::from_toml(&raw).map_err(|e| format!("parse providers.toml: {e}"))?;
    file.apply_env_overrides();
    Ok(file)
}

// =============================================================================
// Application state
// =============================================================================

/// In-memory tracker store. Maps `request_id` -> `LoginTracker`. Bounded by
/// a max-size sweep so a hostile actor can't fill memory by hammering
/// `/login`.
#[derive(Debug, Default)]
struct TrackerStore {
    map: HashMap<String, LoginTracker>,
}

impl TrackerStore {
    const MAX_PENDING: usize = 4096;
    const STALE_AFTER: Duration = Duration::from_mins(15);

    fn insert(&mut self, tracker: LoginTracker) {
        let now = SystemTime::now();
        self.map.retain(|_, t| {
            now.duration_since(t.issued_at)
                .map_or(true, |age| age < Self::STALE_AFTER)
        });

        if self.map.len() >= Self::MAX_PENDING
            && let Some(oldest) = self
                .map
                .iter()
                .min_by_key(|(_, t)| t.issued_at)
                .map(|(k, _)| k.clone())
        {
            self.map.remove(&oldest);
        }
        self.map.insert(tracker.request_id.clone(), tracker);
    }

    fn take(&mut self, request_id: &str) -> Option<LoginTracker> {
        self.map.remove(request_id)
    }
}

/// In-memory pending-logout store, sibling of [`TrackerStore`]. Maps
/// `request_id` -> `LogoutTracker`. Used to bind an inbound
/// `<samlp:LogoutResponse>` back to the `<samlp:LogoutRequest>` we issued so
/// `InResponseTo` and the IdP's identity can be checked.
#[derive(Debug, Default)]
struct LogoutTrackerStore {
    map: HashMap<String, LogoutTracker>,
}

impl LogoutTrackerStore {
    const MAX_PENDING: usize = 4096;
    const STALE_AFTER: Duration = Duration::from_mins(15);

    fn insert(&mut self, tracker: LogoutTracker) {
        let now = SystemTime::now();
        self.map.retain(|_, t| {
            now.duration_since(t.issued_at)
                .map_or(true, |age| age < Self::STALE_AFTER)
        });

        if self.map.len() >= Self::MAX_PENDING
            && let Some(oldest) = self
                .map
                .iter()
                .min_by_key(|(_, t)| t.issued_at)
                .map(|(k, _)| k.clone())
        {
            self.map.remove(&oldest);
        }
        self.map.insert(tracker.request_id.clone(), tracker);
    }

    fn take(&mut self, request_id: &str) -> Option<LogoutTracker> {
        self.map.remove(request_id)
    }

    /// Find a pending tracker by the peer it was issued against. The
    /// Redirect-binding response path can't read `InResponseTo` cheaply
    /// without DEFLATE; this lets the handler route the response by the
    /// RelayState-supplied provider slug, deferring the `request_id`
    /// integrity check to `consume_logout_response`.
    fn find_by_peer(&self, peer_entity_id: &str) -> Option<LogoutTracker> {
        self.map
            .values()
            .find(|t| t.peer_entity_id == peer_entity_id)
            .cloned()
    }
}

/// One ready-to-use provider: config from `providers.toml` plus the parsed
/// IdP descriptor pulled from the metadata URL at startup.
#[derive(Clone)]
pub struct ProviderEntry {
    pub config: ProviderConfig,
    pub idp: Arc<IdpDescriptor>,
}

#[derive(Clone)]
pub struct AppState {
    config: Arc<AppConfig>,
    sp: Arc<ServiceProvider>,
    /// Provider lookup by slug (`/login/:provider_id`).
    by_id: Arc<HashMap<String, ProviderEntry>>,
    /// Provider lookup by IdP `entity_id`. The ACS handler reads the
    /// Issuer off the inbound Response and resolves the matching provider
    /// here, then asserts that the RelayState (if any) matches the
    /// slug-keyed entry under that entity_id.
    by_entity_id: Arc<HashMap<String, ProviderEntry>>,
    /// All configured `[[provider]]` entries from providers.toml, including
    /// ones whose metadata fetch failed at startup. Used to render the
    /// landing page so the operator can still see which IdPs the demo
    /// knows about even when one is offline.
    all_configs: Arc<Vec<ProviderConfig>>,
    trackers: Arc<Mutex<TrackerStore>>,
    /// Pending SP-initiated logouts. Keyed by `LogoutTracker::request_id` so
    /// the `/saml/slo` handler can look up the tracker by the inbound
    /// `LogoutResponse`'s `InResponseTo` value.
    logout_trackers: Arc<Mutex<LogoutTrackerStore>>,
    /// Anti-replay cache shared across all ACS requests.
    replay_cache: Arc<InMemoryReplayCache>,
}

impl AppState {
    pub fn new(
        config: AppConfig,
        sp: ServiceProvider,
        entries: Vec<ProviderEntry>,
        all_configs: Vec<ProviderConfig>,
    ) -> Self {
        let mut by_id: HashMap<String, ProviderEntry> = HashMap::new();
        let mut by_entity_id: HashMap<String, ProviderEntry> = HashMap::new();
        for entry in entries {
            by_entity_id.insert(entry.idp.entity_id.clone(), entry.clone());
            by_id.insert(entry.config.id.clone(), entry);
        }
        Self {
            config: Arc::new(config),
            sp: Arc::new(sp),
            by_id: Arc::new(by_id),
            by_entity_id: Arc::new(by_entity_id),
            all_configs: Arc::new(all_configs),
            trackers: Arc::new(Mutex::new(TrackerStore::default())),
            logout_trackers: Arc::new(Mutex::new(LogoutTrackerStore::default())),
            replay_cache: Arc::new(InMemoryReplayCache::default()),
        }
    }

    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    /// All configured providers, in the order they appeared in
    /// providers.toml. Includes entries whose metadata fetch failed.
    pub fn all_configs(&self) -> &[ProviderConfig] {
        &self.all_configs
    }

    /// Ready-to-use providers keyed by slug.
    pub fn by_id(&self) -> &HashMap<String, ProviderEntry> {
        &self.by_id
    }
}

// =============================================================================
// Wiring
// =============================================================================

/// Build the SP role from the bundled signing key + the runtime config.
/// One SP serves all providers - the SP entity ID, ACS, and SLO endpoints
/// are global.
pub fn build_service_provider(config: &AppConfig) -> Result<ServiceProvider, saml::Error> {
    let kp = KeyPair::from_pkcs8_pem(SP_KEY_PEM)?;
    let cert = saml::X509Certificate::from_pem(SP_CERT_PEM)?;
    let signing_key = kp.with_certificate(cert);

    let acs_url = format!("{}/saml/acs", config.sp_base_url);
    let slo_url = format!("{}/saml/slo", config.sp_base_url);

    ServiceProvider::new(ServiceProviderConfig {
        entity_id: config.sp_entity_id.clone(),
        acs: vec![SsoResponseEndpoint::post(acs_url, 0, true)],
        // Advertise both POST and Redirect bindings on the SLO endpoint.
        // SP-initiated logout prefers Redirect (smaller, GET, no
        // auto-submit form); IdP-initiated chains often arrive via POST
        // because they propagate a longer signed payload. Both terminate
        // at the same handler at /saml/slo, which dispatches by body
        // content (SAMLRequest vs SAMLResponse).
        slo: vec![
            Endpoint::redirect(slo_url.clone(), 0, true),
            Endpoint::post(slo_url, 1, false),
        ],
        // Most IdPs in our roster accept EmailAddress; Zitadel only does
        // Persistent. Advertise both in the SP metadata so all of them
        // interop.
        name_id_formats: vec![NameIdFormat::EmailAddress, NameIdFormat::Persistent],
        signing_key: Some(signing_key.clone()),
        decryption_key: Some(signing_key),
        sign_authn_requests: true,
        // Accept either Response-level or Assertion-level signing. The SP
        // binds the verified identity to whichever element actually
        // carried the signature.
        want_signed: SpWantSigned {
            response: false,
            assertions: true,
        },
        allow_unsolicited: false,
        logout_signing: SpLogoutSigning {
            sign_requests: true,
            sign_responses: true,
        },
        logout_want_signed: SpLogoutWantSigned {
            requests: false,
            responses: false,
        },
        default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
        outbound_digest_algorithm: DigestAlgorithm::Sha256,
    })
}

/// Fetch one IdP's metadata. Bounded retries, then bail with a typed
/// error. The boot path keeps going if a single provider fails so the
/// other six are still wired up.
pub async fn fetch_one_descriptor(
    metadata_url: &str,
) -> Result<IdpDescriptor, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let mut attempts: u32 = 0;
    loop {
        attempts = attempts.saturating_add(1);
        match client.get(metadata_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let xml = resp.bytes().await?;
                return Ok(IdpDescriptor::from_metadata_xml(&xml)?);
            }
            Ok(resp) => {
                warn!(status = %resp.status(), metadata_url, "IdP metadata fetch returned non-success");
            }
            Err(e) => {
                warn!(error = %e, metadata_url, "IdP metadata fetch failed");
            }
        }
        if attempts >= 5 {
            return Err(format!(
                "gave up after {attempts} attempts to fetch IdP metadata from {metadata_url}"
            )
            .into());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Fetch all providers' metadata in parallel via `tokio::spawn`. Returns
/// the live ones; logs (does not error) on per-provider failures so the
/// demo keeps booting with whatever subset is currently reachable.
pub async fn fetch_all_descriptors(index: &ProviderIndex) -> Vec<ProviderEntry> {
    let handles: Vec<_> = index
        .iter()
        .cloned()
        .map(|cfg| {
            tokio::spawn(async move {
                match fetch_one_descriptor(&cfg.metadata_url).await {
                    Ok(mut idp) => {
                        if let Some(override_url) = cfg.sso_url_override.as_deref() {
                            for ep in &mut idp.sso_endpoints {
                                ep.url = override_url.to_string();
                            }
                        }
                        if let Some(override_url) = cfg.slo_url_override.as_deref() {
                            for ep in &mut idp.slo_endpoints {
                                ep.url = override_url.to_string();
                            }
                        }
                        if let Some(override_id) = cfg.idp_entity_id_override.as_deref() {
                            idp.entity_id = override_id.to_string();
                        }
                        for path in &cfg.extra_signing_cert_paths {
                            match std::fs::read(path).and_then(|bytes| {
                                X509Certificate::from_pem(&bytes).map_err(|e| {
                                    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                                })
                            }) {
                                Ok(cert) => idp.signing_certs.push(cert),
                                Err(e) => warn!(
                                    provider = %cfg.id,
                                    path = %path,
                                    error = %e,
                                    "failed to load extra signing cert"
                                ),
                            }
                        }
                        Some(ProviderEntry {
                            config: cfg,
                            idp: Arc::new(idp),
                        })
                    }
                    Err(e) => {
                        warn!(
                            provider = %cfg.id,
                            metadata_url = %cfg.metadata_url,
                            error = %e,
                            "skipping provider - IdP metadata unreachable at startup"
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
            Err(e) => warn!(error = %e, "metadata fetch task panicked"),
        }
    }
    out
}

pub fn build_router(state: AppState) -> Router {
    let static_dir = if std::path::Path::new("examples/demo/static").is_dir() {
        "examples/demo/static"
    } else {
        "static"
    };

    Router::new()
        .route("/", get(handle_index))
        .route("/login/:provider_id", get(handle_login))
        .route("/saml/acs", post(handle_acs))
        .route("/dashboard", get(handle_dashboard))
        .route("/metadata", get(handle_metadata))
        .route("/logout", post(handle_logout))
        .route("/saml/slo", post(handle_slo).get(handle_slo_get))
        .route("/healthz", get(|| async { "ok" }))
        .nest_service("/static", ServeDir::new(static_dir))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

// =============================================================================
// Handlers
// =============================================================================

async fn handle_index(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Response {
    if extract_session(&state, &headers).is_some() {
        return Redirect::to("/dashboard").into_response();
    }
    let banner = raw_query
        .as_deref()
        .and_then(read_msg_query_param)
        .and_then(|msg| banner_for_msg(&msg));
    let cards: Vec<&ProviderConfig> = state.all_configs().iter().collect();
    Html(templates::render_index(
        &state.config.sp_entity_id,
        &cards,
        banner.as_deref(),
    ))
    .into_response()
}

async fn handle_login(
    State(state): State<AppState>,
    Path(provider_id): Path<String>,
) -> Response {
    let Some(entry) = state.by_id.get(&provider_id) else {
        // Either an unknown slug, or a configured provider whose metadata
        // wasn't reachable at startup. Render a useful error rather than
        // 404, since the latter case is operator-actionable.
        return error_page(
            StatusCode::NOT_FOUND,
            &format!(
                "Unknown or unavailable provider `{provider_id}`. If you expected this provider to be live, \
                 check the SP logs for an `IdP metadata unreachable` warning at startup."
            ),
        );
    };

    let opts = StartLogin {
        relay_state: Some(provider_id.as_str()),
        binding: Binding::HttpRedirect,
        force_authn: false,
        is_passive: false,
        requested_name_id_format: entry.config.requested_name_id_format.clone(),
        requested_authn_context: None,
        acs_index: None,
        acs_url: None,
        response_binding: None,
    };
    let result = match state.sp.start_login(&entry.idp, opts) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, provider = %provider_id, "start_login failed");
            return error_page(StatusCode::INTERNAL_SERVER_ERROR, &format!("start_login: {e}"));
        }
    };

    match state.trackers.lock() {
        Ok(mut store) => store.insert(result.tracker),
        Err(e) => {
            warn!(error = %e, "tracker store poisoned");
            return error_page(StatusCode::INTERNAL_SERVER_ERROR, "tracker store unavailable");
        }
    }

    match result.dispatch {
        Dispatch::Redirect(url) => Redirect::to(url.as_str()).into_response(),
        Dispatch::Post(form) => Html(templates::render_post_dispatch(
            form.action.as_str(),
            form.saml_request.as_deref(),
            form.saml_response.as_deref(),
            form.relay_state.as_deref(),
            &entry.config.label,
        ))
        .into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct AcsForm {
    #[serde(rename = "SAMLResponse")]
    saml_response: String,
    #[serde(default, rename = "RelayState")]
    relay_state: Option<String>,
}

async fn handle_acs(State(state): State<AppState>, Form(form): Form<AcsForm>) -> Response {
    let response_xml = match BASE64_STD.decode(form.saml_response.as_bytes()) {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!(error = %e, "ACS: base64 decode failed");
            return error_page(StatusCode::BAD_REQUEST, "SAMLResponse is not valid base64");
        }
    };

    // 1. Read the Issuer off the Response so we know which IdP descriptor
    //    to validate against. The full `consume_response` call below will
    //    re-verify the Issuer against the descriptor as part of its
    //    audience / Issuer checks; this initial peek is just for routing.
    let Some(issuer) = peek_issuer(&response_xml) else {
        warn!("ACS: could not extract Issuer from SAMLResponse");
        return error_page(
            StatusCode::BAD_REQUEST,
            "SAMLResponse did not carry an Issuer element",
        );
    };

    let Some(entry) = state.by_entity_id.get(&issuer).cloned() else {
        warn!(issuer = %issuer, "ACS: no provider configured for this Issuer");
        return error_page(
            StatusCode::UNAUTHORIZED,
            &format!("SAMLResponse Issuer `{issuer}` is not registered with this SP"),
        );
    };

    // 2. Cross-provider replay defense: if the caller sent us a
    //    RelayState (we set it to the provider slug on /login), it must
    //    match the slug we just looked up from the Issuer. Without this,
    //    an attacker with a Response from provider A could ride a
    //    tracker created for provider B.
    if let Some(rs) = form.relay_state.as_deref()
        && rs != entry.config.id
    {
        warn!(
            relay_state = %rs,
            resolved_provider = %entry.config.id,
            issuer = %issuer,
            "ACS: RelayState does not match Issuer-derived provider"
        );
        return error_page(
            StatusCode::UNAUTHORIZED,
            "RelayState does not match the Issuer-derived provider",
        );
    }

    // 3. Pull the matching tracker (if we have it) so InResponseTo /
    //    NotOnOrAfter checks bind to the original AuthnRequest.
    let request_id = peek_in_response_to(&response_xml);
    let tracker = request_id.as_deref().and_then(|id| {
        state
            .trackers
            .lock()
            .ok()
            .and_then(|mut store| store.take(id))
    });

    let acs_url = format!("{}/saml/acs", state.config.sp_base_url);
    let identity = match state.sp.consume_response(ConsumeResponse {
        idp: &entry.idp,
        peer_crypto_policy: None,
        saml_response: &response_xml,
        binding: SsoResponseBinding::HttpPost,
        relay_state: form.relay_state.as_deref(),
        tracker: tracker.as_ref(),
        expected_destination: &acs_url,
        now: SystemTime::now(),
        clock_skew: Duration::from_mins(2),
        replay_cache: Some(state.replay_cache.as_ref()),
        replay_mode: ReplayMode::All,
    }) {
        Ok(id) => id,
        Err(e) => {
            warn!(error = %e, provider = %entry.config.id, "consume_response failed");
            return error_page(
                StatusCode::UNAUTHORIZED,
                &format!("SAML response rejected: {e}"),
            );
        }
    };

    let now_unix = unix_now();
    let authn_instant_unix = identity
        .authn_instant
        .duration_since(UNIX_EPOCH)
        .map_or(now_unix, |d| d.as_secs());

    let session = Session {
        name_id_value: identity.name_id.value.clone(),
        name_id_format: identity.name_id.format.as_uri().to_owned(),
        session_index: identity.session_index.clone(),
        authn_instant_unix,
        issued_at_unix: now_unix,
        idp_entity_id: entry.idp.entity_id.clone(),
        provider_id: entry.config.id.clone(),
        attributes: identity
            .attributes
            .iter()
            .map(attribute_to_session)
            .collect(),
    };

    let cookie_value = match session::encode(&session, &state.config.session_signing_key) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "session encode failed");
            return error_page(StatusCode::INTERNAL_SERVER_ERROR, "session encode failed");
        }
    };

    let mut headers = HeaderMap::new();
    let cookie_header = match HeaderValue::from_str(&session::set_cookie_header(&cookie_value)) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "constructed an invalid Set-Cookie value");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not set session cookie",
            );
        }
    };
    headers.insert(header::SET_COOKIE, cookie_header);

    info!(
        provider = %entry.config.id,
        name_id = %identity.name_id.value,
        attributes = identity.attributes.len(),
        "ACS: session established"
    );

    (headers, Redirect::to("/dashboard")).into_response()
}

async fn handle_dashboard(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(session) = extract_session(&state, &headers) else {
        return Redirect::to("/").into_response();
    };

    // The provider config for this session may have been removed since
    // the cookie was issued (e.g. providers.toml was edited and the SP
    // restarted). Render with a fall-back grey accent if so.
    let provider_cfg = state.by_id.get(&session.provider_id).map(|e| &e.config);
    let provider_label = provider_cfg.map_or("Unknown IdP", |p| p.label.as_str());
    let provider_accent = provider_cfg.map_or("#64748b", |p| p.accent_color.as_str());
    let accent_keys = provider_cfg.map(|p| &p.attribute_keys);

    let name_id_format_email_match = match session.name_id_format.as_str() {
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" => {
            // Honour the per-provider opt-out (Asgardeo, Zitadel).
            let allow = provider_cfg.is_none_or(|p| p.use_name_id_as_email_fallback);
            allow.then_some(session.name_id_value.as_str())
        }
        _ => None,
    };

    let email_owned = accent_keys
        .and_then(|k| session.attribute_first_of(&k.email))
        .or(name_id_format_email_match)
        .unwrap_or("(no email asserted)")
        .to_owned();
    let display_owned = accent_keys
        .and_then(|k| session.attribute_first_of(&k.display_name))
        .map_or_else(
            || {
                // Fall back to a `<given> <surname>` join, then to the NameID.
                let g = accent_keys.and_then(|k| session.attribute_first_of(&k.given_name));
                let s = accent_keys.and_then(|k| session.attribute_first_of(&k.surname));
                match (g, s) {
                    (Some(g), Some(s)) => format!("{g} {s}"),
                    (Some(g), None) => g.to_owned(),
                    (None, Some(s)) => s.to_owned(),
                    (None, None) => session.name_id_value.clone(),
                }
            },
            str::to_owned,
        );

    let initial: String = display_owned
        .chars()
        .next()
        .map_or_else(|| "?".to_owned(), |c| c.to_uppercase().to_string());

    let name_id_format_short = short_name_id_format(&session.name_id_format);
    let authn_instant = format_unix_iso8601(session.authn_instant_unix);
    let session_index = session
        .session_index
        .clone()
        .unwrap_or_else(|| "(none)".to_owned());

    let rows: Vec<templates::AttributeRow<'_>> = session
        .attributes
        .iter()
        .map(|a| templates::AttributeRow {
            name: a.name.as_str(),
            friendly_name: a.friendly_name.as_deref(),
            values: a.values.as_slice(),
        })
        .collect();

    let supports_slo = state
        .by_id
        .get(&session.provider_id)
        .is_some_and(|e| pick_slo_binding(&e.idp).is_some());

    let view = templates::DashboardView {
        display_name: &display_owned,
        email: &email_owned,
        initial: &initial,
        name_id_value: &session.name_id_value,
        name_id_format: &session.name_id_format,
        name_id_format_short: &name_id_format_short,
        session_index: &session_index,
        authn_instant: &authn_instant,
        sp_entity_id: &state.config.sp_entity_id,
        idp_entity_id: &session.idp_entity_id,
        provider_id: &session.provider_id,
        provider_label,
        provider_accent,
        supports_slo,
        attributes: &rows,
    };
    Html(templates::render_dashboard(&view)).into_response()
}

async fn handle_metadata(State(state): State<AppState>) -> Response {
    match state.sp.metadata_xml(false) {
        Ok(xml) => (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/samlmetadata+xml"),
            )],
            xml,
        )
            .into_response(),
        Err(e) => {
            warn!(error = %e, "metadata_xml failed");
            error_page(StatusCode::INTERNAL_SERVER_ERROR, "metadata emit failed")
        }
    }
}

/// `POST /logout` — Sign out everywhere.
///
/// If the active session points at a provider whose IdP advertises a
/// `<SingleLogoutService>` endpoint, build a signed `<samlp:LogoutRequest>`
/// and dispatch the user to the IdP's SLO endpoint (RFC-007 §5.2 step 1).
/// The local session cookie is cleared immediately, before the dispatch,
/// so a never-arriving `LogoutResponse` doesn't strand the user signed in
/// on the SP side.
///
/// If the session is missing, malformed, points at a provider that's no
/// longer configured, or points at one that doesn't advertise SLO, we
/// fall back to a local-only logout and surface the reason via a
/// `?msg=...` query param on the landing page.
async fn handle_logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(session) = extract_session(&state, &headers) else {
        return redirect_with_cleared_cookie("/?msg=already-signed-out");
    };

    let Some(entry) = state.by_id.get(&session.provider_id).cloned() else {
        warn!(
            provider = %session.provider_id,
            "logout: session points at a provider that is no longer configured; local logout only",
        );
        return redirect_with_cleared_cookie("/?msg=signed-out-locally");
    };

    // Prefer Redirect (smaller, GET, no JS auto-form) over POST when the
    // IdP advertises both bindings on its SLO endpoint, unless the provider
    // config overrides the preference.
    let Some(binding) = pick_slo_binding_with_pref(
        &entry.idp,
        entry.config.prefer_slo_binding.as_deref(),
    ) else {
        warn!(
            provider = %session.provider_id,
            "logout: IdP does not advertise an HTTP-Redirect or HTTP-POST SLO endpoint; local logout only",
        );
        return redirect_with_cleared_cookie("/?msg=signed-out-locally-no-slo");
    };

    let name_id = build_name_id(&session);
    // RelayState carries the provider slug so the inbound /saml/slo
    // handler can route the echo back to the right `ProviderEntry`. The
    // matching tracker is looked up by the LogoutResponse's
    // `InResponseTo` value, mirroring the pattern at /saml/acs. Keeping
    // the slug in RelayState means we don't have to peek `InResponseTo`
    // _and_ Issuer; one or the other suffices to route.
    let dispatch_result = match state.sp.start_logout(
        &entry.idp,
        StartLogout {
            name_id: &name_id,
            session_index: session.session_index.as_deref(),
            relay_state: Some(session.provider_id.as_str()),
            reason: None,
            binding,
        },
    ) {
        Ok(d) => d,
        Err(e) => {
            warn!(
                error = %e,
                provider = %session.provider_id,
                "logout: start_logout failed; falling back to local logout",
            );
            return redirect_with_cleared_cookie("/?msg=signed-out-locally");
        }
    };

    match state.logout_trackers.lock() {
        Ok(mut store) => store.insert(dispatch_result.tracker),
        Err(e) => {
            warn!(error = %e, "logout: tracker store poisoned");
            return error_page(StatusCode::INTERNAL_SERVER_ERROR, "tracker store unavailable");
        }
    }

    finalize_logout_dispatch(
        dispatch_result.dispatch,
        &entry.config.label,
        /* clear_cookie */ true,
    )
}

/// `POST /saml/slo` — unified SLO endpoint.
///
/// Dispatches by body content:
/// - `SAMLResponse=...` → inbound `<samlp:LogoutResponse>` echoing an
///   earlier SP-initiated logout (the success/failure path of `/logout`).
/// - `SAMLRequest=...`  → inbound `<samlp:LogoutRequest>` from an
///   IdP-initiated logout chain.
async fn handle_slo(State(state): State<AppState>, Form(form): Form<SloForm>) -> Response {
    match (form.saml_response, form.saml_request) {
        (Some(saml_response), None) => {
            handle_slo_response(&state, &saml_response, form.relay_state.as_deref())
        }
        (None, Some(saml_request)) => {
            handle_slo_request(&state, &saml_request, form.relay_state.as_deref())
        }
        (Some(_), Some(_)) => error_page(
            StatusCode::BAD_REQUEST,
            "/saml/slo received both SAMLRequest and SAMLResponse",
        ),
        (None, None) => error_page(
            StatusCode::BAD_REQUEST,
            "/saml/slo requires either SAMLRequest or SAMLResponse",
        ),
    }
}

/// Inbound `<samlp:LogoutResponse>` handler: finalise an SP-initiated SLO.
fn handle_slo_response(
    state: &AppState,
    saml_response: &str,
    relay_state: Option<&str>,
) -> Response {
    let Some(provider_id) = relay_state else {
        warn!("/saml/slo: LogoutResponse missing RelayState");
        return redirect_with_cleared_cookie("/?msg=signed-out-locally");
    };
    let Some(entry) = state.by_id.get(provider_id).cloned() else {
        warn!(provider = %provider_id, "/saml/slo: unknown provider in RelayState");
        return redirect_with_cleared_cookie("/?msg=signed-out-locally");
    };

    // The tracker is keyed by the LogoutRequest ID we minted on /logout,
    // which the IdP echoes as `InResponseTo` on its LogoutResponse. Peek
    // that out (after base64-decoding the form value) and look it up.
    let decoded = match BASE64_STD.decode(saml_response.as_bytes()) {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!(error = %e, "/saml/slo: SAMLResponse base64 decode failed");
            return error_page(
                StatusCode::BAD_REQUEST,
                "SAMLResponse is not valid base64",
            );
        }
    };
    let Some(request_id) = peek_in_response_to(&decoded) else {
        warn!("/saml/slo: LogoutResponse carries no InResponseTo; cannot bind to a tracker");
        return redirect_with_cleared_cookie("/?msg=signed-out-locally");
    };
    let tracker = match state.logout_trackers.lock() {
        Ok(mut store) => store.take(&request_id),
        Err(e) => {
            warn!(error = %e, "/saml/slo: logout tracker store poisoned");
            return error_page(StatusCode::INTERNAL_SERVER_ERROR, "tracker store unavailable");
        }
    };
    let Some(tracker) = tracker else {
        warn!(
            request_id = %request_id,
            provider = %provider_id,
            "/saml/slo: no pending LogoutTracker for the LogoutResponse's InResponseTo",
        );
        return redirect_with_cleared_cookie("/?msg=signed-out-locally");
    };

    let slo_url = format!("{}/saml/slo", state.config.sp_base_url);
    // For POST binding `consume_logout_response` wants the still-base64
    // value (it decodes internally), per `decode_logout_wire`. We pass the
    // raw bytes of the form field straight through.
    let outcome = state.sp.consume_logout_response(
        &entry.idp,
        ConsumeLogoutResponse {
            peer_crypto_policy: None,
            body: saml_response.as_bytes(),
            binding: Binding::HttpPost,
            detached_signature: None,
            tracker: &tracker,
            expected_destination: &slo_url,
            now: SystemTime::now(),
            clock_skew: Duration::from_mins(2),
        },
    );

    let target = match outcome {
        Ok(LogoutOutcome::Success) => {
            info!(provider = %entry.config.id, "/saml/slo: SP-init SLO succeeded");
            "/?msg=signed-out"
        }
        Ok(LogoutOutcome::PartialLogout { message }) => {
            info!(
                provider = %entry.config.id,
                message = ?message,
                "/saml/slo: SP-init SLO partial success",
            );
            "/?msg=signed-out"
        }
        Ok(LogoutOutcome::Failure { status, message }) => {
            warn!(
                provider = %entry.config.id,
                status = %status,
                message = ?message,
                "/saml/slo: SP-init SLO failed at IdP",
            );
            "/?msg=signed-out-locally"
        }
        Err(e) => {
            warn!(
                provider = %entry.config.id,
                error = %e,
                "/saml/slo: consume_logout_response rejected the LogoutResponse",
            );
            "/?msg=signed-out-locally"
        }
    };
    // Session cookie was already cleared on /logout, but re-clear here in
    // case the user was juggling two tabs and the SP-side cookie got
    // re-set in the interim.
    redirect_with_cleared_cookie(target)
}

/// Inbound `<samlp:LogoutRequest>` handler: respond to an IdP-initiated
/// logout chain. v1: parse, verify, build a Success `<samlp:LogoutResponse>`,
/// clear the local cookie, and send it back.
fn handle_slo_request(
    state: &AppState,
    saml_request: &str,
    relay_state: Option<&str>,
) -> Response {
    // Peek at the Issuer to route the request to the right provider entry,
    // mirroring the trick at /saml/acs. We need the base64-decoded bytes
    // for the peek, but `consume_logout_request` re-decodes internally for
    // the POST binding so we hand it the still-base64 value below.
    let peek_bytes = match BASE64_STD.decode(saml_request.as_bytes()) {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!(error = %e, "/saml/slo: SAMLRequest base64 decode failed");
            return error_page(
                StatusCode::BAD_REQUEST,
                "SAMLRequest is not valid base64",
            );
        }
    };
    let Some(issuer) = peek_issuer(&peek_bytes) else {
        warn!("/saml/slo: LogoutRequest carries no Issuer; cannot route");
        return error_page(
            StatusCode::BAD_REQUEST,
            "LogoutRequest did not carry an Issuer",
        );
    };

    let Some(entry) = state.by_entity_id.get(&issuer).cloned() else {
        warn!(issuer = %issuer, "/saml/slo: no provider for LogoutRequest Issuer");
        return error_page(
            StatusCode::UNAUTHORIZED,
            &format!("LogoutRequest Issuer `{issuer}` is not registered"),
        );
    };

    let slo_url = format!("{}/saml/slo", state.config.sp_base_url);
    let parsed = match state.sp.consume_logout_request(
        &entry.idp,
        ConsumeLogoutRequest {
            peer_crypto_policy: None,
            body: saml_request.as_bytes(),
            binding: Binding::HttpPost,
            detached_signature: None,
            expected_destination: &slo_url,
            now: SystemTime::now(),
            clock_skew: Duration::from_mins(2),
        },
    ) {
        Ok(p) => p,
        Err(e) => {
            warn!(
                error = %e,
                provider = %entry.config.id,
                "/saml/slo: consume_logout_request rejected the request",
            );
            return error_page(
                StatusCode::UNAUTHORIZED,
                &format!("LogoutRequest rejected: {e}"),
            );
        }
    };

    // Prefer Redirect for our response too.
    let Some(binding) = pick_slo_binding(&entry.idp) else {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "IdP no longer advertises a usable SLO binding",
        );
    };

    let dispatch = match state.sp.build_logout_response(
        &entry.idp,
        &parsed,
        LogoutStatus::Success,
        relay_state,
        binding,
    ) {
        Ok(d) => d,
        Err(e) => {
            warn!(
                error = %e,
                provider = %entry.config.id,
                "/saml/slo: build_logout_response failed",
            );
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("build_logout_response: {e}"),
            );
        }
    };

    info!(
        provider = %entry.config.id,
        "/saml/slo: handled IdP-init LogoutRequest; clearing local session and dispatching response",
    );

    finalize_logout_dispatch(dispatch, &entry.config.label, /* clear_cookie */ true)
}

#[derive(Debug, Deserialize)]
struct SloForm {
    #[serde(default, rename = "SAMLRequest")]
    saml_request: Option<String>,
    #[serde(default, rename = "SAMLResponse")]
    saml_response: Option<String>,
    #[serde(default, rename = "RelayState")]
    relay_state: Option<String>,
}

/// `GET /saml/slo` — HTTP-Redirect binding entry. Some IdPs reply to an
/// SP-initiated SLO via the same Redirect binding they were dispatched to
/// (smaller wire frames, GET, no auto-submit form). The raw, still
/// percent-encoded query string is passed straight through to the saml
/// crate, which handles DEFLATE+base64 decoding and signature
/// verification per SAML 2.0 §3.4.4.1.
async fn handle_slo_get(State(state): State<AppState>, RawQuery(raw_query): RawQuery) -> Response {
    let Some(raw_query) = raw_query.filter(|q| !q.is_empty()) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "/saml/slo GET requires a query string with SAMLRequest or SAMLResponse",
        );
    };

    let mut saml_request: Option<&str> = None;
    let mut saml_response: Option<&str> = None;
    let mut relay_state: Option<String> = None;
    for pair in raw_query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        match k {
            "SAMLRequest" => saml_request = Some(v),
            "SAMLResponse" => saml_response = Some(v),
            "RelayState" => {
                relay_state = Some(
                    percent_encoding::percent_decode_str(v)
                        .decode_utf8_lossy()
                        .into_owned(),
                );
            }
            _ => {}
        }
    }

    match (saml_response, saml_request) {
        (Some(_), None) => {
            handle_slo_response_redirect(&state, raw_query.as_bytes(), relay_state.as_deref())
        }
        (None, Some(_)) => {
            handle_slo_request_redirect(&state, raw_query.as_bytes(), relay_state.as_deref())
        }
        (Some(_), Some(_)) => error_page(
            StatusCode::BAD_REQUEST,
            "/saml/slo received both SAMLRequest and SAMLResponse",
        ),
        (None, None) => error_page(
            StatusCode::BAD_REQUEST,
            "/saml/slo requires either SAMLRequest or SAMLResponse",
        ),
    }
}

/// Redirect-binding LogoutResponse. RelayState is the (decoded) provider
/// slug; tracker lookup is by `InResponseTo` once the XML is decoded.
fn handle_slo_response_redirect(
    state: &AppState,
    raw_query: &[u8],
    relay_state: Option<&str>,
) -> Response {
    let Some(provider_id) = relay_state else {
        warn!("/saml/slo GET: LogoutResponse missing RelayState");
        return redirect_with_cleared_cookie("/?msg=signed-out-locally");
    };
    let Some(entry) = state.by_id.get(provider_id).cloned() else {
        warn!(provider = %provider_id, "/saml/slo GET: unknown provider in RelayState");
        return redirect_with_cleared_cookie("/?msg=signed-out-locally");
    };

    // Peek the InResponseTo to find the tracker. Need to DEFLATE the
    // SAMLResponse param first to read the XML; cheaper to read the query
    // string param + base64 + inflate, but for routing we can leave that
    // to the crate: pull the request_id off the dispatch_result tracker
    // stash by walking ALL pending trackers for this provider.
    //
    // The pending-tracker map is small (a few entries in a demo), so the
    // simplest correct thing is to filter trackers by `peer_entity_id`
    // and try each one. The crate verifies `InResponseTo == tracker.id`
    // internally, so the right tracker wins on the consume call.
    let tracker = match state.logout_trackers.lock() {
        Ok(store) => store.find_by_peer(&entry.idp.entity_id),
        Err(e) => {
            warn!(error = %e, "/saml/slo GET: tracker store poisoned");
            return error_page(StatusCode::INTERNAL_SERVER_ERROR, "tracker store unavailable");
        }
    };
    let Some(tracker) = tracker else {
        warn!(provider = %provider_id, "/saml/slo GET: no pending LogoutTracker for provider");
        return redirect_with_cleared_cookie("/?msg=signed-out-locally");
    };

    let slo_url = format!("{}/saml/slo", state.config.sp_base_url);
    let outcome = state.sp.consume_logout_response(
        &entry.idp,
        ConsumeLogoutResponse {
            peer_crypto_policy: None,
            body: raw_query,
            binding: Binding::HttpRedirect,
            detached_signature: None,
            tracker: &tracker,
            expected_destination: &slo_url,
            now: SystemTime::now(),
            clock_skew: Duration::from_mins(2),
        },
    );

    let target = match outcome {
        Ok(LogoutOutcome::Success | LogoutOutcome::PartialLogout { .. }) => {
            info!(provider = %entry.config.id, "/saml/slo GET: SP-init SLO succeeded");
            // Drop the tracker now that it's been redeemed.
            if let Ok(mut store) = state.logout_trackers.lock() {
                store.take(&tracker.request_id);
            }
            "/?msg=signed-out"
        }
        Ok(LogoutOutcome::Failure { status, message }) => {
            warn!(
                provider = %entry.config.id,
                status = %status,
                message = ?message,
                "/saml/slo GET: SP-init SLO failed at IdP",
            );
            "/?msg=signed-out-locally"
        }
        Err(e) => {
            warn!(
                provider = %entry.config.id,
                error = %e,
                "/saml/slo GET: consume_logout_response rejected the LogoutResponse",
            );
            "/?msg=signed-out-locally"
        }
    };
    redirect_with_cleared_cookie(target)
}

/// Redirect-binding LogoutRequest (IdP-initiated). Routes by trial:
/// attempts `consume_logout_request` against each configured provider
/// until one's Issuer + signature verification clears. v1 IdP-init
/// behaviour — see RFC-007 §5.1 for the full chain-propagation algorithm
/// (proxy SLO is out of scope for the demo).
fn handle_slo_request_redirect(
    state: &AppState,
    raw_query: &[u8],
    relay_state: Option<&str>,
) -> Response {
    let slo_url = format!("{}/saml/slo", state.config.sp_base_url);
    let mut last_err: Option<saml::Error> = None;
    let mut matched: Option<(ProviderEntry, ParsedLogoutRequest)> = None;
    for entry in state.by_id.values() {
        match state.sp.consume_logout_request(
            &entry.idp,
            ConsumeLogoutRequest {
                peer_crypto_policy: None,
                body: raw_query,
                binding: Binding::HttpRedirect,
                detached_signature: None,
                expected_destination: &slo_url,
                now: SystemTime::now(),
                clock_skew: Duration::from_mins(2),
            },
        ) {
            Ok(parsed) => {
                matched = Some((entry.clone(), parsed));
                break;
            }
            Err(e) => last_err = Some(e),
        }
    }

    let Some((entry, parsed)) = matched else {
        warn!(
            error = ?last_err,
            "/saml/slo GET: no provider matched the inbound LogoutRequest",
        );
        return error_page(
            StatusCode::UNAUTHORIZED,
            "LogoutRequest did not verify against any configured provider",
        );
    };

    let Some(binding) = pick_slo_binding(&entry.idp) else {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "IdP no longer advertises a usable SLO binding",
        );
    };
    let dispatch = match state.sp.build_logout_response(
        &entry.idp,
        &parsed,
        LogoutStatus::Success,
        relay_state,
        binding,
    ) {
        Ok(d) => d,
        Err(e) => {
            warn!(
                error = %e,
                provider = %entry.config.id,
                "/saml/slo GET: build_logout_response failed",
            );
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("build_logout_response: {e}"),
            );
        }
    };

    info!(
        provider = %entry.config.id,
        "/saml/slo GET: handled IdP-init LogoutRequest; clearing local session",
    );
    finalize_logout_dispatch(dispatch, &entry.config.label, /* clear_cookie */ true)
}

// =============================================================================
// Helpers
// =============================================================================

/// 303 redirect to `target`, with the session cookie cleared. Used by the
/// local-only logout fallbacks and after a successful SP-init SLO round trip.
fn redirect_with_cleared_cookie(target: &str) -> Response {
    let mut headers = HeaderMap::new();
    match HeaderValue::from_str(&session::clear_cookie_header()) {
        Ok(clear) => {
            headers.insert(header::SET_COOKIE, clear);
        }
        Err(e) => {
            warn!(error = %e, "could not clear session cookie");
            return error_page(StatusCode::INTERNAL_SERVER_ERROR, "could not clear cookie");
        }
    }
    (headers, Redirect::to(target)).into_response()
}

/// Finalise an outbound logout dispatch. Clears the local session cookie
/// (so the IdP's response, if any, finds an already-clean SP), then
/// surfaces the binding: 303 for Redirect, 200 + auto-submit HTML for POST.
fn finalize_logout_dispatch(
    dispatch: Dispatch,
    provider_label: &str,
    clear_cookie: bool,
) -> Response {
    let mut headers = HeaderMap::new();
    if clear_cookie {
        match HeaderValue::from_str(&session::clear_cookie_header()) {
            Ok(clear) => {
                headers.insert(header::SET_COOKIE, clear);
            }
            Err(e) => {
                warn!(error = %e, "could not clear session cookie on logout dispatch");
                return error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not clear cookie",
                );
            }
        }
    }
    match dispatch {
        Dispatch::Redirect(url) => (headers, Redirect::to(url.as_str())).into_response(),
        Dispatch::Post(form) => (
            headers,
            Html(templates::render_post_dispatch(
                form.action.as_str(),
                form.saml_request.as_deref(),
                form.saml_response.as_deref(),
                form.relay_state.as_deref(),
                provider_label,
            )),
        )
            .into_response(),
    }
}

/// Pick the binding to use for an outbound SLO message against `idp`.
/// Prefers HTTP-Redirect; falls back to HTTP-POST. Returns `None` if the
/// IdP advertises neither (in which case the caller falls back to a
/// local-only logout).
fn pick_slo_binding(idp: &IdpDescriptor) -> Option<Binding> {
    pick_slo_binding_with_pref(idp, None)
}

fn pick_slo_binding_with_pref(idp: &IdpDescriptor, pref: Option<&str>) -> Option<Binding> {
    let preferred = pref.and_then(|s| match s.to_ascii_lowercase().as_str() {
        "post" => Some(Binding::HttpPost),
        "redirect" => Some(Binding::HttpRedirect),
        _ => None,
    });
    if let Some(p) = preferred
        && idp.slo_endpoint(p).is_some()
    {
        return Some(p);
    }
    if idp.slo_endpoint(Binding::HttpRedirect).is_some() {
        Some(Binding::HttpRedirect)
    } else if idp.slo_endpoint(Binding::HttpPost).is_some() {
        Some(Binding::HttpPost)
    } else {
        None
    }
}

/// Reconstruct a [`NameId`] from the session state for use in a
/// `<samlp:LogoutRequest>`. The SP doesn't persist the name qualifier
/// attributes from the original assertion (the dashboard doesn't need
/// them), so we round-trip just the value + format URI. Per saml-core
/// §3.7.3.1.1, those two are the only fields the IdP is required to
/// match on when locating the session to terminate.
fn build_name_id(session: &Session) -> NameId {
    NameId::new(
        session.name_id_value.clone(),
        NameIdFormat::from_uri(&session.name_id_format),
    )
}

/// Map a `msg=` query value into a one-line banner shown on `/`. Returns
/// `None` for unknown values (the landing page omits the banner entirely
/// rather than echoing an unknown string into the DOM).
fn banner_for_msg(msg: &str) -> Option<String> {
    match msg {
        "signed-out" => Some(
            "Signed out everywhere. Click a provider to sign in again.".to_owned(),
        ),
        "signed-out-locally" => Some(
            "Signed out of this app. Your IdP session may still be active.".to_owned(),
        ),
        "signed-out-locally-no-slo" => Some(
            "Signed out of this app. The IdP didn't advertise a SingleLogoutService endpoint, so the IdP session is still active.".to_owned(),
        ),
        "already-signed-out" => Some("You're already signed out.".to_owned()),
        _ => None,
    }
}

/// Read the `msg` query parameter from a raw query string. Returns the
/// percent-decoded value (or `None` if absent).
fn read_msg_query_param(raw_query: &str) -> Option<String> {
    for pair in raw_query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == "msg" {
            return Some(
                percent_encoding::percent_decode_str(v)
                    .decode_utf8_lossy()
                    .into_owned(),
            );
        }
    }
    None
}

fn extract_session(state: &AppState, headers: &HeaderMap) -> Option<Session> {
    let cookie_header = headers
        .get(header::COOKIE)
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

fn attribute_to_session(a: &Attribute) -> SessionAttribute {
    SessionAttribute {
        name: a.name.clone(),
        friendly_name: a.friendly_name.clone(),
        values: a.values.clone(),
    }
}

fn short_name_id_format(uri: &str) -> String {
    uri.rsplit_once(':')
        .map_or_else(|| uri.to_owned(), |(_, tail)| tail.to_owned())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Trivial best-effort scan for the `InResponseTo` attribute on the root
/// `<samlp:Response>` element. Mirrors the fixed scanner from the
/// per-provider crates that handles a leading `<?xml ... ?>` declaration.
fn peek_in_response_to(xml: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(xml).ok()?;
    let response_tag_start = s.find("Response")?;
    let tag_open = s.get(..response_tag_start)?.rfind('<')?;
    let after_open = s.get(tag_open..)?;
    let tag_end = after_open.find('>')?;
    let tag = after_open.get(..tag_end)?;

    let key = "InResponseTo=\"";
    let start = tag.find(key)?.saturating_add(key.len());
    let rest = tag.get(start..)?;
    let end = rest.find('"')?;
    rest.get(..end).map(str::to_owned)
}

/// Pull the `<saml:Issuer>` element's text content out of a Response XML
/// blob. The ACS handler uses this to resolve the inbound Response back
/// to a provider entry; full canonicalisation + signature verification
/// happens inside `consume_response`. We deliberately do a tiny tag scan
/// here rather than a full parse so a malformed Response gets rejected
/// fast.
fn peek_issuer(xml: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(xml).ok()?;
    // Skip any XML declaration and find the first `<*:Issuer>` open tag
    // (the namespace prefix varies: `saml`, `saml2`, sometimes none).
    let mut cursor = 0usize;
    while cursor < s.len() {
        let rest = s.get(cursor..)?;
        let open_off = rest.find('<')?;
        let after = rest.get(open_off.saturating_add(1)..)?;
        let close = after.find('>')?;
        let tag = after.get(..close)?;
        // Bail on the XML declaration / processing instructions.
        if tag.starts_with('?') || tag.starts_with('!') {
            cursor = cursor
                .saturating_add(open_off)
                .saturating_add(close)
                .saturating_add(2);
            continue;
        }
        let tag_name = tag.split_whitespace().next()?;
        let local = tag_name.rsplit(':').next()?;
        if local.eq_ignore_ascii_case("Issuer") {
            // Found `<...Issuer ...>`; pull text up to `</...Issuer>`.
            let value_start = cursor
                .saturating_add(open_off)
                .saturating_add(close)
                .saturating_add(2);
            let value_rest = s.get(value_start..)?;
            let value_end = value_rest.find("</")?;
            let raw = value_rest.get(..value_end)?.trim();
            if raw.is_empty() {
                return None;
            }
            return Some(raw.to_owned());
        }
        cursor = cursor
            .saturating_add(open_off)
            .saturating_add(close)
            .saturating_add(2);
    }
    None
}

fn format_unix_iso8601(secs: u64) -> String {
    let target = UNIX_EPOCH
        .checked_add(Duration::from_secs(secs))
        .unwrap_or(UNIX_EPOCH);
    saml::format_xs_datetime(target).unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn error_page(status: StatusCode, message: &str) -> Response {
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
<title>Error</title><link rel=\"stylesheet\" href=\"/static/style.css\"></head>\
<body><main class=\"shell\"><header class=\"brand\"><div class=\"mark\">S</div>\
<div class=\"name\">saml-demo <span>· error</span></div></header>\
<section class=\"hero\"><span class=\"kicker\" style=\"background:rgba(185,28,28,0.08);color:#b91c1c;\">\
<span class=\"dot\" style=\"background:#b91c1c;\"></span> Request failed</span>\
<h1>Something went sideways.</h1>\
<p class=\"lede\">{message}</p>\
<a class=\"btn btn-primary\" href=\"/\">Back to start</a>\
</section></main></body></html>",
        message = html_escape(message),
    );
    (status, Html(body)).into_response()
}

fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peek_in_response_to_handles_xml_declaration() {
        let xml = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
            <samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
            ID=\"_resp1\" InResponseTo=\"_req-42\" Version=\"2.0\">\
            <samlp:Status/></samlp:Response>";
        assert_eq!(peek_in_response_to(xml).as_deref(), Some("_req-42"));
    }

    #[test]
    fn peek_in_response_to_returns_none_when_absent() {
        let xml = b"<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
            ID=\"_resp1\" Version=\"2.0\"></samlp:Response>";
        assert_eq!(peek_in_response_to(xml), None);
    }

    #[test]
    fn peek_in_response_to_handles_no_declaration() {
        let xml = b"<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
            ID=\"_resp1\" InResponseTo=\"_abc\" Version=\"2.0\"></samlp:Response>";
        assert_eq!(peek_in_response_to(xml).as_deref(), Some("_abc"));
    }

    #[test]
    fn peek_issuer_pulls_text_content() {
        let xml = b"<?xml version=\"1.0\"?>\
            <samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
              xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_r1\">\
              <saml:Issuer>https://idp.example.com/saml</saml:Issuer>\
              <samlp:Status/>\
            </samlp:Response>";
        assert_eq!(
            peek_issuer(xml).as_deref(),
            Some("https://idp.example.com/saml")
        );
    }

    #[test]
    fn peek_issuer_handles_unprefixed_namespace() {
        let xml = b"<Response xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\">\
            <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\">urn:dev.auth0.com</Issuer>\
            </Response>";
        assert_eq!(peek_issuer(xml).as_deref(), Some("urn:dev.auth0.com"));
    }

    #[test]
    fn peek_issuer_returns_none_when_missing() {
        let xml = b"<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
            ID=\"_r1\"><samlp:Status/></samlp:Response>";
        assert_eq!(peek_issuer(xml), None);
    }

    #[test]
    fn banner_for_msg_maps_known_codes() {
        assert!(banner_for_msg("signed-out").unwrap().contains("everywhere"));
        assert!(
            banner_for_msg("signed-out-locally")
                .unwrap()
                .contains("IdP session may still be active")
        );
        assert!(
            banner_for_msg("signed-out-locally-no-slo")
                .unwrap()
                .contains("SingleLogoutService")
        );
        assert!(
            banner_for_msg("already-signed-out")
                .unwrap()
                .contains("already signed out")
        );
        assert!(banner_for_msg("nope").is_none());
        assert!(banner_for_msg("").is_none());
    }

    #[test]
    fn read_msg_query_param_finds_the_value() {
        assert_eq!(
            read_msg_query_param("msg=signed-out").as_deref(),
            Some("signed-out"),
        );
        assert_eq!(
            read_msg_query_param("foo=bar&msg=signed-out-locally&baz=q").as_deref(),
            Some("signed-out-locally"),
        );
        assert_eq!(read_msg_query_param("foo=bar"), None);
    }

    #[test]
    fn build_name_id_round_trips_email_format() {
        let session = Session {
            name_id_value: "alice@saml-demo.test".into(),
            name_id_format: NameIdFormat::EmailAddress.as_uri().to_owned(),
            session_index: None,
            authn_instant_unix: 0,
            issued_at_unix: 0,
            idp_entity_id: String::new(),
            provider_id: "fusionauth".into(),
            attributes: vec![],
        };
        let nid = build_name_id(&session);
        assert_eq!(nid.value, "alice@saml-demo.test");
        assert_eq!(nid.format, NameIdFormat::EmailAddress);
        assert!(nid.sp_name_qualifier.is_none());
    }

    #[test]
    fn build_name_id_handles_custom_format() {
        let session = Session {
            name_id_value: "opaque-id-123".into(),
            name_id_format: "urn:weird:nameid-format:thing".into(),
            session_index: None,
            authn_instant_unix: 0,
            issued_at_unix: 0,
            idp_entity_id: String::new(),
            provider_id: "asgardeo".into(),
            attributes: vec![],
        };
        let nid = build_name_id(&session);
        assert_eq!(nid.value, "opaque-id-123");
        assert_eq!(
            nid.format,
            NameIdFormat::Custom("urn:weird:nameid-format:thing".into()),
        );
    }

    #[test]
    fn pick_slo_binding_prefers_redirect_then_post() {
        use saml::Endpoint as Ep;
        let mut idp = IdpDescriptor {
            entity_id: "test".into(),
            sso_endpoints: vec![],
            slo_endpoints: vec![Ep::post("http://idp/slo", 0, true)],
            artifact_resolution_endpoints: vec![],
            supported_name_id_formats: vec![],
            signing_certs: vec![],
            encryption_certs: vec![],
            want_authn_requests_signed: false,
            valid_until: None,
            cache_duration: None,
        };
        assert_eq!(pick_slo_binding(&idp), Some(Binding::HttpPost));
        idp.slo_endpoints
            .insert(0, Ep::redirect("http://idp/slo", 0, true));
        assert_eq!(pick_slo_binding(&idp), Some(Binding::HttpRedirect));
        idp.slo_endpoints.clear();
        assert!(pick_slo_binding(&idp).is_none());
    }

    #[test]
    fn logout_tracker_store_insert_and_take_round_trip() {
        let mut store = LogoutTrackerStore::default();
        let tracker = LogoutTracker {
            request_id: "_req-1".into(),
            issued_at: SystemTime::now(),
            peer_entity_id: "https://idp.example/saml".into(),
        };
        store.insert(tracker.clone());
        assert!(store.find_by_peer("https://idp.example/saml").is_some());
        let taken = store.take("_req-1").expect("tracker present");
        assert_eq!(taken.request_id, "_req-1");
        assert!(store.take("_req-1").is_none());
    }

    #[test]
    fn baked_in_providers_toml_parses() {
        let file = ProvidersFile::from_toml(DEFAULT_PROVIDERS_TOML).expect("baked-in toml parses");
        assert!(
            file.provider.len() >= 8,
            "expected at least 8 providers, got {}",
            file.provider.len()
        );
        let ids: Vec<&str> = file.provider.iter().map(|p| p.id.as_str()).collect();
        for expected in [
            "keycloak",
            "authentik",
            "fusionauth",
            "zitadel",
            "auth0",
            "descope",
            "asgardeo",
            "rust-idp",
        ] {
            assert!(ids.contains(&expected), "missing provider id: {expected}");
        }
    }
}
