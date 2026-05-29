//! In-process HTTP-Artifact binding round-trip for the IdP example.
//!
//! Proves the example's `ArtifactResolutionService` end-to-end without binding
//! a socket:
//!
//!   1. A real `ServiceProvider` (artifact ACS) starts login.
//!   2. The IdP example consumes the AuthnRequest and issues the Response.
//!      Because the resolved ACS binding is HTTP-Artifact, `issue_response`
//!      returns `SsoResponseDispatch::Artifact(...)`.
//!   3. We stash the Response XML keyed by the minted artifact via the same
//!      `AppState::stash_artifact` call the dispatch path makes, and confirm
//!      the redirect URL carries `?SAMLart=...`.
//!   4. The SP resolves the artifact. The `HttpClient` routes the SOAP
//!      `<samlp:ArtifactResolve>` POST through the example's axum router into
//!      the real `handle_artifact`, which returns a `<samlp:ArtifactResponse>`.
//!   5. The SP validates the recovered Response and we assert the Identity.
//!
//! Also asserts the artifact is single-use: a second resolve 404s.

#![cfg(feature = "artifact-binding")]

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt as _;

use saml::dsig::algorithms::{DigestAlgorithm, PeerCryptoPolicy, SignatureAlgorithm};
use saml::http::{HttpClient, HttpRequest, HttpResponse};
use saml::{
    Attribute, AuthnContextClassRef, Binding, ConsumeArtifactResponse, ConsumeAuthnRequest,
    Dispatch, IdpDescriptor, IssueResponse, NameId, NameIdFormat, ReplayMode, ServiceProvider,
    ServiceProviderConfig, SpDescriptor, SpWantSigned, SsoResponseBinding, SsoResponseDispatch,
    SsoResponseEndpoint, StartLogin, X509Certificate,
};

use saml_idp_example as idp;
use saml_idp_example::{AppConfig, AppState, SpEntry, SpEntryConfig, StashedArtifact};

const IDP_BASE: &str = "http://idp.test";
const IDP_ENTITY_ID: &str = "http://idp.test/saml/idp";
const SP_ENTITY_ID: &str = "https://sp.example.com/artifact";
const SP_ACS_URL: &str = "https://sp.example.com/artifact/acs";
const USER_EMAIL: &str = "alice@example.com";

/// SP signed with the example's baked keypair (test only). The IdP example
/// requires inbound AuthnRequests to be signed, so the SP must carry a signing
/// key whose cert lands in its descriptor.
fn make_artifact_sp() -> ServiceProvider {
    let kp = saml::KeyPair::from_pkcs8_pem(idp::IDP_KEY_PEM).expect("sp keypair");
    let cert = X509Certificate::from_pem(idp::IDP_CERT_PEM).expect("sp cert");
    let signing_key = kp.with_certificate(cert);

    ServiceProvider::new(ServiceProviderConfig {
        entity_id: SP_ENTITY_ID.to_owned(),
        acs: vec![SsoResponseEndpoint::artifact(SP_ACS_URL, 0, true)],
        slo: vec![],
        name_id_formats: vec![NameIdFormat::EmailAddress, NameIdFormat::Persistent],
        signing_key: Some(signing_key),
        decryption_key: None,
        sign_authn_requests: true,
        want_signed: SpWantSigned {
            response: false,
            assertions: true,
        },
        allow_unsolicited: false,
        logout_signing: saml::SpLogoutSigning::default(),
        logout_want_signed: saml::SpLogoutWantSigned::default(),
        default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
        outbound_digest_algorithm: DigestAlgorithm::Sha256,
    })
    .expect("sp builds")
}

fn make_app_state(sp: &ServiceProvider) -> AppState {
    let config = AppConfig {
        bind_addr: "127.0.0.1:0".parse().expect("addr"),
        idp_entity_id: IDP_ENTITY_ID.to_owned(),
        idp_base_url: IDP_BASE.to_owned(),
        session_signing_key: [0u8; 32],
        users_toml_path: None,
        sps_toml_path: None,
    };
    let idp_provider = idp::build_identity_provider(&config).expect("idp builds");

    let sp_metadata = sp.metadata_xml(false).expect("sp metadata");
    let sp_descriptor = SpDescriptor::from_metadata_xml(sp_metadata.as_bytes()).expect("sp parse");

    let entry = SpEntry {
        config: SpEntryConfig {
            entity_id: SP_ENTITY_ID.to_owned(),
            acs_url: SP_ACS_URL.to_owned(),
            acs_binding: "HTTP-Artifact".to_owned(),
            slo_url: None,
            slo_binding: "HTTP-POST".to_owned(),
            metadata_url: String::new(),
            idp_entity_id_override: None,
        },
        sp: Arc::new(sp_descriptor),
        label: "Artifact SP".to_owned(),
    };

    let users_file = idp::load_users(None).expect("users load");
    let users = idp::auth::UserStore::from_users_file(&users_file).expect("user store");

    AppState::new(config, idp_provider, users, vec![entry], vec![])
}

fn idp_descriptor(state: &AppState) -> IdpDescriptor {
    let xml = state.idp.metadata_xml(false).expect("idp metadata");
    IdpDescriptor::from_metadata_xml(xml.as_bytes()).expect("idp descriptor")
}

/// `HttpClient` that routes the SP's SOAP `ArtifactResolve` POST through the
/// example's axum router into `handle_artifact`.
struct RouterClient {
    state: AppState,
}

impl HttpClient for RouterClient {
    fn send(
        &self,
        request: HttpRequest,
    ) -> impl Future<Output = Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>>> + Send
    {
        let router = idp::build_router(self.state.clone());
        async move {
            let mut builder = Request::builder()
                .method(request.method.as_str())
                .uri(&request.url);
            for (name, value) in &request.headers {
                builder = builder.header(name, value);
            }
            let http_req = builder.body(Body::from(request.body))?;
            let response = router.oneshot(http_req).await?;
            let status = response.status().as_u16();
            let headers = response
                .headers()
                .iter()
                .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()))
                .collect();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await?
                .to_vec();
            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        }
    }
}

#[tokio::test]
async fn artifact_round_trip_through_example_handlers() {
    let sp = make_artifact_sp();
    let state = make_app_state(&sp);
    let idp_descriptor = idp_descriptor(&state);
    let sp_descriptor = state
        .sp_by_entity_id(SP_ENTITY_ID)
        .expect("sp registered")
        .sp;
    let now = SystemTime::now();

    // The IdP descriptor must advertise the ArtifactResolutionService so the
    // SP can find the back-channel endpoint.
    assert_eq!(
        idp_descriptor
            .artifact_resolution_endpoint()
            .map(|e| e.url.as_str()),
        Some(format!("{IDP_BASE}/saml/artifact").as_str()),
    );

    // 1. SP starts login requesting the Artifact response binding.
    let start = sp
        .start_login(
            &idp_descriptor,
            StartLogin {
                relay_state: Some("artifact-relay"),
                binding: Binding::HttpPost,
                force_authn: false,
                is_passive: false,
                requested_name_id_format: Some(NameIdFormat::EmailAddress),
                requested_authn_context: None,
                acs_index: None,
                acs_url: None,
                response_binding: Some(SsoResponseBinding::HttpArtifact),
            },
        )
        .expect("start_login");

    let authn_request_xml = match start.dispatch {
        Dispatch::Post(form) => {
            use base64::Engine as _;
            let b64 = form.saml_request.expect("SAMLRequest present");
            base64::engine::general_purpose::STANDARD
                .decode(b64.as_bytes())
                .expect("base64")
        }
        Dispatch::Redirect(_) => panic!("expected POST dispatch"),
    };

    // 2. IdP consumes the AuthnRequest.
    let parsed = state
        .idp
        .consume_authn_request(ConsumeAuthnRequest {
            sp: &sp_descriptor,
            peer_crypto_policy: None,
            saml_request: &authn_request_xml,
            binding: Binding::HttpPost,
            relay_state: Some("artifact-relay"),
            detached_signature: None,
            expected_destination: &format!("{IDP_BASE}/saml/sso"),
            now,
            clock_skew: Duration::from_mins(2),
        })
        .expect("consume_authn_request");
    assert_eq!(
        parsed.assertion_consumer_service.binding,
        SsoResponseBinding::HttpArtifact,
    );

    // 3. IdP issues the Response — resolves to Artifact dispatch.
    let dispatch = state
        .idp
        .issue_response(IssueResponse {
            sp: &sp_descriptor,
            in_response_to: &parsed,
            name_id: NameId::email(USER_EMAIL),
            attributes: vec![Attribute::email(USER_EMAIL)],
            authn_instant: now,
            session_index: "sess-artifact-1".to_owned(),
            session_not_on_or_after: now.checked_add(Duration::from_hours(1)),
            authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
            force_encrypt_assertion: Some(false),
            now,
            assertion_lifetime: Duration::from_mins(10),
            subject_confirmation_lifetime: Duration::from_mins(5),
        })
        .expect("issue_response");

    let SsoResponseDispatch::Artifact(redirect) = dispatch else {
        panic!("expected Artifact dispatch");
    };

    // 4. Stash exactly as the example's finalize_artifact_dispatch does, and
    //    confirm the redirect carries SAMLart + RelayState.
    state
        .stash_artifact(
            redirect.artifact.clone(),
            StashedArtifact::new(redirect.response_xml.clone(), SP_ENTITY_ID.to_owned()),
        )
        .expect("stash");

    let query: std::collections::HashMap<String, String> = redirect
        .redirect_to
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert_eq!(
        query.get("SAMLart").map(String::as_str),
        Some(redirect.artifact.as_str()),
    );
    assert_eq!(
        query.get("RelayState").map(String::as_str),
        Some("artifact-relay"),
    );

    // 5. SP resolves the artifact through the example's /saml/artifact route.
    let client = RouterClient {
        state: state.clone(),
    };
    let identity = sp
        .consume_response_artifact(
            &client,
            ConsumeArtifactResponse {
                idp: &idp_descriptor,
                peer_crypto_policy: None,
                artifact: &redirect.artifact,
                relay_state: Some("artifact-relay"),
                tracker: Some(&start.tracker),
                expected_destination: SP_ACS_URL,
                now,
                clock_skew: Duration::from_mins(2),
                replay_cache: None,
                replay_mode: ReplayMode::All,
            },
        )
        .await
        .expect("consume_response_artifact");

    assert_eq!(identity.name_id.format, NameIdFormat::EmailAddress);
    assert_eq!(identity.name_id.value, USER_EMAIL);
    assert_eq!(identity.session_index.as_deref(), Some("sess-artifact-1"));

    // 6. The artifact is single-use. A second resolve hits the now-empty
    //    store: handle_artifact returns a 404 error page instead of a SOAP
    //    ArtifactResponse, so the SP-side resolve fails. (Over a real HTTP
    //    transport the SP receives the non-200 body and fails to parse it as
    //    an ArtifactResponse, rather than seeing a transport-level error.)
    let err = sp
        .consume_response_artifact(
            &client,
            ConsumeArtifactResponse {
                idp: &idp_descriptor,
                peer_crypto_policy: None,
                artifact: &redirect.artifact,
                relay_state: Some("artifact-relay"),
                tracker: None,
                expected_destination: SP_ACS_URL,
                now,
                clock_skew: Duration::from_mins(2),
                replay_cache: None,
                replay_mode: ReplayMode::All,
            },
        )
        .await
        .expect_err("second resolve must fail: artifact already consumed");
    // The exact variant depends on the error-page body shape; what matters is
    // that the consumed artifact is no longer resolvable.
    drop(err);
}

/// An unknown artifact is rejected by `handle_artifact` (404) and the SP-side
/// resolve fails rather than recovering a Response.
#[tokio::test]
async fn unknown_artifact_is_rejected() {
    let sp = make_artifact_sp();
    let state = make_app_state(&sp);
    let idp_descriptor = idp_descriptor(&state);
    let client = RouterClient {
        state: state.clone(),
    };

    let result = sp
        .consume_response_artifact(
            &client,
            ConsumeArtifactResponse {
                idp: &idp_descriptor,
                peer_crypto_policy: None,
                artifact: "AAQAA-totally-unknown",
                relay_state: None,
                tracker: None,
                expected_destination: SP_ACS_URL,
                now: SystemTime::now(),
                clock_skew: Duration::from_mins(2),
                replay_cache: None,
                replay_mode: ReplayMode::All,
            },
        )
        .await;
    assert!(
        result.is_err(),
        "unknown artifact must not resolve to an Identity",
    );
}
