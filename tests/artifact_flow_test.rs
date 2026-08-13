//! HTTP-Artifact binding end-to-end test (SAML 2.0 Bindings §3.6).
//!
//! Wires the artifact flow through the role layers:
//! - SP issues an AuthnRequest with `ProtocolBinding=Artifact` and an ACS
//!   endpoint registered as `HttpArtifact`.
//! - IdP's transaction-bearing issuance returns an `IssuedArtifact` carrying
//!   the redirect plus request-time SP trust provenance.
//! - We stash the Response XML and transaction together and atomically remove
//!   them only after authenticating and replay-reserving ArtifactResolve.
//! - A mock `HttpClient` simulates the IdP's ARS: on POST, it calls
//!   `idp.consume_artifact_resolve(...)`, takes the artifact from the stash,
//!   and emits a `<samlp:ArtifactResponse>` SOAP envelope via
//!   `idp.build_artifact_response(...)`.
//! - SP calls `consume_response_artifact(http, ...)` which fetches via SOAP
//!   and validates the recovered Response.

#![cfg(all(
    feature = "artifact-binding",
    feature = "weak-algos",
    feature = "xmlenc"
))]

#[path = "common/mod.rs"]
mod common;

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use saml::attribute::Attribute;
use saml::authn_context::AuthnContextClassRef;
use saml::binding::{Binding, Dispatch, Endpoint, SsoResponseBinding, SsoResponseEndpoint};
use saml::descriptor::{IdpDescriptor, SpDescriptor};
use saml::dsig::algorithms::{
    C14nAlgorithm, DigestAlgorithm, PeerCryptoPolicy, SignatureAlgorithm,
};
use saml::http::{HttpClient, HttpRequest, HttpResponse};
use saml::idp::{
    ArtifactResolveTransaction, ConsumeArtifactResolve, ConsumeAuthnRequest, IdentityProvider,
    IdentityProviderConfig, IssueResponse, IssuedResponse,
};
use saml::nameid::{NameId, NameIdFormat};
use saml::replay::{InMemoryReplayCache, ReplayMode};
use saml::sp::{
    ArtifactBackchannel, ConsumeArtifactResponse, ServiceProvider, ServiceProviderConfig,
    StartLogin,
};
use saml::xmlenc::algorithms::{DataEncryptionAlgorithm, KeyTransportAlgorithm};

const SP_ENTITY_ID: &str = "https://sp.example.com/artifact";
const SP_ACS_URL: &str = "https://sp.example.com/artifact/acs";
const IDP_ENTITY_ID: &str = "https://idp.example.com/artifact";
const IDP_SSO_URL: &str = "https://idp.example.com/artifact/sso";
const IDP_ARS_URL: &str = "https://idp.example.com/artifact/ars";

const USER_EMAIL: &str = "alice@example.com";

/// Build the IdP with an `ArtifactResolutionService` endpoint advertised.
fn make_artifact_idp() -> common::TestResult<IdentityProvider> {
    let signing_key = common::rsa_keypair_with_cert()?;
    Ok(IdentityProvider::new(IdentityProviderConfig {
        entity_id: IDP_ENTITY_ID.to_owned(),
        sso: vec![Endpoint::post(IDP_SSO_URL, 0, true)],
        slo: vec![],
        artifact_resolution: vec![Endpoint::soap(IDP_ARS_URL, Some(7), true)],
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
        max_authn_request_age: saml::IdentityProviderConfig::DEFAULT_MAX_AUTHN_REQUEST_AGE,
        default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
        outbound_digest_algorithm: DigestAlgorithm::Sha256,
        outbound_c14n: C14nAlgorithm::ExclusiveCanonical,
        outbound_data_encryption_algorithm: DataEncryptionAlgorithm::Aes256Gcm,
        outbound_key_transport_algorithm: KeyTransportAlgorithm::RsaOaep,
    })?)
}

/// Build the SP with an `HttpArtifact` ACS endpoint advertised.
fn make_artifact_sp() -> common::TestResult<ServiceProvider> {
    Ok(ServiceProvider::new(ServiceProviderConfig {
        entity_id: SP_ENTITY_ID.to_owned(),
        acs: vec![SsoResponseEndpoint::artifact(SP_ACS_URL, 0, true)],
        slo: vec![],
        name_id_formats: vec![NameIdFormat::EmailAddress, NameIdFormat::Persistent],
        signing_key: Some(common::rsa_keypair_with_cert()?),
        decryption_key: None,
        sign_authn_requests: false,
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

/// Mock `HttpClient` that simulates the IdP's `ArtifactResolutionService`.
///
/// On each `send`, it parses the SOAP body as an `ArtifactResolve`, looks up
/// the artifact value in an in-memory stash, and returns a synthesized
/// `ArtifactResponse` envelope built via the actual IdP role-layer helpers.
struct ArtifactResolutionService<'a> {
    idp: &'a IdentityProvider,
    sp_descriptor: &'a SpDescriptor,
    replay_cache: &'a InMemoryReplayCache,
    stash: Arc<Mutex<HashMap<String, StashedArtifact>>>,
}

struct StashedArtifact {
    response_xml: String,
    transaction: ArtifactResolveTransaction,
}

impl HttpClient for ArtifactResolutionService<'_> {
    fn send(
        &self,
        request: HttpRequest,
    ) -> impl Future<Output = Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>>> + Send
    {
        // Parse only to select the untrusted artifact key. No payload is
        // removed and no parsed field is trusted until the authenticated API
        // below succeeds.
        let selected = self
            .idp
            .parse_artifact_resolve(self.sp_descriptor, &request.body)
            .map_err(|e| format!("parse_artifact_resolve: {e:?}"));
        let stash = self.stash.clone();
        let idp_response = selected.and_then(|selected| {
            let mut guard = stash
                .lock()
                .map_err(|_poison| "stash poisoned".to_string())?;
            let entry = guard
                .get(&selected.artifact)
                .ok_or_else(|| format!("artifact not in stash: {}", selected.artifact))?;
            let req = self
                .idp
                .consume_artifact_resolve(ConsumeArtifactResolve {
                    sp: self.sp_descriptor,
                    transaction: &entry.transaction,
                    replay_cache: self.replay_cache,
                    peer_crypto_policy: None,
                    soap_envelope: &request.body,
                    expected_destination: IDP_ARS_URL,
                    now: std::time::SystemTime::now(),
                    clock_skew: Duration::from_mins(2),
                    require_signed: true,
                })
                .map_err(|e| format!("consume_artifact_resolve: {e:?}"))?;
            let entry = guard
                .remove(&req.artifact)
                .ok_or_else(|| format!("artifact not in stash: {}", req.artifact))?;
            self.idp
                .build_artifact_response(&req, &entry.response_xml)
                .map_err(|e| format!("build_artifact_response: {e:?}"))
        });

        async move {
            let envelope = idp_response
                .map_err(|s| -> Box<dyn std::error::Error + Send + Sync> { s.into() })?;
            Ok(HttpResponse {
                status: 200,
                headers: vec![("Content-Type".to_owned(), "text/xml".to_owned())],
                body: envelope.into_bytes(),
            })
        }
    }
}

#[tokio::test]
async fn artifact_flow_end_to_end() {
    let sp = make_artifact_sp().expect("sp builds");
    let idp = make_artifact_idp().expect("idp builds");
    let idp_descriptor: IdpDescriptor = common::idp_descriptor(&idp).expect("idp descriptor");
    let sp_descriptor: SpDescriptor = common::sp_descriptor(&sp).expect("sp descriptor");
    let now = common::flow_now();

    // 1. SP starts login requesting Artifact response binding.
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

    // 2. Extract AuthnRequest from POST dispatch.
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

    // 3. IdP consumes the AuthnRequest. It resolves the ACS to the
    //    artifact-binding endpoint based on `ProtocolBinding=Artifact`.
    let parsed = idp
        .consume_authn_request(ConsumeAuthnRequest {
            sp: &sp_descriptor,
            peer_crypto_policy: None,
            max_authn_request_age: None,
            saml_request: &authn_request_xml,
            binding: Binding::HttpPost,
            relay_state: Some("artifact-relay"),
            detached_signature: None,
            expected_destination: IDP_SSO_URL,
            now,
            clock_skew: Duration::from_mins(2),
        })
        .expect("consume_authn_request");

    // Sanity: the resolved ACS endpoint binding is Artifact.
    assert_eq!(
        parsed.assertion_consumer_service.binding,
        SsoResponseBinding::HttpArtifact
    );

    // 4. IdP issues the Response and its request-time trust transaction.
    let issued = idp
        .issue_response_with_artifact_transaction(IssueResponse {
            sp: &sp_descriptor,
            in_response_to: &parsed,
            name_id: NameId::email(USER_EMAIL),
            attributes: vec![Attribute::email(USER_EMAIL)],
            authn_instant: now,
            session_index: "sess-artifact-1".to_owned(),
            session_not_on_or_after: Some(
                now.checked_add(Duration::from_hours(1))
                    .expect("session_not_on_or_after fits"),
            ),
            authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
            force_encrypt_assertion: None,
            now,
            assertion_lifetime: Duration::from_mins(10),
            subject_confirmation_lifetime: Duration::from_mins(5),
            holder_of_key_cert: None,
        })
        .expect("idp issue_response");

    let IssuedResponse::Artifact(issued) = issued else {
        panic!("expected IssuedResponse::Artifact");
    };
    let redirect = &issued.redirect;

    // 5. Caller stashes response_xml keyed by artifact. In a real deployment
    //    this is a persistent store keyed by the artifact's MessageHandle
    //    with an atomic take/delete operation.
    let stash: Arc<Mutex<HashMap<String, StashedArtifact>>> = Arc::new(Mutex::new(HashMap::new()));
    stash.lock().expect("stash lock").insert(
        redirect.artifact.clone(),
        StashedArtifact {
            response_xml: redirect.response_xml.clone(),
            transaction: issued.transaction,
        },
    );

    // 6. Confirm the redirect URL carries ?SAMLart=... and RelayState=...
    let query_pairs: HashMap<String, String> = redirect
        .redirect_to
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert_eq!(
        query_pairs.get("SAMLart").map(String::as_str),
        Some(redirect.artifact.as_str())
    );
    assert_eq!(
        query_pairs.get("RelayState").map(String::as_str),
        Some("artifact-relay")
    );

    // 7. Browser hits the SP's ACS with `?SAMLart=...`. SP resolves the
    //    artifact against the IdP via SOAP and validates the recovered
    //    Response.
    let artifact_resolve_replay = InMemoryReplayCache::new(16);
    let ars = ArtifactResolutionService {
        idp: &idp,
        sp_descriptor: &sp_descriptor,
        replay_cache: &artifact_resolve_replay,
        stash: stash.clone(),
    };
    let sp_signing_key = sp
        .config()
        .signing_key
        .as_ref()
        .expect("artifact SP signing key");

    let identity = sp
        .consume_response_artifact(
            &ars,
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
                holder_of_key_cert: None,
                backchannel: Some(ArtifactBackchannel {
                    sign: Some(saml::binding::artifact::SignConfig {
                        key: sp_signing_key,
                        sig_alg: SignatureAlgorithm::RsaSha256,
                        digest_alg: DigestAlgorithm::Sha256,
                        c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                    }),
                    verify: None,
                }),
            },
        )
        .await
        .expect("consume_response_artifact");

    assert!(
        stash.lock().expect("stash lock").is_empty(),
        "successful resolution atomically consumes the one-time artifact"
    );

    // 8. Assertions on the recovered Identity.
    assert_eq!(identity.name_id().format, NameIdFormat::EmailAddress);
    assert_eq!(identity.name_id().value, USER_EMAIL);
    assert_eq!(identity.session_index(), Some("sess-artifact-1"));
    let mail = identity
        .attributes()
        .iter()
        .find(|a| a.friendly_name.as_deref() == Some("mail"))
        .expect("mail attribute");
    assert_eq!(mail.values, vec![USER_EMAIL.to_owned()]);
}

/// Unknown artifact returns an error from the SP-side resolve call.
#[tokio::test]
async fn artifact_flow_unknown_artifact_propagates_error() {
    let sp = make_artifact_sp().expect("sp builds");
    let idp = make_artifact_idp().expect("idp builds");
    let idp_descriptor = common::idp_descriptor(&idp).expect("idp descriptor");
    let sp_descriptor = common::sp_descriptor(&sp).expect("sp descriptor");
    let now = common::flow_now();
    let start = sp
        .start_login(
            &idp_descriptor,
            StartLogin {
                relay_state: None,
                binding: Binding::HttpPost,
                force_authn: false,
                is_passive: false,
                requested_name_id_format: None,
                requested_authn_context: None,
                acs_index: None,
                acs_url: None,
                response_binding: Some(SsoResponseBinding::HttpArtifact),
            },
        )
        .expect("artifact login starts");
    let unknown_artifact =
        saml::binding::artifact::make_artifact(IDP_ENTITY_ID, 7).expect("valid unknown artifact");

    let empty_stash: Arc<Mutex<HashMap<String, StashedArtifact>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let artifact_resolve_replay = InMemoryReplayCache::new(16);
    let ars = ArtifactResolutionService {
        idp: &idp,
        sp_descriptor: &sp_descriptor,
        replay_cache: &artifact_resolve_replay,
        stash: empty_stash,
    };

    let err = sp
        .consume_response_artifact(
            &ars,
            ConsumeArtifactResponse {
                idp: &idp_descriptor,
                peer_crypto_policy: None,
                artifact: &unknown_artifact,
                relay_state: None,
                tracker: Some(&start.tracker),
                expected_destination: SP_ACS_URL,
                now,
                clock_skew: Duration::from_mins(2),
                replay_cache: None,
                replay_mode: ReplayMode::All,
                holder_of_key_cert: None,
                backchannel: None,
            },
        )
        .await
        .unwrap_err();

    // The mock returns an HTTP-layer error because the artifact is unknown.
    // The SP layer surfaces it as `Error::Http`.
    assert!(
        matches!(err, saml::error::Error::Http(_)),
        "expected Error::Http, got {err:?}"
    );
}
