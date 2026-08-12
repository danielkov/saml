//! HTTP-Artifact binding end-to-end test (SAML 2.0 Bindings §3.6).
//!
//! Wires the artifact flow through the role layers:
//! - SP issues an AuthnRequest with `ProtocolBinding=Artifact` and an ACS
//!   endpoint registered as `HttpArtifact`.
//! - IdP's `issue_response` returns `SsoResponseDispatch::Artifact(...)`
//!   carrying the redirect URL, the artifact value, and the stashed Response
//!   XML the IdP must serve from its ArtifactResolutionService.
//! - We stash the Response XML in a `HashMap<artifact, response_xml>`.
//! - A mock `HttpClient` simulates the IdP's ARS: on POST, it calls
//!   `idp.parse_artifact_resolve(...)`, looks up the artifact in the stash,
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
use saml::binding::artifact::SignConfig;
use saml::binding::{
    Binding, Dispatch, Endpoint, SsoResponseBinding, SsoResponseDispatch, SsoResponseEndpoint,
};
use saml::descriptor::{IdpDescriptor, SpDescriptor};
use saml::dsig::algorithms::{
    C14nAlgorithm, DigestAlgorithm, PeerCryptoPolicy, SignatureAlgorithm,
};
use saml::http::{HttpClient, HttpRequest, HttpResponse};
use saml::idp::{ConsumeAuthnRequest, IdentityProvider, IdentityProviderConfig, IssueResponse};
use saml::nameid::{NameId, NameIdFormat};
use saml::replay::ReplayMode;
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
        artifact_resolution: vec![Endpoint::soap(IDP_ARS_URL, None, true)],
        supported_name_id_formats: vec![NameIdFormat::Persistent, NameIdFormat::EmailAddress],
        default_name_id_format: NameIdFormat::EmailAddress,
        signing_key,
        decryption_key: None,
        want_authn_requests_signed: false,
        #[cfg(feature = "artifact-binding")]
        want_artifact_resolve_signed: true,
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

/// Build the SP with an `HttpArtifact` ACS endpoint advertised.
fn make_artifact_sp() -> common::TestResult<ServiceProvider> {
    Ok(ServiceProvider::new(ServiceProviderConfig {
        entity_id: SP_ENTITY_ID.to_owned(),
        acs: vec![SsoResponseEndpoint::artifact(SP_ACS_URL, 0, true)],
        slo: vec![],
        name_id_formats: vec![NameIdFormat::EmailAddress, NameIdFormat::Persistent],
        // An SP that signs its back-channel ArtifactResolve must publish the
        // matching certificate, or the IdP has nothing to verify against.
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
    stash: Arc<Mutex<HashMap<String, String>>>,
}

impl HttpClient for ArtifactResolutionService<'_> {
    fn send(
        &self,
        request: HttpRequest,
    ) -> impl Future<Output = Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>>> + Send
    {
        let parsed = self
            .idp
            .parse_artifact_resolve(self.sp_descriptor, None, IDP_ARS_URL, &request.body)
            .map_err(|e| format!("parse_artifact_resolve: {e:?}"));
        let stash = self.stash.clone();
        let idp_response = parsed.and_then(|req| {
            let guard = stash
                .lock()
                .map_err(|_poison| "stash poisoned".to_string())?;
            let response_xml = guard
                .get(&req.artifact)
                .ok_or_else(|| format!("artifact not in stash: {}", req.artifact))?
                .clone();
            drop(guard);
            self.idp
                .build_artifact_response(&req, SP_ENTITY_ID, &response_xml)
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
    let sp_signing_key = common::rsa_keypair_with_cert().expect("sp signing key");
    let now = common::fixed_now().expect("fixed_now");

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

    // 4. IdP issues the Response. Because the resolved ACS is Artifact,
    //    issue_response returns SsoResponseDispatch::Artifact(...).
    let dispatch = idp
        .issue_response(IssueResponse {
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

    let SsoResponseDispatch::Artifact(redirect) = dispatch else {
        panic!("expected SsoResponseDispatch::Artifact, got {dispatch:?}");
    };

    // 5. Caller stashes response_xml keyed by artifact. In a real deployment
    //    this is a persistent store keyed by the artifact's MessageHandle.
    let stash: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
    stash
        .lock()
        .expect("stash lock")
        .insert(redirect.artifact.clone(), redirect.response_xml.clone());

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
    let ars = ArtifactResolutionService {
        idp: &idp,
        sp_descriptor: &sp_descriptor,
        stash: stash.clone(),
    };

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
                // The IdP fixture requires a signed ArtifactResolve (SAML 2.0
                // Bindings §3.6.3), so the SP authenticates itself on the
                // back-channel. This exercises the full loop: the SP signs the
                // resolve, the IdP verifies it against the SP's metadata certs
                // before the artifact is looked up.
                backchannel: Some(ArtifactBackchannel {
                    sign: Some(SignConfig {
                        key: &sp_signing_key,
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

    // 8. Assertions on the recovered Identity.
    assert_eq!(identity.name_id.format, NameIdFormat::EmailAddress);
    assert_eq!(identity.name_id.value, USER_EMAIL);
    assert_eq!(identity.session_index.as_deref(), Some("sess-artifact-1"));
    let mail = identity
        .attributes
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
    let now = common::fixed_now().expect("fixed_now");
    let sp_signing_key = common::rsa_keypair_with_cert().expect("sp signing key");

    let empty_stash: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let unknown_artifact = saml::binding::artifact::make_artifact(IDP_ENTITY_ID, 0)
        .expect("mint an artifact the store has never seen");
    let ars = ArtifactResolutionService {
        idp: &idp,
        sp_descriptor: &sp_descriptor,
        stash: empty_stash,
    };

    let err = sp
        .consume_response_artifact(
            &ars,
            ConsumeArtifactResponse {
                idp: &idp_descriptor,
                peer_crypto_policy: None,
                // Well-formed type 0x0004 naming the IdP's ARS, so the SP
                // routes it to the backchannel and the store — not rejected
                // as malformed before the path under test is reached.
                artifact: &unknown_artifact,
                relay_state: None,
                tracker: None,
                expected_destination: SP_ACS_URL,
                now,
                clock_skew: Duration::from_mins(2),
                replay_cache: None,
                replay_mode: ReplayMode::All,
                holder_of_key_cert: None,
                // The IdP requires a signed ArtifactResolve. Sending an
                // unsigned one would be refused for the missing signature and
                // never reach the store, so this assertion would pass without
                // exercising the unknown-artifact path at all.
                backchannel: Some(ArtifactBackchannel {
                    sign: Some(SignConfig {
                        key: &sp_signing_key,
                        sig_alg: SignatureAlgorithm::RsaSha256,
                        digest_alg: DigestAlgorithm::Sha256,
                        c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                    }),
                    verify: None,
                }),
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

/// The low-level [`parse_artifact_resolve`] is public and applies none of the
/// role-layer checks — configured certificates, issuer-vs-`IDPSSODescriptor`,
/// the SOAP `ArtifactResolutionService` endpoint, or the `@Destination` rules.
/// It returns the same type the role builder consumes, so without an explicit
/// provenance marker a caller could parse attacker-supplied XML and hand it
/// straight to `build_artifact_response`, leaving only the issuer/recipient
/// comparison standing.
///
/// This is the runtime half of that gate; the compile-time half is the
/// `compile_fail` pair on `ArtifactResolveRequest::issuer`, which proves the
/// marker cannot be set from outside the crate.
#[test]
fn build_artifact_response_refuses_a_request_the_role_layer_did_not_validate() {
    let idp = make_artifact_idp().expect("idp builds");

    // Well-formed and correctly addressed: the *only* thing wrong with it is
    // that it never passed through `IdentityProvider::parse_artifact_resolve`.
    // If the gate keyed off anything else, this would still be accepted.
    let envelope = format!(
        r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
             <soap:Body>
               <samlp:ArtifactResolve xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                      ID="_unvalidated" Version="2.0"
                                      IssueInstant="2024-01-01T00:00:00Z"
                                      Destination="{IDP_ARS_URL}">
                 <saml:Issuer>{SP_ENTITY_ID}</saml:Issuer>
                 <samlp:Artifact>AAQAA-artifact</samlp:Artifact>
               </samlp:ArtifactResolve>
             </soap:Body>
           </soap:Envelope>"#
    );

    let unvalidated = saml::binding::artifact::parse_artifact_resolve(envelope.as_bytes())
        .expect("the low-level parser accepts well-formed XML without any verification");
    assert!(
        !unvalidated.role_validated(),
        "the low-level parser must not vouch for a request"
    );
    assert_eq!(unvalidated.issuer(), SP_ENTITY_ID);

    let err = idp
        .build_artifact_response(&unvalidated, SP_ENTITY_ID, "<samlp:Response/>")
        .expect_err("an unvalidated request must not yield an ArtifactResponse");
    assert!(
        matches!(
            err,
            saml::error::Error::SignatureVerification {
                reason: "ArtifactResolve was not validated by IdentityProvider::parse_artifact_resolve"
            }
        ),
        "expected the provenance gate to fire, got {err:?}"
    );
}
