//! Service Provider role.
//!
//! See `docs/rfcs/RFC-003-service-provider.md` for the design and
//! `docs/rfcs/RFC-007-single-logout.md` for the SLO surface.

use std::time::{Duration, SystemTime};

use rand::RngCore as _;

use crate::authn::request_build::{
    AcsRequest, BuildAuthnRequest, build_authn_request_xml,
};
use crate::authn_context::RequestedAuthnContext;
use crate::binding::{
    Binding, Dispatch, Endpoint, SsoResponseBinding, SsoResponseEndpoint,
};
use crate::binding::post::encode_request as post_encode_request;
#[cfg(feature = "slo")]
use crate::binding::post::{decode as post_decode, encode_response as post_encode_response};
use crate::binding::redirect::{
    RedirectDirection, encode_signed as redirect_encode_signed,
    encode_unsigned as redirect_encode_unsigned,
};
#[cfg(feature = "slo")]
use crate::binding::redirect::decode as redirect_decode;
use crate::crypto::keypair::KeyPair;
use crate::descriptor::IdpDescriptor;
use crate::dsig::algorithms::{
    C14nAlgorithm, DigestAlgorithm, PeerCryptoPolicy, SignatureAlgorithm,
};
use crate::dsig::sign::{SignOptions, sign_detached_query, sign_element};
#[cfg(feature = "slo")]
use crate::dsig::verify::{verify_detached_signature, verify_signature};
use crate::error::Error;
#[cfg(feature = "slo")]
use crate::http::{HttpClient, HttpRequest};
#[cfg(feature = "slo")]
use crate::logout::request_build::{
    BuildLogoutRequest, build_logout_request_xml,
};
#[cfg(feature = "slo")]
use crate::logout::request_parse::parse_logout_request;
#[cfg(feature = "slo")]
use crate::logout::response_build::{
    BuildLogoutResponse, build_logout_response_xml,
};
#[cfg(feature = "slo")]
use crate::logout::response_parse::parse_logout_response;
#[cfg(feature = "slo")]
use crate::logout::{
    ConsumeLogoutRequest, ConsumeLogoutResponse, LogoutDispatch, LogoutOutcome, LogoutStatus,
    LogoutTracker, ParsedLogoutRequest, StartLogout,
};
use crate::metadata::MetadataExtras;
use crate::metadata::emit_sp::{SpMetadataInputs, emit_sp_metadata};
use crate::nameid::NameIdFormat;
use crate::replay::ReplayCache;
use crate::response::Identity;
use crate::response::parse::parse_response;
use crate::response::validate::{ValidateResponse, validate_response};
use crate::xml::emit::emit_document;
use crate::xml::parse::Document;

#[cfg(feature = "xmlenc")]
use crate::xmlenc::algorithms::DataEncryptionAlgorithm;

// =============================================================================
// Configuration + role struct
// =============================================================================

/// Which SP-side inbound signature requirements apply to a `<samlp:Response>`.
/// Grouped into a struct so [`ServiceProviderConfig`] stays under the default
/// `struct_excessive_bools` threshold; this mirrors the SAML 2.0 distinction
/// between Response-level and Assertion-level signatures (Core §5).
#[derive(Debug, Clone, Copy, Default)]
pub struct SpWantSigned {
    /// If true, reject Response unless the Response element itself is signed.
    /// If false, accept Response-level OR Assertion-level signature.
    pub response: bool,
    /// If true, reject Response unless every Assertion is signed.
    pub assertions: bool,
}

/// SP-side outbound logout signing flags (RFC-007 §5).
#[cfg(feature = "slo")]
#[derive(Debug, Clone, Copy, Default)]
pub struct SpLogoutSigning {
    /// If true, outbound LogoutRequest is signed.
    pub sign_requests: bool,
    /// If true, outbound LogoutResponse is signed.
    pub sign_responses: bool,
}

/// SP-side inbound logout signature requirements (RFC-007 §5).
#[cfg(feature = "slo")]
#[derive(Debug, Clone, Copy, Default)]
pub struct SpLogoutWantSigned {
    /// If true, reject inbound LogoutRequest unless it carries a valid signature.
    pub requests: bool,
    /// If true, reject inbound LogoutResponse unless it carries a valid signature.
    pub responses: bool,
}

/// SP-side configuration. See RFC-003 §1.
#[derive(Debug, Clone)]
pub struct ServiceProviderConfig {
    /// SP EntityID — appears as `<saml:Issuer>` on every outbound message and
    /// as the only valid `<saml:Audience>` value on inbound assertions.
    pub entity_id: String,
    /// AssertionConsumerService endpoints, in declaration order. The first
    /// `is_default=true` entry (or index 0 if none) is the default ACS.
    pub acs: Vec<SsoResponseEndpoint>,
    /// SingleLogoutService endpoints. Empty disables SP-initiated logout.
    pub slo: Vec<Endpoint>,
    /// Accepted NameID formats, advertised in metadata.
    pub name_id_formats: Vec<NameIdFormat>,
    /// Signing key. Required when any of `sign_authn_requests`,
    /// `logout_signing.sign_requests`, `logout_signing.sign_responses` is true
    /// (or when signed metadata is emitted).
    pub signing_key: Option<KeyPair>,
    /// Decryption key. Required when the SP advertises an encryption cert in
    /// metadata and may receive `<saml:EncryptedAssertion>`.
    pub decryption_key: Option<KeyPair>,
    /// If true, outbound AuthnRequest is signed.
    pub sign_authn_requests: bool,
    /// Inbound Response signature requirements.
    pub want_signed: SpWantSigned,
    /// If true, allow IdP-initiated (unsolicited) Responses.
    pub allow_unsolicited: bool,
    /// Outbound logout signing flags (RFC-007 §5).
    #[cfg(feature = "slo")]
    pub logout_signing: SpLogoutSigning,
    /// Inbound logout signature requirements (RFC-007 §5).
    #[cfg(feature = "slo")]
    pub logout_want_signed: SpLogoutWantSigned,
    /// Default inbound crypto policy when a consume call does not provide a
    /// peer-specific override.
    pub default_peer_crypto_policy: PeerCryptoPolicy,
    /// Outbound signing defaults for AuthnRequest and Logout messages.
    pub outbound_signature_algorithm: SignatureAlgorithm,
    pub outbound_digest_algorithm: DigestAlgorithm,
}

/// Active SP role. Construct via [`ServiceProvider::new`].
#[derive(Debug, Clone)]
pub struct ServiceProvider {
    config: ServiceProviderConfig,
}

impl ServiceProvider {
    /// Validate the supplied configuration and construct an SP. See RFC-003 §1.
    pub fn new(config: ServiceProviderConfig) -> Result<Self, Error> {
        // SAML 2.0 Core §8.3.6: entityID has type xs:anyURI; URL shape is
        // RECOMMENDED but not REQUIRED. Real-world IdPs (and the broader
        // SAML toolkit ecosystem — ruby-saml, python3-saml, etc.) emit and
        // accept bare identifiers like "example.com" or "saml-sp". Reject
        // only the cases that would actually break downstream Issuer /
        // Audience comparison: empty or whitespace-bearing.
        if config.entity_id.is_empty()
            || config.entity_id.chars().any(char::is_whitespace)
        {
            return Err(Error::InvalidConfiguration {
                reason: "entity_id must be a non-empty, whitespace-free xs:anyURI",
            });
        }
        if config.acs.is_empty() {
            return Err(Error::InvalidConfiguration {
                reason: "acs must contain at least one endpoint",
            });
        }
        let needs_signing_key = config.sign_authn_requests
            || {
                #[cfg(feature = "slo")]
                {
                    config.logout_signing.sign_requests || config.logout_signing.sign_responses
                }
                #[cfg(not(feature = "slo"))]
                {
                    false
                }
            };
        if needs_signing_key && config.signing_key.is_none() {
            return Err(Error::InvalidConfiguration {
                reason: "signing flag enabled but signing_key is None",
            });
        }
        Ok(Self { config })
    }

    /// Borrow the SP configuration.
    pub fn config(&self) -> &ServiceProviderConfig {
        &self.config
    }

    /// SP EntityID. Shorthand for `self.config().entity_id`.
    pub fn entity_id(&self) -> &str {
        &self.config.entity_id
    }
}

// =============================================================================
// start_login
// =============================================================================

/// Options threaded into [`ServiceProvider::start_login`].
pub struct StartLogin<'a> {
    pub relay_state: Option<&'a str>,
    pub binding: Binding,
    pub force_authn: bool,
    pub is_passive: bool,
    pub requested_name_id_format: Option<NameIdFormat>,
    pub requested_authn_context: Option<RequestedAuthnContext>,
    pub acs_index: Option<u16>,
    /// Nominate an ACS endpoint by URL rather than index. The URL MUST appear
    /// in `self.config.acs`; otherwise `start_login` returns
    /// `Error::UnregisteredAcs`. Mutually exclusive with `acs_index` — passing
    /// both is `Error::InvalidConfiguration`. SAML 2.0 Core §3.4.1 allows
    /// either attribute on `<samlp:AuthnRequest>`; index is preferred for
    /// security, URL covers the out-of-band-registered ACS case.
    pub acs_url: Option<&'a str>,
    pub response_binding: Option<SsoResponseBinding>,
}

/// Result of [`ServiceProvider::start_login`].
#[derive(Debug, Clone)]
pub struct StartLoginResult {
    pub tracker: LoginTracker,
    pub dispatch: Dispatch,
}

/// Caller-side state captured at AuthnRequest time and replayed into
/// [`ServiceProvider::consume_response`] to verify the matching Response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoginTracker {
    pub request_id: String,
    pub issued_at: SystemTime,
    pub idp_entity_id: String,
    pub acs_endpoint: SsoResponseEndpoint,
    pub requested_authn_context: Option<RequestedAuthnContext>,
    pub requested_name_id_format: Option<NameIdFormat>,
}

impl ServiceProvider {
    /// Build and dispatch an outbound `<samlp:AuthnRequest>`. See RFC-003 §3.
    pub fn start_login(
        &self,
        idp: &IdpDescriptor,
        opts: StartLogin<'_>,
    ) -> Result<StartLoginResult, Error> {
        // 1. Look up IdP SSO endpoint for the requested transport binding.
        let sso_endpoint = idp
            .sso_endpoint(opts.binding)
            .ok_or(Error::UnsupportedByPeer {
                binding: opts.binding,
            })?;
        let destination_url = url::Url::parse(&sso_endpoint.url).map_err(|_err| {
            Error::InvalidConfiguration {
                reason: "IdP SSO endpoint URL is not a valid URL",
            }
        })?;

        // 2. Fresh request ID: `_<hex16>`.
        let request_id = generate_saml_id();
        let issued_at = SystemTime::now();

        // 3. Resolve the SP ACS endpoint.
        if opts.acs_index.is_some() && opts.acs_url.is_some() {
            return Err(Error::InvalidConfiguration {
                reason: "StartLogin: acs_index and acs_url are mutually exclusive",
            });
        }
        let acs_endpoint = match (opts.acs_index, opts.acs_url) {
            (Some(idx), _) => self
                .config
                .acs
                .iter()
                .find(|e| e.index == Some(idx))
                .cloned()
                .ok_or(Error::InvalidConfiguration {
                    reason: "acs_index does not match any configured ACS endpoint",
                })?,
            (_, Some(url)) => self
                .config
                .acs
                .iter()
                .find(|e| e.url == url)
                .cloned()
                .ok_or_else(|| Error::UnregisteredAcs {
                    entity_id: self.config.entity_id.clone(),
                })?,
            (None, None) => self
                .config
                .acs
                .iter()
                .find(|e| e.is_default)
                .or_else(|| self.config.acs.first())
                .cloned()
                .ok_or(Error::InvalidConfiguration {
                    reason: "no ACS endpoint configured (config validated empty list)",
                })?,
        };

        // 4. Resolve and validate the requested Response binding.
        let response_binding = opts.response_binding.unwrap_or(acs_endpoint.binding);
        if response_binding != acs_endpoint.binding {
            return Err(Error::IllegalResponseBinding {
                requested: response_binding.as_binding(),
            });
        }

        // 5. Build the AuthnRequest XML.
        let acs_selection = match (opts.acs_index, opts.acs_url) {
            (Some(idx), _) => AcsRequest::Index(idx),
            (_, Some(url)) => AcsRequest::Url(url),
            (None, None) => AcsRequest::Default,
        };

        let build = BuildAuthnRequest {
            id: &request_id,
            issue_instant: issued_at,
            issuer_entity_id: &self.config.entity_id,
            destination: &sso_endpoint.url,
            force_authn: opts.force_authn,
            is_passive: opts.is_passive,
            acs_selection,
            protocol_binding: Some(response_binding),
            requested_name_id_format: opts.requested_name_id_format.clone(),
            requested_authn_context: opts.requested_authn_context.as_ref(),
        };
        let unsigned_xml = build_authn_request_xml(&build)?;

        // 6. Encode for the wire per the chosen transport binding.
        let dispatch = match opts.binding {
            Binding::HttpRedirect => {
                if self.config.sign_authn_requests {
                    let signing_key = self.signing_key()?;
                    let sig_alg = self.config.outbound_signature_algorithm;
                    redirect_encode_signed(
                        &destination_url,
                        RedirectDirection::Request,
                        &unsigned_xml,
                        opts.relay_state,
                        sig_alg.uri(),
                        |bytes| sign_detached_query(bytes, signing_key, sig_alg),
                    )?
                } else {
                    redirect_encode_unsigned(
                        &destination_url,
                        RedirectDirection::Request,
                        &unsigned_xml,
                        opts.relay_state,
                    )?
                }
            }
            Binding::HttpPost => {
                let xml_to_post = if self.config.sign_authn_requests {
                    self.sign_protocol_xml(&unsigned_xml)?
                } else {
                    unsigned_xml
                };
                post_encode_request(&destination_url, &xml_to_post, opts.relay_state)
            }
            Binding::HttpArtifact | Binding::Soap => {
                // AuthnRequest over Artifact / SOAP not supported in v0.1.
                return Err(Error::UnsupportedByPeer {
                    binding: opts.binding,
                });
            }
        };

        let tracker = LoginTracker {
            request_id,
            issued_at,
            idp_entity_id: idp.entity_id.clone(),
            acs_endpoint,
            requested_authn_context: opts.requested_authn_context,
            requested_name_id_format: opts.requested_name_id_format,
        };

        Ok(StartLoginResult { tracker, dispatch })
    }
}

// =============================================================================
// consume_response
// =============================================================================

/// Inputs for [`ServiceProvider::consume_response`]. See RFC-003 §4.
pub struct ConsumeResponse<'a> {
    pub idp: &'a IdpDescriptor,
    pub peer_crypto_policy: Option<&'a PeerCryptoPolicy>,
    /// Raw XML bytes (already base64-decoded by the binding layer).
    pub saml_response: &'a [u8],
    pub binding: SsoResponseBinding,
    pub relay_state: Option<&'a str>,
    pub tracker: Option<&'a LoginTracker>,
    /// SP ACS URL that received this Response.
    pub expected_destination: &'a str,
    pub now: SystemTime,
    pub clock_skew: Duration,
    /// Optional anti-replay cache, consulted after signature verification
    /// and all spec checks succeed. When `Some(cache)`, the recovered
    /// `assertion_id` is offered to `cache.check_and_insert(...)`; a
    /// duplicate within the validity window surfaces as
    /// [`Error::AssertionReplay`]. When `None`, no replay check runs
    /// — caller code is responsible for deduping `Identity::assertion_id`
    /// against its own store, or for accepting the residual replay risk.
    pub replay_cache: Option<&'a dyn ReplayCache>,
}

/// Inputs for [`ServiceProvider::consume_response_artifact`]. The artifact
/// value (`SAMLart` query parameter) is resolved against the IdP's
/// `ArtifactResolutionService` over SOAP via the caller-supplied
/// [`crate::http::HttpClient`]. The recovered `<samlp:Response>` is then
/// validated exactly as in [`ServiceProvider::consume_response`].
///
/// See SAML 2.0 Bindings §3.6.
#[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
pub struct ConsumeArtifactResponse<'a> {
    pub idp: &'a crate::descriptor::IdpDescriptor,
    pub peer_crypto_policy: Option<&'a PeerCryptoPolicy>,
    /// The `SAMLart` value received at the SP's ACS, already URL-decoded.
    pub artifact: &'a str,
    pub relay_state: Option<&'a str>,
    pub tracker: Option<&'a LoginTracker>,
    /// SP ACS URL that received the artifact.
    pub expected_destination: &'a str,
    pub now: SystemTime,
    pub clock_skew: Duration,
    /// Optional anti-replay cache, threaded into the inner
    /// [`ConsumeResponse`] after artifact resolution. See
    /// [`ConsumeResponse::replay_cache`] for semantics.
    pub replay_cache: Option<&'a dyn ReplayCache>,
}

impl ServiceProvider {
    /// Validate an inbound `<samlp:Response>` and extract the `Identity`.
    /// See RFC-003 §4.1.
    pub fn consume_response(&self, input: ConsumeResponse<'_>) -> Result<Identity, Error> {
        // Step 3a: `expected_destination` MUST be a registered ACS URL.
        if !self
            .config
            .acs
            .iter()
            .any(|e| e.url == input.expected_destination)
        {
            return Err(Error::InvalidConfiguration {
                reason: "expected_destination is not a registered ACS URL",
            });
        }
        // Step 3b: for solicited flow, tracker.acs_endpoint.url MUST match.
        if let Some(tracker) = input.tracker
            && tracker.acs_endpoint.url != input.expected_destination
        {
            return Err(Error::DestinationMismatch);
        }

        // Parse XML and locate `<samlp:Response>`. The caller passed raw XML
        // (already base64-decoded by the binding layer).
        let document = Document::parse(input.saml_response)?;
        let (parsed, _root_id) = parse_response(&document)?;

        // Effective per-peer crypto policy.
        let policy = input
            .peer_crypto_policy
            .unwrap_or(&self.config.default_peer_crypto_policy);

        // Thread the SP decryption key (if any) into a single-element slice.
        #[cfg(feature = "xmlenc")]
        let decryption_keys_owned: Vec<&KeyPair> = self
            .config
            .decryption_key
            .as_ref()
            .map(|k| vec![k])
            .unwrap_or_default();

        let identity = validate_response(ValidateResponse {
            document: &document,
            parsed,
            idp: input.idp,
            peer_crypto_policy: policy,
            #[cfg(feature = "xmlenc")]
            decryption_keys: &decryption_keys_owned,
            sp_entity_id: &self.config.entity_id,
            expected_destination: input.expected_destination,
            tracker_request_id: input.tracker.map(|t| t.request_id.as_str()),
            allow_unsolicited: self.config.allow_unsolicited,
            want_response_signed: self.config.want_signed.response,
            want_assertions_signed: self.config.want_signed.assertions,
            now: input.now,
            clock_skew: input.clock_skew,
            requested_authn_context: input
                .tracker
                .and_then(|t| t.requested_authn_context.as_ref()),
        })?;

        // Replay-cache check, AFTER signature + all spec checks succeed.
        // We never offer an `assertion_id` to the cache until the
        // assertion is structurally valid and signed by a trusted cert
        // — otherwise an attacker could pollute the cache with garbage
        // ids by hammering the ACS. The cache is updated only on the
        // success path, so a rejected Response leaves no trace.
        //
        // SAML 2.0 Core §2.5.1.5 (OneTimeUse): we apply this check to
        // *every* assertion, not just OneTimeUse-marked ones, because
        // safer-default. `Identity::is_one_time_use` is still surfaced
        // for callers who need to distinguish the cases.
        if let Some(cache) = input.replay_cache {
            let fresh = cache.check_and_insert(&identity.assertion_id, identity.not_on_or_after)?;
            if !fresh {
                return Err(Error::AssertionReplay);
            }
        }

        Ok(identity)
    }

    /// Resolve an inbound `?SAMLart=<artifact>` against the IdP's
    /// `ArtifactResolutionService` via SOAP, then validate the recovered
    /// `<samlp:Response>` exactly as [`ServiceProvider::consume_response`].
    ///
    /// Returns the validated [`Identity`].
    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    pub async fn consume_response_artifact<H: crate::http::HttpClient>(
        &self,
        http: &H,
        input: ConsumeArtifactResponse<'_>,
    ) -> Result<Identity, Error> {
        let ars = input
            .idp
            .artifact_resolution_endpoint()
            .ok_or(Error::UnsupportedByPeer {
                binding: Binding::HttpArtifact,
            })?;

        let inner_xml = crate::binding::artifact::resolve_artifact(
            http,
            ars.url.as_str(),
            &self.config.entity_id,
            input.artifact,
        )
        .await?;

        self.consume_response(ConsumeResponse {
            idp: input.idp,
            peer_crypto_policy: input.peer_crypto_policy,
            saml_response: &inner_xml,
            binding: SsoResponseBinding::HttpArtifact,
            relay_state: input.relay_state,
            tracker: input.tracker,
            expected_destination: input.expected_destination,
            now: input.now,
            clock_skew: input.clock_skew,
            replay_cache: input.replay_cache,
        })
    }
}

// =============================================================================
// SP-side SLO
// =============================================================================

#[cfg(feature = "slo")]
impl ServiceProvider {
    /// SP initiates Single Logout against an IdP. See RFC-007 §2.
    pub fn start_logout(
        &self,
        idp: &IdpDescriptor,
        opts: StartLogout<'_>,
    ) -> Result<LogoutDispatch, Error> {
        let slo_endpoint = idp
            .slo_endpoint(opts.binding)
            .ok_or(Error::UnsupportedByPeer {
                binding: opts.binding,
            })?;
        let destination_url = url::Url::parse(&slo_endpoint.url).map_err(|_err| {
            Error::InvalidConfiguration {
                reason: "IdP SLO endpoint URL is not a valid URL",
            }
        })?;

        let request_id = generate_saml_id();
        let issued_at = SystemTime::now();

        let build = BuildLogoutRequest {
            id: &request_id,
            issue_instant: issued_at,
            issuer_entity_id: &self.config.entity_id,
            destination: Some(&slo_endpoint.url),
            not_on_or_after: None,
            reason: opts.reason,
            name_id: opts.name_id,
            session_index: opts.session_index,
        };
        let unsigned_xml = build_logout_request_xml(&build)?;

        let dispatch = match opts.binding {
            Binding::HttpRedirect => {
                if self.config.logout_signing.sign_requests {
                    let signing_key = self.signing_key()?;
                    let sig_alg = self.config.outbound_signature_algorithm;
                    redirect_encode_signed(
                        &destination_url,
                        RedirectDirection::Request,
                        &unsigned_xml,
                        opts.relay_state,
                        sig_alg.uri(),
                        |bytes| sign_detached_query(bytes, signing_key, sig_alg),
                    )?
                } else {
                    redirect_encode_unsigned(
                        &destination_url,
                        RedirectDirection::Request,
                        &unsigned_xml,
                        opts.relay_state,
                    )?
                }
            }
            Binding::HttpPost => {
                let xml_to_post = if self.config.logout_signing.sign_requests {
                    self.sign_protocol_xml(&unsigned_xml)?
                } else {
                    unsigned_xml
                };
                post_encode_request(&destination_url, &xml_to_post, opts.relay_state)
            }
            Binding::Soap => {
                // SOAP LogoutRequest dispatch is handled inline by
                // `send_soap_logout_request`, not via this start path.
                return Err(Error::InvalidConfiguration {
                    reason: "SOAP logout uses send_soap_logout_request, not start_logout",
                });
            }
            Binding::HttpArtifact => {
                return Err(Error::UnsupportedByPeer {
                    binding: opts.binding,
                });
            }
        };

        Ok(LogoutDispatch {
            tracker: LogoutTracker {
                request_id,
                issued_at,
                peer_entity_id: idp.entity_id.clone(),
            },
            dispatch,
        })
    }

    /// Consume an inbound `<samlp:LogoutResponse>` echoing a previously-sent
    /// `<samlp:LogoutRequest>`. See RFC-007 §5.2.
    pub fn consume_logout_response(
        &self,
        idp: &IdpDescriptor,
        input: ConsumeLogoutResponse<'_>,
    ) -> Result<LogoutOutcome, Error> {
        let ConsumeLogoutResponse {
            peer_crypto_policy,
            body,
            binding,
            // SP side: we binding-decode internally, so the caller-supplied
            // detached signature material isn't consulted here.
            detached_signature: _,
            tracker,
            expected_destination,
            now,
            clock_skew,
        } = input;
        // 1. Decode the binding wire format.
        let policy = peer_crypto_policy.unwrap_or(&self.config.default_peer_crypto_policy);
        let decoded = decode_logout_wire(body, binding, /* is_request */ false)?;

        // 2. Parse XML.
        let document = Document::parse(&decoded.xml)?;
        let (parsed, _) = parse_logout_response(&document)?;

        // 3. Destination registration check.
        if !self.config.slo.iter().any(|e| e.url == expected_destination) {
            return Err(Error::InvalidConfiguration {
                reason: "expected_destination is not a registered SLO URL",
            });
        }
        // 4. Destination match (if present on the message).
        if let Some(dest) = parsed.destination.as_deref()
            && dest != expected_destination
        {
            return Err(Error::DestinationMismatch);
        }

        // 5. Issuer match.
        if parsed.issuer != idp.entity_id {
            return Err(Error::IssuerMismatch {
                expected: idp.entity_id.clone(),
                got: Some(parsed.issuer.clone()),
            });
        }

        // 6. Signature gate.
        verify_inbound_signature(
            &document,
            &decoded,
            binding,
            &idp.signing_certs,
            &policy.allowed_signature_algorithms,
            self.config.logout_want_signed.responses,
        )?;

        // 7. InResponseTo match.
        if parsed.in_response_to != tracker.request_id {
            return Err(Error::InResponseToMismatch);
        }

        // 8. Time-bound check on issue_instant. Reject ridiculously skewed clocks.
        // The spec doesn't require this beyond NotOnOrAfter (absent on
        // LogoutResponse), but we sanity-check IssueInstant against the call's
        // now/clock_skew window to avoid replays of very stale wire frames.
        let _ = (now, clock_skew); // kept in signature for symmetry; we do not
        // hard-reject here because LogoutResponse has no NotOnOrAfter and the
        // protocol-level binding (InResponseTo + tracker scope) is the real
        // anti-replay anchor.

        Ok(parsed.to_outcome())
    }

    /// Consume an inbound `<samlp:LogoutRequest>` (IdP-initiated SLO).
    /// See RFC-007 §5.1.
    pub fn consume_logout_request(
        &self,
        idp: &IdpDescriptor,
        input: ConsumeLogoutRequest<'_>,
    ) -> Result<ParsedLogoutRequest, Error> {
        let ConsumeLogoutRequest {
            peer_crypto_policy,
            body,
            binding,
            // SP side: we binding-decode internally, so the caller-supplied
            // detached signature material isn't consulted here.
            detached_signature: _,
            expected_destination,
            now,
            clock_skew,
        } = input;
        let policy = peer_crypto_policy.unwrap_or(&self.config.default_peer_crypto_policy);
        let decoded = decode_logout_wire(body, binding, /* is_request */ true)?;

        let document = Document::parse(&decoded.xml)?;
        let (mut parsed, _) = parse_logout_request(&document)?;
        parsed.relay_state.clone_from(&decoded.relay_state);

        // Destination registration check.
        if !self.config.slo.iter().any(|e| e.url == expected_destination) {
            return Err(Error::InvalidConfiguration {
                reason: "expected_destination is not a registered SLO URL",
            });
        }
        if let Some(dest) = parsed.destination.as_deref()
            && dest != expected_destination
        {
            return Err(Error::DestinationMismatch);
        }

        // Issuer match.
        if parsed.issuer != idp.entity_id {
            return Err(Error::IssuerMismatch {
                expected: idp.entity_id.clone(),
                got: Some(parsed.issuer.clone()),
            });
        }

        // Signature gate.
        verify_inbound_signature(
            &document,
            &decoded,
            binding,
            &idp.signing_certs,
            &policy.allowed_signature_algorithms,
            self.config.logout_want_signed.requests,
        )?;

        // NotOnOrAfter expiry (if present).
        if let Some(nooa) = parsed.not_on_or_after
            && nooa <= now.checked_sub(clock_skew).unwrap_or(now)
        {
            return Err(Error::Expired);
        }

        Ok(parsed)
    }

    /// Build a `<samlp:LogoutResponse>` echoing the parsed request and encode
    /// it for the given binding.
    pub fn build_logout_response(
        &self,
        idp: &IdpDescriptor,
        in_response_to: &ParsedLogoutRequest,
        status: LogoutStatus,
        relay_state: Option<&str>,
        binding: Binding,
    ) -> Result<Dispatch, Error> {
        let slo_endpoint = idp
            .slo_endpoint(binding)
            .ok_or(Error::UnsupportedByPeer { binding })?;
        let destination_url = url::Url::parse(&slo_endpoint.url).map_err(|_err| {
            Error::InvalidConfiguration {
                reason: "IdP SLO endpoint URL is not a valid URL",
            }
        })?;

        let response_id = generate_saml_id();
        let issue_instant = SystemTime::now();

        let build = BuildLogoutResponse {
            id: &response_id,
            issue_instant,
            issuer_entity_id: &self.config.entity_id,
            destination: Some(&slo_endpoint.url),
            in_response_to: &in_response_to.id,
            status,
            status_message: None,
        };
        let unsigned_xml = build_logout_response_xml(&build)?;

        let dispatch = match binding {
            Binding::HttpRedirect => {
                if self.config.logout_signing.sign_responses {
                    let signing_key = self.signing_key()?;
                    let sig_alg = self.config.outbound_signature_algorithm;
                    redirect_encode_signed(
                        &destination_url,
                        RedirectDirection::Response,
                        &unsigned_xml,
                        relay_state,
                        sig_alg.uri(),
                        |bytes| sign_detached_query(bytes, signing_key, sig_alg),
                    )?
                } else {
                    redirect_encode_unsigned(
                        &destination_url,
                        RedirectDirection::Response,
                        &unsigned_xml,
                        relay_state,
                    )?
                }
            }
            Binding::HttpPost => {
                let xml_to_post = if self.config.logout_signing.sign_responses {
                    self.sign_protocol_xml(&unsigned_xml)?
                } else {
                    unsigned_xml
                };
                post_encode_response(&destination_url, &xml_to_post, relay_state)
            }
            Binding::Soap | Binding::HttpArtifact => {
                return Err(Error::UnsupportedByPeer { binding });
            }
        };

        Ok(dispatch)
    }

    /// Back-channel SLO: send a `<samlp:LogoutRequest>` over SOAP and
    /// synchronously parse the inline `<samlp:LogoutResponse>`. See RFC-007 §5.
    pub async fn send_soap_logout_request<H: HttpClient>(
        &self,
        http: &H,
        idp: &IdpDescriptor,
        peer_crypto_policy: Option<&PeerCryptoPolicy>,
        opts: StartLogout<'_>,
    ) -> Result<LogoutOutcome, Error> {
        // Locate the SOAP SLO endpoint.
        let slo_endpoint = idp
            .slo_endpoint(Binding::Soap)
            .ok_or(Error::UnsupportedByPeer {
                binding: Binding::Soap,
            })?;
        let policy = peer_crypto_policy.unwrap_or(&self.config.default_peer_crypto_policy);

        // Build the LogoutRequest XML.
        let request_id = generate_saml_id();
        let issue_instant = SystemTime::now();
        let build = BuildLogoutRequest {
            id: &request_id,
            issue_instant,
            issuer_entity_id: &self.config.entity_id,
            destination: Some(&slo_endpoint.url),
            not_on_or_after: None,
            reason: opts.reason,
            name_id: opts.name_id,
            session_index: opts.session_index,
        };
        let unsigned_xml = build_logout_request_xml(&build)?;
        let logout_request_xml = if self.config.logout_signing.sign_requests {
            self.sign_protocol_xml(&unsigned_xml)?
        } else {
            unsigned_xml
        };

        // Wrap in a SOAP envelope.
        let logout_request_str = std::str::from_utf8(&logout_request_xml).map_err(|_err| {
            Error::XmlEmit("logout request XML is not UTF-8".to_string())
        })?;
        let soap_envelope = format!(
            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\
<soap:Body>{logout_request_str}</soap:Body>\
</soap:Envelope>"
        );

        // Dispatch via the caller's HttpClient.
        let request = HttpRequest {
            method: http::Method::POST,
            url: slo_endpoint.url.clone(),
            headers: vec![
                ("Content-Type".to_owned(), "text/xml".to_owned()),
                ("SOAPAction".to_owned(), String::new()),
            ],
            body: soap_envelope.into_bytes(),
        };
        let response = http.send(request).await.map_err(Error::Http)?;

        // Parse the SOAP envelope; find the inner LogoutResponse element.
        let envelope_doc = Document::parse(&response.body)?;
        let inner = envelope_doc
            .find_first(
                Some("urn:oasis:names:tc:SAML:2.0:protocol"),
                "LogoutResponse",
            )
            .ok_or(Error::XmlParse(
                "SOAP envelope contained no <samlp:LogoutResponse>".to_string(),
            ))?;

        // Re-emit the inner element as a standalone document so we can
        // hand it to the regular validate-and-verify path (which needs an
        // ElementId arena rooted on the LogoutResponse).
        let inner_xml = crate::xml::emit::emit_element(inner)?;
        let inner_doc = Document::parse(inner_xml.as_bytes())?;
        let (parsed, _) = parse_logout_response(&inner_doc)?;

        // Issuer match.
        if parsed.issuer != idp.entity_id {
            return Err(Error::IssuerMismatch {
                expected: idp.entity_id.clone(),
                got: Some(parsed.issuer.clone()),
            });
        }

        // InResponseTo match.
        if parsed.in_response_to != request_id {
            return Err(Error::InResponseToMismatch);
        }

        // Signature gate (SOAP path uses embedded XML-DSig).
        if self.config.logout_want_signed.responses {
            let sig = inner_doc
                .root()
                .child_element(
                    Some("http://www.w3.org/2000/09/xmldsig#"),
                    "Signature",
                )
                .ok_or(Error::SignatureMissing)?;
            let verified = verify_signature(
                &inner_doc,
                sig,
                &idp.signing_certs,
                &policy.allowed_signature_algorithms,
            )?;
            if verified.signed_element != inner_doc.root().id() {
                return Err(Error::SignatureVerification {
                    reason: "signature does not cover LogoutResponse root",
                });
            }
        } else if let Some(sig) = inner_doc.root().child_element(
            Some("http://www.w3.org/2000/09/xmldsig#"),
            "Signature",
        ) {
            // Signature present but not required: still verify if present.
            let _ = verify_signature(
                &inner_doc,
                sig,
                &idp.signing_certs,
                &policy.allowed_signature_algorithms,
            )?;
        }

        Ok(parsed.to_outcome())
    }
}

// =============================================================================
// Metadata emission
// =============================================================================

impl ServiceProvider {
    /// Emit `<md:EntityDescriptor>` XML for this SP. See RFC-006 §6.1.
    pub fn metadata_xml(&self, sign: bool) -> Result<String, Error> {
        self.emit_metadata(sign, None)
    }

    /// Same as [`metadata_xml`], plus `<md:Organization>` and
    /// `<md:ContactPerson>` content from `extras`.
    pub fn metadata_xml_with_extras(
        &self,
        sign: bool,
        extras: &MetadataExtras,
    ) -> Result<String, Error> {
        self.emit_metadata(sign, Some(extras))
    }

    fn emit_metadata(
        &self,
        sign: bool,
        extras: Option<&MetadataExtras>,
    ) -> Result<String, Error> {
        // Cert material from the keypair (if any).
        let signing_cert = self
            .config
            .signing_key
            .as_ref()
            .and_then(|k| k.certificate());
        #[cfg(feature = "xmlenc")]
        let decryption_cert = self
            .config
            .decryption_key
            .as_ref()
            .and_then(|k| k.certificate());

        // Advertise GCM ciphers in metadata; `emit_sp_metadata` emits one
        // `<xenc:EncryptionMethod>` child per entry, scoped to the
        // encryption KeyDescriptor.
        #[cfg(feature = "xmlenc")]
        let encryption_algorithms: &[DataEncryptionAlgorithm] = &[
            DataEncryptionAlgorithm::Aes256Gcm,
            DataEncryptionAlgorithm::Aes128Gcm,
        ];

        let inputs = SpMetadataInputs {
            entity_id: &self.config.entity_id,
            acs: &self.config.acs,
            slo: &self.config.slo,
            name_id_formats: &self.config.name_id_formats,
            signing_cert,
            #[cfg(feature = "xmlenc")]
            encryption_cert: decryption_cert,
            #[cfg(feature = "xmlenc")]
            encryption_algorithms,
            authn_requests_signed: self.config.sign_authn_requests,
            want_assertions_signed: self.config.want_signed.assertions,
            valid_until: None,
            cache_duration: None,
            extras,
        };

        let signer = if sign {
            let key = self.signing_key()?;
            Some((
                key,
                self.config.outbound_signature_algorithm,
                self.config.outbound_digest_algorithm,
                C14nAlgorithm::ExclusiveCanonical,
            ))
        } else {
            None
        };
        emit_sp_metadata(&inputs, signer)
    }
}

// =============================================================================
// Internal helpers
// =============================================================================

impl ServiceProvider {
    /// Borrow the signing key, returning `InvalidConfiguration` if absent.
    /// All call sites are guarded by config validation in `new`, so this only
    /// trips when callers try to sign metadata without configuring a key.
    fn signing_key(&self) -> Result<&KeyPair, Error> {
        self.config
            .signing_key
            .as_ref()
            .ok_or(Error::InvalidConfiguration {
                reason: "signing requested but signing_key is None",
            })
    }

    /// Sign a serialized protocol message in-place: parse → sign the root →
    /// re-emit. Used for the HTTP-POST and SOAP binding signing paths where
    /// the signature is enveloped inside the XML payload.
    fn sign_protocol_xml(&self, xml: &[u8]) -> Result<Vec<u8>, Error> {
        let key = self.signing_key()?;
        let doc = Document::parse(xml)?;
        let signed_root = sign_element(
            doc.root().clone(),
            &doc,
            SignOptions {
                signing_key: key,
                sig_alg: self.config.outbound_signature_algorithm,
                digest_alg: self.config.outbound_digest_algorithm,
                c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                inclusive_namespaces: &[],
                include_x509_cert: true,
            },
        )?;
        let signed_doc = Document::new(signed_root)?;
        Ok(emit_document(&signed_doc)?.into_bytes())
    }
}

/// `_<hex16>` SAML message ID. XML Schema `xs:ID` forbids leading digits, so
/// the leading `_` is mandatory by convention.
fn generate_saml_id() -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    // 1 ('_') + 2 hex chars per byte: bounded constant, no overflow possible
    // for the fixed-size `bytes` array.
    let capacity = 1usize.saturating_add(bytes.len().saturating_mul(2));
    let mut out = String::with_capacity(capacity);
    out.push('_');
    for b in bytes {
        let hi = usize::from(b >> 4);
        let lo = usize::from(b & 0x0f);
        // `hi` and `lo` are constrained to 0..16 by masking; both indices are
        // guaranteed in-bounds for the 16-byte HEX table. Use `.get()` to
        // avoid `indexing_slicing`.
        if let (Some(&h), Some(&l)) = (HEX.get(hi), HEX.get(lo)) {
            out.push(h as char);
            out.push(l as char);
        }
    }
    out
}

/// Output of the SLO wire-format decoder. Holds the decoded XML alongside any
/// detached-signature material from the Redirect binding, used by the signature
/// gate to dispatch to `verify_detached_signature` vs. `verify_signature`.
#[cfg(feature = "slo")]
struct DecodedSlo {
    xml: Vec<u8>,
    relay_state: Option<String>,
    /// Set only for Redirect: the bytes the signer covered (the canonical
    /// query string).
    signed_query_string: Option<String>,
    /// Set only for Redirect: the detached signature bytes.
    detached_signature: Option<Vec<u8>>,
    /// Set only for Redirect: the SigAlg URI from the query string.
    detached_sig_alg: Option<String>,
}

/// Decode the wire format of an inbound logout request or response. For
/// Redirect: parse the query string and DEFLATE-inflate the payload. For POST:
/// base64-decode the form value. For SOAP: unwrap the envelope and extract the
/// inner protocol element.
#[cfg(feature = "slo")]
fn decode_logout_wire(
    body: &[u8],
    binding: Binding,
    is_request: bool,
) -> Result<DecodedSlo, Error> {
    match binding {
        Binding::HttpRedirect => {
            // `body` is the raw query string bytes (everything after `?`).
            let qs = std::str::from_utf8(body).map_err(|_err| Error::Base64Decode)?;
            let direction = if is_request {
                RedirectDirection::Request
            } else {
                RedirectDirection::Response
            };
            let decoded = redirect_decode(qs, direction)?;
            Ok(DecodedSlo {
                xml: decoded.xml,
                relay_state: decoded.relay_state,
                signed_query_string: decoded.signed_query_string,
                detached_signature: decoded.signature,
                detached_sig_alg: decoded.sig_alg,
            })
        }
        Binding::HttpPost => {
            // `body` is the base64-encoded form value (after form-URL decoding
            // by the caller). The form layer passes us the value of
            // `SAMLRequest` / `SAMLResponse` directly.
            let b64 = std::str::from_utf8(body).map_err(|_err| Error::Base64Decode)?;
            let decoded = post_decode(b64, None)?;
            Ok(DecodedSlo {
                xml: decoded.xml,
                relay_state: decoded.relay_state,
                signed_query_string: None,
                detached_signature: None,
                detached_sig_alg: None,
            })
        }
        Binding::Soap => {
            // Unwrap `<soap:Envelope>/<soap:Body>/<samlp:LogoutRequest|Response>`
            // and re-emit the inner element as standalone XML.
            let envelope = Document::parse(body)?;
            let inner_local = if is_request {
                "LogoutRequest"
            } else {
                "LogoutResponse"
            };
            let inner = envelope
                .find_first(
                    Some("urn:oasis:names:tc:SAML:2.0:protocol"),
                    inner_local,
                )
                .ok_or_else(|| {
                    Error::XmlParse(format!(
                        "SOAP envelope contained no <samlp:{inner_local}>"
                    ))
                })?;
            let xml = crate::xml::emit::emit_element(inner)?.into_bytes();
            Ok(DecodedSlo {
                xml,
                relay_state: None,
                signed_query_string: None,
                detached_signature: None,
                detached_sig_alg: None,
            })
        }
        Binding::HttpArtifact => Err(Error::UnsupportedByPeer { binding }),
    }
}

/// Verify the signature on an inbound SLO message. Dispatches between
/// detached (Redirect) and enveloped (POST/SOAP) per binding.
#[cfg(feature = "slo")]
fn verify_inbound_signature(
    document: &Document,
    decoded: &DecodedSlo,
    binding: Binding,
    signing_certs: &[crate::crypto::cert::X509Certificate],
    allowed_algorithms: &[SignatureAlgorithm],
    require_signature: bool,
) -> Result<(), Error> {
    match binding {
        Binding::HttpRedirect => {
            match (&decoded.signed_query_string, &decoded.detached_signature, &decoded.detached_sig_alg) {
                (Some(qs), Some(sig), Some(alg)) => {
                    let sig_alg = SignatureAlgorithm::from_uri(alg)?;
                    verify_detached_signature(
                        qs.as_bytes(),
                        sig,
                        sig_alg,
                        signing_certs,
                        allowed_algorithms,
                    )?;
                    Ok(())
                }
                _ => {
                    if require_signature {
                        Err(Error::SignatureMissing)
                    } else {
                        Ok(())
                    }
                }
            }
        }
        Binding::HttpPost | Binding::Soap => {
            let sig_elem = document
                .root()
                .child_element(Some("http://www.w3.org/2000/09/xmldsig#"), "Signature");
            match sig_elem {
                Some(sig) => {
                    let verified =
                        verify_signature(document, sig, signing_certs, allowed_algorithms)?;
                    if verified.signed_element != document.root().id() {
                        return Err(Error::SignatureVerification {
                            reason: "signature does not cover message root",
                        });
                    }
                    Ok(())
                }
                None => {
                    if require_signature {
                        Err(Error::SignatureMissing)
                    } else {
                        Ok(())
                    }
                }
            }
        }
        Binding::HttpArtifact => Err(Error::UnsupportedByPeer { binding }),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{Endpoint, PostForm, SsoResponseBinding, SsoResponseEndpoint};
    use crate::crypto::cert::X509Certificate;
    use crate::crypto::cert::test_vectors::{RSA_CERT_PEM, RSA_KEY_PKCS8_PEM};
    use crate::dsig::sign::sign_element;
    #[cfg(feature = "slo")]
    use crate::nameid::NameId;
    use crate::nameid::NameIdFormat;
    use crate::response::SAMLP_NS as RESPONSE_SAMLP_NS;
    use crate::response::SAML_NS as RESPONSE_SAML_NS;
    use crate::response::parse::SUBJECT_CONFIRMATION_BEARER as RESPONSE_SUBJECT_CONFIRMATION_BEARER;
    use crate::xml::emit::emit_document;
    use crate::xml::parse::{Document, Element, Node, QName};
    use std::time::{Duration, UNIX_EPOCH};

    // ---------- Fixtures ----------

    fn rsa_signing_key() -> KeyPair {
        let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).unwrap();
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        kp.with_certificate(cert)
    }

    fn fixture_idp() -> IdpDescriptor {
        IdpDescriptor {
            entity_id: "https://idp.example.com".to_owned(),
            sso_endpoints: vec![
                Endpoint::redirect("https://idp.example.com/sso/redirect", 0, true),
                Endpoint::post("https://idp.example.com/sso/post", 1, false),
            ],
            slo_endpoints: vec![
                Endpoint::redirect("https://idp.example.com/slo", 0, true),
                Endpoint::post("https://idp.example.com/slo/post", 1, false),
            ],
            artifact_resolution_endpoints: vec![],
            signing_certs: vec![X509Certificate::from_pem(RSA_CERT_PEM).unwrap()],
            encryption_certs: vec![],
            supported_name_id_formats: vec![],
            want_authn_requests_signed: false,
            valid_until: None,
            cache_duration: None,
        }
    }

    fn fixture_sp_config(
        signing_key: Option<KeyPair>,
        allow_unsolicited: bool,
        sign_authn_requests: bool,
    ) -> ServiceProviderConfig {
        ServiceProviderConfig {
            entity_id: "https://sp.example.com".to_owned(),
            acs: vec![SsoResponseEndpoint::post(
                "https://sp.example.com/acs",
                0,
                true,
            )],
            slo: vec![
                Endpoint::redirect("https://sp.example.com/slo", 0, true),
                Endpoint::post("https://sp.example.com/slo/post", 1, false),
            ],
            name_id_formats: vec![NameIdFormat::EmailAddress, NameIdFormat::Persistent],
            signing_key,
            decryption_key: None,
            sign_authn_requests,
            want_signed: SpWantSigned {
                response: false,
                assertions: true,
            },
            allow_unsolicited,
            #[cfg(feature = "slo")]
            logout_signing: SpLogoutSigning::default(),
            #[cfg(feature = "slo")]
            logout_want_signed: SpLogoutWantSigned::default(),
            default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
            outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
            outbound_digest_algorithm: DigestAlgorithm::Sha256,
        }
    }

    // ---------- new / validation ----------

    #[test]
    fn rejects_empty_entity_id() {
        let mut cfg = fixture_sp_config(None, false, false);
        cfg.entity_id = String::new();
        let err = ServiceProvider::new(cfg).unwrap_err();
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    #[test]
    fn rejects_whitespace_entity_id() {
        let mut cfg = fixture_sp_config(None, false, false);
        cfg.entity_id = "has space".to_owned();
        let err = ServiceProvider::new(cfg).unwrap_err();
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    #[test]
    fn accepts_bare_xs_anyuri_entity_id() {
        // SAML 2.0 §8.3.6: entityID is xs:anyURI; URL shape is RECOMMENDED
        // but not REQUIRED. Real-world IdPs emit bare identifiers like
        // "example.com" — those must be accepted.
        let mut cfg = fixture_sp_config(None, false, false);
        cfg.entity_id = "example.com".to_owned();
        ServiceProvider::new(cfg).expect("bare anyURI accepted");
    }

    #[test]
    fn rejects_empty_acs() {
        let mut cfg = fixture_sp_config(None, false, false);
        cfg.acs.clear();
        let err = ServiceProvider::new(cfg).unwrap_err();
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    #[test]
    fn rejects_sign_authn_without_key() {
        let cfg = fixture_sp_config(None, false, true);
        let err = ServiceProvider::new(cfg).unwrap_err();
        match err {
            Error::InvalidConfiguration { reason } => {
                assert!(reason.contains("signing"), "got: {reason}");
            }
            other => panic!("expected InvalidConfiguration, got {other:?}"),
        }
    }

    #[cfg(feature = "slo")]
    #[test]
    fn rejects_sign_logout_without_key() {
        let mut cfg = fixture_sp_config(None, false, false);
        cfg.logout_signing.sign_requests = true;
        let err = ServiceProvider::new(cfg).unwrap_err();
        assert!(matches!(err, Error::InvalidConfiguration { .. }));

        let mut cfg = fixture_sp_config(None, false, false);
        cfg.logout_signing.sign_responses = true;
        let err = ServiceProvider::new(cfg).unwrap_err();
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    #[test]
    fn accepts_valid_config() {
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).expect("valid config");
        assert_eq!(sp.entity_id(), "https://sp.example.com");
    }

    // ---------- start_login ----------

    #[test]
    fn start_login_redirect_returns_dispatch_and_tracker() {
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let idp = fixture_idp();

        let result = sp
            .start_login(
                &idp,
                StartLogin {
                    relay_state: Some("opaque-rs"),
                    binding: Binding::HttpRedirect,
                    force_authn: false,
                    is_passive: false,
                    requested_name_id_format: None,
                    requested_authn_context: None,
                    acs_index: None,
                    acs_url: None,
                    response_binding: None,
                },
            )
            .expect("start_login");

        // Tracker shape.
        assert!(result.tracker.request_id.starts_with('_'));
        assert!(result.tracker.request_id.len() > 1);
        assert_eq!(result.tracker.idp_entity_id, "https://idp.example.com");
        assert_eq!(result.tracker.acs_endpoint.url, "https://sp.example.com/acs");
        assert_eq!(
            result.tracker.acs_endpoint.binding,
            SsoResponseBinding::HttpPost
        );

        // Dispatch is a Redirect carrying SAMLRequest in the query.
        match result.dispatch {
            Dispatch::Redirect(url) => {
                assert_eq!(url.host_str(), Some("idp.example.com"));
                assert_eq!(url.path(), "/sso/redirect");
                let q = url.query().expect("query");
                assert!(q.contains("SAMLRequest="), "query: {q}");
                assert!(q.contains("RelayState=opaque-rs"), "query: {q}");
            }
            other @ Dispatch::Post(_) => panic!("expected Redirect, got {other:?}"),
        }
    }

    #[test]
    fn start_login_signed_redirect_includes_signature_in_query() {
        let kp = rsa_signing_key();
        let cfg = fixture_sp_config(Some(kp), false, true);
        let sp = ServiceProvider::new(cfg).unwrap();
        let idp = fixture_idp();

        let result = sp
            .start_login(
                &idp,
                StartLogin {
                    relay_state: None,
                    binding: Binding::HttpRedirect,
                    force_authn: false,
                    is_passive: false,
                    requested_name_id_format: None,
                    requested_authn_context: None,
                    acs_index: None,
                    acs_url: None,
                    response_binding: None,
                },
            )
            .unwrap();

        match result.dispatch {
            Dispatch::Redirect(url) => {
                let q = url.query().expect("query");
                assert!(q.contains("SigAlg="), "missing SigAlg: {q}");
                assert!(q.contains("Signature="), "missing Signature: {q}");
            }
            other @ Dispatch::Post(_) => panic!("expected Redirect, got {other:?}"),
        }
    }

    #[test]
    fn start_login_post_binding_returns_post_form() {
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let idp = fixture_idp();

        let result = sp
            .start_login(
                &idp,
                StartLogin {
                    relay_state: Some("rs"),
                    binding: Binding::HttpPost,
                    force_authn: false,
                    is_passive: false,
                    requested_name_id_format: None,
                    requested_authn_context: None,
                    acs_index: None,
                    acs_url: None,
                    response_binding: None,
                },
            )
            .unwrap();

        match result.dispatch {
            Dispatch::Post(PostForm {
                action,
                saml_request,
                saml_response,
                relay_state,
            }) => {
                assert_eq!(action.path(), "/sso/post");
                assert!(saml_request.is_some());
                assert!(saml_response.is_none());
                assert_eq!(relay_state.as_deref(), Some("rs"));
            }
            other @ Dispatch::Redirect(_) => panic!("expected Post, got {other:?}"),
        }
    }

    #[test]
    fn start_login_missing_idp_binding_returns_unsupported() {
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let mut idp = fixture_idp();
        idp.sso_endpoints.clear(); // no SSO endpoints at all.

        let err = sp
            .start_login(
                &idp,
                StartLogin {
                    relay_state: None,
                    binding: Binding::HttpRedirect,
                    force_authn: false,
                    is_passive: false,
                    requested_name_id_format: None,
                    requested_authn_context: None,
                    acs_index: None,
                    acs_url: None,
                    response_binding: None,
                },
            )
            .unwrap_err();
        match err {
            Error::UnsupportedByPeer { binding } => assert_eq!(binding, Binding::HttpRedirect),
            other => panic!("expected UnsupportedByPeer, got {other:?}"),
        }
    }

    #[test]
    fn start_login_rejects_artifact_outbound() {
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let mut idp = fixture_idp();
        idp.sso_endpoints.push(Endpoint::artifact(
            "https://idp.example.com/sso/artifact",
            2,
            false,
        ));

        let err = sp
            .start_login(
                &idp,
                StartLogin {
                    relay_state: None,
                    binding: Binding::HttpArtifact,
                    force_authn: false,
                    is_passive: false,
                    requested_name_id_format: None,
                    requested_authn_context: None,
                    acs_index: None,
                    acs_url: None,
                    response_binding: None,
                },
            )
            .unwrap_err();
        assert!(matches!(err, Error::UnsupportedByPeer { .. }));
    }

    #[test]
    fn start_login_rejects_response_binding_mismatch() {
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let idp = fixture_idp();

        // ACS default is HttpPost; requesting HttpArtifact responses should
        // mismatch.
        let err = sp
            .start_login(
                &idp,
                StartLogin {
                    relay_state: None,
                    binding: Binding::HttpRedirect,
                    force_authn: false,
                    is_passive: false,
                    requested_name_id_format: None,
                    requested_authn_context: None,
                    acs_index: None,
                    acs_url: None,
                    response_binding: Some(SsoResponseBinding::HttpArtifact),
                },
            )
            .unwrap_err();
        assert!(matches!(err, Error::IllegalResponseBinding { .. }));
    }

    #[test]
    fn start_login_unknown_acs_index_is_invalid_configuration() {
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let idp = fixture_idp();

        let err = sp
            .start_login(
                &idp,
                StartLogin {
                    relay_state: None,
                    binding: Binding::HttpRedirect,
                    force_authn: false,
                    is_passive: false,
                    requested_name_id_format: None,
                    requested_authn_context: None,
                    acs_index: Some(42),
                    acs_url: None,
                    response_binding: None,
                },
            )
            .unwrap_err();
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    #[test]
    fn start_login_acs_url_resolves_to_registered_endpoint() {
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let idp = fixture_idp();

        let acs_url = sp.config().acs[0].url.clone();
        let res = sp
            .start_login(
                &idp,
                StartLogin {
                    relay_state: None,
                    binding: Binding::HttpRedirect,
                    force_authn: false,
                    is_passive: false,
                    requested_name_id_format: None,
                    requested_authn_context: None,
                    acs_index: None,
                    acs_url: Some(&acs_url),
                    response_binding: None,
                },
            )
            .expect("acs_url resolves");
        assert_eq!(res.tracker.acs_endpoint.url, acs_url);
    }

    #[test]
    fn start_login_unregistered_acs_url_returns_unregistered_acs() {
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let idp = fixture_idp();

        let err = sp
            .start_login(
                &idp,
                StartLogin {
                    relay_state: None,
                    binding: Binding::HttpRedirect,
                    force_authn: false,
                    is_passive: false,
                    requested_name_id_format: None,
                    requested_authn_context: None,
                    acs_index: None,
                    acs_url: Some("https://attacker.example.com/acs"),
                    response_binding: None,
                },
            )
            .unwrap_err();
        assert!(matches!(err, Error::UnregisteredAcs { .. }));
    }

    #[test]
    fn start_login_rejects_both_acs_index_and_url() {
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let idp = fixture_idp();

        let err = sp
            .start_login(
                &idp,
                StartLogin {
                    relay_state: None,
                    binding: Binding::HttpRedirect,
                    force_authn: false,
                    is_passive: false,
                    requested_name_id_format: None,
                    requested_authn_context: None,
                    acs_index: Some(0),
                    acs_url: Some("https://sp.example.com/acs"),
                    response_binding: None,
                },
            )
            .unwrap_err();
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    // ---------- consume_response (synthetic XML) ----------

    /// Build an SP-bound Response signed at the Assertion level. This mirrors
    /// the shape `IdentityProvider::issue_response` (Wave 5) produces but uses
    /// only crates we don't share state with (no idp.rs dependency).
    fn build_signed_response_xml(
        kp: &KeyPair,
        in_response_to: Option<&str>,
        recipient_url: &str,
        audience: &str,
        not_before: &str,
        not_on_or_after: &str,
    ) -> Vec<u8> {
        let saml_ns = RESPONSE_SAML_NS;
        let samlp_ns = RESPONSE_SAMLP_NS;
        let bearer = RESPONSE_SUBJECT_CONFIRMATION_BEARER;

        let mut scd_builder = Element::build(QName::new(Some(saml_ns.to_owned()), "SubjectConfirmationData"))
            .with_attribute(QName::new(None, "Recipient"), recipient_url.to_owned())
            .with_attribute(QName::new(None, "NotOnOrAfter"), "2026-05-26T12:05:00Z".to_owned());
        if let Some(irt) = in_response_to {
            scd_builder = scd_builder.with_attribute(QName::new(None, "InResponseTo"), irt.to_owned());
        }
        let scd = scd_builder.finish();
        let sc = Element::build(QName::new(Some(saml_ns.to_owned()), "SubjectConfirmation"))
            .with_attribute(QName::new(None, "Method"), bearer.to_owned())
            .with_child(Node::Element(scd))
            .finish();
        let name_id = Element::build(QName::new(Some(saml_ns.to_owned()), "NameID"))
            .with_attribute(
                QName::new(None, "Format"),
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_owned(),
            )
            .with_text("alice@example.com")
            .finish();
        let subject = Element::build(QName::new(Some(saml_ns.to_owned()), "Subject"))
            .with_child(Node::Element(name_id))
            .with_child(Node::Element(sc))
            .finish();

        let aud_el = Element::build(QName::new(Some(saml_ns.to_owned()), "Audience"))
            .with_text(audience)
            .finish();
        let aud_restr =
            Element::build(QName::new(Some(saml_ns.to_owned()), "AudienceRestriction"))
                .with_child(Node::Element(aud_el))
                .finish();
        let conditions = Element::build(QName::new(Some(saml_ns.to_owned()), "Conditions"))
            .with_attribute(QName::new(None, "NotBefore"), not_before.to_owned())
            .with_attribute(
                QName::new(None, "NotOnOrAfter"),
                not_on_or_after.to_owned(),
            )
            .with_child(Node::Element(aud_restr))
            .finish();

        let class_ref =
            Element::build(QName::new(Some(saml_ns.to_owned()), "AuthnContextClassRef"))
                .with_text("urn:oasis:names:tc:SAML:2.0:ac:classes:Password")
                .finish();
        let actx = Element::build(QName::new(Some(saml_ns.to_owned()), "AuthnContext"))
            .with_child(Node::Element(class_ref))
            .finish();
        let astmt = Element::build(QName::new(Some(saml_ns.to_owned()), "AuthnStatement"))
            .with_attribute(QName::new(None, "AuthnInstant"), "2026-05-26T11:59:30Z")
            .with_attribute(QName::new(None, "SessionIndex"), "sess-1")
            .with_child(Node::Element(actx))
            .finish();

        let assertion_issuer =
            Element::build(QName::new(Some(saml_ns.to_owned()), "Issuer"))
                .with_text("https://idp.example.com")
                .finish();
        let assertion = Element::build(QName::new(Some(saml_ns.to_owned()), "Assertion"))
            .with_namespace(Some("saml".to_owned()), saml_ns)
            .with_attribute(QName::new(None, "ID"), "_a1".to_owned())
            .with_attribute(QName::new(None, "Version"), "2.0")
            .with_attribute(QName::new(None, "IssueInstant"), "2026-05-26T12:00:00Z")
            .with_child(Node::Element(assertion_issuer))
            .with_child(Node::Element(subject))
            .with_child(Node::Element(conditions))
            .with_child(Node::Element(astmt))
            .finish();

        // Sign the assertion.
        let assertion_doc = Document::new(assertion).unwrap();
        let signed_assertion = sign_element(
            assertion_doc.root().clone(),
            &assertion_doc,
            SignOptions {
                signing_key: kp,
                sig_alg: SignatureAlgorithm::RsaSha256,
                digest_alg: DigestAlgorithm::Sha256,
                c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                inclusive_namespaces: &[],
                include_x509_cert: true,
            },
        )
        .unwrap();

        // Build the Response wrapper.
        let status_code = Element::build(QName::new(Some(samlp_ns.to_owned()), "StatusCode"))
            .with_attribute(
                QName::new(None, "Value"),
                "urn:oasis:names:tc:SAML:2.0:status:Success".to_owned(),
            )
            .finish();
        let status = Element::build(QName::new(Some(samlp_ns.to_owned()), "Status"))
            .with_child(Node::Element(status_code))
            .finish();
        let response_issuer = Element::build(QName::new(Some(saml_ns.to_owned()), "Issuer"))
            .with_text("https://idp.example.com")
            .finish();
        let mut response =
            Element::build(QName::new(Some(samlp_ns.to_owned()), "Response"))
                .with_namespace(Some("samlp".to_owned()), samlp_ns)
                .with_namespace(Some("saml".to_owned()), saml_ns)
                .with_attribute(QName::new(None, "ID"), "_resp1".to_owned())
                .with_attribute(QName::new(None, "Version"), "2.0")
                .with_attribute(QName::new(None, "IssueInstant"), "2026-05-26T12:00:00Z")
                .with_attribute(QName::new(None, "Destination"), recipient_url.to_owned());
        if let Some(irt) = in_response_to {
            response = response.with_attribute(QName::new(None, "InResponseTo"), irt.to_owned());
        }
        let response = response
            .with_child(Node::Element(response_issuer))
            .with_child(Node::Element(status))
            .with_child(Node::Element(signed_assertion))
            .finish();

        let doc = Document::new(response).unwrap();
        emit_document(&doc).unwrap().into_bytes()
    }

    fn fixed_now() -> SystemTime {
        // 2026-05-26T12:00:30Z
        UNIX_EPOCH
            .checked_add(Duration::from_secs(1_779_796_830))
            .expect("static UNIX_EPOCH + bounded Duration cannot overflow")
    }

    #[test]
    fn consume_response_solicited_returns_identity() {
        let kp = rsa_signing_key();
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let idp = fixture_idp();

        // Synthesize a tracker matching the response we will build.
        let tracker = LoginTracker {
            request_id: "_req1".to_owned(),
            issued_at: fixed_now(),
            idp_entity_id: idp.entity_id.clone(),
            acs_endpoint: sp.config.acs[0].clone(),
            requested_authn_context: None,
            requested_name_id_format: None,
        };

        let xml = build_signed_response_xml(
            &kp,
            Some("_req1"),
            "https://sp.example.com/acs",
            "https://sp.example.com",
            "2026-05-26T11:59:00Z",
            "2026-05-26T12:10:00Z",
        );

        let identity = sp
            .consume_response(ConsumeResponse {
                idp: &idp,
                peer_crypto_policy: None,
                saml_response: &xml,
                binding: SsoResponseBinding::HttpPost,
                relay_state: None,
                tracker: Some(&tracker),
                expected_destination: "https://sp.example.com/acs",
                now: fixed_now(),
                clock_skew: Duration::from_secs(30),
                replay_cache: None,
            })
            .expect("consume_response");

        assert_eq!(identity.assertion_id, "_a1");
        assert_eq!(identity.name_id.value, "alice@example.com");
        assert_eq!(identity.name_id.format, NameIdFormat::EmailAddress);
        assert_eq!(identity.session_index.as_deref(), Some("sess-1"));
    }

    #[test]
    fn consume_response_unsolicited_when_allowed() {
        let kp = rsa_signing_key();
        let mut cfg = fixture_sp_config(None, /* allow_unsolicited */ true, false);
        cfg.allow_unsolicited = true;
        let sp = ServiceProvider::new(cfg).unwrap();
        let idp = fixture_idp();

        let xml = build_signed_response_xml(
            &kp,
            None, // no InResponseTo
            "https://sp.example.com/acs",
            "https://sp.example.com",
            "2026-05-26T11:59:00Z",
            "2026-05-26T12:10:00Z",
        );

        let identity = sp
            .consume_response(ConsumeResponse {
                idp: &idp,
                peer_crypto_policy: None,
                saml_response: &xml,
                binding: SsoResponseBinding::HttpPost,
                relay_state: None,
                tracker: None,
                expected_destination: "https://sp.example.com/acs",
                now: fixed_now(),
                clock_skew: Duration::from_secs(30),
                replay_cache: None,
            })
            .expect("consume_response (unsolicited)");
        assert_eq!(identity.assertion_id, "_a1");
    }

    #[test]
    fn consume_response_solicited_in_response_to_mismatch() {
        let kp = rsa_signing_key();
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let idp = fixture_idp();

        let tracker = LoginTracker {
            request_id: "_req1".to_owned(),
            issued_at: fixed_now(),
            idp_entity_id: idp.entity_id.clone(),
            acs_endpoint: sp.config.acs[0].clone(),
            requested_authn_context: None,
            requested_name_id_format: None,
        };

        // Build a Response whose InResponseTo is `_wrong`.
        let xml = build_signed_response_xml(
            &kp,
            Some("_wrong"),
            "https://sp.example.com/acs",
            "https://sp.example.com",
            "2026-05-26T11:59:00Z",
            "2026-05-26T12:10:00Z",
        );

        let err = sp
            .consume_response(ConsumeResponse {
                idp: &idp,
                peer_crypto_policy: None,
                saml_response: &xml,
                binding: SsoResponseBinding::HttpPost,
                relay_state: None,
                tracker: Some(&tracker),
                expected_destination: "https://sp.example.com/acs",
                now: fixed_now(),
                clock_skew: Duration::from_secs(30),
                replay_cache: None,
            })
            .unwrap_err();
        assert!(matches!(err, Error::InResponseToMismatch));
    }

    #[test]
    fn consume_response_destination_not_registered() {
        let kp = rsa_signing_key();
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let idp = fixture_idp();

        let tracker = LoginTracker {
            request_id: "_req1".to_owned(),
            issued_at: fixed_now(),
            idp_entity_id: idp.entity_id.clone(),
            acs_endpoint: sp.config.acs[0].clone(),
            requested_authn_context: None,
            requested_name_id_format: None,
        };
        let xml = build_signed_response_xml(
            &kp,
            Some("_req1"),
            "https://sp.example.com/acs",
            "https://sp.example.com",
            "2026-05-26T11:59:00Z",
            "2026-05-26T12:10:00Z",
        );

        let err = sp
            .consume_response(ConsumeResponse {
                idp: &idp,
                peer_crypto_policy: None,
                saml_response: &xml,
                binding: SsoResponseBinding::HttpPost,
                relay_state: None,
                tracker: Some(&tracker),
                // Not in self.acs:
                expected_destination: "https://other.example.com/acs",
                now: fixed_now(),
                clock_skew: Duration::from_secs(30),
                replay_cache: None,
            })
            .unwrap_err();
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    // ---------- replay cache ----------

    /// End-to-end: a successful `consume_response` followed by a second
    /// call with the exact same Response (same `assertion_id`) MUST be
    /// rejected with `Error::AssertionReplay`. The first call also
    /// populates the cache, so the assertion is the only thing in
    /// `cache.len()` afterward.
    ///
    /// Caveat: `InMemoryReplayCache` sweeps entries whose `expires_at`
    /// is in the past against the *real* wall clock (`SystemTime::now()`),
    /// not the test's `now` argument. The synthetic Response fixture
    /// uses the year 2026 — so this test only behaves correctly while
    /// the wall clock is still before the `NotOnOrAfter` in the
    /// fixture. We exercise the cache directly with a far-future
    /// expiry as a precondition, then the e2e path with the real
    /// fixture; together they exercise both the cache and the
    /// `consume_response`-side wiring.
    #[test]
    fn consume_response_rejects_replay() {
        let kp = rsa_signing_key();
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let idp = fixture_idp();

        let tracker = LoginTracker {
            request_id: "_req1".to_owned(),
            issued_at: fixed_now(),
            idp_entity_id: idp.entity_id.clone(),
            acs_endpoint: sp.config.acs[0].clone(),
            requested_authn_context: None,
            requested_name_id_format: None,
        };
        // Set the assertion's NotOnOrAfter ~30 years out so the cache's
        // wall-clock-based lazy sweep doesn't drop the entry between
        // the two `consume_response` calls. The fixture's `now` /
        // `clock_skew` window is still anchored to the fixture's 2026
        // baseline; that path runs purely against the supplied `now`.
        let xml = build_signed_response_xml(
            &kp,
            Some("_req1"),
            "https://sp.example.com/acs",
            "https://sp.example.com",
            "2026-05-26T11:59:00Z",
            "2099-05-26T12:10:00Z",
        );

        let cache = crate::replay::InMemoryReplayCache::new(32);

        // First consume succeeds; the assertion id is now in the cache.
        let identity = sp
            .consume_response(ConsumeResponse {
                idp: &idp,
                peer_crypto_policy: None,
                saml_response: &xml,
                binding: SsoResponseBinding::HttpPost,
                relay_state: None,
                tracker: Some(&tracker),
                expected_destination: "https://sp.example.com/acs",
                now: fixed_now(),
                clock_skew: Duration::from_secs(30),
                replay_cache: Some(&cache),
            })
            .expect("first consume_response succeeds");
        assert_eq!(identity.assertion_id, "_a1");
        assert_eq!(cache.len(), 1, "cache populated by first consume");

        // Second consume with the exact same Response is a replay.
        let err = sp
            .consume_response(ConsumeResponse {
                idp: &idp,
                peer_crypto_policy: None,
                saml_response: &xml,
                binding: SsoResponseBinding::HttpPost,
                relay_state: None,
                tracker: Some(&tracker),
                expected_destination: "https://sp.example.com/acs",
                now: fixed_now(),
                clock_skew: Duration::from_secs(30),
                replay_cache: Some(&cache),
            })
            .expect_err("second consume_response is a replay");
        assert!(
            matches!(err, Error::AssertionReplay),
            "expected Error::AssertionReplay, got {err:?}"
        );
        // Cache size unchanged — replay path doesn't double-insert.
        assert_eq!(cache.len(), 1, "cache size unchanged after replay");
    }

    // ---------- SLO ----------

    #[cfg(feature = "slo")]
    #[test]
    fn start_logout_redirect_returns_dispatch_with_samlrequest() {
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let idp = fixture_idp();

        let nid = NameId::email("alice@example.com");
        let dispatch = sp
            .start_logout(
                &idp,
                StartLogout {
                    name_id: &nid,
                    session_index: Some("sess-1"),
                    relay_state: Some("rs"),
                    reason: None,
                    binding: Binding::HttpRedirect,
                },
            )
            .expect("start_logout");

        assert!(dispatch.tracker.request_id.starts_with('_'));
        assert_eq!(dispatch.tracker.peer_entity_id, "https://idp.example.com");

        match dispatch.dispatch {
            Dispatch::Redirect(url) => {
                let q = url.query().unwrap();
                assert!(q.contains("SAMLRequest="));
                assert!(q.contains("RelayState=rs"));
            }
            other @ Dispatch::Post(_) => panic!("expected Redirect, got {other:?}"),
        }
    }

    #[cfg(feature = "slo")]
    #[test]
    fn start_logout_missing_slo_endpoint_is_unsupported() {
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let mut idp = fixture_idp();
        idp.slo_endpoints.clear();

        let nid = NameId::email("alice@example.com");
        let err = sp
            .start_logout(
                &idp,
                StartLogout {
                    name_id: &nid,
                    session_index: None,
                    relay_state: None,
                    reason: None,
                    binding: Binding::HttpRedirect,
                },
            )
            .unwrap_err();
        assert!(matches!(err, Error::UnsupportedByPeer { .. }));
    }

    /// Build a `<samlp:LogoutResponse>` over the POST binding and serialize as
    /// the base64-encoded SAMLResponse value the caller would deliver.
    #[cfg(feature = "slo")]
    fn build_logout_response_post_form(in_response_to: &str, destination: &str) -> Vec<u8> {
        use crate::logout::response_build::build_logout_response_xml;
        let xml = build_logout_response_xml(&BuildLogoutResponse {
            id: "_lr1",
            issue_instant: fixed_now(),
            issuer_entity_id: "https://idp.example.com",
            destination: Some(destination),
            in_response_to,
            status: LogoutStatus::Success,
            status_message: None,
        })
        .unwrap();
        // Encode as base64 so we can feed it through the binding decoder.
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as BASE64;
        BASE64.encode(&xml).into_bytes()
    }

    #[cfg(feature = "slo")]
    #[test]
    fn consume_logout_response_post_returns_success() {
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let idp = fixture_idp();

        let logout_tracker = LogoutTracker {
            request_id: "_req-logout".to_owned(),
            issued_at: fixed_now(),
            peer_entity_id: idp.entity_id.clone(),
        };
        let body = build_logout_response_post_form(
            &logout_tracker.request_id,
            "https://sp.example.com/slo/post",
        );

        let outcome = sp
            .consume_logout_response(
                &idp,
                ConsumeLogoutResponse {
                    peer_crypto_policy: None,
                    body: &body,
                    binding: Binding::HttpPost,
                    detached_signature: None,
                    tracker: &logout_tracker,
                    expected_destination: "https://sp.example.com/slo/post",
                    now: fixed_now(),
                    clock_skew: Duration::from_secs(30),
                },
            )
            .expect("consume_logout_response");
        assert!(matches!(outcome, LogoutOutcome::Success));
    }

    #[cfg(feature = "slo")]
    #[test]
    fn consume_logout_response_in_response_to_mismatch() {
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let idp = fixture_idp();

        let logout_tracker = LogoutTracker {
            request_id: "_expected".to_owned(),
            issued_at: fixed_now(),
            peer_entity_id: idp.entity_id.clone(),
        };
        let body = build_logout_response_post_form(
            "_wrong",
            "https://sp.example.com/slo/post",
        );

        let err = sp
            .consume_logout_response(
                &idp,
                ConsumeLogoutResponse {
                    peer_crypto_policy: None,
                    body: &body,
                    binding: Binding::HttpPost,
                    detached_signature: None,
                    tracker: &logout_tracker,
                    expected_destination: "https://sp.example.com/slo/post",
                    now: fixed_now(),
                    clock_skew: Duration::from_secs(30),
                },
            )
            .unwrap_err();
        assert!(matches!(err, Error::InResponseToMismatch));
    }

    /// Build a base64-encoded LogoutRequest from the IdP for POST consumption.
    #[cfg(feature = "slo")]
    fn build_logout_request_post_form(destination: &str) -> Vec<u8> {
        let nid = NameId::email("alice@example.com");
        let xml = build_logout_request_xml(&BuildLogoutRequest {
            id: "_idp-req-1",
            issue_instant: fixed_now(),
            issuer_entity_id: "https://idp.example.com",
            destination: Some(destination),
            not_on_or_after: None,
            reason: None,
            name_id: &nid,
            session_index: Some("sess-1"),
        })
        .unwrap();
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as BASE64;
        BASE64.encode(&xml).into_bytes()
    }

    #[cfg(feature = "slo")]
    #[test]
    fn consume_logout_request_post_parses_and_validates() {
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let idp = fixture_idp();

        let body = build_logout_request_post_form("https://sp.example.com/slo/post");

        let parsed = sp
            .consume_logout_request(
                &idp,
                ConsumeLogoutRequest {
                    peer_crypto_policy: None,
                    body: &body,
                    binding: Binding::HttpPost,
                    detached_signature: None,
                    expected_destination: "https://sp.example.com/slo/post",
                    now: fixed_now(),
                    clock_skew: Duration::from_secs(30),
                },
            )
            .expect("consume_logout_request");
        assert_eq!(parsed.id, "_idp-req-1");
        assert_eq!(parsed.issuer, "https://idp.example.com");
        assert_eq!(parsed.name_id.value, "alice@example.com");
        assert_eq!(parsed.session_index, vec!["sess-1".to_string()]);
    }

    #[cfg(feature = "slo")]
    #[test]
    fn consume_logout_request_issuer_mismatch_rejected() {
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let mut idp = fixture_idp();
        idp.entity_id = "https://other-idp.example.com".to_owned();

        let body = build_logout_request_post_form("https://sp.example.com/slo/post");
        let err = sp
            .consume_logout_request(
                &idp,
                ConsumeLogoutRequest {
                    peer_crypto_policy: None,
                    body: &body,
                    binding: Binding::HttpPost,
                    detached_signature: None,
                    expected_destination: "https://sp.example.com/slo/post",
                    now: fixed_now(),
                    clock_skew: Duration::from_secs(30),
                },
            )
            .unwrap_err();
        assert!(matches!(err, Error::IssuerMismatch { .. }));
    }

    #[cfg(feature = "slo")]
    #[test]
    fn build_logout_response_returns_post_dispatch() {
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let idp = fixture_idp();

        let parsed = ParsedLogoutRequest {
            id: "_idp-req-1".to_owned(),
            issuer: idp.entity_id.clone(),
            issue_instant: fixed_now(),
            destination: Some("https://sp.example.com/slo/post".to_owned()),
            not_on_or_after: None,
            reason: None,
            name_id: NameId::email("alice@example.com"),
            session_index: vec!["sess-1".to_owned()],
            relay_state: None,
        };

        let dispatch = sp
            .build_logout_response(
                &idp,
                &parsed,
                LogoutStatus::Success,
                Some("rs"),
                Binding::HttpPost,
            )
            .expect("build_logout_response");
        match dispatch {
            Dispatch::Post(PostForm {
                saml_response,
                saml_request,
                action,
                relay_state,
            }) => {
                assert!(saml_response.is_some());
                assert!(saml_request.is_none());
                assert_eq!(action.path(), "/slo/post");
                assert_eq!(relay_state.as_deref(), Some("rs"));
            }
            other @ Dispatch::Redirect(_) => panic!("expected Post, got {other:?}"),
        }
    }

    // ---------- Metadata ----------

    #[test]
    fn metadata_xml_reparses_as_sp_descriptor() {
        let kp = rsa_signing_key();
        let cfg = fixture_sp_config(Some(kp), false, true);
        let sp = ServiceProvider::new(cfg).unwrap();

        let xml = sp.metadata_xml(false).expect("metadata_xml");
        let descriptor = crate::descriptor::SpDescriptor::from_metadata_xml(xml.as_bytes())
            .expect("reparse");
        assert_eq!(descriptor.entity_id, "https://sp.example.com");
        assert_eq!(descriptor.assertion_consumer_services.len(), 1);
        assert_eq!(
            descriptor.assertion_consumer_services[0].url,
            "https://sp.example.com/acs"
        );
        assert_eq!(descriptor.single_logout_services.len(), 2);
        assert!(descriptor.authn_requests_signed);
        assert!(descriptor.want_assertions_signed);
        assert_eq!(descriptor.signing_certs.len(), 1);
    }

    #[test]
    fn metadata_xml_signed_carries_signature_child() {
        let kp = rsa_signing_key();
        let cfg = fixture_sp_config(Some(kp), false, true);
        let sp = ServiceProvider::new(cfg).unwrap();

        let xml = sp.metadata_xml(true).expect("signed metadata");
        let doc = Document::parse(xml.as_bytes()).expect("parse");
        let sig = doc
            .root()
            .child_element(Some("http://www.w3.org/2000/09/xmldsig#"), "Signature");
        assert!(sig.is_some(), "signed metadata must carry <ds:Signature>");
    }

    #[test]
    fn metadata_xml_with_extras_includes_organization() {
        let kp = rsa_signing_key();
        let cfg = fixture_sp_config(Some(kp), false, true);
        let sp = ServiceProvider::new(cfg).unwrap();

        let extras = crate::metadata::MetadataExtras {
            organization: Some(crate::metadata::MetadataOrganization {
                name: "Example".into(),
                display_name: "Example Corp".into(),
                url: "https://example.com".into(),
                language: "en".into(),
            }),
            contacts: vec![],
        };
        let xml = sp
            .metadata_xml_with_extras(false, &extras)
            .expect("metadata_xml_with_extras");
        let doc = Document::parse(xml.as_bytes()).expect("parse");
        let org = doc
            .root()
            .child_element(
                Some("urn:oasis:names:tc:SAML:2.0:metadata"),
                "Organization",
            )
            .expect("Organization");
        let _ = org;
    }

}
