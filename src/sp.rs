//! Service Provider role.
//!
//! See `docs/rfcs/RFC-003-service-provider.md` for the design and
//! `docs/rfcs/RFC-007-single-logout.md` for the SLO surface.

use std::time::{Duration, SystemTime};

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore as _;

use crate::authn::request_build::{AcsRequest, BuildAuthnRequest, build_authn_request_xml};
use crate::authn_context::RequestedAuthnContext;
use crate::binding::post::encode_request as post_encode_request;
#[cfg(feature = "slo")]
use crate::binding::post::{decode as post_decode, encode_response as post_encode_response};
#[cfg(feature = "slo")]
use crate::binding::redirect::decode as redirect_decode;
use crate::binding::redirect::{
    RedirectDirection, encode_signed as redirect_encode_signed,
    encode_unsigned as redirect_encode_unsigned,
};
use crate::binding::{Binding, Dispatch, Endpoint, SsoResponseBinding, SsoResponseEndpoint};
use crate::crypto::cert::certificate_fingerprint_set;
use crate::crypto::keypair::KeyPair;
use crate::descriptor::IdpDescriptor;
use crate::dsig::algorithms::{
    C14nAlgorithm, DigestAlgorithm, PeerCryptoPolicy, SignatureAlgorithm,
};
#[cfg(feature = "slo")]
use crate::dsig::reference::DS_NS;
use crate::dsig::sign::{SignOptions, sign_detached_query, sign_element};
#[cfg(feature = "slo")]
use crate::dsig::verify::{verify_detached_signature, verify_signature};
use crate::error::Error;
#[cfg(feature = "slo")]
use crate::http::{HttpClient, HttpRequest};
#[cfg(feature = "slo")]
use crate::logout::request_build::{BuildLogoutRequest, build_logout_request_xml};
#[cfg(feature = "slo")]
use crate::logout::request_parse::parse_logout_request;
#[cfg(feature = "slo")]
use crate::logout::response_build::{BuildLogoutResponse, build_logout_response_xml};
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
use crate::replay::{ReplayCache, ReplayEntry, ReplayMode};
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
        if config.entity_id.is_empty() || config.entity_id.chars().any(char::is_whitespace) {
            return Err(Error::InvalidConfiguration {
                reason: "entity_id must be a non-empty, whitespace-free xs:anyURI",
            });
        }
        if config.acs.is_empty() {
            return Err(Error::InvalidConfiguration {
                reason: "acs must contain at least one endpoint",
            });
        }
        let needs_signing_key = config.sign_authn_requests || {
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
///
/// Every field is read-only outside this crate. Mutation and construction from
/// whole cloth do not compile:
///
/// ```compile_fail
/// # use saml::LoginTracker;
/// fn cross_wire(tracker: &mut LoginTracker) {
///     tracker.request_id.clear();
/// }
/// ```
#[derive(Debug, Clone)]
pub struct LoginTracker {
    request_id: String,
    issued_at: SystemTime,
    idp_entity_id: String,
    acs_endpoint: SsoResponseEndpoint,
    /// What this login asked the IdP for, as issued.
    ///
    /// Private: these drive response-side policy checks, so a caller that
    /// could clear them after `start_login` would simply switch those checks
    /// off — `requested_authn_context` disables non-downgrade enforcement,
    /// `requested_name_id_format` disables the returned-format check. Read via
    /// [`requested_authn_context`](Self::requested_authn_context) and
    /// [`requested_name_id_format`](Self::requested_name_id_format).
    ///
    /// # Serialized trackers
    ///
    /// A tracker is usually stashed in a cookie or session store across the
    /// round trip. Privacy here constrains this process, not that storage: if
    /// you serialize a tracker, the serialized form MUST be
    /// integrity-protected, or an attacker who can rewrite it can strip these
    /// requirements exactly as a caller with public fields could.
    requested_authn_context: Option<RequestedAuthnContext>,
    requested_name_id_format: Option<NameIdFormat>,
    /// SHA-256 fingerprints of the IdP signing certificates trusted when this
    /// login began.
    ///
    /// `idp_entity_id` pins who the response claims to be from, not which keys
    /// may speak for them — and `consume_response` takes a fresh
    /// `IdpDescriptor`. Without this, a same-entity descriptor carrying an
    /// attacker's certificate becomes the validation trust root, exactly as on
    /// the proxy path before it sealed the same fingerprints.
    idp_signing_cert_fingerprints: Vec<[u8; 32]>,
    /// Canonical IdP ArtifactResolutionService endpoints trusted when this
    /// login began. Artifact routing uses this snapshot, never a fresh
    /// descriptor's URL, so a substituted index cannot induce an outbound
    /// request to an attacker-controlled destination.
    idp_artifact_resolution_services: Vec<Endpoint>,
}

/// Serialized form of a [`LoginTracker`].
///
/// Transparent wire form for storage and custom authenticated containers.
///
/// This value is deliberately not accepted by response validation. It becomes
/// an authoritative [`LoginTracker`] only after [`LoginTracker::open`]
/// authenticates a blob sealed by [`LoginTrackerPayload::seal`]. The sealing
/// key holder is therefore a tracker-issuing trust root: it can construct a
/// payload with arbitrary correlation or policy fields and authorize it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoginTrackerPayload {
    pub request_id: String,
    pub issued_at: SystemTime,
    pub idp_entity_id: String,
    pub acs_endpoint: SsoResponseEndpoint,
    pub requested_authn_context: Option<RequestedAuthnContext>,
    pub requested_name_id_format: Option<NameIdFormat>,
    /// See [`LoginTracker`]'s field of the same name.
    pub idp_signing_cert_fingerprints: Vec<[u8; 32]>,
    /// See [`LoginTracker`]'s field of the same name.
    #[serde(default)]
    pub idp_artifact_resolution_services: Vec<Endpoint>,
}

impl LoginTrackerPayload {
    /// Seal this payload into an authenticated blob for the caller's storage.
    ///
    /// A tracker crosses the round trip in a cookie or session store, so it
    /// leaves this process and comes back. Private fields say nothing about
    /// what happens in between: a plain `Deserialize`, or any public
    /// constructor, lets whoever controls that storage rebuild the tracker
    /// with `requested_authn_context` and `requested_name_id_format` cleared —
    /// which switches off non-downgrade enforcement and the returned-format
    /// check exactly as mutating the fields would have.
    ///
    /// Sealing is therefore the only honest way to hand a tracker out. Same
    /// construction as [`Aes256GcmCodec`](crate::Aes256GcmCodec):
    /// `base64url(nonce_12 || ciphertext || tag_16)` under a 32-byte key the
    /// application holds.
    ///
    /// # Errors
    ///
    /// If serialization or encryption fails.
    pub fn seal(&self, key: &[u8; 32]) -> Result<String, Error> {
        let wire = self;
        let plaintext =
            postcard::to_allocvec(&wire).map_err(|_err| Error::InvalidConfiguration {
                reason: "login tracker serialize",
            })?;
        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|_err| Error::InvalidConfiguration {
                reason: "AES-256-GCM key size mismatch",
            })?;
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let ct = cipher
            .encrypt(
                aes_gcm::Nonce::from_slice(&nonce_bytes),
                aes_gcm::aead::Payload {
                    msg: &plaintext,
                    aad: &[],
                },
            )
            .map_err(|_err| Error::DecryptFailed {
                reason: "login tracker",
            })?;
        let mut buf = Vec::with_capacity(12usize.saturating_add(ct.len()));
        buf.extend_from_slice(&nonce_bytes);
        buf.extend_from_slice(&ct);
        Ok(URL_SAFE_NO_PAD.encode(&buf))
    }
}

impl LoginTracker {
    /// The inert wire form, for embedding in something the crate authenticates.
    #[must_use]
    pub fn to_payload(&self) -> LoginTrackerPayload {
        LoginTrackerPayload {
            request_id: self.request_id.clone(),
            issued_at: self.issued_at,
            idp_entity_id: self.idp_entity_id.clone(),
            acs_endpoint: self.acs_endpoint.clone(),
            requested_authn_context: self.requested_authn_context.clone(),
            requested_name_id_format: self.requested_name_id_format.clone(),
            idp_signing_cert_fingerprints: self.idp_signing_cert_fingerprints.clone(),
            idp_artifact_resolution_services: self.idp_artifact_resolution_services.clone(),
        }
    }

    /// Rebuild from a payload. Crate-internal: the caller reaching this would
    /// be able to clear the policy fields, which is what privacy prevents.
    pub(crate) fn from_payload(payload: LoginTrackerPayload) -> Self {
        Self {
            request_id: payload.request_id,
            issued_at: payload.issued_at,
            idp_entity_id: payload.idp_entity_id,
            acs_endpoint: payload.acs_endpoint,
            requested_authn_context: payload.requested_authn_context,
            requested_name_id_format: payload.requested_name_id_format,
            idp_signing_cert_fingerprints: payload.idp_signing_cert_fingerprints,
            idp_artifact_resolution_services: payload.idp_artifact_resolution_services,
        }
    }

    /// Recover a tracker sealed by [`LoginTrackerPayload::seal`].
    ///
    /// # What the key establishes
    ///
    /// The sealing key is the tracker-issuing trust root, and this crate makes
    /// no claim beyond that. [`LoginTrackerPayload`] is public with public
    /// fields, so whoever holds the key can mint a tracker with the policy
    /// fields cleared just as easily as a genuine one — an AEAD proves the
    /// holder of a key sealed something, not that this crate did.
    ///
    /// What it does establish is integrity across the round trip: a tracker
    /// that went out through a cookie or session store comes back unmodified,
    /// or not at all. That is the property that was missing, since the
    /// response-side checks it carries — non-downgrade enforcement and the
    /// returned-format check — are switched off by clearing the fields.
    ///
    /// The application is not in the threat model here: it can already skip
    /// those checks by passing no tracker at all. Keep the key where the
    /// application keeps its other secrets, and treat anyone who obtains it as
    /// able to issue trackers.
    ///
    /// `max_age` bounds how long a sealed tracker stays usable. An
    /// authenticated blob is still a bearer token: without a bound, one
    /// captured from a log or a stale cookie authorizes a correlation
    /// indefinitely.
    ///
    /// # Errors
    ///
    /// If the blob is malformed, fails authentication, or is older than
    /// `max_age`.
    pub fn open(
        blob: &str,
        key: &[u8; 32],
        now: SystemTime,
        max_age: Duration,
    ) -> Result<Self, Error> {
        let bytes =
            URL_SAFE_NO_PAD
                .decode(blob.as_bytes())
                .map_err(|_err| Error::DecryptFailed {
                    reason: "login tracker",
                })?;
        if bytes.len() < 12 + 16 {
            return Err(Error::DecryptFailed {
                reason: "login tracker",
            });
        }
        let (nonce_bytes, ct) = bytes.split_at(12);
        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|_err| Error::InvalidConfiguration {
                reason: "AES-256-GCM key size mismatch",
            })?;
        let plaintext = cipher
            .decrypt(
                aes_gcm::Nonce::from_slice(nonce_bytes),
                aes_gcm::aead::Payload { msg: ct, aad: &[] },
            )
            .map_err(|_err| Error::DecryptFailed {
                reason: "login tracker",
            })?;
        let wire: LoginTrackerPayload =
            postcard::from_bytes(&plaintext).map_err(|_err| Error::DecryptFailed {
                reason: "login tracker",
            })?;

        // Bounded in both directions, for the same reason the proxy context is:
        // `issued_at` is whatever was sealed, so an unbounded future date would
        // make `max_age` meaningless.
        match now.duration_since(wire.issued_at) {
            Ok(age) if age > max_age => {
                return Err(Error::Expired);
            }
            Err(ahead) if ahead.duration() > Duration::from_mins(5) => {
                return Err(Error::InvalidConfiguration {
                    reason: "login tracker is dated too far in the future",
                });
            }
            _ => {}
        }

        Ok(Self::from_payload(wire))
    }

    /// SHA-256 fingerprints of the IdP signing certificates trusted when this
    /// login began. Crate-issued trackers always contain at least one; an
    /// externally minted payload with an empty set fails response preflight.
    #[must_use]
    pub fn idp_signing_cert_fingerprints(&self) -> &[[u8; 32]] {
        &self.idp_signing_cert_fingerprints
    }

    /// IdP ArtifactResolutionService endpoints pinned when login began.
    #[must_use]
    pub fn idp_artifact_resolution_services(&self) -> &[Endpoint] {
        &self.idp_artifact_resolution_services
    }

    /// AuthnRequest `@ID` this tracker correlates.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Time at which the tracked AuthnRequest was issued.
    #[must_use]
    pub fn issued_at(&self) -> SystemTime {
        self.issued_at
    }

    /// Entity ID of the IdP selected when the login began.
    #[must_use]
    pub fn idp_entity_id(&self) -> &str {
        &self.idp_entity_id
    }

    /// ACS endpoint selected when the login began.
    #[must_use]
    pub fn acs_endpoint(&self) -> &SsoResponseEndpoint {
        &self.acs_endpoint
    }

    /// The `<samlp:RequestedAuthnContext>` this login was issued with.
    #[must_use]
    pub fn requested_authn_context(&self) -> Option<&RequestedAuthnContext> {
        self.requested_authn_context.as_ref()
    }

    /// The `<samlp:NameIDPolicy>/@Format` this login was issued with.
    #[must_use]
    pub fn requested_name_id_format(&self) -> Option<&NameIdFormat> {
        self.requested_name_id_format.as_ref()
    }
}

impl ServiceProvider {
    /// Build and dispatch an outbound `<samlp:AuthnRequest>`. See RFC-003 §3.
    pub fn start_login(
        &self,
        idp: &IdpDescriptor,
        opts: StartLogin<'_>,
    ) -> Result<StartLoginResult, Error> {
        // 1. Pin a real response-validation trust root before issuing a
        // request. An empty set cannot authenticate the eventual response and
        // would turn the tracker's subset check into a vacuous one.
        let idp_signing_cert_fingerprints = certificate_fingerprint_set(&idp.signing_certs);
        if idp_signing_cert_fingerprints.is_empty() {
            return Err(Error::NoPeerSigningCert);
        }

        // 2. Look up IdP SSO endpoint for the requested transport binding.
        let sso_endpoint = idp
            .sso_endpoint(opts.binding)
            .ok_or(Error::UnsupportedByPeer {
                binding: opts.binding,
            })?;
        let destination_url =
            url::Url::parse(&sso_endpoint.url).map_err(|_err| Error::InvalidConfiguration {
                reason: "IdP SSO endpoint URL is not a valid URL",
            })?;

        // 2. Fresh request ID: `_<hex16>`.
        let request_id = crate::binding::random_xml_id()?;
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
        let idp_artifact_resolution_services =
            if response_binding == SsoResponseBinding::HttpArtifact {
                validate_and_pin_artifact_resolution_services(idp)?
            } else {
                Vec::new()
            };

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
            idp_signing_cert_fingerprints,
            idp_artifact_resolution_services,
        };

        Ok(StartLoginResult { tracker, dispatch })
    }
}

#[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
fn validate_and_pin_artifact_resolution_services(
    idp: &IdpDescriptor,
) -> Result<Vec<Endpoint>, Error> {
    if idp.artifact_resolution_endpoints.is_empty() {
        return Err(Error::UnsupportedByPeer {
            binding: Binding::HttpArtifact,
        });
    }

    let mut endpoints = idp.artifact_resolution_endpoints.clone();
    if endpoints
        .iter()
        .any(|endpoint| endpoint.binding != Binding::Soap || endpoint.index.is_none())
    {
        return Err(Error::InvalidConfiguration {
            reason: "ArtifactResolutionService endpoints must use SOAP and carry an index",
        });
    }
    endpoints.sort_by_key(|endpoint| endpoint.index);
    if endpoints.windows(2).any(|pair| {
        pair.first().map(|endpoint| endpoint.index) == pair.get(1).map(|endpoint| endpoint.index)
    }) {
        return Err(Error::InvalidConfiguration {
            reason: "ArtifactResolutionService endpoint indices must be unique",
        });
    }
    Ok(endpoints)
}

#[cfg(not(all(feature = "artifact-binding", feature = "weak-algos")))]
fn validate_and_pin_artifact_resolution_services(
    _idp: &IdpDescriptor,
) -> Result<Vec<Endpoint>, Error> {
    Err(Error::UnsupportedByPeer {
        binding: Binding::HttpArtifact,
    })
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
    /// — caller code is responsible for deduping an ordinary
    /// `Identity::assertion_id` against its own store, or for accepting that
    /// residual risk. `<OneTimeUse>` is never accepted without this cache.
    pub replay_cache: Option<&'a dyn ReplayCache>,
    /// Selects which subset of assertions are submitted to `replay_cache`.
    /// Defaults to [`ReplayMode::All`] — the strictest setting and the
    /// crate's pre-`ReplayMode` behavior. See [`ReplayMode`] for the
    /// trade-offs each variant makes. Ignored when `replay_cache` is `None`
    /// except for `<OneTimeUse>`: that directive fails closed unless a cache
    /// is present and the mode is not [`ReplayMode::Off`].
    pub replay_mode: ReplayMode,
    /// Opt-in Holder-of-Key confirmation (SAML 2.0 Profiles §3.1; SAML V2.0
    /// HoK SSO Profile). Supply the client certificate presented on the
    /// mutually-authenticated TLS connection that delivered this Response; the
    /// library does not own the socket, so the caller extracts it from their
    /// TLS terminator. When `Some`, a `<saml:SubjectConfirmation>` whose
    /// `@Method` is `urn:oasis:names:tc:SAML:2.0:cm:holder-of-key` is accepted
    /// only if this cert's public key matches the confirmation's `<ds:KeyInfo>`
    /// (in addition to the usual SubjectConfirmationData constraints). When
    /// `None` (the default), HoK confirmations are unusable and the assertion
    /// must carry a satisfying bearer confirmation — preserving the pre-HoK
    /// behavior exactly. An assertion offering ONLY HoK with `None` here is
    /// rejected with [`Error::HolderOfKeyConfirmation`].
    pub holder_of_key_cert: Option<&'a crate::crypto::cert::X509Certificate>,
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
    /// Replay-mode policy threaded into the inner [`ConsumeResponse`]
    /// after artifact resolution. See [`ConsumeResponse::replay_mode`] for
    /// semantics.
    pub replay_mode: ReplayMode,
    /// Presenter certificate for Holder-of-Key confirmation, threaded into the
    /// inner [`ConsumeResponse`] after artifact resolution. See
    /// [`ConsumeResponse::holder_of_key_cert`] for semantics.
    pub holder_of_key_cert: Option<&'a crate::crypto::cert::X509Certificate>,
    /// Optional SOAP back-channel hardening for the artifact-resolution
    /// exchange itself. When `None`, mutually authenticated TLS MUST
    /// authenticate the back channel: the outbound
    /// `<samlp:ArtifactResolve>` is sent unsigned and the inbound
    /// `<samlp:ArtifactResponse>` *envelope* signature is not checked — the
    /// recovered `<samlp:Response>`/assertion is still independently verified
    /// downstream by [`ServiceProvider::consume_response`], which remains the
    /// safety anchor. Supply [`ArtifactBackchannel`] to additionally sign the
    /// outbound resolve and/or verify the inbound envelope signature against
    /// the IdP certificates. See [`ArtifactBackchannel`].
    pub backchannel: Option<ArtifactBackchannel<'a>>,
}

/// Opt-in SOAP back-channel hardening for [`ConsumeArtifactResponse`].
///
/// The artifact back channel must authenticate both peers, either through
/// mutually authenticated TLS or these message signatures. This
/// struct lets the high-level SP artifact path route through the first-class
/// [`BackchannelClient`](crate::binding::artifact::BackchannelClient) instead
/// of the bare unsigned/unverified resolution helper:
///
/// - `sign` enveloped-signs the outbound `<samlp:ArtifactResolve>`,
///   authenticating the SP to the IdP.
/// - `verify` checks the inbound `<samlp:ArtifactResponse>` *envelope*
///   signature against the IdP certificates.
///
/// Both are additive and independent — either, both, or neither may be set.
/// Leaving the field `None` on [`ConsumeArtifactResponse`] is safe only when
/// mutual TLS supplies the missing authentication.
#[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
#[derive(Default)]
pub struct ArtifactBackchannel<'a> {
    /// When set, enveloped-sign the outbound `ArtifactResolve` with this key
    /// and algorithms.
    pub sign: Option<crate::binding::artifact::SignConfig<'a>>,
    /// When set, verify the inbound `ArtifactResponse` envelope signature
    /// against these certificates / algorithms.
    pub verify: Option<crate::binding::artifact::VerifyConfig<'a>>,
}

impl ServiceProvider {
    /// Validate everything about an inbound response that can be checked
    /// without the response itself: that `expected_destination` is one of this
    /// SP's registered ACS URLs, and — for a solicited flow — that the
    /// response correlates with the `LoginTracker` captured when the
    /// `AuthnRequest` was issued.
    ///
    /// Checking only the ACS URL let a response arrive from a different
    /// registered IdP, or over a different binding than the nominated
    /// endpoint, while still correlating by request ID. `InResponseTo` does
    /// not close the IdP gap on its own: the request ID is visible to
    /// whichever IdP the request was sent to.
    ///
    /// This is deliberately pure and free of I/O so the artifact path can run
    /// it *before* dereferencing the IdP's artifact-resolution endpoint —
    /// otherwise a mis-correlated response would cost a backchannel HTTP
    /// request, carrying the artifact, to an IdP the login was never issued
    /// to. `consume_response` runs the same checks, so calling it directly is
    /// equally safe.
    ///
    /// The tracker legs are a no-op for unsolicited flows (`tracker == None`).
    fn validate_tracker_context(
        &self,
        tracker: Option<&LoginTracker>,
        idp: &IdpDescriptor,
        expected_destination: &str,
        binding: SsoResponseBinding,
    ) -> Result<(), Error> {
        // Step 3a: `expected_destination` MUST be a registered ACS URL.
        if !self
            .config
            .acs
            .iter()
            .any(|e| e.url == expected_destination)
        {
            return Err(Error::InvalidConfiguration {
                reason: "expected_destination is not a registered ACS URL",
            });
        }

        // Step 3b: solicited responses stay bound to the tracked IdP and ACS.
        let Some(tracker) = tracker else {
            return Ok(());
        };
        if tracker.idp_entity_id() != idp.entity_id {
            return Err(Error::IssuerMismatch {
                expected: tracker.idp_entity_id().to_owned(),
                got: Some(idp.entity_id.clone()),
            });
        }
        if tracker.acs_endpoint().url != expected_destination {
            return Err(Error::DestinationMismatch);
        }
        if tracker.acs_endpoint().binding != binding {
            return Err(Error::ResponseBindingMismatch {
                expected: tracker.acs_endpoint().binding.as_binding(),
                received: binding.as_binding(),
            });
        }
        // Requiring every current certificate to be pinned broke additive
        // rotation. This preflight establishes that a current-and-pinned
        // verification root remains; response validation below receives only
        // that intersection, so newly introduced roots are never candidates.
        if !idp.signing_certs.iter().any(|cert| {
            tracker
                .idp_signing_cert_fingerprints()
                .contains(&cert.fingerprint_sha256())
        }) {
            return Err(Error::IdpTrustRootMismatch);
        }
        Ok(())
    }

    /// Validate an inbound `<samlp:Response>` and extract the `Identity`.
    /// See RFC-003 §4.1.
    pub fn consume_response(&self, input: ConsumeResponse<'_>) -> Result<Identity, Error> {
        self.consume_response_with_replay(input, None, Error::AssertionReplay)
    }

    /// Validate a Response and optionally substitute a caller-supplied replay
    /// tombstone for the assertion ID. The proxy uses one namespaced
    /// transaction tombstone: the already-validated `InResponseTo` binds that
    /// transaction to this assertion, so one cache slot makes the complete
    /// login single-use even if the IdP later emits a fresh assertion ID.
    pub(crate) fn consume_response_with_replay(
        &self,
        input: ConsumeResponse<'_>,
        transaction_replay_entry: Option<ReplayEntry<'_>>,
        replay_error: Error,
    ) -> Result<Identity, Error> {
        // Steps 3a/3b: registered ACS URL, plus tracker correlation for a
        // solicited flow. Shared with the artifact path, which runs them
        // before it dereferences the artifact.
        self.validate_tracker_context(
            input.tracker,
            input.idp,
            input.expected_destination,
            input.binding,
        )?;

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

        // For a solicited response, verification candidates are exactly the
        // intersection of the IdP's current metadata and the roots pinned when
        // the login began. This permits ordinary additive rotation
        // (`[old] -> [old, new]`) without allowing `new` to authenticate any
        // part of this in-flight response. Filtering before validation matters
        // for responses that require both Response and Assertion signatures:
        // a single post-validation fingerprint cannot describe both keys.
        let pinned_idp = input.tracker.map(|tracker| {
            let mut idp = input.idp.clone();
            idp.signing_certs.retain(|cert| {
                tracker
                    .idp_signing_cert_fingerprints()
                    .contains(&cert.fingerprint_sha256())
            });
            idp
        });
        let validation_idp = pinned_idp.as_ref().unwrap_or(input.idp);

        let identity = validate_response(ValidateResponse {
            document: &document,
            parsed,
            idp: validation_idp,
            peer_crypto_policy: policy,
            #[cfg(feature = "xmlenc")]
            decryption_keys: &decryption_keys_owned,
            sp_entity_id: &self.config.entity_id,
            expected_destination: input.expected_destination,
            tracker_request_id: input.tracker.map(LoginTracker::request_id),
            allow_unsolicited: self.config.allow_unsolicited,
            want_response_signed: self.config.want_signed.response,
            want_assertions_signed: self.config.want_signed.assertions,
            now: input.now,
            clock_skew: input.clock_skew,
            requested_authn_context: input
                .tracker
                .and_then(LoginTracker::requested_authn_context),
            holder_of_key_cert: input.holder_of_key_cert,
        })?;

        // The NameID Format must be the one we asked for.
        //
        // Core §3.4.1.1 requires the IdP to answer `InvalidNameIDPolicy`
        // rather than substitute a format it cannot produce, but an SP cannot
        // assume every peer does. A substituted format has different
        // semantics — a persistent pseudonym where a transient one was
        // requested is durably linkable across sessions — so accepting it
        // silently defeats the reason the format was specified.
        if let Some(requested) = input
            .tracker
            .and_then(LoginTracker::requested_name_id_format)
            && identity.name_id().format != *requested
        {
            return Err(Error::UnsupportedNameIdPolicy {
                requested: requested.as_uri().to_owned(),
            });
        }

        if matches!(identity.name_id().format, NameIdFormat::Persistent)
            && let Some(qualifier) = identity.name_id().sp_name_qualifier.as_deref()
            && qualifier != self.config.entity_id
        {
            return Err(Error::NameIdSpQualifierMismatch {
                expected: self.config.entity_id.clone(),
                got: qualifier.to_owned(),
            });
        }

        // Replay-cache check, AFTER signature + all spec checks succeed.
        // We never offer an `assertion_id` to the cache until the
        // assertion is structurally valid and signed by a trusted cert
        // — otherwise an attacker could pollute the cache with garbage
        // ids by hammering the ACS. The cache is updated only on the
        // success path, so a rejected Response leaves no trace.
        //
        // SAML 2.0 Core §2.5.1.5 (OneTimeUse): `<OneTimeUse/>` MUST be
        // enforced. For other assertions the spec recommends but does not
        // mandate replay defense; `input.replay_mode` selects the policy.
        // `<saml:OneTimeUse>` is a MUST (Core §2.5.1.5), not a preference: the
        // asserting party has said this assertion is good for exactly one
        // consumption. Accepting it with no cache — or with `ReplayMode::Off`
        // — silently ignores that, which is the one case where failing closed
        // is not a judgement call. Other assertions keep the opt-in policy,
        // where the spec recommends rather than mandates replay defence.
        if identity.is_one_time_use()
            && (input.replay_cache.is_none() || input.replay_mode == ReplayMode::Off)
        {
            return Err(Error::OneTimeUseUnenforceable);
        }

        if let Some(cache) = input.replay_cache
            && (replay_check_needed(input.replay_mode, identity.is_one_time_use())
                || transaction_replay_entry.is_some())
        {
            // The tombstone must outlive every instant at which the assertion
            // would still validate — see `replay_expires_at`.
            let expires_at = replay_expires_at(identity.not_on_or_after, input.clock_skew)?;
            let assertion_entry = ReplayEntry::assertion(&identity.assertion_id, expires_at);
            // The proxy substitutes its transaction tombstone for the raw
            // assertion ID. `InResponseTo` binds the assertion to that exact
            // transaction, so one namespaced key enforces both assertion and
            // transaction single-use while needing only one cache slot.
            let entry = transaction_replay_entry.unwrap_or(assertion_entry);
            let fresh = cache.check_and_insert(&[entry], input.now)?;
            if !fresh {
                return Err(replay_error);
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
        // Correlate against the tracker BEFORE resolving the artifact. The
        // resolve step is an outbound HTTP request to the IdP's ARS, so
        // checking afterwards would leak a backchannel call to an IdP the
        // request was never issued to.
        self.validate_tracker_context(
            input.tracker,
            input.idp,
            input.expected_destination,
            SsoResponseBinding::HttpArtifact,
        )?;
        let tracker = input.tracker.ok_or(Error::ArtifactTrackerRequired)?;

        // A Type-4 artifact is routing data, not an opaque URL-independent
        // token. Parse and authenticate all routing fields before touching the
        // network: SourceID binds it to the tracked IdP and EndpointIndex
        // selects from the ARS URLs pinned by `start_login`. The fresh
        // descriptor is intentionally not the source of the outbound URL.
        let parsed = crate::binding::artifact::parse_type4_artifact(input.artifact)?;
        let expected_source = crate::binding::artifact::source_id(tracker.idp_entity_id());
        if parsed.source_id != expected_source {
            return Err(Error::ArtifactSourceIdMismatch);
        }
        let ars = tracker
            .idp_artifact_resolution_services()
            .iter()
            .find(|endpoint| endpoint.index == Some(parsed.endpoint_index))
            .ok_or(Error::ArtifactResolutionServiceMismatch {
                index: parsed.endpoint_index,
            })?;

        // Intersection of the caller's verification certificates with those
        // pinned when the login began. Hoisted here so it outlives the
        // borrow the client holds.
        //
        // Equality would break additive rotation: an IdP mid-rotation offers
        // `[old, new]` while only `old` was pinned, and refusing that takes
        // the transaction down for no security gain. Verifying against the
        // intersection accepts `old` and never offers `new`.
        let pinned_certs: Vec<_> = input
            .backchannel
            .as_ref()
            .and_then(|bc| bc.verify.as_ref())
            .map(|verify| {
                verify
                    .certs
                    .iter()
                    .filter(|cert| {
                        tracker
                            .idp_signing_cert_fingerprints()
                            .contains(&cert.fingerprint_sha256())
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        // Route through the first-class BackchannelClient so callers can opt
        // into signing the outbound resolve and/or verifying the inbound
        // envelope signature. ArtifactResponse/Issuer is optional, so the
        // high-level path does not require it: the envelope is authenticated
        // by pinned signing roots or the caller's mutually-authenticated
        // transport, and the embedded Response is independently validated
        // against the tracked IdP below. Low-level callers that require an
        // exact outer Issuer can opt into `expect_response_issuer` directly.
        let mut client = crate::binding::artifact::BackchannelClient::new(http);
        if let Some(bc) = input.backchannel {
            if let Some(sign) = bc.sign {
                client = client.sign_with(sign);
            }
            if let Some(verify) = bc.verify {
                if pinned_certs.is_empty() {
                    return Err(Error::IdpTrustRootMismatch);
                }
                client = client.verify_with(crate::binding::artifact::VerifyConfig {
                    certs: &pinned_certs,
                    ..verify
                });
            }
        }
        let inner_xml = client
            .resolve_artifact(ars.url.as_str(), &self.config.entity_id, input.artifact)
            .await?
            .payload_xml;

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
            replay_mode: input.replay_mode,
            holder_of_key_cert: input.holder_of_key_cert,
        })
    }
}

/// The instant a replay tombstone may be dropped: the last moment the
/// assertion could still pass validation.
///
/// Validation accepts an assertion until `NotOnOrAfter + clock_skew`, so a
/// tombstone expiring at the raw `NotOnOrAfter` would reopen a replay interval
/// `clock_skew` wide during which the assertion still validates but the cache
/// no longer remembers it.
///
/// Fails closed on overflow rather than saturating: a saturated expiry would
/// silently pin the entry near the end of representable time, which for a
/// bounded-capacity cache converts a bad input into `ReplayCacheFull` for
/// unrelated logins. Extracted alongside [`replay_check_needed`] so the
/// fail-closed branch is unit-testable independently of `consume_response` —
/// see `replay_expires_at_fails_closed_on_overflow`, which reaches it
/// directly. It is not reachable *through* `consume_response`: validation
/// computes `now + clock_skew` and `now - clock_skew` first, and with
/// `now` within minutes of `NotOnOrAfter` those guards fire on any skew large
/// enough to overflow here.
fn replay_expires_at(
    not_on_or_after: SystemTime,
    clock_skew: Duration,
) -> Result<SystemTime, Error> {
    not_on_or_after.checked_add(clock_skew).ok_or_else(|| {
        Error::XmlParse("Conditions NotOnOrAfter + clock_skew overflows SystemTime".to_owned())
    })
}

/// Whether the replay cache should be consulted for an assertion, given the
/// caller-selected mode and whether the assertion carried `<OneTimeUse/>`.
/// Encapsulates the policy decision so it can be unit-tested independently
/// of the surrounding `consume_response` machinery.
fn replay_check_needed(mode: ReplayMode, is_one_time_use: bool) -> bool {
    match mode {
        ReplayMode::All => true,
        ReplayMode::OneTimeUseOnly => is_one_time_use,
        ReplayMode::Off => false,
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
        let destination_url =
            url::Url::parse(&slo_endpoint.url).map_err(|_err| Error::InvalidConfiguration {
                reason: "IdP SLO endpoint URL is not a valid URL",
            })?;

        let request_id = crate::binding::random_xml_id()?;
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
        if !self
            .config
            .slo
            .iter()
            .any(|e| e.url == expected_destination)
        {
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
            policy,
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
        if !self
            .config
            .slo
            .iter()
            .any(|e| e.url == expected_destination)
        {
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
            policy,
            self.config.logout_want_signed.requests,
        )?;

        // EncryptedID: now that the request is authenticated, decrypt the
        // subject if the IdP encrypted it to our key. Cleartext NameID requests
        // leave `parsed.name_id` untouched.
        #[cfg(feature = "xmlenc")]
        {
            let decryption_keys: Vec<&KeyPair> = self
                .config
                .decryption_key
                .as_ref()
                .map(|k| vec![k])
                .unwrap_or_default();
            if let Some(name_id) = crate::logout::request_parse::decrypt_encrypted_name_id(
                &document,
                &decryption_keys,
                policy,
            )? {
                parsed.name_id = name_id;
            }
        }

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
        let destination_url =
            url::Url::parse(&slo_endpoint.url).map_err(|_err| Error::InvalidConfiguration {
                reason: "IdP SLO endpoint URL is not a valid URL",
            })?;

        let response_id = crate::binding::random_xml_id()?;
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
        let request_id = crate::binding::random_xml_id()?;
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
        let logout_request_str = std::str::from_utf8(&logout_request_xml)
            .map_err(|_err| Error::XmlEmit("logout request XML is not UTF-8".to_string()))?;
        let soap_envelope = crate::binding::soap::wrap(logout_request_str)?;

        // Dispatch via the caller's HttpClient.
        let request = HttpRequest {
            method: http::Method::POST,
            url: slo_endpoint.url.clone(),
            headers: crate::binding::soap::request_headers(),
            body: soap_envelope.into_bytes(),
        };
        let response = http.send(request).await.map_err(Error::Http)?;

        // Unwrap the SOAP envelope (a <soap:Fault> surfaces as
        // Error::SoapFault) and re-parse the inner element as a standalone
        // document so we can hand it to the regular validate-and-verify path
        // (which needs an ElementId arena rooted on the LogoutResponse).
        let inner_xml = crate::binding::soap::unwrap(&response.body)?.payload_xml()?;
        let inner_doc = Document::parse(&inner_xml)?;
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
                .child_element(Some(DS_NS), "Signature")
                .ok_or(Error::SignatureMissing)?;
            let verified = verify_signature(&inner_doc, sig, &idp.signing_certs, policy)?;
            if verified.signed_element != inner_doc.root().id() {
                return Err(Error::SignatureVerification {
                    reason: "signature does not cover LogoutResponse root",
                });
            }
        } else if let Some(sig) = inner_doc.root().child_element(Some(DS_NS), "Signature") {
            // Signature present but not required: still verify if present.
            let _ = verify_signature(&inner_doc, sig, &idp.signing_certs, policy)?;
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

    /// Same as [`Self::metadata_xml`], plus `<md:Organization>` and
    /// `<md:ContactPerson>` content from `extras`.
    pub fn metadata_xml_with_extras(
        &self,
        sign: bool,
        extras: &MetadataExtras,
    ) -> Result<String, Error> {
        self.emit_metadata(sign, Some(extras))
    }

    fn emit_metadata(&self, sign: bool, extras: Option<&MetadataExtras>) -> Result<String, Error> {
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
            // and re-emit the inner element as standalone XML. A <soap:Fault>
            // body surfaces as Error::SoapFault.
            let _ = is_request;
            let xml = crate::binding::soap::unwrap(body)?.payload_xml()?;
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
    policy: &PeerCryptoPolicy,
    require_signature: bool,
) -> Result<(), Error> {
    match binding {
        Binding::HttpRedirect => {
            match (
                &decoded.signed_query_string,
                &decoded.detached_signature,
                &decoded.detached_sig_alg,
            ) {
                (Some(qs), Some(sig), Some(alg)) => {
                    let sig_alg = SignatureAlgorithm::from_uri(alg)?;
                    verify_detached_signature(
                        qs.as_bytes(),
                        sig,
                        sig_alg,
                        signing_certs,
                        &policy.allowed_signature_algorithms,
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
            let sig_elem = document.root().child_element(Some(DS_NS), "Signature");
            match sig_elem {
                Some(sig) => {
                    let verified = verify_signature(document, sig, signing_certs, policy)?;
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
    use crate::response::SAML_NS as RESPONSE_SAML_NS;
    use crate::response::SAMLP_NS as RESPONSE_SAMLP_NS;
    use crate::response::parse::SUBJECT_CONFIRMATION_BEARER as RESPONSE_SUBJECT_CONFIRMATION_BEARER;
    use crate::xml::emit::emit_document;
    use crate::xml::parse::{Document, Element, Node, QName};
    use std::time::{Duration, UNIX_EPOCH};

    const SECOND_RSA_CERT_PEM: &[u8] = include_bytes!("../examples/demo/keys/sp.crt");
    const SECOND_RSA_KEY_PEM: &[u8] = include_bytes!("../examples/demo/keys/sp.key");

    // ---------- Fixtures ----------

    fn rsa_signing_key() -> KeyPair {
        let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).unwrap();
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        kp.with_certificate(cert)
            .expect("matching test certificate")
    }

    fn second_rsa_signing_key() -> KeyPair {
        KeyPair::from_pkcs8_pem(SECOND_RSA_KEY_PEM)
            .expect("second RSA key")
            .with_certificate(
                X509Certificate::from_pem(SECOND_RSA_CERT_PEM).expect("second RSA cert"),
            )
            .expect("matching second RSA certificate")
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
        assert_eq!(
            result.tracker.acs_endpoint.url,
            "https://sp.example.com/acs"
        );
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
    fn start_login_tracker_pins_idp_signing_roots() {
        let sp = ServiceProvider::new(fixture_sp_config(None, false, false)).unwrap();
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
            .expect("start login");

        assert_eq!(
            result.tracker.idp_signing_cert_fingerprints(),
            &[idp.signing_certs[0].fingerprint_sha256()]
        );
    }

    #[test]
    fn sealed_login_tracker_round_trips_authoritative_policy_and_rejects_tampering() {
        use crate::authn_context::{AuthnContextClassRef, AuthnContextComparison};

        let sp = ServiceProvider::new(fixture_sp_config(None, false, false)).unwrap();
        let idp = fixture_idp();
        let mut tracker = sp
            .start_login(
                &idp,
                StartLogin {
                    relay_state: None,
                    binding: Binding::HttpRedirect,
                    force_authn: false,
                    is_passive: false,
                    requested_name_id_format: Some(NameIdFormat::Persistent),
                    requested_authn_context: Some(RequestedAuthnContext {
                        class_refs: vec![AuthnContextClassRef::MultiFactorAuth],
                        comparison: AuthnContextComparison::Minimum,
                    }),
                    acs_index: None,
                    acs_url: None,
                    response_binding: None,
                },
            )
            .expect("start login")
            .tracker;
        // Pin deterministic time so expiry/future checks do not depend on the
        // wall clock used by start_login.
        tracker.issued_at = fixed_now();
        let key = [0x5au8; 32];
        let blob = tracker.to_payload().seal(&key).expect("seal tracker");

        let opened = LoginTracker::open(
            &blob,
            &key,
            fixed_now() + Duration::from_mins(1),
            Duration::from_mins(2),
        )
        .expect("open tracker");
        assert_eq!(opened.request_id(), tracker.request_id());
        assert_eq!(opened.issued_at(), fixed_now());
        assert_eq!(opened.idp_entity_id(), idp.entity_id);
        assert_eq!(opened.acs_endpoint(), tracker.acs_endpoint());
        assert_eq!(
            opened.requested_name_id_format(),
            Some(&NameIdFormat::Persistent)
        );
        assert_eq!(
            opened.requested_authn_context(),
            tracker.requested_authn_context()
        );
        assert_eq!(
            opened.idp_signing_cert_fingerprints(),
            tracker.idp_signing_cert_fingerprints()
        );
        assert_eq!(
            opened.idp_artifact_resolution_services(),
            tracker.idp_artifact_resolution_services()
        );

        let mut tampered = URL_SAFE_NO_PAD.decode(&blob).expect("sealed base64");
        let last = tampered.last_mut().expect("ciphertext tag");
        *last ^= 1;
        let tampered = URL_SAFE_NO_PAD.encode(tampered);
        assert!(matches!(
            LoginTracker::open(&tampered, &key, fixed_now(), Duration::from_mins(2)),
            Err(Error::DecryptFailed {
                reason: "login tracker"
            })
        ));
    }

    #[test]
    fn sealed_login_tracker_rejects_malformed_expired_and_future_blobs() {
        let tracker = LoginTracker {
            request_id: "_sealed".to_owned(),
            issued_at: fixed_now(),
            idp_entity_id: "https://idp.example.com".to_owned(),
            acs_endpoint: SsoResponseEndpoint::post("https://sp.example.com/acs", 0, true),
            requested_authn_context: None,
            requested_name_id_format: None,
            idp_signing_cert_fingerprints: vec![[7; 32]],
            idp_artifact_resolution_services: vec![],
        };
        let key = [0x31u8; 32];
        let blob = tracker.to_payload().seal(&key).expect("seal tracker");

        let truncated = URL_SAFE_NO_PAD.encode([0u8; 27]);
        for malformed in ["%%not-base64%%", truncated.as_str()] {
            assert!(matches!(
                LoginTracker::open(malformed, &key, fixed_now(), Duration::from_mins(1)),
                Err(Error::DecryptFailed {
                    reason: "login tracker"
                })
            ));
        }
        assert!(matches!(
            LoginTracker::open(
                &blob,
                &key,
                fixed_now() + Duration::from_secs(61),
                Duration::from_mins(1),
            ),
            Err(Error::Expired)
        ));
        assert!(matches!(
            LoginTracker::open(
                &blob,
                &key,
                fixed_now() - Duration::from_secs(301),
                Duration::from_mins(1),
            ),
            Err(Error::InvalidConfiguration {
                reason: "login tracker is dated too far in the future"
            })
        ));
    }

    #[test]
    fn start_login_rejects_an_idp_without_a_signing_root() {
        let sp = ServiceProvider::new(fixture_sp_config(None, false, false)).unwrap();
        let mut idp = fixture_idp();
        idp.signing_certs.clear();

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
            .expect_err("there is no response-validation trust root to pin");

        assert!(matches!(err, Error::NoPeerSigningCert), "got {err:?}");
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
    /// Options block for [`build_signed_response_xml_with_options`]. Keeps the
    /// builder under clippy's `too_many_arguments` ceiling without bouncing
    /// off the lint, and lets new fields land additively.
    struct ResponseFixtureOptions<'a> {
        in_response_to: Option<&'a str>,
        recipient_url: &'a str,
        audience: &'a str,
        not_before: &'a str,
        not_on_or_after: &'a str,
        assertion_id: &'a str,
        one_time_use: bool,
        name_id_format: NameIdFormat,
        sp_name_qualifier: Option<&'a str>,
    }

    fn build_signed_response_xml(
        kp: &KeyPair,
        in_response_to: Option<&str>,
        recipient_url: &str,
        audience: &str,
        not_before: &str,
        not_on_or_after: &str,
    ) -> Vec<u8> {
        build_signed_response_xml_with_options(
            kp,
            &ResponseFixtureOptions {
                in_response_to,
                recipient_url,
                audience,
                not_before,
                not_on_or_after,
                assertion_id: "_a1",
                one_time_use: false,
                name_id_format: NameIdFormat::EmailAddress,
                sp_name_qualifier: None,
            },
        )
    }

    fn build_signed_response_xml_with_options(
        kp: &KeyPair,
        opts: &ResponseFixtureOptions<'_>,
    ) -> Vec<u8> {
        let in_response_to = opts.in_response_to;
        let recipient_url = opts.recipient_url;
        let audience = opts.audience;
        let not_before = opts.not_before;
        let not_on_or_after = opts.not_on_or_after;
        let assertion_id = opts.assertion_id;
        let one_time_use = opts.one_time_use;

        let saml_ns = RESPONSE_SAML_NS;
        let samlp_ns = RESPONSE_SAMLP_NS;
        let bearer = RESPONSE_SUBJECT_CONFIRMATION_BEARER;

        let mut scd_builder = Element::build(QName::new(
            Some(saml_ns.to_owned()),
            "SubjectConfirmationData",
        ))
        .with_attribute(QName::new(None, "Recipient"), recipient_url.to_owned())
        .with_attribute(
            QName::new(None, "NotOnOrAfter"),
            "2026-05-26T12:05:00Z".to_owned(),
        );
        if let Some(irt) = in_response_to {
            scd_builder =
                scd_builder.with_attribute(QName::new(None, "InResponseTo"), irt.to_owned());
        }
        let scd = scd_builder.finish();
        let sc = Element::build(QName::new(Some(saml_ns.to_owned()), "SubjectConfirmation"))
            .with_attribute(QName::new(None, "Method"), bearer.to_owned())
            .with_child(Node::Element(scd))
            .finish();
        let name_id = Element::build(QName::new(Some(saml_ns.to_owned()), "NameID"))
            .with_attribute(
                QName::new(None, "Format"),
                opts.name_id_format.as_uri().to_owned(),
            );
        let name_id = if let Some(qualifier) = opts.sp_name_qualifier {
            name_id.with_attribute(QName::new(None, "SPNameQualifier"), qualifier.to_owned())
        } else {
            name_id
        }
        .with_text("alice@example.com")
        .finish();
        let subject = Element::build(QName::new(Some(saml_ns.to_owned()), "Subject"))
            .with_child(Node::Element(name_id))
            .with_child(Node::Element(sc))
            .finish();

        let aud_el = Element::build(QName::new(Some(saml_ns.to_owned()), "Audience"))
            .with_text(audience)
            .finish();
        let aud_restr = Element::build(QName::new(Some(saml_ns.to_owned()), "AudienceRestriction"))
            .with_child(Node::Element(aud_el))
            .finish();
        let mut conditions_builder =
            Element::build(QName::new(Some(saml_ns.to_owned()), "Conditions"))
                .with_attribute(QName::new(None, "NotBefore"), not_before.to_owned())
                .with_attribute(QName::new(None, "NotOnOrAfter"), not_on_or_after.to_owned())
                .with_child(Node::Element(aud_restr));
        if one_time_use {
            let one_time_use_el =
                Element::build(QName::new(Some(saml_ns.to_owned()), "OneTimeUse")).finish();
            conditions_builder = conditions_builder.with_child(Node::Element(one_time_use_el));
        }
        let conditions = conditions_builder.finish();

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

        let assertion_issuer = Element::build(QName::new(Some(saml_ns.to_owned()), "Issuer"))
            .with_text("https://idp.example.com")
            .finish();
        let assertion = Element::build(QName::new(Some(saml_ns.to_owned()), "Assertion"))
            .with_namespace(Some("saml".to_owned()), saml_ns)
            .with_attribute(QName::new(None, "ID"), assertion_id.to_owned())
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
        let mut response = Element::build(QName::new(Some(samlp_ns.to_owned()), "Response"))
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
            idp_signing_cert_fingerprints: certificate_fingerprint_set(&idp.signing_certs),
            idp_artifact_resolution_services: vec![],
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
                replay_mode: ReplayMode::All,
                holder_of_key_cert: None,
            })
            .expect("consume_response");

        assert_eq!(identity.assertion_id, "_a1");
        assert_eq!(identity.name_id.value, "alice@example.com");
        assert_eq!(identity.name_id.format, NameIdFormat::EmailAddress);
        assert_eq!(identity.session_index.as_deref(), Some("sess-1"));
    }

    #[test]
    fn consume_response_enforces_the_tracked_name_id_format() {
        let kp = rsa_signing_key();
        let sp = ServiceProvider::new(fixture_sp_config(None, false, false)).unwrap();
        let idp = fixture_idp();
        let tracker = LoginTracker {
            request_id: "_req-nameid-format".to_owned(),
            issued_at: fixed_now(),
            idp_entity_id: idp.entity_id.clone(),
            acs_endpoint: sp.config.acs[0].clone(),
            requested_authn_context: None,
            requested_name_id_format: Some(NameIdFormat::Transient),
            idp_signing_cert_fingerprints: certificate_fingerprint_set(&idp.signing_certs),
            idp_artifact_resolution_services: vec![],
        };
        let xml = build_signed_response_xml(
            &kp,
            Some("_req-nameid-format"),
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
                replay_mode: ReplayMode::All,
                holder_of_key_cert: None,
            })
            .expect_err("IdP substituted a different NameID format");

        assert!(matches!(
            err,
            Error::UnsupportedNameIdPolicy { ref requested }
                if requested == NameIdFormat::Transient.as_uri()
        ));
    }

    #[test]
    fn consume_response_rejects_persistent_name_id_scoped_to_another_sp() {
        let kp = rsa_signing_key();
        let sp = ServiceProvider::new(fixture_sp_config(None, false, false)).unwrap();
        let idp = fixture_idp();
        let tracker = LoginTracker {
            request_id: "_req-nameid-scope".to_owned(),
            issued_at: fixed_now(),
            idp_entity_id: idp.entity_id.clone(),
            acs_endpoint: sp.config.acs[0].clone(),
            requested_authn_context: None,
            requested_name_id_format: Some(NameIdFormat::Persistent),
            idp_signing_cert_fingerprints: certificate_fingerprint_set(&idp.signing_certs),
            idp_artifact_resolution_services: vec![],
        };
        let xml = build_signed_response_xml_with_options(
            &kp,
            &ResponseFixtureOptions {
                in_response_to: Some("_req-nameid-scope"),
                recipient_url: "https://sp.example.com/acs",
                audience: "https://sp.example.com",
                not_before: "2026-05-26T11:59:00Z",
                not_on_or_after: "2026-05-26T12:10:00Z",
                assertion_id: "_a-nameid-scope",
                one_time_use: false,
                name_id_format: NameIdFormat::Persistent,
                sp_name_qualifier: Some("https://other-sp.example.com"),
            },
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
                replay_mode: ReplayMode::All,
                holder_of_key_cert: None,
            })
            .expect_err("persistent identifier belongs to another SP");

        assert!(matches!(
            err,
            Error::NameIdSpQualifierMismatch { ref expected, ref got }
                if expected == "https://sp.example.com"
                    && got == "https://other-sp.example.com"
        ));
    }

    #[test]
    fn consume_response_rejects_a_signing_root_introduced_after_start_login() {
        use crate::crypto::cert::test_vectors::EC_P256_CERT_PEM;

        let sp = ServiceProvider::new(fixture_sp_config(None, false, false)).unwrap();
        let trusted = fixture_idp();
        let tracker = sp
            .start_login(
                &trusted,
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
            .expect("start login")
            .tracker;
        let mut substituted = trusted.clone();
        substituted.signing_certs = vec![X509Certificate::from_pem(EC_P256_CERT_PEM).unwrap()];
        let xml = build_signed_response_xml(
            &rsa_signing_key(),
            Some(tracker.request_id()),
            "https://sp.example.com/acs",
            "https://sp.example.com",
            "2026-05-26T11:59:00Z",
            "2026-05-26T12:10:00Z",
        );

        let err = sp
            .consume_response(ConsumeResponse {
                idp: &substituted,
                peer_crypto_policy: None,
                saml_response: &xml,
                binding: SsoResponseBinding::HttpPost,
                relay_state: None,
                tracker: Some(&tracker),
                expected_destination: "https://sp.example.com/acs",
                now: fixed_now(),
                clock_skew: Duration::from_secs(30),
                replay_cache: None,
                replay_mode: ReplayMode::All,
                holder_of_key_cert: None,
            })
            .expect_err("a fresh same-entity signing root must not be trusted");

        assert!(matches!(err, Error::IdpTrustRootMismatch), "got {err:?}");
    }

    #[test]
    fn consume_response_accepts_the_pinned_key_during_additive_rotation() {
        let sp = ServiceProvider::new(fixture_sp_config(None, false, false)).unwrap();
        let trusted = fixture_idp();
        let tracker = sp
            .start_login(
                &trusted,
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
            .expect("start login")
            .tracker;
        let mut rotating = trusted.clone();
        rotating.signing_certs.push(
            second_rsa_signing_key()
                .certificate()
                .expect("second key carries cert")
                .clone(),
        );
        let xml = build_signed_response_xml(
            &rsa_signing_key(),
            Some(tracker.request_id()),
            "https://sp.example.com/acs",
            "https://sp.example.com",
            "2026-05-26T11:59:00Z",
            "2026-05-26T12:10:00Z",
        );

        sp.consume_response(ConsumeResponse {
            idp: &rotating,
            peer_crypto_policy: None,
            saml_response: &xml,
            binding: SsoResponseBinding::HttpPost,
            relay_state: None,
            tracker: Some(&tracker),
            expected_destination: "https://sp.example.com/acs",
            now: fixed_now(),
            clock_skew: Duration::from_secs(30),
            replay_cache: None,
            replay_mode: ReplayMode::All,
            holder_of_key_cert: None,
        })
        .expect("the pinned key remains valid while a new key overlaps");
    }

    #[test]
    fn consume_response_never_uses_the_new_key_in_a_double_signed_response() {
        let mut cfg = fixture_sp_config(None, false, false);
        cfg.want_signed.response = true;
        cfg.want_signed.assertions = true;
        let sp = ServiceProvider::new(cfg).unwrap();
        let trusted = fixture_idp();
        let tracker = sp
            .start_login(
                &trusted,
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
            .expect("start login")
            .tracker;
        let new_key = second_rsa_signing_key();
        let mut rotating = trusted.clone();
        rotating.signing_certs.push(
            new_key
                .certificate()
                .expect("second key carries cert")
                .clone(),
        );

        // The Assertion is signed by the old, pinned key. Add a required
        // Response signature made with the newly introduced key. A singular
        // post-validation fingerprint sees only the Assertion key, so this is
        // the regression that requires filtering verification roots up front.
        let assertion_signed = build_signed_response_xml(
            &rsa_signing_key(),
            Some(tracker.request_id()),
            "https://sp.example.com/acs",
            "https://sp.example.com",
            "2026-05-26T11:59:00Z",
            "2026-05-26T12:10:00Z",
        );
        let document = Document::parse(&assertion_signed).expect("response parses");
        let double_signed = sign_element(
            document.root().clone(),
            &document,
            SignOptions {
                signing_key: &new_key,
                sig_alg: SignatureAlgorithm::RsaSha256,
                digest_alg: DigestAlgorithm::Sha256,
                c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                inclusive_namespaces: &[],
                include_x509_cert: true,
            },
        )
        .expect("sign Response with new key");
        let double_signed = emit_document(&Document::new(double_signed).expect("document"))
            .expect("emit")
            .into_bytes();

        let err = sp
            .consume_response(ConsumeResponse {
                idp: &rotating,
                peer_crypto_policy: None,
                saml_response: &double_signed,
                binding: SsoResponseBinding::HttpPost,
                relay_state: None,
                tracker: Some(&tracker),
                expected_destination: "https://sp.example.com/acs",
                now: fixed_now(),
                clock_skew: Duration::from_secs(30),
                replay_cache: None,
                replay_mode: ReplayMode::All,
                holder_of_key_cert: None,
            })
            .expect_err("a newly introduced key cannot satisfy any required signature");
        assert!(
            matches!(err, Error::SignatureVerification { .. }),
            "got {err:?}"
        );
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
                replay_mode: ReplayMode::All,
                holder_of_key_cert: None,
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
            idp_signing_cert_fingerprints: certificate_fingerprint_set(&idp.signing_certs),
            idp_artifact_resolution_services: vec![],
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
                replay_mode: ReplayMode::All,
                holder_of_key_cert: None,
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
            idp_signing_cert_fingerprints: certificate_fingerprint_set(&idp.signing_certs),
            idp_artifact_resolution_services: vec![],
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
                replay_mode: ReplayMode::All,
                holder_of_key_cert: None,
            })
            .unwrap_err();
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    #[test]
    fn consume_response_rejects_tracker_for_different_idp() {
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let mut idp = fixture_idp();
        let tracker = LoginTracker {
            request_id: "_req1".to_owned(),
            issued_at: fixed_now(),
            idp_entity_id: idp.entity_id.clone(),
            acs_endpoint: sp.config.acs[0].clone(),
            requested_authn_context: None,
            requested_name_id_format: None,
            idp_signing_cert_fingerprints: certificate_fingerprint_set(&idp.signing_certs),
            idp_artifact_resolution_services: vec![],
        };
        idp.entity_id = "https://different-idp.example.com".to_owned();

        let err = sp
            .consume_response(ConsumeResponse {
                idp: &idp,
                peer_crypto_policy: None,
                saml_response: b"not parsed because tracker correlation fails first",
                binding: SsoResponseBinding::HttpPost,
                relay_state: None,
                tracker: Some(&tracker),
                expected_destination: "https://sp.example.com/acs",
                now: fixed_now(),
                clock_skew: Duration::from_secs(30),
                replay_cache: None,
                replay_mode: ReplayMode::All,
                holder_of_key_cert: None,
            })
            .unwrap_err();
        assert!(matches!(
            err,
            Error::IssuerMismatch { expected, got }
                if expected == "https://idp.example.com"
                    && got.as_deref() == Some("https://different-idp.example.com")
        ));
    }

    #[test]
    fn consume_response_rejects_binding_different_from_tracker_acs() {
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
            idp_signing_cert_fingerprints: certificate_fingerprint_set(&idp.signing_certs),
            idp_artifact_resolution_services: vec![],
        };

        let err = sp
            .consume_response(ConsumeResponse {
                idp: &idp,
                peer_crypto_policy: None,
                saml_response: b"not parsed because tracker correlation fails first",
                binding: SsoResponseBinding::HttpArtifact,
                relay_state: None,
                tracker: Some(&tracker),
                expected_destination: "https://sp.example.com/acs",
                now: fixed_now(),
                clock_skew: Duration::from_secs(30),
                replay_cache: None,
                replay_mode: ReplayMode::All,
                holder_of_key_cert: None,
            })
            .unwrap_err();
        assert!(matches!(
            err,
            Error::ResponseBindingMismatch {
                expected: Binding::HttpPost,
                received: Binding::HttpArtifact,
            }
        ));
    }

    // ---------- replay cache ----------

    /// Shared [`ReplayCache`] double recording every `check_and_insert`.
    ///
    /// One double for both the "records the right expiry" and the "must not be
    /// consulted" cases: a cache that only ever panics would leave its own body
    /// uncovered, which is a poor way to assert that something never runs.
    #[derive(Default)]
    struct RecordingReplayCache {
        calls: std::sync::Mutex<Vec<SystemTime>>,
    }

    impl RecordingReplayCache {
        /// Expiries handed to the cache, in call order.
        fn recorded(&self) -> Vec<SystemTime> {
            self.calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    impl ReplayCache for RecordingReplayCache {
        fn check_and_insert(
            &self,
            entries: &[ReplayEntry<'_>],
            _now: SystemTime,
        ) -> Result<bool, Error> {
            // Recover through poisoning rather than mapping it to an error:
            // this double has no failure mode worth modelling, and an error
            // arm here would never execute, leaving a hole in its own
            // coverage.
            self.calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend(entries.iter().map(|entry| entry.expires_at));
            Ok(true)
        }
    }

    #[test]
    fn replay_cache_expiry_includes_accepted_clock_skew() {
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
            idp_signing_cert_fingerprints: certificate_fingerprint_set(&idp.signing_certs),
            idp_artifact_resolution_services: vec![],
        };
        let xml = build_signed_response_xml(
            &kp,
            Some("_req1"),
            "https://sp.example.com/acs",
            "https://sp.example.com",
            "2026-05-26T11:59:00Z",
            "2026-05-26T12:10:00Z",
        );
        let cache = RecordingReplayCache::default();
        let clock_skew = Duration::from_secs(90);

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
                clock_skew,
                replay_cache: Some(&cache),
                replay_mode: ReplayMode::All,
                holder_of_key_cert: None,
            })
            .expect("valid response");

        assert_eq!(
            cache.recorded(),
            vec![
                identity
                    .not_on_or_after
                    .checked_add(clock_skew)
                    .expect("fixture expiry is representable")
            ]
        );
    }

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
            idp_signing_cert_fingerprints: certificate_fingerprint_set(&idp.signing_certs),
            idp_artifact_resolution_services: vec![],
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
                replay_mode: ReplayMode::All,
                holder_of_key_cert: None,
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
                replay_mode: ReplayMode::All,
                holder_of_key_cert: None,
            })
            .expect_err("second consume_response is a replay");
        assert!(
            matches!(err, Error::AssertionReplay),
            "expected Error::AssertionReplay, got {err:?}"
        );
        // Cache size unchanged — replay path doesn't double-insert.
        assert_eq!(cache.len(), 1, "cache size unchanged after replay");
    }

    /// `ReplayMode::OneTimeUseOnly` must accept a replayed assertion that
    /// does NOT carry `<OneTimeUse/>`, mirroring real-world IdPs that
    /// legitimately resend the same `AssertionID` on retry.
    #[test]
    fn replay_mode_one_time_use_only_accepts_repeated_non_one_time_use() {
        let kp = rsa_signing_key();
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let idp = fixture_idp();
        let tracker = LoginTracker {
            request_id: "_req-otu-1".to_owned(),
            issued_at: fixed_now(),
            idp_entity_id: idp.entity_id.clone(),
            acs_endpoint: sp.config.acs[0].clone(),
            requested_authn_context: None,
            requested_name_id_format: None,
            idp_signing_cert_fingerprints: certificate_fingerprint_set(&idp.signing_certs),
            idp_artifact_resolution_services: vec![],
        };
        let xml = build_signed_response_xml_with_options(
            &kp,
            &ResponseFixtureOptions {
                in_response_to: Some("_req-otu-1"),
                recipient_url: "https://sp.example.com/acs",
                audience: "https://sp.example.com",
                not_before: "2026-05-26T11:59:00Z",
                not_on_or_after: "2099-05-26T12:10:00Z",
                assertion_id: "_a-otu-skip",
                one_time_use: false,
                name_id_format: NameIdFormat::EmailAddress,
                sp_name_qualifier: None,
            },
        );
        let cache = crate::replay::InMemoryReplayCache::new(32);

        let first = sp
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
                replay_mode: ReplayMode::OneTimeUseOnly,
                holder_of_key_cert: None,
            })
            .expect("first consume succeeds");
        assert_eq!(first.assertion_id, "_a-otu-skip");
        assert!(!first.is_one_time_use);
        assert_eq!(
            cache.len(),
            0,
            "non-OneTimeUse assertion bypasses the cache"
        );

        // Second consume of the same assertion succeeds: not OneTimeUse, so
        // OneTimeUseOnly mode never offered it to the cache.
        let second = sp
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
                replay_mode: ReplayMode::OneTimeUseOnly,
                holder_of_key_cert: None,
            })
            .expect("second consume must succeed under OneTimeUseOnly");
        assert_eq!(second.assertion_id, "_a-otu-skip");
        assert_eq!(cache.len(), 0, "cache still untouched");
    }

    /// `ReplayMode::OneTimeUseOnly` must still reject a replayed assertion
    /// that carries `<OneTimeUse/>` — spec-mandated minimum (Core §2.5.1.5).
    #[test]
    fn replay_mode_one_time_use_only_rejects_repeated_one_time_use() {
        let kp = rsa_signing_key();
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let idp = fixture_idp();
        let tracker = LoginTracker {
            request_id: "_req-otu-2".to_owned(),
            issued_at: fixed_now(),
            idp_entity_id: idp.entity_id.clone(),
            acs_endpoint: sp.config.acs[0].clone(),
            requested_authn_context: None,
            requested_name_id_format: None,
            idp_signing_cert_fingerprints: certificate_fingerprint_set(&idp.signing_certs),
            idp_artifact_resolution_services: vec![],
        };
        let xml = build_signed_response_xml_with_options(
            &kp,
            &ResponseFixtureOptions {
                in_response_to: Some("_req-otu-2"),
                recipient_url: "https://sp.example.com/acs",
                audience: "https://sp.example.com",
                not_before: "2026-05-26T11:59:00Z",
                not_on_or_after: "2099-05-26T12:10:00Z",
                assertion_id: "_a-otu-must",
                one_time_use: true,
                name_id_format: NameIdFormat::EmailAddress,
                sp_name_qualifier: None,
            },
        );
        let cache = crate::replay::InMemoryReplayCache::new(32);

        let first = sp
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
                replay_mode: ReplayMode::OneTimeUseOnly,
                holder_of_key_cert: None,
            })
            .expect("first OneTimeUse consume succeeds");
        assert!(first.is_one_time_use);
        assert_eq!(
            cache.len(),
            1,
            "OneTimeUse assertion was offered to the cache"
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
                replay_cache: Some(&cache),
                replay_mode: ReplayMode::OneTimeUseOnly,
                holder_of_key_cert: None,
            })
            .expect_err("replay of OneTimeUse assertion must reject");
        assert!(
            matches!(err, Error::AssertionReplay),
            "expected Error::AssertionReplay, got {err:?}"
        );
    }

    /// Core §2.5.1.5 makes `<saml:OneTimeUse>` a MUST. With no cache — or
    /// with `ReplayMode::Off` — there is no way to honour it, and accepting
    /// the assertion anyway silently discards the asserting party's
    /// instruction. It fails closed instead.
    #[test]
    fn one_time_use_without_enforcement_is_refused() {
        let kp = rsa_signing_key();
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let idp = fixture_idp();
        let tracker = LoginTracker {
            request_id: "_req-otu".to_owned(),
            issued_at: fixed_now(),
            idp_entity_id: idp.entity_id.clone(),
            acs_endpoint: sp.config.acs[0].clone(),
            requested_authn_context: None,
            requested_name_id_format: None,
            idp_signing_cert_fingerprints: certificate_fingerprint_set(&idp.signing_certs),
            idp_artifact_resolution_services: vec![],
        };
        let xml = build_signed_response_xml_with_options(
            &kp,
            &ResponseFixtureOptions {
                in_response_to: Some("_req-otu"),
                recipient_url: "https://sp.example.com/acs",
                audience: "https://sp.example.com",
                not_before: "2026-05-26T11:59:00Z",
                not_on_or_after: "2099-05-26T12:10:00Z",
                assertion_id: "_a-otu",
                one_time_use: true,
                name_id_format: NameIdFormat::EmailAddress,
                sp_name_qualifier: None,
            },
        );
        let cache = crate::replay::InMemoryReplayCache::new(32);

        let consume = |replay_cache: Option<&dyn crate::replay::ReplayCache>, mode| {
            sp.consume_response(ConsumeResponse {
                idp: &idp,
                peer_crypto_policy: None,
                saml_response: &xml,
                binding: SsoResponseBinding::HttpPost,
                relay_state: None,
                tracker: Some(&tracker),
                expected_destination: "https://sp.example.com/acs",
                now: fixed_now(),
                clock_skew: Duration::from_secs(30),
                replay_cache,
                replay_mode: mode,
                holder_of_key_cert: None,
            })
        };

        // No cache at all.
        let err = consume(None, ReplayMode::All).expect_err("nothing can enforce it");
        assert!(matches!(err, Error::OneTimeUseUnenforceable), "got {err:?}");

        // A cache, but explicitly disabled.
        let err = consume(Some(&cache), ReplayMode::Off).expect_err("Off cannot enforce it");
        assert!(matches!(err, Error::OneTimeUseUnenforceable), "got {err:?}");

        // With enforcement available it is accepted — once.
        consume(Some(&cache), ReplayMode::All).expect("first consumption is allowed");
        let err = consume(Some(&cache), ReplayMode::All).expect_err("exactly one consumption");
        assert!(matches!(err, Error::AssertionReplay), "got {err:?}");
    }

    /// `ReplayMode::Off` must never consult the cache, even for a literal
    /// repeat of the same assertion bytes.
    ///
    /// Uses an assertion *without* `<saml:OneTimeUse>`: that directive is a
    /// MUST, so it now fails closed rather than being silently discarded by
    /// `Off`. This test is about the opt-out for assertions the spec merely
    /// recommends deduplicating.
    #[test]
    fn replay_mode_off_accepts_repeated_assertion() {
        let kp = rsa_signing_key();
        let cfg = fixture_sp_config(None, false, false);
        let sp = ServiceProvider::new(cfg).unwrap();
        let idp = fixture_idp();
        let tracker = LoginTracker {
            request_id: "_req-off".to_owned(),
            issued_at: fixed_now(),
            idp_entity_id: idp.entity_id.clone(),
            acs_endpoint: sp.config.acs[0].clone(),
            requested_authn_context: None,
            requested_name_id_format: None,
            idp_signing_cert_fingerprints: certificate_fingerprint_set(&idp.signing_certs),
            idp_artifact_resolution_services: vec![],
        };
        let xml = build_signed_response_xml_with_options(
            &kp,
            &ResponseFixtureOptions {
                in_response_to: Some("_req-off"),
                recipient_url: "https://sp.example.com/acs",
                audience: "https://sp.example.com",
                not_before: "2026-05-26T11:59:00Z",
                not_on_or_after: "2099-05-26T12:10:00Z",
                assertion_id: "_a-off",
                one_time_use: false,
                name_id_format: NameIdFormat::EmailAddress,
                sp_name_qualifier: None,
            },
        );
        let cache = crate::replay::InMemoryReplayCache::new(32);

        sp.consume_response(ConsumeResponse {
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
            replay_mode: ReplayMode::Off,
            holder_of_key_cert: None,
        })
        .expect("first consume under Off mode succeeds");

        sp.consume_response(ConsumeResponse {
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
            replay_mode: ReplayMode::Off,
            holder_of_key_cert: None,
        })
        .expect("second consume under Off mode also succeeds — cache never consulted");

        assert_eq!(cache.len(), 0, "cache stays untouched under Off mode");
    }

    #[test]
    fn replay_expires_at_extends_through_the_skew_window() {
        let noa = fixed_now() + Duration::from_mins(10);
        let skew = Duration::from_secs(90);

        assert_eq!(
            replay_expires_at(noa, skew).expect("no overflow"),
            noa + skew,
            "the tombstone must outlive the last instant the assertion validates"
        );
        assert_eq!(
            replay_expires_at(noa, Duration::ZERO).expect("no overflow"),
            noa,
            "zero skew degenerates to the raw NotOnOrAfter"
        );
    }

    #[test]
    fn replay_expires_at_fails_closed_on_overflow() {
        // `Duration::MAX` overflows every platform's `SystemTime`, so this
        // reaches the fail-closed branch without assuming a particular
        // representable range (Unix stores i64 seconds; Windows a 64-bit
        // 100ns FILETIME, a far narrower window).
        let err = replay_expires_at(fixed_now(), Duration::MAX)
            .expect_err("NotOnOrAfter + Duration::MAX cannot be represented");

        // Fails closed rather than saturating: a saturated expiry would pin
        // the entry near the end of representable time and starve a
        // bounded-capacity cache.
        assert!(matches!(
            err,
            Error::XmlParse(ref m) if m == "Conditions NotOnOrAfter + clock_skew overflows SystemTime"
        ));
    }

    /// A `clock_skew` too large to add to a `SystemTime` must be refused
    /// before anything is written to the replay cache.
    ///
    /// The error that surfaces is validation's own overflow guard, not
    /// `replay_expires_at`: `consume_response` computes `now + clock_skew`
    /// (Conditions `NotBefore`, and again for `SubjectConfirmationData`) and
    /// `now - clock_skew` well before the replay block, and `now` sits within
    /// minutes of `NotOnOrAfter`. Any skew large enough to overflow the
    /// tombstone arithmetic therefore trips those first, on every platform.
    /// `replay_expires_at_fails_closed_on_overflow` covers the replay branch
    /// itself. What this test pins is the property that matters at the API
    /// boundary: the call fails closed, and the cache is never consulted.
    #[test]
    fn overflowing_clock_skew_never_reaches_the_replay_cache() {
        let cache = RecordingReplayCache::default();
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
            idp_signing_cert_fingerprints: certificate_fingerprint_set(&idp.signing_certs),
            idp_artifact_resolution_services: vec![],
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
                expected_destination: "https://sp.example.com/acs",
                now: fixed_now(),
                clock_skew: Duration::MAX,
                replay_cache: Some(&cache),
                replay_mode: ReplayMode::All,
                holder_of_key_cert: None,
            })
            .expect_err("an unrepresentable clock skew must fail closed");

        assert!(
            matches!(err, Error::XmlParse(_)),
            "expected XmlParse, got {err:?}"
        );
        assert!(
            cache.recorded().is_empty(),
            "replay cache consulted despite a failed expiry computation"
        );
    }

    #[test]
    fn replay_check_needed_truth_table() {
        // All — always check.
        assert!(replay_check_needed(ReplayMode::All, false));
        assert!(replay_check_needed(ReplayMode::All, true));
        // OneTimeUseOnly — check only when <OneTimeUse/> is set.
        assert!(!replay_check_needed(ReplayMode::OneTimeUseOnly, false));
        assert!(replay_check_needed(ReplayMode::OneTimeUseOnly, true));
        // Off — never check.
        assert!(!replay_check_needed(ReplayMode::Off, false));
        assert!(!replay_check_needed(ReplayMode::Off, true));
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
        let body = build_logout_response_post_form("_wrong", "https://sp.example.com/slo/post");

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
        let descriptor =
            crate::descriptor::SpDescriptor::from_metadata_xml(xml.as_bytes()).expect("reparse");
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
            #[cfg(feature = "idp-disco")]
            discovery_response_endpoints: vec![],
        };
        let xml = sp
            .metadata_xml_with_extras(false, &extras)
            .expect("metadata_xml_with_extras");
        let doc = Document::parse(xml.as_bytes()).expect("parse");
        let org = doc
            .root()
            .child_element(Some("urn:oasis:names:tc:SAML:2.0:metadata"), "Organization")
            .expect("Organization");
        let _ = org;
    }

    // ---------- artifact back-channel envelope verification ----------
    //
    // These cover Item 1: the high-level SP artifact path can opt into
    // verifying the inbound `<samlp:ArtifactResponse>` *envelope* signature
    // (routed through `BackchannelClient`), independently of the inner
    // `<samlp:Response>` validation that always runs downstream.
    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    mod artifact_backchannel {
        use super::*;
        use crate::binding::artifact::VerifyConfig;
        use crate::binding::soap;
        use crate::dsig::algorithms::C14nAlgorithm;
        use crate::http::{HttpClient, HttpRequest, HttpResponse};
        use std::future::Future;
        use std::time::Duration;

        const SAMLP_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
        const SAML_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
        const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
        const ARS_URL: &str = "https://idp.example.com/ars";
        const ARS_INDEX: u16 = 23;

        /// Mock `HttpClient` whose ArtifactResponse echoes the generated
        /// ArtifactResolve ID, as the real synchronous protocol requires.
        struct MockClient {
            signed: bool,
            tamper: bool,
        }

        impl HttpClient for MockClient {
            fn send(
                &self,
                request: HttpRequest,
            ) -> impl Future<
                Output = Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>>,
            > + Send {
                let document = Document::parse(&request.body).expect("resolve parses");
                let resolve = document
                    .find_first(Some(SAMLP_NS), "ArtifactResolve")
                    .expect("ArtifactResolve");
                let request_id = resolve.attribute(None, "ID").expect("resolve ID");
                let body = if self.signed {
                    signed_envelope(request_id, self.tamper)
                } else {
                    let inner = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_inner-art" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"/>"#;
                    crate::binding::artifact::build_artifact_response(
                        "https://idp.example.com",
                        request_id,
                        inner,
                    )
                    .expect("build unsigned envelope")
                    .into_bytes()
                };
                async move {
                    Ok(HttpResponse {
                        status: 200,
                        headers: vec![("Content-Type".to_owned(), "text/xml".to_owned())],
                        body,
                    })
                }
            }
        }

        /// Models a SOAP channel authenticated by mutual TLS: the outer
        /// ArtifactResponse needs no XML signature and deliberately omits its
        /// optional Issuer, while the embedded Response remains signed.
        struct IssuerlessMockClient {
            inner_xml: Vec<u8>,
        }

        impl HttpClient for IssuerlessMockClient {
            fn send(
                &self,
                request: HttpRequest,
            ) -> impl Future<
                Output = Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>>,
            > + Send {
                assert_eq!(request.url, ARS_URL);
                let resolve_document = Document::parse(&request.body).expect("resolve parses");
                let request_id = resolve_document
                    .find_first(Some(SAMLP_NS), "ArtifactResolve")
                    .expect("ArtifactResolve")
                    .attribute(None, "ID")
                    .expect("resolve ID");
                let inner_document =
                    Document::parse(&self.inner_xml).expect("inner Response parses");

                let status_code =
                    Element::build(QName::new(Some(SAMLP_NS.to_owned()), "StatusCode"))
                        .with_attribute(QName::new(None, "Value"), STATUS_SUCCESS.to_owned())
                        .finish();
                let status = Element::build(QName::new(Some(SAMLP_NS.to_owned()), "Status"))
                    .with_child(Node::Element(status_code))
                    .finish();
                let artifact_response =
                    Element::build(QName::new(Some(SAMLP_NS.to_owned()), "ArtifactResponse"))
                        .with_namespace(Some("samlp".to_owned()), SAMLP_NS)
                        .with_attribute(QName::new(None, "ID"), "_issuerless-art-resp")
                        .with_attribute(QName::new(None, "Version"), "2.0")
                        .with_attribute(QName::new(None, "IssueInstant"), "2026-05-26T12:00:00Z")
                        .with_attribute(QName::new(None, "InResponseTo"), request_id.to_owned())
                        .with_child(Node::Element(status))
                        .with_child(Node::Element(inner_document.root().clone()))
                        .finish();
                let body = soap::wrap_element(artifact_response)
                    .expect("wrap issuer-less ArtifactResponse")
                    .into_bytes();

                async move {
                    Ok(HttpResponse {
                        status: 200,
                        headers: vec![("Content-Type".to_owned(), "text/xml".to_owned())],
                        body,
                    })
                }
            }
        }

        /// IdP descriptor advertising an `ArtifactResolutionService` so the SP
        /// artifact path resolves an ARS endpoint.
        fn artifact_idp() -> IdpDescriptor {
            let mut idp = fixture_idp();
            idp.artifact_resolution_endpoints =
                vec![Endpoint::soap(ARS_URL, Some(ARS_INDEX), true)];
            idp
        }

        fn artifact_sp() -> ServiceProvider {
            let mut cfg = fixture_sp_config(None, false, false);
            cfg.acs = vec![SsoResponseEndpoint::artifact(
                "https://sp.example.com/acs",
                0,
                true,
            )];
            ServiceProvider::new(cfg).expect("sp builds")
        }

        /// Build an `<samlp:ArtifactResponse>` SOAP envelope whose
        /// ArtifactResponse element is enveloped-signed with the fixture key.
        /// When `tamper` is set, an attribute is mutated after signing so the
        /// envelope signature no longer verifies.
        fn signed_envelope(request_id: &str, tamper: bool) -> Vec<u8> {
            signed_envelope_with(request_id, tamper, &rsa_signing_key())
        }

        fn signed_envelope_with(request_id: &str, tamper: bool, kp: &KeyPair) -> Vec<u8> {
            let inner = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_inner-art" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer></samlp:Response>"#;
            let inner_doc = Document::parse(inner.as_bytes()).expect("inner parse");
            let inner_elem = inner_doc.root().clone();

            let issuer = Element::build(QName::new(Some(SAML_NS.to_owned()), "Issuer"))
                .with_text("https://idp.example.com".to_owned())
                .finish();
            let status_code = Element::build(QName::new(Some(SAMLP_NS.to_owned()), "StatusCode"))
                .with_attribute(QName::new(None, "Value"), STATUS_SUCCESS.to_owned())
                .finish();
            let status = Element::build(QName::new(Some(SAMLP_NS.to_owned()), "Status"))
                .with_child(Node::Element(status_code))
                .finish();
            let ar = Element::build(QName::new(Some(SAMLP_NS.to_owned()), "ArtifactResponse"))
                .with_namespace(Some("samlp".to_owned()), SAMLP_NS)
                .with_namespace(Some("saml".to_owned()), SAML_NS)
                .with_attribute(QName::new(None, "ID"), "_art-resp".to_owned())
                .with_attribute(QName::new(None, "Version"), "2.0")
                .with_attribute(QName::new(None, "InResponseTo"), request_id.to_owned())
                .with_attribute(QName::new(None, "IssueInstant"), "2026-01-01T00:00:00Z")
                .with_child(Node::Element(issuer))
                .with_child(Node::Element(status))
                .with_child(Node::Element(inner_elem))
                .finish();

            let stash = Document::new(ar).expect("stash doc");
            let signed = sign_element(
                stash.root().clone(),
                &stash,
                SignOptions {
                    signing_key: kp,
                    sig_alg: SignatureAlgorithm::RsaSha256,
                    digest_alg: DigestAlgorithm::Sha256,
                    c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                    inclusive_namespaces: &[],
                    include_x509_cert: true,
                },
            )
            .expect("sign");
            let envelope = soap::wrap_element(signed).expect("wrap");
            if tamper {
                envelope.replace("_art-resp", "_art-TAMP").into_bytes()
            } else {
                envelope.into_bytes()
            }
        }

        fn consume_input<'a>(
            idp: &'a IdpDescriptor,
            tracker: &'a LoginTracker,
            artifact: &'a str,
            backchannel: Option<ArtifactBackchannel<'a>>,
        ) -> ConsumeArtifactResponse<'a> {
            ConsumeArtifactResponse {
                idp,
                peer_crypto_policy: None,
                artifact,
                relay_state: None,
                tracker: Some(tracker),
                expected_destination: "https://sp.example.com/acs",
                now: SystemTime::UNIX_EPOCH
                    .checked_add(Duration::from_hours(490_896))
                    .expect("fixed now fits"),
                clock_skew: Duration::from_mins(2),
                replay_cache: None,
                replay_mode: ReplayMode::All,
                holder_of_key_cert: None,
                backchannel,
            }
        }

        fn tracked_artifact(sp: &ServiceProvider, idp: &IdpDescriptor) -> (LoginTracker, String) {
            let tracker = artifact_tracker(sp, &idp.entity_id, &idp.signing_certs);
            let artifact = crate::binding::artifact::make_artifact(&idp.entity_id, ARS_INDEX)
                .expect("artifact");
            (tracker, artifact)
        }

        /// Mock `HttpClient` that records how many requests it received and
        /// fails loudly if one arrives. Used to prove that tracker
        /// correlation short-circuits the artifact path before the
        /// backchannel resolve.
        #[derive(Default)]
        struct CountingClient {
            calls: std::sync::atomic::AtomicUsize,
            urls: std::sync::Mutex<Vec<String>>,
        }

        impl CountingClient {
            fn calls(&self) -> usize {
                self.calls.load(std::sync::atomic::Ordering::SeqCst)
            }

            fn urls(&self) -> Vec<String> {
                self.urls.lock().expect("URL log lock").clone()
            }
        }

        impl HttpClient for CountingClient {
            fn send(
                &self,
                request: HttpRequest,
            ) -> impl Future<
                Output = Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>>,
            > + Send {
                self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                self.urls.lock().expect("URL log lock").push(request.url);
                async move {
                    Err::<HttpResponse, Box<dyn std::error::Error + Send + Sync>>(
                        "artifact resolve must not be reached".into(),
                    )
                }
            }
        }

        fn artifact_tracker(
            sp: &ServiceProvider,
            idp_entity_id: &str,
            signing_certs: &[X509Certificate],
        ) -> LoginTracker {
            LoginTracker {
                request_id: "_req1".to_owned(),
                issued_at: fixed_now(),
                idp_entity_id: idp_entity_id.to_owned(),
                acs_endpoint: sp.config.acs[0].clone(),
                requested_authn_context: None,
                requested_name_id_format: None,
                idp_signing_cert_fingerprints: certificate_fingerprint_set(signing_certs),
                idp_artifact_resolution_services: vec![Endpoint::soap(
                    ARS_URL,
                    Some(ARS_INDEX),
                    true,
                )],
            }
        }

        async fn consume_artifact_with(
            sp: &ServiceProvider,
            client: &CountingClient,
            idp: &IdpDescriptor,
            tracker: &LoginTracker,
        ) -> Result<Identity, Error> {
            let artifact =
                crate::binding::artifact::make_artifact(tracker.idp_entity_id(), ARS_INDEX)?;
            sp.consume_response_artifact(
                client,
                ConsumeArtifactResponse {
                    idp,
                    peer_crypto_policy: None,
                    artifact: &artifact,
                    relay_state: None,
                    tracker: Some(tracker),
                    expected_destination: "https://sp.example.com/acs",
                    now: fixed_now(),
                    clock_skew: Duration::from_secs(30),
                    replay_cache: None,
                    replay_mode: ReplayMode::All,
                    holder_of_key_cert: None,
                    backchannel: None,
                },
            )
            .await
        }

        /// A tracker naming a different IdP must be rejected *before* the
        /// artifact is dereferenced. Resolving first would send a backchannel
        /// request — carrying the artifact — to an IdP this login was never
        /// issued to.
        #[tokio::test]
        async fn artifact_tracker_idp_mismatch_makes_no_http_call() {
            let sp = artifact_sp();
            let idp = artifact_idp();
            let tracker =
                artifact_tracker(&sp, "https://other-idp.example.com", &idp.signing_certs);
            let client = CountingClient::default();

            let err = consume_artifact_with(&sp, &client, &idp, &tracker)
                .await
                .expect_err("tracker names a different IdP");

            assert!(matches!(
                err,
                Error::IssuerMismatch { ref expected, .. }
                    if expected == "https://other-idp.example.com"
            ));
            assert_eq!(
                client.calls(),
                0,
                "artifact must not be resolved against an uncorrelated IdP"
            );
        }

        /// Same ordering guarantee for the ACS URL leg of the correlation.
        #[tokio::test]
        async fn artifact_tracker_acs_mismatch_makes_no_http_call() {
            let sp = artifact_sp();
            let idp = artifact_idp();
            let mut tracker = artifact_tracker(&sp, &idp.entity_id, &idp.signing_certs);
            tracker.acs_endpoint.url = "https://sp.example.com/other-acs".to_owned();
            let client = CountingClient::default();

            let err = consume_artifact_with(&sp, &client, &idp, &tracker)
                .await
                .expect_err("tracker names a different ACS URL");

            assert!(matches!(err, Error::DestinationMismatch));
            assert_eq!(client.calls(), 0, "artifact must not be resolved");
        }

        #[tokio::test]
        async fn malformed_or_untrusted_artifact_routing_makes_no_http_call() {
            enum ExpectedFailure {
                Malformed,
                Source,
                Index,
            }

            let sp = artifact_sp();
            let idp = artifact_idp();
            let tracker = artifact_tracker(&sp, &idp.entity_id, &idp.signing_certs);

            for (artifact, expected) in [
                ("not-base64".to_owned(), ExpectedFailure::Malformed),
                (
                    crate::binding::artifact::make_artifact(
                        "https://other-idp.example.com",
                        ARS_INDEX,
                    )
                    .expect("artifact"),
                    ExpectedFailure::Source,
                ),
                (
                    crate::binding::artifact::make_artifact(&idp.entity_id, ARS_INDEX + 1)
                        .expect("artifact"),
                    ExpectedFailure::Index,
                ),
            ] {
                let client = CountingClient::default();
                let err = sp
                    .consume_response_artifact(
                        &client,
                        consume_input(&idp, &tracker, &artifact, None),
                    )
                    .await
                    .expect_err("preflight must reject artifact");
                match expected {
                    ExpectedFailure::Malformed => {
                        assert!(matches!(err, Error::MalformedArtifact { .. }));
                    }
                    ExpectedFailure::Source => {
                        assert!(matches!(err, Error::ArtifactSourceIdMismatch));
                    }
                    ExpectedFailure::Index => assert!(matches!(
                        err,
                        Error::ArtifactResolutionServiceMismatch { index }
                            if index == ARS_INDEX + 1
                    )),
                }
                assert_eq!(client.calls(), 0, "artifact preflight must precede HTTP");
            }
        }

        #[tokio::test]
        async fn fresh_descriptor_ars_substitution_cannot_change_destination() {
            let sp = artifact_sp();
            let mut idp = artifact_idp();
            let tracker = artifact_tracker(&sp, &idp.entity_id, &idp.signing_certs);
            idp.artifact_resolution_endpoints = vec![Endpoint::soap(
                "https://attacker.example.com/ars",
                Some(ARS_INDEX),
                true,
            )];
            let artifact = crate::binding::artifact::make_artifact(&idp.entity_id, ARS_INDEX)
                .expect("artifact");
            let client = CountingClient::default();

            let err = sp
                .consume_response_artifact(&client, consume_input(&idp, &tracker, &artifact, None))
                .await
                .expect_err("mock pinned ARS refuses the request");

            assert!(matches!(err, Error::Http(_)), "got {err:?}");
            assert_eq!(client.calls(), 1);
            assert_eq!(client.urls(), vec![ARS_URL.to_owned()]);
        }

        /// A validly-signed envelope passes envelope verification routed
        /// through the SP API; the error (if any) then comes from the *inner*
        /// Response validation, never from the envelope signature stage.
        #[tokio::test]
        async fn sp_verifies_signed_envelope_end_to_end() {
            let sp = artifact_sp();
            let idp = artifact_idp();
            let certs = idp.signing_certs.clone();
            let policy = PeerCryptoPolicy::strong_defaults();
            let client = MockClient {
                signed: true,
                tamper: false,
            };
            let (tracker, artifact) = tracked_artifact(&sp, &idp);

            let bc = ArtifactBackchannel {
                sign: None,
                verify: Some(VerifyConfig {
                    certs: &certs,
                    policy: &policy,
                    require_signed: true,
                }),
            };

            // The envelope signature is valid, so resolution proceeds past the
            // envelope-verify stage. The minimal inner Response is not a
            // fully-valid login, so consume_response rejects it downstream —
            // but crucially NOT with an envelope SignatureVerification/Missing
            // error, which would mean the envelope check itself failed.
            let err = sp
                .consume_response_artifact(
                    &client,
                    consume_input(&idp, &tracker, &artifact, Some(bc)),
                )
                .await
                .expect_err("inner Response is minimal -> downstream rejects");
            assert!(
                !matches!(
                    err,
                    Error::SignatureMissing | Error::SignatureVerification { .. }
                ),
                "envelope signature must have verified; got {err:?}"
            );
        }

        /// Envelope verification uses only current roots pinned when the
        /// transaction began: an overlapping new root neither breaks the old
        /// key nor gains authority itself.
        #[tokio::test]
        async fn sp_filters_artifact_envelope_roots_during_additive_rotation() {
            struct RotatingClient {
                key: KeyPair,
            }

            impl HttpClient for RotatingClient {
                fn send(
                    &self,
                    request: HttpRequest,
                ) -> impl Future<
                    Output = Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>>,
                > + Send {
                    let document = Document::parse(&request.body).expect("resolve parses");
                    let request_id = document
                        .find_first(Some(SAMLP_NS), "ArtifactResolve")
                        .expect("ArtifactResolve")
                        .attribute(None, "ID")
                        .expect("resolve ID");
                    let body = signed_envelope_with(request_id, false, &self.key);
                    async move {
                        Ok(HttpResponse {
                            status: 200,
                            headers: vec![("Content-Type".to_owned(), "text/xml".to_owned())],
                            body,
                        })
                    }
                }
            }

            let sp = artifact_sp();
            let idp = artifact_idp();
            let new_key = second_rsa_signing_key();
            let mut rotating_certs = idp.signing_certs.clone();
            rotating_certs.push(
                new_key
                    .certificate()
                    .expect("second key carries cert")
                    .clone(),
            );
            let policy = PeerCryptoPolicy::strong_defaults();

            for (client, old_key_should_verify) in [
                (
                    RotatingClient {
                        key: rsa_signing_key(),
                    },
                    true,
                ),
                (RotatingClient { key: new_key }, false),
            ] {
                let (tracker, artifact) = tracked_artifact(&sp, &idp);
                let bc = ArtifactBackchannel {
                    sign: None,
                    verify: Some(VerifyConfig {
                        certs: &rotating_certs,
                        policy: &policy,
                        require_signed: true,
                    }),
                };
                let result = sp
                    .consume_response_artifact(
                        &client,
                        consume_input(&idp, &tracker, &artifact, Some(bc)),
                    )
                    .await;
                if old_key_should_verify {
                    let err = result.expect_err("minimal inner Response remains invalid");
                    assert!(
                        !matches!(
                            err,
                            Error::SignatureMissing | Error::SignatureVerification { .. }
                        ),
                        "old pinned envelope key must verify; got {err:?}"
                    );
                } else {
                    assert!(
                        matches!(result, Err(Error::SignatureVerification { .. })),
                        "new envelope key must be ignored; got {result:?}"
                    );
                }
            }
        }

        /// A tampered envelope signature is rejected by the SP artifact path
        /// before any inner-Response processing.
        #[tokio::test]
        async fn sp_rejects_tampered_envelope_signature() {
            let sp = artifact_sp();
            let idp = artifact_idp();
            let certs = idp.signing_certs.clone();
            let policy = PeerCryptoPolicy::strong_defaults();
            let client = MockClient {
                signed: true,
                tamper: true,
            };
            let (tracker, artifact) = tracked_artifact(&sp, &idp);

            let bc = ArtifactBackchannel {
                sign: None,
                verify: Some(VerifyConfig {
                    certs: &certs,
                    policy: &policy,
                    require_signed: true,
                }),
            };

            let err = sp
                .consume_response_artifact(
                    &client,
                    consume_input(&idp, &tracker, &artifact, Some(bc)),
                )
                .await
                .expect_err("tampered envelope signature must be rejected");
            assert!(
                matches!(err, Error::SignatureVerification { .. }),
                "got {err:?}"
            );
        }

        /// `require_signed: true` rejects an unsigned envelope at the SP path.
        #[tokio::test]
        async fn sp_require_signed_rejects_unsigned_envelope() {
            let sp = artifact_sp();
            let idp = artifact_idp();
            let certs = idp.signing_certs.clone();
            let policy = PeerCryptoPolicy::strong_defaults();
            let client = MockClient {
                signed: false,
                tamper: false,
            };
            let (tracker, artifact) = tracked_artifact(&sp, &idp);

            let bc = ArtifactBackchannel {
                sign: None,
                verify: Some(VerifyConfig {
                    certs: &certs,
                    policy: &policy,
                    require_signed: true,
                }),
            };

            let err = sp
                .consume_response_artifact(
                    &client,
                    consume_input(&idp, &tracker, &artifact, Some(bc)),
                )
                .await
                .expect_err("require_signed must reject an unsigned envelope");
            assert!(matches!(err, Error::SignatureMissing), "got {err:?}");
        }

        /// Default (no backchannel config) leaves behavior unchanged: an
        /// unsigned envelope is accepted at the envelope layer and processing
        /// continues to inner-Response validation.
        #[tokio::test]
        async fn sp_default_is_unchanged_no_envelope_check() {
            let sp = artifact_sp();
            let idp = artifact_idp();
            let client = MockClient {
                signed: false,
                tamper: false,
            };
            let (tracker, artifact) = tracked_artifact(&sp, &idp);

            let err = sp
                .consume_response_artifact(&client, consume_input(&idp, &tracker, &artifact, None))
                .await
                .expect_err("minimal inner Response -> downstream rejects");
            // No envelope signature check ran: the failure is a downstream
            // SAML-level rejection, not an envelope SignatureMissing.
            assert!(
                !matches!(err, Error::SignatureMissing),
                "default path must not require an envelope signature; got {err:?}"
            );
        }

        /// SAML Core makes StatusResponseType/Issuer optional. On a mutually
        /// authenticated SOAP channel, an unsigned, issuer-less outer
        /// ArtifactResponse is conforming; trust in the embedded Response is
        /// still established by its own IdP signature and normal SP checks.
        #[tokio::test]
        async fn sp_accepts_issuerless_artifact_response_over_authenticated_transport() {
            let sp = artifact_sp();
            let idp = artifact_idp();
            let (tracker, artifact) = tracked_artifact(&sp, &idp);
            let client = IssuerlessMockClient {
                inner_xml: build_signed_response_xml(
                    &rsa_signing_key(),
                    Some("_req1"),
                    "https://sp.example.com/acs",
                    "https://sp.example.com",
                    "2026-05-26T11:59:00Z",
                    "2026-05-26T12:10:00Z",
                ),
            };

            let identity = sp
                .consume_response_artifact(
                    &client,
                    ConsumeArtifactResponse {
                        idp: &idp,
                        peer_crypto_policy: None,
                        artifact: &artifact,
                        relay_state: None,
                        tracker: Some(&tracker),
                        expected_destination: "https://sp.example.com/acs",
                        now: fixed_now(),
                        clock_skew: Duration::from_secs(30),
                        replay_cache: None,
                        replay_mode: ReplayMode::All,
                        holder_of_key_cert: None,
                        backchannel: None,
                    },
                )
                .await
                .expect("issuer-less ArtifactResponse is conforming");

            assert_eq!(identity.assertion_id, "_a1");
            assert_eq!(identity.name_id.value, "alice@example.com");
        }
    }
}
