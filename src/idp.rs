//! Identity Provider role.
//!
//! Implements the active IdP-role surface defined in RFC-004:
//! [`IdentityProvider`], [`IdentityProviderConfig`], AuthnRequest validation,
//! Response issuance, error Response issuance, and IdP-side Single Logout
//! (RFC-007 §3).
//!
//! ## Scope
//!
//! This module owns the *protocol mechanics* — it does not provide user
//! authentication, session management, MFA, consent flows, attribute storage,
//! or any admin UI. The caller authenticates the user out of band and then
//! asks the library to mint an Assertion.
//!
//! ## Binding-layer responsibility
//!
//! The IdP role consumes already-decoded SAML XML. The caller is responsible
//! for binding-layer decoding *before* calling [`IdentityProvider::consume_authn_request`]
//! or any of the SLO consume methods. The crate exposes a one-call wire
//! decoder for this — [`crate::decode_wire`] — which handles both bindings:
//!
//! - HTTP-Redirect: hand `decode_wire` the raw query string. It percent-,
//!   base64-, and DEFLATE-decodes the `SAMLRequest` / `SAMLResponse` value
//!   and surfaces the detached `Signature` / `SigAlg` / canonical signed
//!   query string in the returned [`crate::DecodedWire`] for plumbing into a
//!   [`DetachedSignature`].
//! - HTTP-POST: hand `decode_wire` the form value (after form-URL decoding).
//!   It base64-decodes into XML.
//! - SOAP: caller unwraps the `soap:Envelope/soap:Body` and hands the inner
//!   SAML element XML to this layer. `decode_wire` does not cover SOAP.
//!
//! This split keeps the signature path explicit — see RFC-004 §2.1 step 6
//! and RFC-007 §5.1 step 5 — and lets the role layer enforce the
//! XML-DSig / detached-signature dispatch consistently.

use std::time::{Duration, SystemTime};

#[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
use aes_gcm::Aes256Gcm;
#[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
use aes_gcm::aead::{Aead as _, KeyInit as _, Payload as AeadPayload};
#[cfg(any(
    feature = "slo",
    all(feature = "artifact-binding", feature = "weak-algos")
))]
use base64::Engine as _;
#[cfg(feature = "slo")]
use base64::engine::general_purpose::STANDARD as BASE64;
#[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
use rand::RngCore as _;

use crate::attribute::Attribute;
use crate::authn::request_parse::parse_authn_request;
use crate::authn::request_validate::validate_authn_request;
use crate::authn_context::AuthnContextClassRef;
#[cfg(any(feature = "slo", test))]
use crate::binding::Dispatch;
use crate::binding::{Binding, Endpoint, SsoResponseBinding, SsoResponseDispatch};
#[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
use crate::crypto::cert::certificate_fingerprint_set;
use crate::crypto::keypair::KeyPair;
use crate::descriptor::SpDescriptor;
use crate::dsig::algorithms::{
    C14nAlgorithm, DigestAlgorithm, PeerCryptoPolicy, SignatureAlgorithm,
};
use crate::dsig::reference::DS_NS;
use crate::dsig::verify::{verify_detached_signature, verify_signature};
use crate::error::Error;
#[cfg(feature = "slo")]
use crate::http::{HttpClient, HttpRequest, HttpResponse};
#[cfg(feature = "slo")]
use crate::logout::request_build::{BuildLogoutRequest, build_logout_request_element};
#[cfg(feature = "slo")]
use crate::logout::request_parse::parse_logout_request;
#[cfg(feature = "slo")]
use crate::logout::response_build::{BuildLogoutResponse, build_logout_response_element};
#[cfg(feature = "slo")]
use crate::logout::response_parse::parse_logout_response;
#[cfg(feature = "slo")]
use crate::logout::{
    ConsumeLogoutRequest, ConsumeLogoutResponse, LogoutDispatch, LogoutOutcome, LogoutStatus,
    LogoutTracker, ParsedLogoutRequest, StartLogout,
};
use crate::metadata::MetadataExtras;
use crate::metadata::emit_idp::{IdpMetadataInputs, emit_idp_metadata};
use crate::nameid::{NameId, NameIdFormat};
#[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
use crate::replay::{ReplayCache, ReplayEntry};
use crate::response::issue::{
    IssueErrorResponseInputs, IssueResponseInputs, SamlStatusCode, issue_error_response,
    issue_response,
};
#[cfg(feature = "slo")]
use crate::xml::emit::emit_document;
use crate::xml::parse::{Document, Element};

pub use crate::authn::request_validate::{AcsSelection, ParsedAuthnRequest};

// =============================================================================
// SAML / SOAP namespaces (local copies — `crate::logout` exposes them only
// pub(crate) and we'd otherwise have to plumb a re-export).
// =============================================================================

#[cfg(test)]
const SAMLP_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";

// =============================================================================
// Configuration
// =============================================================================

/// IdP-side outbound assertion signing flags. SAML 2.0 Core §5 treats
/// Response- and Assertion-level signatures as independent decisions; we group
/// them here so [`IdentityProviderConfig`] stays under the default
/// `struct_excessive_bools` threshold.
#[derive(Debug, Clone, Copy, Default)]
pub struct IdpAssertionSigning {
    /// If true, sign the `<samlp:Response>` envelope.
    pub sign_responses: bool,
    /// If true, sign each `<saml:Assertion>` inside the Response.
    pub sign_assertions: bool,
}

/// IdP-side outbound logout signing flags (RFC-007 §5).
#[cfg(feature = "slo")]
#[derive(Debug, Clone, Copy, Default)]
pub struct IdpLogoutSigning {
    /// If true, outbound LogoutRequest is signed.
    pub sign_requests: bool,
    /// If true, outbound LogoutResponse is signed.
    pub sign_responses: bool,
}

/// IdP-side inbound logout signature requirements (RFC-007 §5).
#[cfg(feature = "slo")]
#[derive(Debug, Clone, Copy, Default)]
pub struct IdpLogoutWantSigned {
    /// If true, reject inbound LogoutRequest unless it carries a valid signature.
    pub requests: bool,
    /// If true, reject inbound LogoutResponse unless it carries a valid signature.
    pub responses: bool,
}

/// IdP role configuration. See RFC-004 §1.
#[derive(Debug, Clone)]
pub struct IdentityProviderConfig {
    pub entity_id: String,
    /// SSO endpoints (where downstream SPs send AuthnRequests).
    pub sso: Vec<Endpoint>,
    /// SLO endpoints.
    pub slo: Vec<Endpoint>,
    /// ArtifactResolutionService endpoints.
    pub artifact_resolution: Vec<Endpoint>,
    pub supported_name_id_formats: Vec<NameIdFormat>,
    pub default_name_id_format: NameIdFormat,
    /// Required — IdP must sign Responses and/or Assertions.
    pub signing_key: KeyPair,
    /// Optional — for decrypting inbound `EncryptedID` / `EncryptedAttribute`
    /// (rare in practice).
    pub decryption_key: Option<KeyPair>,
    pub want_authn_requests_signed: bool,
    /// Outbound assertion / Response signing flags.
    pub assertion_signing: IdpAssertionSigning,
    pub encrypt_assertions_when_possible: bool,
    /// Outbound logout signing flags (RFC-007 §5).
    #[cfg(feature = "slo")]
    pub logout_signing: IdpLogoutSigning,
    /// Inbound logout signature requirements (RFC-007 §5).
    #[cfg(feature = "slo")]
    pub logout_want_signed: IdpLogoutWantSigned,
    pub default_session_duration: Duration,
    pub default_peer_crypto_policy: PeerCryptoPolicy,
    pub outbound_signature_algorithm: SignatureAlgorithm,
    pub outbound_digest_algorithm: DigestAlgorithm,
    pub outbound_c14n: C14nAlgorithm,
    #[cfg(feature = "xmlenc")]
    pub outbound_data_encryption_algorithm: crate::xmlenc::algorithms::DataEncryptionAlgorithm,
    #[cfg(feature = "xmlenc")]
    pub outbound_key_transport_algorithm: crate::xmlenc::algorithms::KeyTransportAlgorithm,
}

/// IdP role handle. Holds the role config plus derived state.
#[derive(Debug, Clone)]
pub struct IdentityProvider {
    config: IdentityProviderConfig,
}

impl IdentityProvider {
    /// Build an [`IdentityProvider`] from validated configuration.
    ///
    /// Validation (RFC-004 §1):
    ///
    /// - `entity_id` MUST parse as an absolute URI. Most IdP/SP federations
    ///   identify entities by URL; the parse is the minimum sanity check.
    /// - `sso` MUST be non-empty — an IdP with no SSO endpoints cannot
    ///   receive AuthnRequests.
    /// - `signing_key` is a required field by type (not `Option`), so its
    ///   presence is enforced by the type system.
    pub fn new(config: IdentityProviderConfig) -> Result<Self, Error> {
        // SAML 2.0 Core §8.3.6: entityID is xs:anyURI; URL shape is
        // RECOMMENDED but not REQUIRED. See ServiceProvider::new for the
        // ecosystem-compat reasoning.
        if config.entity_id.is_empty() || config.entity_id.chars().any(char::is_whitespace) {
            return Err(Error::InvalidConfiguration {
                reason: "IdentityProviderConfig.entity_id must be a non-empty, whitespace-free xs:anyURI",
            });
        }
        if config.sso.is_empty() {
            return Err(Error::InvalidConfiguration {
                reason: "IdentityProviderConfig.sso must contain at least one endpoint",
            });
        }
        if config
            .artifact_resolution
            .iter()
            .any(|endpoint| endpoint.binding != Binding::Soap || endpoint.index.is_none())
        {
            return Err(Error::InvalidConfiguration {
                reason: "IdentityProviderConfig.artifact_resolution endpoints must use SOAP and carry an index",
            });
        }
        let mut ars_indices: Vec<u16> = config
            .artifact_resolution
            .iter()
            .filter_map(|endpoint| endpoint.index)
            .collect();
        ars_indices.sort_unstable();
        if ars_indices
            .windows(2)
            .any(|pair| pair.first() == pair.get(1))
        {
            return Err(Error::InvalidConfiguration {
                reason: "IdentityProviderConfig.artifact_resolution indices must be unique",
            });
        }
        Ok(Self { config })
    }

    /// Borrow the configuration.
    pub fn config(&self) -> &IdentityProviderConfig {
        &self.config
    }

    /// IdP's own `entityID`.
    pub fn entity_id(&self) -> &str {
        &self.config.entity_id
    }
}

// =============================================================================
// Consume AuthnRequest (RFC-004 §2)
// =============================================================================

/// Inputs to [`IdentityProvider::consume_authn_request`]. See RFC-004 §2.
pub struct ConsumeAuthnRequest<'a> {
    pub sp: &'a SpDescriptor,
    /// Per-peer inbound crypto policy. `None` falls back to the IdP's
    /// `default_peer_crypto_policy`.
    pub peer_crypto_policy: Option<&'a PeerCryptoPolicy>,
    /// Already-decoded SAML XML bytes — caller is responsible for binding-
    /// layer decoding before passing the message here (see module docs).
    pub saml_request: &'a [u8],
    pub binding: Binding,
    pub relay_state: Option<&'a str>,
    /// Detached HTTP-Redirect query-string signature, when present. Required
    /// for signed Redirect requests; ignored otherwise.
    pub detached_signature: Option<DetachedSignature<'a>>,
    /// The IdP SSO endpoint URL that received this request. Used to validate
    /// `AuthnRequest/@Destination`. MUST resolve to one of the URLs in
    /// `self.config.sso`.
    pub expected_destination: &'a str,
    pub now: SystemTime,
    pub clock_skew: Duration,
}

/// Detached signature payload extracted from an HTTP-Redirect query string.
/// See SAML 2.0 Bindings §3.4.4.1.
pub struct DetachedSignature<'a> {
    /// Raw signature bytes (already base64-decoded from the `Signature=`
    /// query parameter). Use [`crate::DecodedWire::as_detached_signature`]
    /// to skip the manual wire-decoding.
    pub signature: &'a [u8],
    /// `SigAlg=` algorithm URI.
    pub sig_alg: &'a str,
    /// The canonical signed query string per spec §3.4.4.1.
    pub raw_query_string: &'a str,
}

impl IdentityProvider {
    /// Validate an inbound `<samlp:AuthnRequest>` and return the structured,
    /// security-checked view per RFC-004 §2.1.
    ///
    /// `input.saml_request` is the *already-decoded* SAML XML body — the
    /// caller does binding decoding before calling here (see module-level
    /// docs).
    pub fn consume_authn_request(
        &self,
        input: ConsumeAuthnRequest<'_>,
    ) -> Result<ParsedAuthnRequest, Error> {
        // 1. Parse XML (hardening applied by `Document::parse`).
        let doc = Document::parse(input.saml_request)?;

        // 2. Parse the AuthnRequest envelope. Returns a `RawParsedAuthnRequest`
        //    plus a borrow of the root element handle for signature checks.
        //    `ProtocolBinding` is narrowed here (RFC-004 §2.1 step 5a) and
        //    `Error::IllegalResponseBinding` is propagated.
        let (raw, root) = parse_authn_request(&doc)?;
        let root_id = root.id();

        // 3. Cross-check Issuer / Destination / ACS selection / binding
        //    consistency (RFC-004 §2.1 steps 4, 5, 7, 7a).
        let sso_urls: Vec<String> = self.config.sso.iter().map(|e| e.url.clone()).collect();
        let mut parsed =
            validate_authn_request(raw, input.sp, input.expected_destination, &sso_urls)?;

        // 4. Signature check (RFC-004 §2.1 step 6).
        let policy = input
            .peer_crypto_policy
            .unwrap_or(&self.config.default_peer_crypto_policy);
        let signature_required =
            self.config.want_authn_requests_signed || input.sp.authn_requests_signed;

        match input.binding {
            Binding::HttpRedirect => {
                verify_redirect_request_signature(
                    signature_required,
                    input.detached_signature.as_ref(),
                    &input.sp.signing_certs,
                    &policy.allowed_signature_algorithms,
                )?;
                // Verifying the signature over `raw_query_string` establishes
                // what the SP signed — not that it is what we just parsed.
                // `saml_request`, `relay_state` and `detached_signature` are
                // three independent arguments here, so a caller can present a
                // genuine signed query alongside different XML or a different
                // RelayState and every check still passes. Bind them.
                if let Some(detached) = input.detached_signature.as_ref() {
                    ensure_signed_query_matches(
                        detached.raw_query_string,
                        input.saml_request,
                        input.relay_state,
                    )?;
                }
            }
            Binding::HttpPost | Binding::Soap => {
                verify_envelope_signature(
                    signature_required,
                    &doc,
                    root,
                    root_id,
                    &input.sp.signing_certs,
                    policy,
                )?;
            }
            // Artifact inbound AuthnRequest isn't a real binding — the spec
            // doesn't define artifact-bound AuthnRequests. Reject to keep the
            // call surface explicit.
            Binding::HttpArtifact => {
                return Err(Error::UnsupportedByPeer {
                    binding: Binding::HttpArtifact,
                });
            }
        }

        // Time-skew on AuthnRequest is not part of the spec validation set —
        // `IssueInstant` is informational. We still surface `now` /
        // `clock_skew` so future versions can plug in replay-window checks
        // without breaking the call signature.
        let _ = (input.now, input.clock_skew);

        parsed.seal_relay_state(input.relay_state.map(str::to_owned));
        Ok(parsed)
    }

    /// Convenience wrapper around [`IdentityProvider::consume_authn_request`]
    /// that takes the raw binding wire payload (Redirect query string or POST
    /// `SAMLRequest` form value) instead of pre-decoded XML.
    ///
    /// Internally this delegates to [`crate::decode_wire`] with
    /// [`crate::WireDirection::Request`], extracts any Redirect-binding
    /// detached signature via [`crate::DecodedWire::as_detached_signature`],
    /// and dispatches to [`IdentityProvider::consume_authn_request`]. For
    /// HTTP-POST the `RelayState` rides a separate form field and the decoder
    /// cannot see it; callers MUST set [`ConsumeAuthnRequestWire::relay_state`]
    /// from that form value. For HTTP-Redirect the decoder pulls `RelayState`
    /// from the query string; setting `relay_state` to `Some` overrides the
    /// decoded value, `None` preserves it.
    ///
    /// `input.wire_body` is what would be passed to [`crate::decode_wire`]:
    ///
    /// - HTTP-Redirect: the raw, percent-encoded query string (everything
    ///   after `?`, before `#`).
    /// - HTTP-POST: the base64 `SAMLRequest` form value, already
    ///   form-URL-decoded.
    /// - SOAP / Artifact: rejected as [`Error::UnsupportedByPeer`] — those
    ///   bindings carry richer envelopes and need the explicit
    ///   [`IdentityProvider::consume_authn_request`] path.
    ///
    /// # Errors
    ///
    /// Propagates [`crate::decode_wire`] failures verbatim, then anything
    /// [`IdentityProvider::consume_authn_request`] surfaces.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::time::{Duration, SystemTime};
    /// use saml::{
    ///     Binding, ConsumeAuthnRequestWire, IdentityProvider, SpDescriptor,
    /// };
    ///
    /// # fn run(idp: &IdentityProvider, sp: &SpDescriptor, raw_query: &str)
    /// #     -> Result<(), saml::Error> {
    /// let parsed = idp.consume_authn_request_wire(ConsumeAuthnRequestWire {
    ///     sp,
    ///     peer_crypto_policy: None,
    ///     wire_body: raw_query.as_bytes(),
    ///     binding: Binding::HttpRedirect,
    ///     relay_state: None,
    ///     expected_destination: "https://idp.example.com/sso",
    ///     now: SystemTime::now(),
    ///     clock_skew: Duration::from_secs(60),
    /// })?;
    /// let _ = parsed.id;
    /// # Ok(()) }
    /// ```
    pub fn consume_authn_request_wire(
        &self,
        input: ConsumeAuthnRequestWire<'_>,
    ) -> Result<ParsedAuthnRequest, Error> {
        let decoded = crate::binding::decode_wire(
            input.wire_body,
            input.binding,
            crate::binding::WireDirection::Request,
        )?;
        let detached_signature = decoded.as_detached_signature();
        // On Redirect the RelayState travels in the signed query string, so a
        // separately-supplied value that disagrees would keep the signature
        // valid while swapping the application correlation token. The decoded
        // value is authoritative there; only POST carries RelayState in a
        // separate form field the caller must pass in.
        let resolved_relay_state = if input.binding == Binding::HttpRedirect {
            if let Some(supplied) = input.relay_state
                && Some(supplied) != decoded.relay_state.as_deref()
            {
                return Err(Error::InvalidConfiguration {
                    reason: "Redirect RelayState is covered by the signature; \
                             the supplied value disagrees with the decoded one",
                });
            }
            decoded.relay_state.as_deref()
        } else {
            input.relay_state.or(decoded.relay_state.as_deref())
        };
        self.consume_authn_request(ConsumeAuthnRequest {
            sp: input.sp,
            peer_crypto_policy: input.peer_crypto_policy,
            saml_request: &decoded.xml,
            binding: input.binding,
            relay_state: resolved_relay_state,
            detached_signature,
            expected_destination: input.expected_destination,
            now: input.now,
            clock_skew: input.clock_skew,
        })
    }
}

/// Inputs to [`IdentityProvider::consume_authn_request_wire`] — the wire-level
/// counterpart to [`ConsumeAuthnRequest`] that absorbs the binding-layer
/// decode internally.
pub struct ConsumeAuthnRequestWire<'a> {
    pub sp: &'a SpDescriptor,
    /// Per-peer inbound crypto policy. `None` falls back to the IdP's
    /// `default_peer_crypto_policy`.
    pub peer_crypto_policy: Option<&'a PeerCryptoPolicy>,
    /// Raw binding wire payload — query string for HTTP-Redirect, base64
    /// form value for HTTP-POST. See
    /// [`IdentityProvider::consume_authn_request_wire`] for binding-by-
    /// binding details.
    pub wire_body: &'a [u8],
    pub binding: Binding,
    /// Override the `RelayState` value extracted by the wire decoder. For
    /// HTTP-POST the decoder cannot see `RelayState` (it rides a separate
    /// form field); callers MUST set this from that field. For HTTP-Redirect
    /// the decoder pulls `RelayState` from the query string when present;
    /// setting `Some` here overrides it, `None` preserves it.
    pub relay_state: Option<&'a str>,
    /// The IdP SSO endpoint URL that received this request. Used to validate
    /// `AuthnRequest/@Destination`. MUST resolve to one of the URLs in
    /// `self.config.sso`.
    pub expected_destination: &'a str,
    pub now: SystemTime,
    pub clock_skew: Duration,
}

/// Verify the detached query-string signature on a Redirect AuthnRequest.
fn verify_redirect_request_signature(
    required: bool,
    detached: Option<&DetachedSignature<'_>>,
    candidate_certs: &[crate::crypto::cert::X509Certificate],
    allowed_algorithms: &[SignatureAlgorithm],
) -> Result<(), Error> {
    match detached {
        None if required => Err(Error::SignatureMissing),
        None => Ok(()),
        Some(d) => {
            let sig_alg = SignatureAlgorithm::from_uri(d.sig_alg)?;
            verify_detached_signature(
                d.raw_query_string.as_bytes(),
                d.signature,
                sig_alg,
                candidate_certs,
                allowed_algorithms,
            )?;
            Ok(())
        }
    }
}

/// Verify the enveloped XML-DSig signature on a POST / SOAP envelope SAML
/// message. The verified `signed_element` MUST equal `root_id` — otherwise an
/// XSW attempt has wrapped a signature around a sibling element.
fn verify_envelope_signature(
    required: bool,
    doc: &Document,
    root: &Element,
    root_id: crate::xml::parse::ElementId,
    candidate_certs: &[crate::crypto::cert::X509Certificate],
    policy: &PeerCryptoPolicy,
) -> Result<(), Error> {
    let sig_elem = root.child_element(Some(DS_NS), "Signature");
    match sig_elem {
        None if required => Err(Error::SignatureMissing),
        None => Ok(()),
        Some(sig) => {
            let verified = verify_signature(doc, sig, candidate_certs, policy)?;
            if verified.signed_element != root_id {
                return Err(Error::SignatureVerification {
                    reason: "signature covers a different element than the message root (XSW)",
                });
            }
            Ok(())
        }
    }
}

// =============================================================================
// Issue Response / Error Response (RFC-004 §3 / §4)
// =============================================================================

/// Inputs to [`IdentityProvider::issue_response`]. See RFC-004 §3.
pub struct IssueResponse<'a> {
    pub sp: &'a SpDescriptor,
    pub in_response_to: &'a ParsedAuthnRequest,
    pub name_id: NameId,
    pub attributes: Vec<Attribute>,
    pub authn_instant: SystemTime,
    pub session_index: String,
    pub session_not_on_or_after: Option<SystemTime>,
    pub authn_context_class_ref: AuthnContextClassRef,
    /// `Some(true)` forces encryption; `Some(false)` forbids it; `None` uses
    /// the per-IdP `encrypt_assertions_when_possible` default gated on
    /// `sp.encryption_cert()` presence.
    pub force_encrypt_assertion: Option<bool>,
    pub now: SystemTime,
    pub assertion_lifetime: Duration,
    pub subject_confirmation_lifetime: Duration,
    /// Opt-in Holder-of-Key (SAML V2.0 HoK SSO Profile). When `Some`, the
    /// issued assertion's `<saml:SubjectConfirmation>` uses the holder-of-key
    /// method and embeds this subject certificate in its `<ds:KeyInfo>`. The
    /// SP later confirms the presenter holds the matching key via its client
    /// TLS certificate. When `None` (the default), a bearer confirmation is
    /// emitted.
    pub holder_of_key_cert: Option<&'a crate::crypto::cert::X509Certificate>,
}

/// Inputs to [`IdentityProvider::issue_error_response`]. See RFC-004 §4.
pub struct IssueErrorResponse<'a> {
    pub sp: &'a SpDescriptor,
    pub in_response_to: &'a ParsedAuthnRequest,
    pub status_code: SamlStatusCode,
    pub second_level_status_code: Option<SamlStatusCode>,
    pub message: Option<String>,
    pub now: SystemTime,
}

fn artifact_issuance_without_transaction_error() -> Error {
    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    {
        Error::ArtifactTransactionRequired
    }
    #[cfg(not(all(feature = "artifact-binding", feature = "weak-algos")))]
    {
        Error::UnsupportedByPeer {
            binding: Binding::HttpArtifact,
        }
    }
}

impl IdentityProvider {
    /// Mint and binding-encode a success `<samlp:Response>` for an SP.
    /// See RFC-004 §3.1. This compatibility API refuses HTTP-Artifact because
    /// its return type cannot carry the trust transaction required by an
    /// authenticated ArtifactResolutionService. Use
    /// [`issue_response_with_artifact_transaction`](Self::issue_response_with_artifact_transaction)
    /// for an Artifact-capable request.
    pub fn issue_response(&self, input: IssueResponse<'_>) -> Result<SsoResponseDispatch, Error> {
        if input.in_response_to.validated_acs().binding == SsoResponseBinding::HttpArtifact {
            return Err(artifact_issuance_without_transaction_error());
        }
        self.issue_response_dispatch(input)
    }

    /// Shared success-response implementation. Artifact-capable callers must
    /// immediately bind any Artifact result to request-time provenance.
    fn issue_response_dispatch(
        &self,
        input: IssueResponse<'_>,
    ) -> Result<SsoResponseDispatch, Error> {
        ensure_request_belongs_to_sp(input.in_response_to, input.sp)?;
        match input.force_encrypt_assertion {
            Some(true) => ensure_sp_key_material_matches(input.in_response_to, input.sp)?,
            None if self.config.encrypt_assertions_when_possible => {
                // Compare before consulting the fresh descriptor for key
                // availability. Otherwise removing a transaction-pinned key
                // silently downgrades opportunistic encryption to plaintext.
                ensure_sp_key_material_matches(input.in_response_to, input.sp)?;
            }
            // Explicit plaintext issuance does not consume encryption-key
            // provenance, so ordinary key rotation is irrelevant.
            Some(false) | None => {}
        }
        ensure_authn_context_satisfies_request(
            input.in_response_to,
            &input.authn_context_class_ref,
        )?;
        // Canonical endpoint from the SP's metadata, not the `pub` field:
        // `SsoResponseEndpoint::index` is public too, and artifact issuance
        // names the endpoint by index.
        let acs_endpoint = input.in_response_to.validated_acs();
        let relay_state = input.in_response_to.validated_relay_state();
        let artifact_resolution_service =
            self.artifact_resolution_service_for(acs_endpoint.binding)?;

        // Resolve outbound `NameID` Format from validated provenance. The
        // caller/transform must have minted a value for exactly that format;
        // relabelling its result changes the identifier's signed semantics.
        let chosen_format =
            self.resolve_name_id_format(input.in_response_to.validated_name_id_format())?;
        let name_id = input.name_id;
        ensure_name_id_format(&name_id, &chosen_format)?;

        let inputs = IssueResponseInputs {
            sp: input.sp,
            idp_entity_id: &self.config.entity_id,
            in_response_to: Some(input.in_response_to.validated_request_id()),
            name_id,
            attributes: input.attributes,
            authn_instant: input.authn_instant,
            session_index: input.session_index,
            session_not_on_or_after: input.session_not_on_or_after,
            authn_context_class_ref: input.authn_context_class_ref,
            force_encrypt_assertion: input.force_encrypt_assertion,
            encrypt_assertions_when_possible: self.config.encrypt_assertions_when_possible,
            now: input.now,
            assertion_lifetime: input.assertion_lifetime,
            subject_confirmation_lifetime: input.subject_confirmation_lifetime,
            signing_key: &self.config.signing_key,
            sign_responses: self.config.assertion_signing.sign_responses,
            sign_assertions: self.config.assertion_signing.sign_assertions,
            outbound_signature_algorithm: self.config.outbound_signature_algorithm,
            outbound_digest_algorithm: self.config.outbound_digest_algorithm,
            outbound_c14n: self.config.outbound_c14n,
            #[cfg(feature = "xmlenc")]
            outbound_data_encryption_algorithm: self.config.outbound_data_encryption_algorithm,
            #[cfg(feature = "xmlenc")]
            outbound_key_transport_algorithm: self.config.outbound_key_transport_algorithm,
            acs_endpoint,
            artifact_resolution_service,
            relay_state,
            holder_of_key_cert: input.holder_of_key_cert,
        };

        issue_response(inputs)
    }

    /// Issue an SSO response while preserving the trust transaction required
    /// by authenticated HTTP-Artifact resolution.
    ///
    /// POST results contain only the form dispatch. Artifact results couple
    /// the redirect and an opaque [`ArtifactResolveTransaction`] minted from
    /// the same call's immutable AuthnRequest provenance. Use this API for
    /// every Artifact-capable request; the compatibility
    /// [`issue_response`](Self::issue_response) API refuses Artifact because it
    /// cannot carry this transaction.
    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    pub fn issue_response_with_artifact_transaction(
        &self,
        input: IssueResponse<'_>,
    ) -> Result<IssuedResponse, Error> {
        let in_response_to = input.in_response_to;
        match self.issue_response_dispatch(input)? {
            SsoResponseDispatch::Post(form) => Ok(IssuedResponse::Post(form)),
            SsoResponseDispatch::Artifact(redirect) => {
                let transaction = self.bind_artifact(in_response_to, &redirect)?;
                Ok(IssuedResponse::Artifact(IssuedArtifact {
                    redirect,
                    transaction,
                }))
            }
        }
    }

    /// Resolve NameID negotiation without issuing a response. The proxy uses
    /// this before caller callbacks so an unsupported downstream policy fails
    /// before attribute-release or pseudonym-generation side effects occur.
    pub(crate) fn resolve_name_id_format(
        &self,
        requested: Option<&NameIdFormat>,
    ) -> Result<NameIdFormat, Error> {
        pick_name_id_format(
            requested,
            &self.config.supported_name_id_formats,
            &self.config.default_name_id_format,
        )
    }

    /// Mint and binding-encode an error `<samlp:Response>` for an SP. The
    /// shape mirrors a success Response (same Issuer, Destination, ACS,
    /// signing rules) but carries `Status != Success` and no Assertion.
    /// See RFC-004 §4.
    /// This compatibility API refuses HTTP-Artifact because its return type
    /// cannot carry the required trust transaction. Use
    /// [`issue_error_response_with_artifact_transaction`](Self::issue_error_response_with_artifact_transaction)
    /// for an Artifact-capable request.
    pub fn issue_error_response(
        &self,
        input: IssueErrorResponse<'_>,
    ) -> Result<SsoResponseDispatch, Error> {
        if input.in_response_to.validated_acs().binding == SsoResponseBinding::HttpArtifact {
            return Err(artifact_issuance_without_transaction_error());
        }
        self.issue_error_response_dispatch(input)
    }

    fn issue_error_response_dispatch(
        &self,
        input: IssueErrorResponse<'_>,
    ) -> Result<SsoResponseDispatch, Error> {
        ensure_request_belongs_to_sp(input.in_response_to, input.sp)?;
        // Canonical endpoint from the SP's metadata, not the `pub` field:
        // `SsoResponseEndpoint::index` is public too, and artifact issuance
        // names the endpoint by index.
        let acs_endpoint = input.in_response_to.validated_acs();
        let relay_state = input.in_response_to.validated_relay_state();
        let artifact_resolution_service =
            self.artifact_resolution_service_for(acs_endpoint.binding)?;

        let inputs = IssueErrorResponseInputs {
            idp_entity_id: &self.config.entity_id,
            in_response_to: Some(input.in_response_to.validated_request_id()),
            now: input.now,
            status_code: input.status_code,
            second_level_status_code: input.second_level_status_code,
            message: input.message,
            signing_key: &self.config.signing_key,
            sign_responses: self.config.assertion_signing.sign_responses,
            outbound_signature_algorithm: self.config.outbound_signature_algorithm,
            outbound_digest_algorithm: self.config.outbound_digest_algorithm,
            outbound_c14n: self.config.outbound_c14n,
            acs_endpoint,
            artifact_resolution_service,
            relay_state,
        };

        issue_error_response(inputs)
    }

    /// Issue an error response while preserving the trust transaction needed
    /// for authenticated HTTP-Artifact resolution.
    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    pub fn issue_error_response_with_artifact_transaction(
        &self,
        input: IssueErrorResponse<'_>,
    ) -> Result<IssuedResponse, Error> {
        let in_response_to = input.in_response_to;
        match self.issue_error_response_dispatch(input)? {
            SsoResponseDispatch::Post(form) => Ok(IssuedResponse::Post(form)),
            SsoResponseDispatch::Artifact(redirect) => {
                let transaction = self.bind_artifact(in_response_to, &redirect)?;
                Ok(IssuedResponse::Artifact(IssuedArtifact {
                    redirect,
                    transaction,
                }))
            }
        }
    }

    /// Select the IdP's canonical SOAP ArtifactResolutionService when the
    /// outbound SSO response uses HTTP-Artifact. Its index is embedded in the
    /// Type-4 artifact; the SP ACS index is unrelated.
    fn artifact_resolution_service_for(
        &self,
        response_binding: SsoResponseBinding,
    ) -> Result<Option<&Endpoint>, Error> {
        if response_binding != SsoResponseBinding::HttpArtifact {
            return Ok(None);
        }
        let endpoint = self
            .config
            .artifact_resolution
            .iter()
            .find(|endpoint| endpoint.is_default)
            .or_else(|| self.config.artifact_resolution.first())
            .ok_or(Error::UnsupportedByPeer {
                binding: Binding::HttpArtifact,
            })?;
        if endpoint.binding != Binding::Soap {
            return Err(Error::InvalidConfiguration {
                reason: "ArtifactResolutionService endpoint must use SOAP binding",
            });
        }
        if endpoint.index.is_none() {
            return Err(Error::InvalidConfiguration {
                reason: "ArtifactResolutionService endpoint is missing its required index",
            });
        }
        Ok(Some(endpoint))
    }

    /// Bind an issued Type-4 artifact to the immutable SP provenance of the
    /// AuthnRequest transaction that produced it.
    ///
    /// Persist the returned opaque value beside `artifact.response_xml` under
    /// the exact `artifact.artifact` key. The ArtifactResolutionService must
    /// take that stored pair atomically, but only after
    /// [`consume_artifact_resolve`](Self::consume_artifact_resolve) has
    /// authenticated and replay-reserved the resolve request.
    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    fn bind_artifact(
        &self,
        in_response_to: &ParsedAuthnRequest,
        artifact: &crate::binding::ArtifactRedirect,
    ) -> Result<ArtifactResolveTransaction, Error> {
        if in_response_to.validated_acs().binding != SsoResponseBinding::HttpArtifact {
            return Err(Error::UnsupportedByPeer {
                binding: Binding::HttpArtifact,
            });
        }
        let ars = self
            .artifact_resolution_service_for(SsoResponseBinding::HttpArtifact)?
            .ok_or(Error::UnsupportedByPeer {
                binding: Binding::HttpArtifact,
            })?;
        let ars_index = ars.index.ok_or(Error::InvalidConfiguration {
            reason: "ArtifactResolutionService endpoint is missing its required index",
        })?;
        let parsed = crate::binding::artifact::parse_type4_artifact(&artifact.artifact)?;
        if parsed.endpoint_index != ars_index
            || parsed.source_id != crate::binding::artifact::source_id(&self.config.entity_id)
        {
            return Err(Error::MalformedArtifact {
                reason: "artifact routing does not identify this IdP's selected ARS",
            });
        }

        Ok(ArtifactResolveTransaction {
            artifact: artifact.artifact.clone(),
            sp_entity_id: in_response_to.validated_sp().to_owned(),
            sp_signing_cert_fingerprints: in_response_to
                .validated_signing_cert_fingerprints()
                .to_vec(),
        })
    }

    /// Parse an inbound `<samlp:ArtifactResolve>` SOAP envelope received at
    /// this IdP's `ArtifactResolutionService` endpoint. The caller atomically
    /// takes the one-time artifact value from its store and constructs the response via
    /// [`IdentityProvider::build_artifact_response`].
    ///
    /// This compatibility API performs structural parsing and an issuer-text
    /// comparison only. It does **not** authenticate the request. It may be
    /// used as an untrusted lookup step to locate the transaction stored under
    /// `request.artifact`, provided nothing is removed or disclosed before
    /// [`consume_artifact_resolve`](Self::consume_artifact_resolve) succeeds.
    /// Treating its result as authoritative is safe only when the SOAP
    /// transport already authenticates the SP with mutual TLS. Otherwise use
    /// [`IdentityProvider::consume_artifact_resolve`] to verify the root XML
    /// signature, destination, and freshness.
    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    pub fn parse_artifact_resolve(
        &self,
        sp: &SpDescriptor,
        soap_envelope: &[u8],
    ) -> Result<crate::binding::artifact::ArtifactResolveRequest, Error> {
        let req = crate::binding::artifact::parse_artifact_resolve(soap_envelope)?;
        if req.issuer != sp.entity_id {
            return Err(Error::IssuerMismatch {
                expected: sp.entity_id.clone(),
                got: Some(req.issuer.clone()),
            });
        }
        Ok(req)
    }

    /// Validate and authenticate an inbound ArtifactResolve.
    ///
    /// The request must use SAML 2.0, name `input.expected_destination`, carry
    /// the supplied SP issuer, fall within `clock_skew` of `now`, and satisfy
    /// the configured root-signature requirement. A present signature is
    /// always verified even when `require_signed` is false.
    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    pub fn consume_artifact_resolve(
        &self,
        input: ConsumeArtifactResolve<'_>,
    ) -> Result<crate::binding::artifact::ArtifactResolveRequest, Error> {
        let (request, unwrapped) =
            crate::binding::artifact::unwrap_artifact_resolve(input.soap_envelope)?;
        let document = unwrapped.document_ref();
        let root = document.root();

        let artifact_route =
            crate::binding::artifact::parse_type4_artifact(&input.transaction.artifact)?;
        if artifact_route.source_id != crate::binding::artifact::source_id(&self.config.entity_id) {
            return Err(Error::MalformedArtifact {
                reason: "artifact SourceID does not identify this IdP",
            });
        }
        let Some(receiving_ars) = self
            .config
            .artifact_resolution
            .iter()
            .find(|endpoint| endpoint.index == Some(artifact_route.endpoint_index))
        else {
            return Err(Error::MalformedArtifact {
                reason: "artifact endpoint index is not registered by this IdP",
            });
        };
        if receiving_ars.binding != Binding::Soap || receiving_ars.url != input.expected_destination
        {
            return Err(Error::InvalidConfiguration {
                reason: "expected_destination is not the ArtifactResolutionService selected by the artifact",
            });
        }
        if input.clock_skew.is_zero() {
            return Err(Error::InvalidConfiguration {
                reason: "ArtifactResolve clock_skew must be greater than zero",
            });
        }
        if request.issuer != input.sp.entity_id {
            return Err(Error::IssuerMismatch {
                expected: input.sp.entity_id.clone(),
                got: Some(request.issuer.clone()),
            });
        }
        if request.issuer != input.transaction.sp_entity_id {
            return Err(Error::IssuerMismatch {
                expected: input.transaction.sp_entity_id.clone(),
                got: Some(request.issuer.clone()),
            });
        }
        if request.artifact != input.transaction.artifact {
            return Err(Error::MalformedArtifact {
                reason: "ArtifactResolve does not match the issued artifact transaction",
            });
        }
        if root.attribute(None, "Destination") != Some(input.expected_destination) {
            return Err(Error::DestinationMismatch);
        }

        let issue_instant = root
            .attribute(None, "IssueInstant")
            .ok_or_else(|| Error::XmlParse("ArtifactResolve: missing @IssueInstant".to_owned()))
            .and_then(crate::time::parse_xs_datetime)?;
        let earliest = input
            .now
            .checked_sub(input.clock_skew)
            .ok_or_else(|| Error::XmlParse("now - clock_skew overflows SystemTime".to_owned()))?;
        let latest = input
            .now
            .checked_add(input.clock_skew)
            .ok_or_else(|| Error::XmlParse("now + clock_skew overflows SystemTime".to_owned()))?;
        if issue_instant < earliest || issue_instant > latest {
            return Err(Error::Expired);
        }

        let signature = root.child_element(Some(DS_NS), "Signature");
        match signature {
            Some(signature) => {
                // Metadata rotation may retire a root during the transaction,
                // but it must never introduce signing authority that the
                // AuthnRequest was not validated against. Empty fresh roots
                // cannot authenticate an XML signature. The unsigned branch
                // remains available only for explicitly mTLS-authenticated
                // transports.
                let current_sp_roots = certificate_fingerprint_set(&input.sp.signing_certs);
                if current_sp_roots.is_empty()
                    || !current_sp_roots.iter().all(|fingerprint| {
                        input
                            .transaction
                            .sp_signing_cert_fingerprints
                            .contains(fingerprint)
                    })
                {
                    return Err(Error::ArtifactSpTrustRootMismatch);
                }
                let policy = input
                    .peer_crypto_policy
                    .unwrap_or(&self.config.default_peer_crypto_policy);
                let verified =
                    verify_signature(document, signature, &input.sp.signing_certs, policy)?;
                if verified.signed_element != root.id() {
                    return Err(Error::SignatureVerification {
                        reason: "ArtifactResolve signature does not cover the message root",
                    });
                }
            }
            None if input.require_signed => return Err(Error::SignatureMissing),
            None => {}
        }

        // Reserve only after every structural, correlation, trust, freshness,
        // and signature check. This prevents invalid traffic from poisoning
        // the cache while ensuring the caller cannot take the artifact before
        // a captured signed request loses its replay race.
        // Freshness accepts both endpoints. ReplayCache expiry is exclusive
        // (`expires_at <= now` is evicted), so retain the tombstone one tick
        // beyond the inclusive upper endpoint.
        let replay_expires_at = issue_instant
            .checked_add(input.clock_skew)
            .and_then(|expires_at| expires_at.checked_add(Duration::from_nanos(1)))
            .ok_or_else(|| {
                Error::XmlParse("ArtifactResolve replay expiry overflows SystemTime".to_owned())
            })?;
        let replay_id = format!("{}\0{}", input.transaction.sp_entity_id, request.request_id);
        if !input.replay_cache.check_and_insert(
            &[ReplayEntry::artifact_resolve(&replay_id, replay_expires_at)],
            input.now,
        )? {
            return Err(Error::ArtifactResolveReplay);
        }

        Ok(request)
    }

    /// Build and sign an outbound `<samlp:ArtifactResponse>` SOAP envelope wrapping
    /// `payload_xml` (typically the previously-stashed `<samlp:Response>`
    /// atomically taken by `request.artifact`). `request` must be the
    /// [`crate::binding::artifact::ArtifactResolveRequest`] returned from the
    /// authenticated [`IdentityProvider::consume_artifact_resolve`] path (or
    /// the mTLS-only [`IdentityProvider::parse_artifact_resolve`] path).
    ///
    /// The returned SOAP envelope is ready to be served as the HTTP response
    /// body with `Content-Type: text/xml`.
    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    pub fn build_artifact_response(
        &self,
        request: &crate::binding::artifact::ArtifactResolveRequest,
        payload_xml: &str,
    ) -> Result<String, Error> {
        let unsigned = crate::binding::artifact::build_artifact_response(
            &self.config.entity_id,
            &request.request_id,
            payload_xml,
        )?;
        let body = crate::binding::soap::unwrap(unsigned.as_bytes())?;
        let signed = self.maybe_sign_outbound(body.payload().clone(), true)?;
        crate::binding::soap::wrap_element(signed)
    }
}

/// Security-bearing input to [`IdentityProvider::consume_artifact_resolve`].
#[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
pub struct ConsumeArtifactResolve<'a> {
    pub sp: &'a SpDescriptor,
    /// Opaque trust record stored with the exact one-time artifact at issue.
    pub transaction: &'a ArtifactResolveTransaction,
    /// Linearizable insert-if-absent store for authenticated request IDs.
    pub replay_cache: &'a dyn ReplayCache,
    pub peer_crypto_policy: Option<&'a PeerCryptoPolicy>,
    pub soap_envelope: &'a [u8],
    /// Exact IdP ArtifactResolutionService URL receiving this SOAP request.
    pub expected_destination: &'a str,
    pub now: SystemTime,
    /// Positive freshness tolerance. Zero is rejected because SAML wire
    /// timestamps are quantized and cannot reliably equal the receiver's
    /// higher-precision clock.
    pub clock_skew: Duration,
    /// When true, reject an unsigned request. When false, a present signature
    /// is still verified rather than ignored.
    pub require_signed: bool,
}

/// SSO response issued with the artifact-resolution trust transaction intact.
#[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
#[derive(Debug)]
pub enum IssuedResponse {
    Post(crate::binding::SsoResponsePostForm),
    Artifact(IssuedArtifact),
}

/// An Artifact redirect and the opaque transaction that must be persisted
/// beside its response XML.
#[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
#[derive(Debug)]
pub struct IssuedArtifact {
    pub redirect: crate::binding::ArtifactRedirect,
    pub transaction: ArtifactResolveTransaction,
}

/// Opaque trust and correlation record for one issued Type-4 artifact.
///
/// It has no public constructor, mutable fields, or unauthenticated
/// deserialization path. The IdP role creates it only from a validated
/// AuthnRequest and the exact issued artifact through
/// [`IdentityProvider::issue_response_with_artifact_transaction`].
#[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
#[derive(Clone)]
pub struct ArtifactResolveTransaction {
    artifact: String,
    sp_entity_id: String,
    sp_signing_cert_fingerprints: Vec<[u8; 32]>,
}

#[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
#[derive(serde::Serialize, serde::Deserialize)]
struct ArtifactResolveTransactionWire {
    artifact: String,
    sp_entity_id: String,
    sp_signing_cert_fingerprints: Vec<[u8; 32]>,
}

#[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
impl std::fmt::Debug for ArtifactResolveTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArtifactResolveTransaction")
            .finish_non_exhaustive()
    }
}

#[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
impl ArtifactResolveTransaction {
    /// Seal this transaction into authenticated opaque bytes suitable for a
    /// database, cache, or another worker.
    ///
    /// The 32-byte key is the transaction-issuing trust root: anyone holding it
    /// can produce a blob `open` will accept. Keep it server-side and separate
    /// from untrusted artifact values.
    pub fn seal(&self, key: &[u8; 32]) -> Result<String, Error> {
        let wire = ArtifactResolveTransactionWire {
            artifact: self.artifact.clone(),
            sp_entity_id: self.sp_entity_id.clone(),
            sp_signing_cert_fingerprints: self.sp_signing_cert_fingerprints.clone(),
        };
        let plaintext =
            postcard::to_allocvec(&wire).map_err(|_err| Error::InvalidConfiguration {
                reason: "artifact transaction serialize",
            })?;
        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|_err| Error::InvalidConfiguration {
                reason: "AES-256-GCM key size mismatch",
            })?;
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                aes_gcm::Nonce::from_slice(&nonce_bytes),
                AeadPayload {
                    msg: &plaintext,
                    aad: b"saml-artifact-resolve-transaction-v1",
                },
            )
            .map_err(|_err| Error::DecryptFailed {
                reason: "artifact transaction",
            })?;
        let mut bytes = Vec::with_capacity(12usize.saturating_add(ciphertext.len()));
        bytes.extend_from_slice(&nonce_bytes);
        bytes.extend_from_slice(&ciphertext);
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Authenticate and recover a transaction previously produced by
    /// [`seal`](Self::seal).
    pub fn open(blob: &str, key: &[u8; 32]) -> Result<Self, Error> {
        let bytes =
            URL_SAFE_NO_PAD
                .decode(blob.as_bytes())
                .map_err(|_err| Error::DecryptFailed {
                    reason: "artifact transaction",
                })?;
        if bytes.len() < 12 + 16 {
            return Err(Error::DecryptFailed {
                reason: "artifact transaction",
            });
        }
        let (nonce, ciphertext) = bytes.split_at(12);
        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|_err| Error::InvalidConfiguration {
                reason: "AES-256-GCM key size mismatch",
            })?;
        let plaintext = cipher
            .decrypt(
                aes_gcm::Nonce::from_slice(nonce),
                AeadPayload {
                    msg: ciphertext,
                    aad: b"saml-artifact-resolve-transaction-v1",
                },
            )
            .map_err(|_err| Error::DecryptFailed {
                reason: "artifact transaction",
            })?;
        let wire: ArtifactResolveTransactionWire =
            postcard::from_bytes(&plaintext).map_err(|_err| Error::DecryptFailed {
                reason: "artifact transaction",
            })?;
        if wire.artifact.is_empty() || wire.sp_entity_id.is_empty() {
            return Err(Error::DecryptFailed {
                reason: "artifact transaction",
            });
        }
        Ok(Self {
            artifact: wire.artifact,
            sp_entity_id: wire.sp_entity_id,
            sp_signing_cert_fingerprints: wire.sp_signing_cert_fingerprints,
        })
    }
}

/// Confirm a validated `AuthnRequest` actually came from the SP the caller is
/// now issuing to.
///
/// [`ParsedAuthnRequest`] is only produced by `consume_authn_request`, which
/// checks the request's `<saml:Issuer>` against *one* [`SpDescriptor`]. Nothing
/// carries that binding forward, so the issue methods take `sp` and
/// `in_response_to` as independent parameters and would otherwise let a caller
/// pair a request from SP-A with SP-B's descriptor.
///
/// The result is an assertion audienced to SP-B and encrypted to SP-B's key,
/// delivered to SP-A's `AssertionConsumerService` URL — the ACS is resolved
/// from the request, everything else from `sp`. A conforming SP rejects it on
/// `AudienceRestriction`, but that is the *peer's* check saving us; the IdP
/// should not emit a cross-wired assertion in the first place, and an SP that
/// flattens audience groups would accept it.
/// Refuse to sign an assertion whose `<saml:AuthnContextClassRef>` does not
/// satisfy what the SP's validated request asked for.
///
/// The proxy enforces this on its own relay path, but every IdP built on this
/// crate reaches issuance directly, and nothing here checked it: an
/// `Exact(MultiFactorAuth)` request could be answered with a signed Password
/// assertion. The SP is expected to re-check on receipt, but an IdP should not
/// mint the downgrade in the first place — and an SP that omits the check has
/// no other line of defence.
///
/// Uses the validated provenance rather than the `pub` field, and collapses
/// `NotSatisfied` and `NotComparable` alike, matching the SP-side validator
/// and the proxy.
fn ensure_authn_context_satisfies_request(
    request: &ParsedAuthnRequest,
    emitted: &AuthnContextClassRef,
) -> Result<(), Error> {
    let Some(requested) = request.validated_authn_context() else {
        return Ok(());
    };
    match crate::authn_context::StandardComparator.evaluate(requested, emitted.as_uri()) {
        crate::authn_context::ComparatorOutcome::Satisfied => Ok(()),
        crate::authn_context::ComparatorOutcome::NotSatisfied
        | crate::authn_context::ComparatorOutcome::NotComparable => {
            Err(Error::AuthnContextDowngrade)
        }
    }
}

/// Confirm the XML and RelayState we were handed are the ones inside the
/// signed Redirect query.
///
/// The signature covers `raw_query_string`; without this, that proves only
/// that *some* request was signed by the SP. A caller holding one genuine
/// signed query could pair it with any XML — a request for a different ACS,
/// a different subject, a different `ForceAuthn` — and the signature check
/// would still pass.
/// Confirm the SP descriptor carries the encryption key material this request
/// was validated against.
///
/// Issuance encrypts the assertion to `sp`'s certificate, and entity ID plus
/// ACS do not pin that: a descriptor with the same identity and a substituted
/// certificate has the assertion encrypted to the substituted key, and one
/// with the certificate removed silently downgrades opportunistic encryption
/// to plaintext.
///
/// Compared as a set. Metadata ordering is not semantically meaningful, and an
/// order-sensitive check refuses a peer that merely re-serialized its
/// descriptor — a false positive that teaches callers to work around the
/// check.
///
/// Applied only where an assertion is actually encrypted. Error responses
/// carry none, so failing them on key material would reject the very path a
/// deployment uses to report trouble.
fn ensure_sp_key_material_matches(
    request: &ParsedAuthnRequest,
    sp: &SpDescriptor,
) -> Result<(), Error> {
    let mut sealed = request.validated_encryption_cert_fingerprints().to_vec();
    let mut current: Vec<[u8; 32]> = sp
        .encryption_certs
        .iter()
        .map(crate::crypto::cert::X509Certificate::fingerprint_sha256)
        .collect();
    sealed.sort_unstable();
    sealed.dedup();
    current.sort_unstable();
    current.dedup();
    if current == sealed {
        Ok(())
    } else {
        Err(Error::SpKeyMaterialMismatch)
    }
}

fn ensure_signed_query_matches(
    raw_query_string: &str,
    saml_request: &[u8],
    relay_state: Option<&str>,
) -> Result<(), Error> {
    let decoded = crate::binding::decode_wire(
        raw_query_string.as_bytes(),
        Binding::HttpRedirect,
        crate::binding::WireDirection::Request,
    )?;

    if decoded.xml != saml_request {
        return Err(Error::SignatureVerification {
            reason: "saml_request is not the XML covered by the detached Redirect signature",
        });
    }
    if decoded.relay_state.as_deref() != relay_state {
        return Err(Error::SignatureVerification {
            reason: "relay_state is not the value covered by the detached Redirect signature",
        });
    }
    Ok(())
}

fn ensure_request_belongs_to_sp(
    request: &ParsedAuthnRequest,
    sp: &SpDescriptor,
) -> Result<(), Error> {
    // Correlate on the provenance binding, not on the wire-derived fields.
    //
    // `issuer` and `assertion_consumer_service` are both `pub`, so neither can
    // carry provenance: a caller can validate against SP-A and rewrite either
    // or both to SP-B's values, and a check built on them agrees. Comparing
    // ACS membership does not close it either — SP-A and SP-B may legitimately
    // share a URL and binding. `validated_sp()` records what
    // `validate_authn_request` actually saw and no caller can set it.
    if request.validated_sp() != sp.entity_id {
        return Err(Error::IssuerMismatch {
            expected: request.validated_sp().to_owned(),
            got: Some(sp.entity_id.clone()),
        });
    }
    Ok(())
}

/// Pick the `NameID` Format for the outbound Assertion. The SP-requested
/// format wins iff it appears in our `supported_name_id_formats`; otherwise
/// we fall back to the IdP default. This matches the SAML 2.0 NameIDPolicy
/// negotiation rules (Core §3.4.1.1).
/// Resolve the outbound `NameID` Format.
///
/// Core §3.4.1.1: an explicit `<samlp:NameIDPolicy>/@Format` the IdP cannot
/// produce is an error, not an invitation to substitute. Falling back handed
/// the SP an identifier with different semantics under a request it believed
/// was satisfied — a persistent pseudonym where it asked for a transient one,
/// for instance. The default applies only when the SP requested nothing.
fn pick_name_id_format(
    requested: Option<&NameIdFormat>,
    supported: &[NameIdFormat],
    default: &NameIdFormat,
) -> Result<NameIdFormat, Error> {
    match requested {
        Some(fmt) if supported.contains(fmt) => Ok(fmt.clone()),
        Some(fmt) => Err(Error::UnsupportedNameIdPolicy {
            requested: fmt.as_uri().to_owned(),
        }),
        None => Ok(default.clone()),
    }
}

fn ensure_name_id_format(name_id: &NameId, expected: &NameIdFormat) -> Result<(), Error> {
    if &name_id.format == expected {
        Ok(())
    } else {
        Err(Error::NameIdFormatMismatch {
            expected: expected.as_uri().to_owned(),
            got: name_id.format.as_uri().to_owned(),
        })
    }
}

// =============================================================================
// IdP-side SLO (RFC-007 §3 / §5)
// =============================================================================

#[cfg(feature = "slo")]
impl IdentityProvider {
    /// Validate an inbound `<samlp:LogoutRequest>` per RFC-007 §5.1.
    pub fn consume_logout_request(
        &self,
        sp: &SpDescriptor,
        input: ConsumeLogoutRequest<'_>,
    ) -> Result<ParsedLogoutRequest, Error> {
        let ConsumeLogoutRequest {
            peer_crypto_policy,
            body,
            binding,
            detached_signature,
            expected_destination,
            now,
            clock_skew,
        } = input;
        let doc = Document::parse(body)?;
        let (mut parsed, root_id) = parse_logout_request(&doc)?;

        // Issuer match.
        if parsed.issuer != sp.entity_id {
            return Err(Error::IssuerMismatch {
                expected: sp.entity_id.clone(),
                got: Some(parsed.issuer.clone()),
            });
        }

        // Destination binding (§5.1 step 4).
        if !self
            .config
            .slo
            .iter()
            .any(|e| e.url == expected_destination)
        {
            return Err(Error::InvalidConfiguration {
                reason: "expected_destination is not a registered SLO endpoint",
            });
        }
        if let Some(dest) = parsed.destination.as_deref()
            && dest != expected_destination
        {
            return Err(Error::DestinationMismatch);
        }

        // Signature (§5.1 step 5).
        let policy = peer_crypto_policy.unwrap_or(&self.config.default_peer_crypto_policy);
        let signature_required = self.config.logout_want_signed.requests;
        verify_logout_signature(
            signature_required,
            binding,
            &doc,
            root_id,
            detached_signature.as_ref(),
            &sp.signing_certs,
            policy,
        )?;

        // EncryptedID (§5.1): now that the request is authenticated, decrypt the
        // subject if the SP encrypted it to our key. Cleartext NameID requests
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
                &doc,
                &decryption_keys,
                policy,
            )? {
                parsed.name_id = name_id;
            }
        }

        // NotOnOrAfter (§5.1 step 6).
        if let Some(noa) = parsed.not_on_or_after
            && noa <= now.checked_sub(clock_skew).unwrap_or(now)
        {
            return Err(Error::Expired);
        }

        // RelayState rides the binding envelope, not the XML; let the caller
        // supply it via a follow-up assignment if needed.
        parsed.relay_state = None;
        Ok(parsed)
    }

    /// Build a `<samlp:LogoutResponse>` to echo back to the SP. The output is
    /// already binding-encoded — POST returns a [`Dispatch::Post`], Redirect a
    /// [`Dispatch::Redirect`], SOAP returns the raw XML wrapped in a
    /// `soap:Envelope` (a [`Dispatch::Post`] of MIME `text/xml`). See
    /// RFC-007 §5.3.
    pub fn build_logout_response(
        &self,
        sp: &SpDescriptor,
        in_response_to: &ParsedLogoutRequest,
        status: LogoutStatus,
        relay_state: Option<&str>,
        binding: Binding,
    ) -> Result<Dispatch, Error> {
        let destination_endpoint = sp
            .slo_endpoint(binding)
            .ok_or(Error::UnsupportedByPeer { binding })?;

        let id = crate::binding::random_xml_id()?;
        let build = BuildLogoutResponse {
            id: &id,
            issue_instant: SystemTime::now(),
            issuer_entity_id: &self.config.entity_id,
            destination: Some(destination_endpoint.url.as_str()),
            in_response_to: in_response_to.id.as_str(),
            status,
            status_message: None,
        };
        let element = build_logout_response_element(&build)?;
        let element =
            self.maybe_sign_outbound(element, self.config.logout_signing.sign_responses)?;
        let xml = serialize_element(element)?;

        encode_logout_dispatch_response(binding, &destination_endpoint.url, &xml, relay_state)
    }

    /// Initiate IdP-side SLO toward an SP — typically for chain propagation
    /// when the IdP is acting as a proxy. RFC-007 §3.
    pub fn start_logout(
        &self,
        sp: &SpDescriptor,
        opts: StartLogout<'_>,
    ) -> Result<LogoutDispatch, Error> {
        let destination_endpoint =
            sp.slo_endpoint(opts.binding)
                .ok_or(Error::UnsupportedByPeer {
                    binding: opts.binding,
                })?;

        let id = crate::binding::random_xml_id()?;
        let issue_instant = SystemTime::now();
        let build = BuildLogoutRequest {
            id: &id,
            issue_instant,
            issuer_entity_id: &self.config.entity_id,
            destination: Some(destination_endpoint.url.as_str()),
            not_on_or_after: None,
            reason: opts.reason,
            name_id: opts.name_id,
            session_index: opts.session_index,
        };
        let element = build_logout_request_element(&build)?;

        // For POST we sign the enveloped XML in place. For Redirect we sign
        // the canonical query string in the binding-encode helper. SOAP is a
        // back-channel binding and not representable as a front-channel
        // `Dispatch`; callers wanting SOAP SLO must use
        // [`send_soap_logout_request`](Self::send_soap_logout_request).
        let dispatch = match opts.binding {
            Binding::HttpRedirect => {
                let xml = serialize_element(element)?;
                encode_logout_redirect_request(
                    &destination_endpoint.url,
                    &xml,
                    opts.relay_state,
                    self.config.logout_signing.sign_requests.then_some(self),
                )?
            }
            Binding::HttpPost => {
                let element =
                    self.maybe_sign_outbound(element, self.config.logout_signing.sign_requests)?;
                let xml = serialize_element(element)?;
                crate::binding::post::encode_request(
                    &parse_url(&destination_endpoint.url)?,
                    &xml,
                    opts.relay_state,
                )
            }
            Binding::Soap => {
                return Err(Error::InvalidConfiguration {
                    reason: "Soap SLO must go through send_soap_logout_request, not start_logout",
                });
            }
            Binding::HttpArtifact => {
                return Err(Error::UnsupportedByPeer {
                    binding: Binding::HttpArtifact,
                });
            }
        };

        let tracker = LogoutTracker {
            request_id: id,
            issued_at: issue_instant,
            peer_entity_id: sp.entity_id.clone(),
        };
        Ok(LogoutDispatch { tracker, dispatch })
    }

    /// Validate an inbound `<samlp:LogoutResponse>` per RFC-007 §5.2.
    pub fn consume_logout_response(
        &self,
        sp: &SpDescriptor,
        input: ConsumeLogoutResponse<'_>,
    ) -> Result<LogoutOutcome, Error> {
        let ConsumeLogoutResponse {
            peer_crypto_policy,
            body,
            binding,
            detached_signature,
            tracker,
            expected_destination,
            now,
            clock_skew,
        } = input;
        // `now` and `clock_skew` are accepted for API symmetry with SLO §5.2;
        // LogoutResponse has no time-bound attribute to validate against.
        let _ = (now, clock_skew);

        let doc = Document::parse(body)?;
        let (parsed, root_id) = parse_logout_response(&doc)?;

        // Issuer match.
        if parsed.issuer != sp.entity_id {
            return Err(Error::IssuerMismatch {
                expected: sp.entity_id.clone(),
                got: Some(parsed.issuer.clone()),
            });
        }

        // Destination binding (§5.2 step 4).
        if !self
            .config
            .slo
            .iter()
            .any(|e| e.url == expected_destination)
        {
            return Err(Error::InvalidConfiguration {
                reason: "expected_destination is not a registered SLO endpoint",
            });
        }
        if let Some(dest) = parsed.destination.as_deref()
            && dest != expected_destination
        {
            return Err(Error::DestinationMismatch);
        }

        // Signature (§5.2 step 5).
        let policy = peer_crypto_policy.unwrap_or(&self.config.default_peer_crypto_policy);
        let signature_required = self.config.logout_want_signed.responses;
        verify_logout_signature(
            signature_required,
            binding,
            &doc,
            root_id,
            detached_signature.as_ref(),
            &sp.signing_certs,
            policy,
        )?;

        // InResponseTo match (§5.2 step 6).
        if parsed.in_response_to != tracker.request_id {
            return Err(Error::InResponseToMismatch);
        }

        Ok(parsed.to_outcome())
    }

    /// Convenience wrapper around [`IdentityProvider::consume_logout_request`]
    /// that takes the raw binding wire payload instead of pre-decoded XML.
    ///
    /// Internally this delegates to [`crate::decode_wire`] with
    /// [`crate::WireDirection::Request`] (a `<samlp:LogoutRequest>` rides the
    /// `SAMLRequest=…` parameter on Redirect / POST), extracts any
    /// Redirect-binding detached signature via
    /// [`crate::DecodedWire::as_detached_signature`], and dispatches to
    /// [`IdentityProvider::consume_logout_request`].
    ///
    /// See [`IdentityProvider::consume_authn_request_wire`] for the details on
    /// what `wire_body` should contain per binding.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::time::{Duration, SystemTime};
    /// use saml::{
    ///     Binding, ConsumeLogoutRequestWire, IdentityProvider, SpDescriptor,
    /// };
    ///
    /// # fn run(idp: &IdentityProvider, sp: &SpDescriptor, raw_query: &str)
    /// #     -> Result<(), saml::Error> {
    /// let parsed = idp.consume_logout_request_wire(ConsumeLogoutRequestWire {
    ///     sp,
    ///     peer_crypto_policy: None,
    ///     wire_body: raw_query.as_bytes(),
    ///     binding: Binding::HttpRedirect,
    ///     expected_destination: "https://idp.example.com/slo",
    ///     now: SystemTime::now(),
    ///     clock_skew: Duration::from_secs(60),
    /// })?;
    /// let _ = parsed.id;
    /// # Ok(()) }
    /// ```
    pub fn consume_logout_request_wire(
        &self,
        input: ConsumeLogoutRequestWire<'_>,
    ) -> Result<ParsedLogoutRequest, Error> {
        let decoded = crate::binding::decode_wire(
            input.wire_body,
            input.binding,
            crate::binding::WireDirection::Request,
        )?;
        let detached_signature = decoded.as_detached_signature();
        self.consume_logout_request(
            input.sp,
            ConsumeLogoutRequest {
                peer_crypto_policy: input.peer_crypto_policy,
                body: &decoded.xml,
                binding: input.binding,
                detached_signature,
                expected_destination: input.expected_destination,
                now: input.now,
                clock_skew: input.clock_skew,
            },
        )
    }

    /// Convenience wrapper around [`IdentityProvider::consume_logout_response`]
    /// that takes the raw binding wire payload instead of pre-decoded XML.
    ///
    /// Internally this delegates to [`crate::decode_wire`] with
    /// [`crate::WireDirection::Response`] (a `<samlp:LogoutResponse>` rides
    /// the `SAMLResponse=…` parameter on Redirect / POST), extracts any
    /// Redirect-binding detached signature via
    /// [`crate::DecodedWire::as_detached_signature`], and dispatches to
    /// [`IdentityProvider::consume_logout_response`].
    ///
    /// See [`IdentityProvider::consume_authn_request_wire`] for the details on
    /// what `wire_body` should contain per binding.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::time::{Duration, SystemTime};
    /// use saml::{
    ///     Binding, ConsumeLogoutResponseWire, IdentityProvider, LogoutTracker, SpDescriptor,
    /// };
    ///
    /// # fn run(
    /// #     idp: &IdentityProvider,
    /// #     sp: &SpDescriptor,
    /// #     tracker: &LogoutTracker,
    /// #     raw_query: &str,
    /// # ) -> Result<(), saml::Error> {
    /// let outcome = idp.consume_logout_response_wire(ConsumeLogoutResponseWire {
    ///     sp,
    ///     peer_crypto_policy: None,
    ///     wire_body: raw_query.as_bytes(),
    ///     binding: Binding::HttpRedirect,
    ///     tracker,
    ///     expected_destination: "https://idp.example.com/slo",
    ///     now: SystemTime::now(),
    ///     clock_skew: Duration::from_secs(60),
    /// })?;
    /// let _ = outcome;
    /// # Ok(()) }
    /// ```
    pub fn consume_logout_response_wire(
        &self,
        input: ConsumeLogoutResponseWire<'_>,
    ) -> Result<LogoutOutcome, Error> {
        let decoded = crate::binding::decode_wire(
            input.wire_body,
            input.binding,
            crate::binding::WireDirection::Response,
        )?;
        let detached_signature = decoded.as_detached_signature();
        self.consume_logout_response(
            input.sp,
            ConsumeLogoutResponse {
                peer_crypto_policy: input.peer_crypto_policy,
                body: &decoded.xml,
                binding: input.binding,
                detached_signature,
                tracker: input.tracker,
                expected_destination: input.expected_destination,
                now: input.now,
                clock_skew: input.clock_skew,
            },
        )
    }

    /// Back-channel SOAP-bound SLO toward an SP. Sends the outbound
    /// `<samlp:LogoutRequest>` and consumes the synchronous SOAP
    /// `<samlp:LogoutResponse>` reply. See RFC-007 §6.
    pub async fn send_soap_logout_request<H: HttpClient>(
        &self,
        http: &H,
        sp: &SpDescriptor,
        peer_crypto_policy: Option<&PeerCryptoPolicy>,
        opts: StartLogout<'_>,
    ) -> Result<LogoutOutcome, Error> {
        if !matches!(opts.binding, Binding::Soap) {
            return Err(Error::InvalidConfiguration {
                reason: "send_soap_logout_request requires StartLogout.binding = Soap",
            });
        }

        let destination_endpoint =
            sp.slo_endpoint(Binding::Soap)
                .ok_or(Error::UnsupportedByPeer {
                    binding: Binding::Soap,
                })?;

        let id = crate::binding::random_xml_id()?;
        let issue_instant = SystemTime::now();
        let build = BuildLogoutRequest {
            id: &id,
            issue_instant,
            issuer_entity_id: &self.config.entity_id,
            destination: Some(destination_endpoint.url.as_str()),
            not_on_or_after: None,
            reason: opts.reason,
            name_id: opts.name_id,
            session_index: opts.session_index,
        };
        let element = build_logout_request_element(&build)?;
        let element =
            self.maybe_sign_outbound(element, self.config.logout_signing.sign_requests)?;
        let xml = serialize_element(element)?;
        let xml_str = std::str::from_utf8(&xml)
            .map_err(|_err| Error::XmlEmit("non-UTF-8 outbound XML".to_string()))?;
        let envelope = wrap_soap_envelope(xml_str)?;

        let request = HttpRequest {
            method: http::Method::POST,
            url: destination_endpoint.url.clone(),
            headers: crate::binding::soap::request_headers(),
            body: envelope.into_bytes(),
        };
        let HttpResponse { body, .. } = http.send(request).await.map_err(Error::Http)?;
        let response_xml = unwrap_soap_envelope(&body)?;

        let tracker = LogoutTracker {
            request_id: id,
            issued_at: issue_instant,
            peer_entity_id: sp.entity_id.clone(),
        };
        // For SOAP back-channel SLO the response is the synchronous HTTP
        // reply; there is no real "endpoint that received the response."
        // We thread the IdP's own SLO endpoint URL through as the expected
        // destination so the registration check in `consume_logout_response`
        // passes; well-behaved SPs omit `Destination` from SOAP replies, so
        // the per-message `Destination` mismatch branch is a no-op here.
        let expected_destination = self
            .config
            .slo
            .first()
            .map(|e| e.url.clone())
            .unwrap_or_default();
        self.consume_logout_response(
            sp,
            ConsumeLogoutResponse {
                peer_crypto_policy,
                body: &response_xml,
                binding: Binding::Soap,
                detached_signature: None,
                tracker: &tracker,
                expected_destination: &expected_destination,
                now: SystemTime::now(),
                clock_skew: Duration::ZERO,
            },
        )
    }

    /// Sign `element` in place when `should_sign`. Helper that wires the
    /// outbound algorithm config into the dsig signer.
    fn maybe_sign_outbound(&self, element: Element, should_sign: bool) -> Result<Element, Error> {
        if !should_sign {
            return Ok(element);
        }
        let stash = Document::new(element)?;
        crate::dsig::sign::sign_element(
            stash.root().clone(),
            &stash,
            crate::dsig::sign::SignOptions {
                signing_key: &self.config.signing_key,
                sig_alg: self.config.outbound_signature_algorithm,
                digest_alg: self.config.outbound_digest_algorithm,
                c14n_alg: self.config.outbound_c14n,
                inclusive_namespaces: &[],
                include_x509_cert: true,
            },
        )
    }
}

/// Inputs to [`IdentityProvider::consume_logout_request_wire`] — the wire-level
/// counterpart to [`ConsumeLogoutRequest`] that absorbs the binding-layer
/// decode internally.
#[cfg(feature = "slo")]
pub struct ConsumeLogoutRequestWire<'a> {
    pub sp: &'a SpDescriptor,
    /// Per-peer inbound crypto policy. `None` falls back to the IdP's
    /// `default_peer_crypto_policy`.
    pub peer_crypto_policy: Option<&'a PeerCryptoPolicy>,
    /// Raw binding wire payload — query string for HTTP-Redirect, base64
    /// form value for HTTP-POST. See
    /// [`IdentityProvider::consume_authn_request_wire`] for binding-by-
    /// binding details.
    pub wire_body: &'a [u8],
    pub binding: Binding,
    pub expected_destination: &'a str,
    pub now: SystemTime,
    pub clock_skew: Duration,
}

/// Inputs to [`IdentityProvider::consume_logout_response_wire`] — the
/// wire-level counterpart to [`ConsumeLogoutResponse`] that absorbs the
/// binding-layer decode internally.
#[cfg(feature = "slo")]
pub struct ConsumeLogoutResponseWire<'a> {
    pub sp: &'a SpDescriptor,
    /// Per-peer inbound crypto policy. `None` falls back to the IdP's
    /// `default_peer_crypto_policy`.
    pub peer_crypto_policy: Option<&'a PeerCryptoPolicy>,
    /// Raw binding wire payload — query string for HTTP-Redirect, base64
    /// form value for HTTP-POST. See
    /// [`IdentityProvider::consume_authn_request_wire`] for binding-by-
    /// binding details.
    pub wire_body: &'a [u8],
    pub binding: Binding,
    /// The tracker recorded when the matching `<samlp:LogoutRequest>` was
    /// sent — provides the `InResponseTo` anchor (RFC-007 §5.2 step 6).
    pub tracker: &'a LogoutTracker,
    pub expected_destination: &'a str,
    pub now: SystemTime,
    pub clock_skew: Duration,
}

/// Verify the signature on an inbound SLO message. POST/SOAP get the embedded
/// XML-DSig path; Redirect goes through detached signature verification using
/// the (optional) `detached` parameter.
#[cfg(feature = "slo")]
fn verify_logout_signature(
    required: bool,
    binding: Binding,
    doc: &Document,
    root_id: crate::xml::parse::ElementId,
    detached: Option<&DetachedSignature<'_>>,
    candidate_certs: &[crate::crypto::cert::X509Certificate],
    policy: &PeerCryptoPolicy,
) -> Result<(), Error> {
    match binding {
        Binding::HttpRedirect => verify_redirect_request_signature(
            required,
            detached,
            candidate_certs,
            &policy.allowed_signature_algorithms,
        ),
        Binding::HttpPost | Binding::Soap => {
            let root = doc.element(root_id).ok_or(Error::SignatureVerification {
                reason: "could not locate root element for signature check",
            })?;
            verify_envelope_signature(required, doc, root, root_id, candidate_certs, policy)
        }
        Binding::HttpArtifact => Err(Error::UnsupportedByPeer {
            binding: Binding::HttpArtifact,
        }),
    }
}

/// Wrap a SAML protocol message XML body in a SOAP 1.1 envelope.
#[cfg(feature = "slo")]
fn wrap_soap_envelope(saml_xml: &str) -> Result<String, Error> {
    crate::binding::soap::wrap(saml_xml)
}

/// Unwrap a SOAP 1.1 envelope and return the inner SAML protocol message
/// element re-serialized to XML bytes. A `<soap:Fault>` body surfaces as
/// [`Error::SoapFault`].
#[cfg(feature = "slo")]
fn unwrap_soap_envelope(envelope_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    crate::binding::soap::unwrap(envelope_bytes)?.payload_xml()
}

/// Encode an outbound LogoutResponse over the requested binding. POST returns
/// a `Dispatch::Post`; Redirect returns a `Dispatch::Redirect`; SOAP returns
/// a `Dispatch::Post` carrying the SOAP envelope.
#[cfg(feature = "slo")]
fn encode_logout_dispatch_response(
    binding: Binding,
    destination_url: &str,
    xml: &[u8],
    relay_state: Option<&str>,
) -> Result<Dispatch, Error> {
    let dest = parse_url(destination_url)?;
    match binding {
        Binding::HttpPost => Ok(crate::binding::post::encode_response(
            &dest,
            xml,
            relay_state,
        )),
        Binding::HttpRedirect => crate::binding::redirect::encode_unsigned(
            &dest,
            crate::binding::redirect::RedirectDirection::Response,
            xml,
            relay_state,
        ),
        Binding::Soap => {
            let xml_str = std::str::from_utf8(xml)
                .map_err(|_err| Error::XmlEmit("non-UTF-8 outbound XML".to_string()))?;
            let envelope = wrap_soap_envelope(xml_str)?;
            Ok(Dispatch::Post(crate::binding::PostForm {
                action: dest,
                saml_request: None,
                saml_response: Some(BASE64.encode(envelope.as_bytes())),
                relay_state: relay_state.map(str::to_owned),
            }))
        }
        Binding::HttpArtifact => Err(Error::UnsupportedByPeer {
            binding: Binding::HttpArtifact,
        }),
    }
}

/// Encode a Redirect-bound outbound LogoutRequest. When `signer` is `Some` the
/// canonical query string is signed by the IdP's `signing_key` per spec
/// §3.4.4.1; otherwise an unsigned redirect is emitted.
#[cfg(feature = "slo")]
fn encode_logout_redirect_request(
    destination_url: &str,
    xml: &[u8],
    relay_state: Option<&str>,
    signer: Option<&IdentityProvider>,
) -> Result<Dispatch, Error> {
    let dest = parse_url(destination_url)?;
    match signer {
        None => crate::binding::redirect::encode_unsigned(
            &dest,
            crate::binding::redirect::RedirectDirection::Request,
            xml,
            relay_state,
        ),
        Some(idp) => {
            let sig_alg = idp.config.outbound_signature_algorithm;
            let sig_alg_uri = sig_alg.uri().to_owned();
            let signing_key = &idp.config.signing_key;
            crate::binding::redirect::encode_signed(
                &dest,
                crate::binding::redirect::RedirectDirection::Request,
                xml,
                relay_state,
                &sig_alg_uri,
                |to_sign| crate::dsig::sign::sign_detached_query(to_sign, signing_key, sig_alg),
            )
        }
    }
}

/// Parse a URL string into a [`url::Url`], surfacing the standard library
/// error as an `InvalidConfiguration`.
#[cfg(feature = "slo")]
fn parse_url(url: &str) -> Result<url::Url, Error> {
    url::Url::parse(url).map_err(|_err| Error::InvalidConfiguration {
        reason: "endpoint URL is not a valid URL",
    })
}

/// Wrap an [`Element`] in a fresh [`Document`] and serialize to UTF-8 bytes.
#[cfg(feature = "slo")]
fn serialize_element(element: Element) -> Result<Vec<u8>, Error> {
    let doc = Document::new(element)?;
    Ok(emit_document(&doc)?.into_bytes())
}

// =============================================================================
// Metadata (RFC-004 §6 / RFC-006 §6.2)
// =============================================================================

impl IdentityProvider {
    /// Emit IdP `<md:EntityDescriptor>` XML with the configured signing /
    /// encryption certs, endpoints, and NameID formats. Optionally sign.
    pub fn metadata_xml(&self, sign: bool) -> Result<String, Error> {
        self.metadata_xml_with_extras(sign, &MetadataExtras::default())
    }

    /// Same as [`metadata_xml`](Self::metadata_xml) but additionally emits the
    /// optional `<md:Organization>` and `<md:ContactPerson>` payloads.
    pub fn metadata_xml_with_extras(
        &self,
        sign: bool,
        extras: &MetadataExtras,
    ) -> Result<String, Error> {
        let signing_cert =
            self.config
                .signing_key
                .certificate()
                .ok_or(Error::InvalidConfiguration {
                    reason: "signing_key must carry a certificate for metadata emission",
                })?;
        #[cfg(feature = "xmlenc")]
        let encryption_cert = self
            .config
            .decryption_key
            .as_ref()
            .and_then(|k| k.certificate());

        #[cfg(feature = "xmlenc")]
        let encryption_algorithms = [self.config.outbound_data_encryption_algorithm];

        let inputs = IdpMetadataInputs {
            entity_id: &self.config.entity_id,
            sso: &self.config.sso,
            slo: &self.config.slo,
            artifact_resolution: &self.config.artifact_resolution,
            name_id_formats: &self.config.supported_name_id_formats,
            signing_cert,
            #[cfg(feature = "xmlenc")]
            encryption_cert,
            #[cfg(feature = "xmlenc")]
            encryption_algorithms: &encryption_algorithms,
            want_authn_requests_signed: self.config.want_authn_requests_signed,
            valid_until: None,
            cache_duration: None,
            extras: Some(extras),
        };
        let signer = if sign {
            Some((
                &self.config.signing_key,
                self.config.outbound_signature_algorithm,
                self.config.outbound_digest_algorithm,
                self.config.outbound_c14n,
            ))
        } else {
            None
        };
        emit_idp_metadata(&inputs, signer)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribute::Attribute;
    use crate::authn::request_build::{AcsRequest, BuildAuthnRequest, build_authn_request_element};
    use crate::authn_context::{
        AuthnContextClassRef, AuthnContextComparison, RequestedAuthnContext,
    };
    use crate::binding::{Binding, Endpoint, SsoResponseDispatch, SsoResponseEndpoint};
    use crate::crypto::cert::X509Certificate;
    use crate::crypto::cert::test_vectors::{RSA_CERT_PEM, RSA_KEY_PKCS8_PEM};
    use crate::descriptor::IdpDescriptor;
    use crate::dsig::algorithms::{
        C14nAlgorithm, DigestAlgorithm, PeerCryptoPolicy, SignatureAlgorithm,
    };
    #[cfg(feature = "slo")]
    use crate::logout::request_build::BuildLogoutRequest;
    #[cfg(feature = "slo")]
    use crate::logout::{LogoutOutcome, LogoutStatus, StartLogout};
    use crate::nameid::{NameId, NameIdFormat};
    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    use crate::replay::InMemoryReplayCache;
    use crate::response::issue::SamlStatusCode;
    use crate::xml::emit::emit_document;
    use crate::xml::parse::Node;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    const SECOND_RSA_CERT_PEM: &[u8] = include_bytes!("../examples/demo/keys/sp.crt");
    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    const SECOND_RSA_KEY_PEM: &[u8] = include_bytes!("../examples/demo/keys/sp.key");

    // -------------------------------------------------------------------------
    // Fixtures
    // -------------------------------------------------------------------------

    fn rsa_keypair_with_cert() -> KeyPair {
        let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).unwrap();
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        kp.with_certificate(cert)
    }

    fn rsa_cert() -> X509Certificate {
        X509Certificate::from_pem(RSA_CERT_PEM).unwrap()
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    fn second_rsa_keypair_with_cert() -> KeyPair {
        KeyPair::from_pkcs8_pem(SECOND_RSA_KEY_PEM)
            .expect("second RSA key")
            .with_certificate(
                X509Certificate::from_pem(SECOND_RSA_CERT_PEM).expect("second RSA cert"),
            )
    }

    fn idp_with(want_authn_requests_signed: bool, sign_responses: bool) -> IdentityProvider {
        IdentityProvider::new(IdentityProviderConfig {
            entity_id: "https://idp.example.com/saml".into(),
            sso: vec![
                Endpoint::post("https://idp.example.com/sso", 0, true),
                Endpoint::redirect("https://idp.example.com/sso", 1, false),
            ],
            slo: vec![Endpoint::post("https://idp.example.com/slo", 0, true)],
            artifact_resolution: vec![],
            supported_name_id_formats: vec![NameIdFormat::Persistent, NameIdFormat::EmailAddress],
            default_name_id_format: NameIdFormat::Persistent,
            signing_key: rsa_keypair_with_cert(),
            decryption_key: None,
            want_authn_requests_signed,
            assertion_signing: IdpAssertionSigning {
                sign_responses,
                sign_assertions: true,
            },
            encrypt_assertions_when_possible: false,
            #[cfg(feature = "slo")]
            logout_signing: IdpLogoutSigning::default(),
            #[cfg(feature = "slo")]
            logout_want_signed: IdpLogoutWantSigned::default(),
            default_session_duration: Duration::from_hours(1),
            default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
            outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
            outbound_digest_algorithm: DigestAlgorithm::Sha256,
            outbound_c14n: C14nAlgorithm::ExclusiveCanonical,
            #[cfg(feature = "xmlenc")]
            outbound_data_encryption_algorithm:
                crate::xmlenc::algorithms::DataEncryptionAlgorithm::Aes256Gcm,
            #[cfg(feature = "xmlenc")]
            outbound_key_transport_algorithm:
                crate::xmlenc::algorithms::KeyTransportAlgorithm::RsaOaep,
        })
        .expect("idp config valid")
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    fn artifact_idp() -> IdentityProvider {
        let mut config = idp_with(false, false).config.clone();
        config.artifact_resolution =
            vec![Endpoint::soap("https://idp.example.com/ars", Some(7), true)];
        IdentityProvider::new(config).expect("IdP with ArtifactResolutionService")
    }

    /// Synthetic SP descriptor with the IdP's test cert as its signing cert
    /// (so signatures we mint with the test KeyPair verify against the SP's
    /// metadata view).
    fn sp_descriptor(authn_requests_signed: bool) -> SpDescriptor {
        SpDescriptor {
            entity_id: "https://sp.example.com/saml".into(),
            assertion_consumer_services: vec![SsoResponseEndpoint::post(
                "https://sp.example.com/acs",
                0,
                true,
            )],
            single_logout_services: vec![Endpoint::post("https://sp.example.com/slo", 0, true)],
            signing_certs: vec![rsa_cert()],
            encryption_certs: vec![],
            supported_name_id_formats: vec![],
            want_assertions_signed: false,
            authn_requests_signed,
            valid_until: None,
            cache_duration: None,
            #[cfg(feature = "idp-disco")]
            discovery_response_endpoints: vec![],
        }
    }

    fn fixed_now() -> SystemTime {
        UNIX_EPOCH
            .checked_add(Duration::from_hours(494_388))
            .expect("static UNIX_EPOCH + bounded Duration cannot overflow")
    }

    fn build_unsigned_authn_request_with_authn_context(
        id: &str,
        rac: &RequestedAuthnContext,
    ) -> Vec<u8> {
        let build = BuildAuthnRequest {
            id,
            issue_instant: fixed_now(),
            issuer_entity_id: "https://sp.example.com/saml",
            destination: "https://idp.example.com/sso",
            force_authn: false,
            is_passive: false,
            acs_selection: AcsRequest::Index(0),
            protocol_binding: None,
            requested_name_id_format: Some(NameIdFormat::Persistent),
            requested_authn_context: Some(rac),
        };
        let element = build_authn_request_element(&build).unwrap();
        let doc = Document::new(element).unwrap();
        emit_document(&doc).unwrap().into_bytes()
    }

    fn build_unsigned_authn_request(id: &str, with_destination: bool) -> Vec<u8> {
        let build = BuildAuthnRequest {
            id,
            issue_instant: fixed_now(),
            issuer_entity_id: "https://sp.example.com/saml",
            destination: if with_destination {
                "https://idp.example.com/sso"
            } else {
                ""
            },
            force_authn: false,
            is_passive: false,
            acs_selection: AcsRequest::Index(0),
            protocol_binding: None,
            requested_name_id_format: Some(NameIdFormat::Persistent),
            requested_authn_context: None,
        };
        let element = build_authn_request_element(&build).unwrap();
        let doc = Document::new(element).unwrap();
        emit_document(&doc).unwrap().into_bytes()
    }

    fn build_signed_authn_request(id: &str) -> Vec<u8> {
        let build = BuildAuthnRequest {
            id,
            issue_instant: fixed_now(),
            issuer_entity_id: "https://sp.example.com/saml",
            destination: "https://idp.example.com/sso",
            force_authn: false,
            is_passive: false,
            acs_selection: AcsRequest::Index(0),
            protocol_binding: None,
            requested_name_id_format: Some(NameIdFormat::Persistent),
            requested_authn_context: None,
        };
        let element = build_authn_request_element(&build).unwrap();
        let stash = Document::new(element).unwrap();
        let kp = rsa_keypair_with_cert();
        let signed = crate::dsig::sign::sign_element(
            stash.root().clone(),
            &stash,
            crate::dsig::sign::SignOptions {
                signing_key: &kp,
                sig_alg: SignatureAlgorithm::RsaSha256,
                digest_alg: DigestAlgorithm::Sha256,
                c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                inclusive_namespaces: &[],
                include_x509_cert: true,
            },
        )
        .expect("sign");
        let final_doc = Document::new(signed).unwrap();
        emit_document(&final_doc).unwrap().into_bytes()
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    fn artifact_resolve_envelope(
        issuer: &str,
        destination: &str,
        issue_instant: SystemTime,
        signed: bool,
    ) -> Vec<u8> {
        let issue_instant = crate::time::format_xs_datetime(issue_instant).expect("format time");
        let artifact = test_type4_artifact();
        let payload = format!(
            r#"<samlp:ArtifactResolve xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                       xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                       ID="_artifact-resolve-1" Version="2.0"
                       IssueInstant="{issue_instant}" Destination="{destination}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:Artifact>{artifact}</samlp:Artifact>
</samlp:ArtifactResolve>"#,
        );

        let payload = if signed {
            let unsigned = Document::parse(payload.as_bytes()).expect("parse ArtifactResolve");
            let key = rsa_keypair_with_cert();
            let signed = crate::dsig::sign::sign_element(
                unsigned.root().clone(),
                &unsigned,
                crate::dsig::sign::SignOptions {
                    signing_key: &key,
                    sig_alg: SignatureAlgorithm::RsaSha256,
                    digest_alg: DigestAlgorithm::Sha256,
                    c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                    inclusive_namespaces: &[],
                    include_x509_cert: true,
                },
            )
            .expect("sign ArtifactResolve");
            emit_document(&Document::new(signed).expect("signed document"))
                .expect("emit signed ArtifactResolve")
        } else {
            payload
        };

        crate::binding::soap::wrap(&payload)
            .expect("wrap ArtifactResolve in SOAP")
            .into_bytes()
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    fn artifact_resolve_envelope_signed_with(
        issuer: &str,
        artifact: &str,
        request_id: &str,
        key: &KeyPair,
    ) -> Vec<u8> {
        let issue_instant =
            crate::time::format_xs_datetime(fixed_now()).expect("format fixed time");
        let payload = format!(
            r#"<samlp:ArtifactResolve xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                       xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                       ID="{request_id}" Version="2.0"
                       IssueInstant="{issue_instant}" Destination="https://idp.example.com/ars">
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:Artifact>{artifact}</samlp:Artifact>
</samlp:ArtifactResolve>"#,
        );
        let unsigned = Document::parse(payload.as_bytes()).expect("parse ArtifactResolve");
        let signed = crate::dsig::sign::sign_element(
            unsigned.root().clone(),
            &unsigned,
            crate::dsig::sign::SignOptions {
                signing_key: key,
                sig_alg: SignatureAlgorithm::RsaSha256,
                digest_alg: DigestAlgorithm::Sha256,
                c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                inclusive_namespaces: &[],
                include_x509_cert: true,
            },
        )
        .expect("sign ArtifactResolve");
        let xml = emit_document(&Document::new(signed).expect("signed document"))
            .expect("emit ArtifactResolve");
        crate::binding::soap::wrap(&xml)
            .expect("wrap ArtifactResolve")
            .into_bytes()
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    fn artifact_transaction(sp: &SpDescriptor) -> ArtifactResolveTransaction {
        ArtifactResolveTransaction {
            artifact: test_type4_artifact(),
            sp_entity_id: sp.entity_id.clone(),
            sp_signing_cert_fingerprints: certificate_fingerprint_set(&sp.signing_certs),
        }
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    fn test_type4_artifact() -> String {
        use base64::engine::general_purpose::STANDARD as BASE64;

        let mut bytes = [0u8; 44];
        bytes[..2].copy_from_slice(&0x0004u16.to_be_bytes());
        bytes[2..4].copy_from_slice(&7u16.to_be_bytes());
        bytes[4..24].copy_from_slice(&crate::binding::artifact::source_id(
            "https://idp.example.com/saml",
        ));
        bytes[24..].fill(0x5a);
        BASE64.encode(bytes)
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    fn artifact_authn_request(sp: &SpDescriptor) -> ParsedAuthnRequest {
        ParsedAuthnRequest::for_proxy_reissue(
            sp,
            "_artifact-authn-request".to_owned(),
            fixed_now(),
            sp.assertion_consumer_services[0].clone(),
            Some(NameIdFormat::EmailAddress),
            None,
            None,
        )
        .expect("fixture ACS is registered")
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    fn issue_artifact_with_transaction(
        idp: &IdentityProvider,
        sp: &SpDescriptor,
    ) -> IssuedArtifact {
        let request = artifact_authn_request(sp);
        let issued = idp
            .issue_response_with_artifact_transaction(IssueResponse {
                sp,
                in_response_to: &request,
                name_id: NameId::email("alice@example.com"),
                attributes: vec![],
                authn_instant: fixed_now(),
                session_index: "artifact-session".to_owned(),
                session_not_on_or_after: None,
                authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
                force_encrypt_assertion: Some(false),
                now: fixed_now(),
                assertion_lifetime: Duration::from_mins(10),
                subject_confirmation_lifetime: Duration::from_mins(5),
                holder_of_key_cert: None,
            })
            .expect("issue artifact with trust transaction");
        let IssuedResponse::Artifact(issued) = issued else {
            panic!("fixture must issue Artifact")
        };
        issued
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    fn artifact_resolve_envelope_signed_over_artifact(issuer: &str, destination: &str) -> Vec<u8> {
        let issue_instant =
            crate::time::format_xs_datetime(fixed_now()).expect("format fixed time");
        let payload = format!(
            r#"<samlp:ArtifactResolve xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                       xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                       ID="_artifact-resolve-1" Version="2.0"
                       IssueInstant="{issue_instant}" Destination="{destination}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:Artifact ID="_signed-artifact">{}</samlp:Artifact>
</samlp:ArtifactResolve>"#,
            test_type4_artifact(),
        );
        let unsigned = Document::parse(payload.as_bytes()).expect("parse ArtifactResolve");
        let mut artifact = unsigned
            .root()
            .child_element(Some(SAMLP_NS), "Artifact")
            .expect("Artifact child")
            .clone();
        artifact
            .namespaces_declared_here
            .push((Some("samlp".to_owned()), SAMLP_NS.to_owned()));
        let signed_artifact = crate::dsig::sign::sign_element(
            artifact.clone(),
            &unsigned,
            crate::dsig::sign::SignOptions {
                signing_key: &rsa_keypair_with_cert(),
                sig_alg: SignatureAlgorithm::RsaSha256,
                digest_alg: DigestAlgorithm::Sha256,
                c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                inclusive_namespaces: &[],
                include_x509_cert: true,
            },
        )
        .expect("sign Artifact child");
        let signature = signed_artifact
            .child_element(Some(DS_NS), "Signature")
            .expect("generated Signature")
            .clone();

        // Put a cryptographically valid child-targeting signature where the
        // role API expects the message signature. Verification must not treat
        // that as authentication of the ArtifactResolve root.
        let mut root = unsigned.root().clone();
        let original_artifact = root
            .children
            .iter_mut()
            .find_map(|node| match node {
                Node::Element(element)
                    if element.qname().namespace() == Some(SAMLP_NS)
                        && element.qname().local() == "Artifact" =>
                {
                    Some(element)
                }
                _ => None,
            })
            .expect("Artifact child in cloned root");
        *original_artifact = artifact;
        root.children.insert(1, Node::Element(signature));
        let xml = emit_document(&Document::new(root).expect("renumber signed request"))
            .expect("emit child-signed ArtifactResolve");
        crate::binding::soap::wrap(&xml)
            .expect("wrap ArtifactResolve in SOAP")
            .into_bytes()
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    fn consume_artifact_resolve<'a>(
        idp: &IdentityProvider,
        sp: &'a SpDescriptor,
        envelope: &'a [u8],
        destination: &'a str,
        require_signed: bool,
    ) -> Result<crate::binding::artifact::ArtifactResolveRequest, Error> {
        let transaction = artifact_transaction(sp);
        let replay_cache = InMemoryReplayCache::new(16);
        idp.consume_artifact_resolve(ConsumeArtifactResolve {
            sp,
            transaction: &transaction,
            replay_cache: &replay_cache,
            peer_crypto_policy: None,
            soap_envelope: envelope,
            expected_destination: destination,
            now: fixed_now(),
            clock_skew: Duration::from_mins(2),
            require_signed,
        })
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    #[test]
    fn consume_artifact_resolve_accepts_valid_signed_request() {
        let idp = artifact_idp();
        let sp = sp_descriptor(false);
        let envelope = artifact_resolve_envelope(
            &sp.entity_id,
            "https://idp.example.com/ars",
            fixed_now(),
            true,
        );

        let request =
            consume_artifact_resolve(&idp, &sp, &envelope, "https://idp.example.com/ars", true)
                .expect("valid signed request");
        assert_eq!(request.request_id, "_artifact-resolve-1");
        assert_eq!(request.issuer, sp.entity_id);
        assert_eq!(request.artifact, test_type4_artifact());
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    #[test]
    fn consume_artifact_resolve_rejects_unsigned_when_required() {
        let idp = artifact_idp();
        let sp = sp_descriptor(false);
        let envelope = artifact_resolve_envelope(
            &sp.entity_id,
            "https://idp.example.com/ars",
            fixed_now(),
            false,
        );

        let err =
            consume_artifact_resolve(&idp, &sp, &envelope, "https://idp.example.com/ars", true)
                .expect_err("signature is required");
        assert!(matches!(err, Error::SignatureMissing), "got {err:?}");
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    #[test]
    fn consume_artifact_resolve_rejects_wrong_issuer_and_destination() {
        let idp = artifact_idp();
        let sp = sp_descriptor(false);
        let wrong_issuer = artifact_resolve_envelope(
            "https://other-sp.example.com/saml",
            "https://idp.example.com/ars",
            fixed_now(),
            false,
        );
        let err = consume_artifact_resolve(
            &idp,
            &sp,
            &wrong_issuer,
            "https://idp.example.com/ars",
            false,
        )
        .expect_err("another SP must not resolve an artifact");
        assert!(matches!(err, Error::IssuerMismatch { .. }), "got {err:?}");

        let wrong_destination = artifact_resolve_envelope(
            &sp.entity_id,
            "https://idp.example.com/other-ars",
            fixed_now(),
            false,
        );
        let err = consume_artifact_resolve(
            &idp,
            &sp,
            &wrong_destination,
            "https://idp.example.com/ars",
            false,
        )
        .expect_err("request must name the receiving endpoint");
        assert!(matches!(err, Error::DestinationMismatch), "got {err:?}");
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    #[test]
    fn consume_artifact_resolve_rejects_stale_issue_instant() {
        let idp = artifact_idp();
        let sp = sp_descriptor(false);
        let stale = fixed_now()
            .checked_sub(Duration::from_mins(3))
            .expect("fixed time minus three minutes");
        let envelope =
            artifact_resolve_envelope(&sp.entity_id, "https://idp.example.com/ars", stale, false);

        let err =
            consume_artifact_resolve(&idp, &sp, &envelope, "https://idp.example.com/ars", false)
                .expect_err("stale request must be rejected");
        assert!(matches!(err, Error::Expired), "got {err:?}");
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    #[test]
    fn consume_artifact_resolve_verifies_present_optional_signature() {
        let idp = artifact_idp();
        let sp = sp_descriptor(false);
        let envelope = artifact_resolve_envelope(
            &sp.entity_id,
            "https://idp.example.com/ars",
            fixed_now(),
            true,
        );
        let tampered = String::from_utf8(envelope)
            .expect("SOAP envelope is UTF-8")
            .replace("_artifact-resolve-1", "_artifact-resolve-x")
            .into_bytes();

        let err =
            consume_artifact_resolve(&idp, &sp, &tampered, "https://idp.example.com/ars", false)
                .expect_err("a present signature must never be ignored");
        assert!(
            matches!(err, Error::SignatureVerification { .. }),
            "got {err:?}"
        );
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    #[test]
    fn consume_artifact_resolve_accepts_optional_unsigned_at_registered_endpoint() {
        let idp = artifact_idp();
        let sp = sp_descriptor(false);
        let envelope = artifact_resolve_envelope(
            &sp.entity_id,
            "https://idp.example.com/ars",
            fixed_now(),
            false,
        );

        let request =
            consume_artifact_resolve(&idp, &sp, &envelope, "https://idp.example.com/ars", false)
                .expect("mTLS deployments may make the XML signature optional");
        assert_eq!(request.artifact, test_type4_artifact());
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    #[test]
    fn consume_artifact_resolve_rejects_unregistered_receiver_and_child_signature() {
        let idp = artifact_idp();
        let sp = sp_descriptor(false);
        let envelope = artifact_resolve_envelope(
            &sp.entity_id,
            "https://idp.example.com/ars",
            fixed_now(),
            false,
        );
        let err = consume_artifact_resolve(
            &idp,
            &sp,
            &envelope,
            "https://idp.example.com/unregistered-ars",
            false,
        )
        .expect_err("the receiving endpoint must come from IdP metadata");
        assert!(matches!(err, Error::InvalidConfiguration { .. }));

        let child_signed = artifact_resolve_envelope_signed_over_artifact(
            &sp.entity_id,
            "https://idp.example.com/ars",
        );
        let err = consume_artifact_resolve(
            &idp,
            &sp,
            &child_signed,
            "https://idp.example.com/ars",
            true,
        )
        .expect_err("a signed child must not authenticate the message root");
        assert!(matches!(err, Error::SignatureVerification { .. }));
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    #[test]
    fn consume_artifact_resolve_binds_the_type4_index_to_the_receiving_ars() {
        let mut idp = artifact_idp();
        idp.config.artifact_resolution.push(Endpoint::soap(
            "https://idp.example.com/ars-secondary",
            Some(8),
            false,
        ));
        let sp = sp_descriptor(false);
        let envelope = artifact_resolve_envelope(
            &sp.entity_id,
            "https://idp.example.com/ars-secondary",
            fixed_now(),
            false,
        );

        let err = consume_artifact_resolve(
            &idp,
            &sp,
            &envelope,
            "https://idp.example.com/ars-secondary",
            false,
        )
        .expect_err("an index-7 artifact cannot be resolved at the index-8 ARS");
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    #[test]
    fn idp_build_artifact_response_signs_the_outer_envelope() {
        let idp = artifact_idp();
        let request = crate::binding::artifact::ArtifactResolveRequest {
            request_id: "_resolve-response-signing".to_owned(),
            issuer: "https://sp.example.com/saml".to_owned(),
            artifact: test_type4_artifact(),
        };
        let payload = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_inner" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"/>"#;
        let envelope = idp
            .build_artifact_response(&request, payload)
            .expect("build signed ArtifactResponse");
        let body = crate::binding::soap::unwrap(envelope.as_bytes()).expect("unwrap SOAP");
        let response = body.payload();
        let signature = response
            .child_element(Some(DS_NS), "Signature")
            .expect("outer ArtifactResponse signature");
        let verified = verify_signature(
            body.document_ref(),
            signature,
            &[rsa_cert()],
            &PeerCryptoPolicy::strong_defaults(),
        )
        .expect("verify outer signature");
        assert_eq!(verified.signed_element, response.id());
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    #[test]
    fn consume_artifact_resolve_rejects_a_root_introduced_after_issuance() {
        let idp = artifact_idp();
        let mut original_sp = sp_descriptor(false);
        original_sp.assertion_consumer_services = vec![SsoResponseEndpoint::artifact(
            "https://sp.example.com/acs-artifact",
            9,
            true,
        )];
        let issued = issue_artifact_with_transaction(&idp, &original_sp);
        let attacker_key = second_rsa_keypair_with_cert();
        let mut substituted_sp = original_sp.clone();
        substituted_sp.signing_certs = vec![
            attacker_key
                .certificate()
                .expect("attacker test key carries cert")
                .clone(),
        ];
        let envelope = artifact_resolve_envelope_signed_with(
            &substituted_sp.entity_id,
            &issued.redirect.artifact,
            "_substituted-root",
            &attacker_key,
        );
        let replay_cache = InMemoryReplayCache::new(16);

        let err = idp
            .consume_artifact_resolve(ConsumeArtifactResolve {
                sp: &substituted_sp,
                transaction: &issued.transaction,
                replay_cache: &replay_cache,
                peer_crypto_policy: None,
                soap_envelope: &envelope,
                expected_destination: "https://idp.example.com/ars",
                now: fixed_now(),
                clock_skew: Duration::from_mins(2),
                require_signed: true,
            })
            .expect_err("fresh metadata cannot introduce artifact-resolution authority");
        assert!(matches!(err, Error::ArtifactSpTrustRootMismatch));
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    #[test]
    fn consume_artifact_resolve_atomically_reserves_request_id() {
        let idp = artifact_idp();
        let mut sp = sp_descriptor(false);
        sp.assertion_consumer_services = vec![SsoResponseEndpoint::artifact(
            "https://sp.example.com/acs-artifact",
            9,
            true,
        )];
        let issued = issue_artifact_with_transaction(&idp, &sp);
        let envelope = artifact_resolve_envelope_signed_with(
            &sp.entity_id,
            &issued.redirect.artifact,
            "_captured-resolve",
            &rsa_keypair_with_cert(),
        );
        let replay_cache = InMemoryReplayCache::new(16);
        let consume = || {
            idp.consume_artifact_resolve(ConsumeArtifactResolve {
                sp: &sp,
                transaction: &issued.transaction,
                replay_cache: &replay_cache,
                peer_crypto_policy: None,
                soap_envelope: &envelope,
                expected_destination: "https://idp.example.com/ars",
                now: fixed_now(),
                clock_skew: Duration::from_mins(2),
                require_signed: true,
            })
        };

        consume().expect("first authenticated resolve reserves its ID");
        let err = consume().expect_err("captured resolve ID must be single-use");
        assert!(matches!(err, Error::ArtifactResolveReplay));
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    #[test]
    fn consume_artifact_resolve_rejects_zero_skew_explicitly() {
        let idp = artifact_idp();
        let mut sp = sp_descriptor(false);
        sp.signing_certs.clear();
        let transaction = artifact_transaction(&sp);
        let envelope = artifact_resolve_envelope(
            &sp.entity_id,
            "https://idp.example.com/ars",
            fixed_now(),
            false,
        );
        let replay_cache = InMemoryReplayCache::new(16);
        let err = idp
            .consume_artifact_resolve(ConsumeArtifactResolve {
                sp: &sp,
                transaction: &transaction,
                replay_cache: &replay_cache,
                peer_crypto_policy: None,
                soap_envelope: &envelope,
                expected_destination: "https://idp.example.com/ars",
                now: fixed_now(),
                clock_skew: Duration::ZERO,
                require_signed: false,
            })
            .expect_err("wire timestamp quantization makes zero skew unusable");
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    #[test]
    fn artifact_transaction_seal_round_trips_and_rejects_tampering() {
        let mut sp = sp_descriptor(false);
        sp.signing_certs.clear();
        let transaction = artifact_transaction(&sp);
        let key = [37u8; 32];
        let sealed = transaction.seal(&key).expect("seal transaction");
        let opened = ArtifactResolveTransaction::open(&sealed, &key).expect("open transaction");
        assert_eq!(opened.artifact, transaction.artifact);
        assert_eq!(opened.sp_entity_id, transaction.sp_entity_id);
        assert_eq!(
            opened.sp_signing_cert_fingerprints,
            transaction.sp_signing_cert_fingerprints
        );
        assert!(
            opened.sp_signing_cert_fingerprints.is_empty(),
            "mTLS-only transactions legitimately have no XML signing roots"
        );

        let mut bytes = sealed.into_bytes();
        let last = bytes.last_mut().expect("sealed transaction is nonempty");
        *last = if *last == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).expect("base64url is UTF-8");
        assert!(matches!(
            ArtifactResolveTransaction::open(&tampered, &key),
            Err(Error::DecryptFailed { .. })
        ));
        assert!(matches!(
            ArtifactResolveTransaction::open("short", &key),
            Err(Error::DecryptFailed { .. })
        ));
    }

    // -------------------------------------------------------------------------
    // new() validation
    // -------------------------------------------------------------------------

    #[test]
    fn new_rejects_empty_entity_id() {
        let mut cfg = idp_with(false, false).config.clone();
        cfg.entity_id = String::new();
        let err = IdentityProvider::new(cfg).unwrap_err();
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    #[test]
    fn new_rejects_whitespace_entity_id() {
        let mut cfg = idp_with(false, false).config.clone();
        cfg.entity_id = "not a uri".into();
        let err = IdentityProvider::new(cfg).unwrap_err();
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    #[test]
    fn new_accepts_bare_xs_anyuri_entity_id() {
        // SAML 2.0 §8.3.6: entityID is xs:anyURI. Real-world IdPs emit
        // bare identifiers like "example.com"; those must be accepted.
        let mut cfg = idp_with(false, false).config.clone();
        cfg.entity_id = "example.com".into();
        IdentityProvider::new(cfg).expect("bare anyURI accepted");
    }

    #[test]
    fn new_rejects_empty_sso() {
        let mut cfg = idp_with(false, false).config.clone();
        cfg.sso = vec![];
        let err = IdentityProvider::new(cfg).unwrap_err();
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    #[test]
    fn new_rejects_non_soap_or_duplicate_artifact_resolution_services() {
        let mut cfg = idp_with(false, false).config.clone();
        cfg.artifact_resolution = vec![Endpoint::post("https://idp.example.com/ars", 7, true)];
        let err = IdentityProvider::new(cfg).unwrap_err();
        assert!(matches!(err, Error::InvalidConfiguration { .. }));

        let mut cfg = idp_with(false, false).config.clone();
        cfg.artifact_resolution = vec![
            Endpoint::soap("https://idp.example.com/ars-a", Some(7), true),
            Endpoint::soap("https://idp.example.com/ars-b", Some(7), false),
        ];
        let err = IdentityProvider::new(cfg).unwrap_err();
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    #[test]
    fn artifact_dispatch_revalidates_mutated_service_shape() {
        let mut idp = idp_with(false, false);
        idp.config.artifact_resolution =
            vec![Endpoint::post("https://idp.example.com/ars", 7, true)];
        let err = idp
            .artifact_resolution_service_for(SsoResponseBinding::HttpArtifact)
            .expect_err("a non-SOAP service must never route artifact resolution");
        assert!(matches!(err, Error::InvalidConfiguration { .. }));

        idp.config.artifact_resolution =
            vec![Endpoint::soap("https://idp.example.com/ars", None, true)];
        let err = idp
            .artifact_resolution_service_for(SsoResponseBinding::HttpArtifact)
            .expect_err("a Type-4 artifact cannot omit its ARS endpoint index");
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    #[test]
    fn new_accessors_return_config_fields() {
        let idp = idp_with(true, false);
        assert_eq!(idp.entity_id(), "https://idp.example.com/saml");
        assert!(idp.config().want_authn_requests_signed);
    }

    // -------------------------------------------------------------------------
    // consume_authn_request
    // -------------------------------------------------------------------------

    #[test]
    fn consume_signed_post_request_succeeds_and_resolves_acs() {
        let idp = idp_with(true, false);
        let sp = sp_descriptor(true);
        let xml = build_signed_authn_request("_req-1");
        let parsed = idp
            .consume_authn_request(ConsumeAuthnRequest {
                sp: &sp,
                peer_crypto_policy: None,
                saml_request: &xml,
                binding: Binding::HttpPost,
                relay_state: Some("opaque-state"),
                detached_signature: None,
                expected_destination: "https://idp.example.com/sso",
                now: fixed_now(),
                clock_skew: Duration::from_mins(1),
            })
            .expect("consume ok");

        assert_eq!(parsed.id, "_req-1");
        assert_eq!(parsed.issuer, "https://sp.example.com/saml");
        assert_eq!(
            parsed.assertion_consumer_service.url,
            "https://sp.example.com/acs"
        );
        assert_eq!(parsed.relay_state.as_deref(), Some("opaque-state"));
    }

    #[test]
    fn consume_unsigned_post_request_rejected_when_required() {
        let idp = idp_with(true, false);
        let sp = sp_descriptor(false); // SP does not opt in
        let xml = build_unsigned_authn_request("_req-2", true);
        let err = idp
            .consume_authn_request(ConsumeAuthnRequest {
                sp: &sp,
                peer_crypto_policy: None,
                saml_request: &xml,
                binding: Binding::HttpPost,
                relay_state: None,
                detached_signature: None,
                expected_destination: "https://idp.example.com/sso",
                now: fixed_now(),
                clock_skew: Duration::from_mins(1),
            })
            .unwrap_err();
        assert!(matches!(err, Error::SignatureMissing));
    }

    #[test]
    fn consume_unsigned_post_request_accepted_when_not_required() {
        let idp = idp_with(false, false);
        let sp = sp_descriptor(false);
        let xml = build_unsigned_authn_request("_req-3", true);
        let parsed = idp
            .consume_authn_request(ConsumeAuthnRequest {
                sp: &sp,
                peer_crypto_policy: None,
                saml_request: &xml,
                binding: Binding::HttpPost,
                relay_state: None,
                detached_signature: None,
                expected_destination: "https://idp.example.com/sso",
                now: fixed_now(),
                clock_skew: Duration::from_mins(1),
            })
            .expect("consume ok");
        assert_eq!(parsed.id, "_req-3");
    }

    #[test]
    fn consume_redirect_request_missing_detached_sig_rejected() {
        let idp = idp_with(true, false);
        let sp = sp_descriptor(false);
        let xml = build_unsigned_authn_request("_req-4", true);
        let err = idp
            .consume_authn_request(ConsumeAuthnRequest {
                sp: &sp,
                peer_crypto_policy: None,
                saml_request: &xml,
                binding: Binding::HttpRedirect,
                relay_state: None,
                detached_signature: None,
                expected_destination: "https://idp.example.com/sso",
                now: fixed_now(),
                clock_skew: Duration::from_mins(1),
            })
            .unwrap_err();
        assert!(matches!(err, Error::SignatureMissing));
    }

    #[test]
    fn consume_destination_mismatch_rejected() {
        let idp = idp_with(false, false);
        let sp = sp_descriptor(false);
        let xml = build_unsigned_authn_request("_req-5", true);
        let err = idp
            .consume_authn_request(ConsumeAuthnRequest {
                sp: &sp,
                peer_crypto_policy: None,
                saml_request: &xml,
                binding: Binding::HttpPost,
                relay_state: None,
                detached_signature: None,
                // Wrong endpoint — does not match request's Destination.
                expected_destination: "https://idp.example.com/sso-other",
                now: fixed_now(),
                clock_skew: Duration::from_mins(1),
            })
            .unwrap_err();
        match err {
            Error::InvalidConfiguration { .. } | Error::DestinationMismatch => {}
            other => panic!("expected destination-binding error, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // issue_response / issue_error_response
    // -------------------------------------------------------------------------

    /// A *validated* request carrying `rac`, so the requirement lives in the
    /// private provenance where issuance reads it.
    fn parsed_authn_request_with_authn_context(rac: RequestedAuthnContext) -> ParsedAuthnRequest {
        use crate::authn::request_parse::parse_authn_request;
        let xml = build_unsigned_authn_request_with_authn_context("_req-rac", &rac);
        let doc = Document::parse(&xml).unwrap();
        let (raw, _root) = parse_authn_request(&doc).unwrap();
        let sp = sp_descriptor(false);
        let sso_urls = vec!["https://idp.example.com/sso".to_string()];
        validate_authn_request(raw, &sp, "https://idp.example.com/sso", &sso_urls)
            .expect("validate")
    }

    fn parsed_authn_request_fixture() -> ParsedAuthnRequest {
        use crate::authn::request_parse::parse_authn_request;
        let xml = build_unsigned_authn_request("_req-issue", true);
        let doc = Document::parse(&xml).unwrap();
        let (raw, _root) = parse_authn_request(&doc).unwrap();
        let sp = sp_descriptor(false);
        let sso_urls = vec!["https://idp.example.com/sso".to_string()];
        let mut parsed = validate_authn_request(raw, &sp, "https://idp.example.com/sso", &sso_urls)
            .expect("validate");
        // Via the sealing path the role layer uses; assigning the pub field
        // no longer counts, which is the point of the provenance.
        parsed.seal_relay_state(Some("rs-token".into()));
        parsed
    }

    #[test]
    fn issue_response_rejects_request_from_a_different_sp() {
        // The request was validated against `sp_descriptor()`; issuing it to a
        // different SP would audience and encrypt the assertion to that SP
        // while delivering it to the requesting SP's ACS URL.
        let idp = idp_with(false, false);
        let mut other_sp = sp_descriptor(false);
        other_sp.entity_id = "https://other-sp.example.com".to_owned();
        let parsed_req = parsed_authn_request_fixture();

        let err = idp
            .issue_response(IssueResponse {
                sp: &other_sp,
                in_response_to: &parsed_req,
                name_id: NameId::email("alice@example.com"),
                attributes: vec![],
                authn_instant: fixed_now(),
                session_index: "sess-1".into(),
                session_not_on_or_after: None,
                authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
                force_encrypt_assertion: Some(false),
                now: fixed_now(),
                assertion_lifetime: Duration::from_mins(10),
                subject_confirmation_lifetime: Duration::from_mins(5),
                holder_of_key_cert: None,
            })
            .expect_err("request issuer does not match the supplied SP");

        assert!(matches!(
            err,
            Error::IssuerMismatch { ref expected, ref got }
                if expected == &parsed_req.issuer
                    && got.as_deref() == Some("https://other-sp.example.com")
        ));
    }

    /// Rewriting the wire-derived fields must not relabel a validated
    /// request. Both are `pub`, so a caller can set `issuer` *and*
    /// `assertion_consumer_service` to SP-B's values after validating against
    /// SP-A — at which point every check built on those fields agrees. Only
    /// the private provenance binding still disagrees.
    #[test]
    fn mutating_both_wire_fields_does_not_relabel_the_request() {
        let idp = idp_with(false, false);
        let mut other_sp = sp_descriptor(false);
        other_sp.entity_id = "https://other-sp.example.com".to_owned();
        other_sp.assertion_consumer_services = vec![SsoResponseEndpoint::post(
            "https://other-sp.example.com/acs",
            0,
            true,
        )];

        let mut parsed_req = parsed_authn_request_fixture();
        parsed_req.issuer = other_sp.entity_id.clone();
        parsed_req.assertion_consumer_service = other_sp.assertion_consumer_services[0].clone();

        let err = issue_to(&idp, &other_sp, &parsed_req)
            .expect_err("the request was validated against a different SP");
        assert!(
            matches!(err, Error::IssuerMismatch { ref expected, .. }
                if expected == "https://sp.example.com/saml"),
            "got {err:?}"
        );
    }

    /// Two SPs may legitimately register the same ACS URL and binding, so ACS
    /// membership alone cannot establish which one a request was validated
    /// against. Rewriting `issuer` is then enough to pass every wire-derived
    /// check.
    #[test]
    fn shared_acs_between_sps_does_not_permit_relabelling() {
        let idp = idp_with(false, false);
        let original = sp_descriptor(false);
        let mut twin = sp_descriptor(false);
        twin.entity_id = "https://twin-sp.example.com".to_owned();
        // Same ACS URL and binding as the SP the request was validated against.
        twin.assertion_consumer_services = original.assertion_consumer_services.clone();

        let mut parsed_req = parsed_authn_request_fixture();
        parsed_req.issuer = twin.entity_id.clone();

        let err = issue_to(&idp, &twin, &parsed_req)
            .expect_err("a shared ACS does not make these the same SP");
        assert!(matches!(err, Error::IssuerMismatch { .. }), "got {err:?}");
    }

    /// The Type-4 endpoint index identifies the issuing IdP's ARS, never the
    /// receiving SP's ACS. A caller-mutated ACS index therefore cannot affect
    /// the artifact, and a deliberately different ARS index reaches the wire.
    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    #[test]
    fn mutating_the_acs_index_does_not_reach_the_artifact() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as BASE64;

        const ACS_INDEX: u16 = 3;
        const ARS_INDEX: u16 = 47;
        let mut idp = idp_with(false, false);
        idp.config.artifact_resolution = vec![Endpoint::soap(
            "https://idp.example.com/ars",
            Some(ARS_INDEX),
            true,
        )];
        let mut sp = sp_descriptor(false);
        sp.assertion_consumer_services = vec![SsoResponseEndpoint::artifact(
            "https://sp.example.com/acs-artifact",
            ACS_INDEX,
            true,
        )];

        let mut parsed_req = ParsedAuthnRequest::for_proxy_reissue(
            &sp,
            "_req-artifact".into(),
            fixed_now(),
            sp.assertion_consumer_services[0].clone(),
            Some(NameIdFormat::EmailAddress),
            None,
            None,
        )
        .expect("the fixture ACS is registered");

        // Rewrite the public field the way a caller could.
        parsed_req.assertion_consumer_service.index = Some(99);

        let dispatch = issue_to(&idp, &sp, &parsed_req).expect("issuance succeeds");
        let SsoResponseDispatch::Artifact(redirect) = dispatch else {
            panic!("expected an artifact dispatch");
        };

        let decoded = BASE64
            .decode(redirect.artifact.as_bytes())
            .expect("artifact is base64");
        let emitted_index = u16::from_be_bytes([decoded[2], decoded[3]]);
        assert_eq!(
            emitted_index, ARS_INDEX,
            "the artifact must name the IdP ARS, not any ACS index"
        );
    }

    fn issue_to(
        idp: &IdentityProvider,
        sp: &SpDescriptor,
        req: &ParsedAuthnRequest,
    ) -> Result<SsoResponseDispatch, Error> {
        let requested_format = req
            .validated_name_id_format()
            .cloned()
            .unwrap_or_else(|| idp.config.default_name_id_format.clone());
        let input = IssueResponse {
            sp,
            in_response_to: req,
            name_id: NameId::new("alice@example.com", requested_format),
            attributes: vec![],
            authn_instant: fixed_now(),
            session_index: "sess-1".into(),
            session_not_on_or_after: None,
            authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
            force_encrypt_assertion: Some(false),
            now: fixed_now(),
            assertion_lifetime: Duration::from_mins(10),
            subject_confirmation_lifetime: Duration::from_mins(5),
            holder_of_key_cert: None,
        };
        #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
        if req.validated_acs().binding == SsoResponseBinding::HttpArtifact {
            return idp.issue_response_with_artifact_transaction(input).map(
                |issued| match issued {
                    IssuedResponse::Post(form) => SsoResponseDispatch::Post(form),
                    IssuedResponse::Artifact(artifact) => {
                        SsoResponseDispatch::Artifact(artifact.redirect)
                    }
                },
            );
        }
        idp.issue_response(input)
    }

    #[test]
    fn issue_response_rejects_relabelling_a_name_id_value() {
        let idp = idp_with(false, false);
        let sp = sp_descriptor(false);
        let req = parsed_authn_request_fixture();

        let err = idp
            .issue_response(IssueResponse {
                sp: &sp,
                in_response_to: &req,
                // The request negotiated Persistent. An EmailAddress value
                // cannot simply be stamped Persistent by issuance.
                name_id: NameId::email("alice@example.com"),
                attributes: vec![],
                authn_instant: fixed_now(),
                session_index: "sess-1".into(),
                session_not_on_or_after: None,
                authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
                force_encrypt_assertion: Some(false),
                now: fixed_now(),
                assertion_lifetime: Duration::from_mins(10),
                subject_confirmation_lifetime: Duration::from_mins(5),
                holder_of_key_cert: None,
            })
            .expect_err("issuance must not relabel a NameID format");

        assert!(
            matches!(err, Error::NameIdFormatMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn plaintext_issuance_allows_encryption_key_rotation() {
        let idp = idp_with(false, false);
        let original_sp = sp_descriptor(false);
        let request = parsed_authn_request_fixture();
        let mut rotated_sp = original_sp;
        rotated_sp.encryption_certs = vec![rsa_cert()];

        idp.issue_response(IssueResponse {
            sp: &rotated_sp,
            in_response_to: &request,
            name_id: NameId::persistent_for_sp("alice-id", &rotated_sp.entity_id),
            attributes: vec![],
            authn_instant: fixed_now(),
            session_index: "sess-1".into(),
            session_not_on_or_after: None,
            authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
            force_encrypt_assertion: Some(false),
            now: fixed_now(),
            assertion_lifetime: Duration::from_mins(10),
            subject_confirmation_lifetime: Duration::from_mins(5),
            holder_of_key_cert: None,
        })
        .expect("plaintext issuance is independent of encryption-key rotation");
    }

    #[cfg(feature = "xmlenc")]
    #[test]
    fn opportunistic_encryption_rejects_removing_the_validated_key() {
        use crate::authn::request_parse::parse_authn_request;

        let mut config = idp_with(false, false).config.clone();
        config.encrypt_assertions_when_possible = true;
        let idp = IdentityProvider::new(config).expect("IdP config");
        let mut validated_sp = sp_descriptor(false);
        validated_sp.encryption_certs = vec![rsa_cert()];
        let xml = build_unsigned_authn_request("_req-encryption-removal", true);
        let document = Document::parse(&xml).expect("request XML");
        let (raw, _root) = parse_authn_request(&document).expect("request parse");
        let request = validate_authn_request(
            raw,
            &validated_sp,
            "https://idp.example.com/sso",
            &["https://idp.example.com/sso".to_owned()],
        )
        .expect("request validation");
        let mut stripped_sp = validated_sp;
        stripped_sp.encryption_certs.clear();

        let err = idp
            .issue_response(IssueResponse {
                sp: &stripped_sp,
                in_response_to: &request,
                name_id: NameId::persistent_for_sp("alice-id", &stripped_sp.entity_id),
                attributes: vec![],
                authn_instant: fixed_now(),
                session_index: "sess-1".into(),
                session_not_on_or_after: None,
                authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
                force_encrypt_assertion: None,
                now: fixed_now(),
                assertion_lifetime: Duration::from_mins(10),
                subject_confirmation_lifetime: Duration::from_mins(5),
                holder_of_key_cert: None,
            })
            .expect_err("removing the pinned key must not downgrade to plaintext");
        assert!(matches!(err, Error::SpKeyMaterialMismatch), "got {err:?}");
    }

    /// `@ID` is caller-mutable after validation, and it becomes the Response's
    /// `@InResponseTo` — which the SP correlates against its own tracker. So
    /// rewriting it to another outstanding request from the *same* SP
    /// cross-wires the two transactions without tripping any issuer or ACS
    /// check. Issuance echoes the validated ID instead.
    #[test]
    fn issuance_echoes_the_validated_request_id_not_the_mutable_one() {
        let idp = idp_with(false, false);
        let sp = sp_descriptor(false);
        let mut req = parsed_authn_request_fixture();
        let genuine = req.validated_request_id().to_owned();

        // Post-validation tampering: claim to answer a different transaction.
        req.id = "_some-other-outstanding-request".to_owned();

        let dispatch = issue_to(&idp, &sp, &req).expect("issue");
        let SsoResponseDispatch::Post(form) = dispatch else {
            panic!("expected Post");
        };
        let decoded = crate::binding::post::decode(&form.saml_response, None).expect("decode");
        let xml = String::from_utf8(decoded.xml).expect("utf8");

        assert!(
            xml.contains(&format!("InResponseTo=\"{genuine}\"")),
            "must echo the validated request ID, got: {xml}"
        );
        assert!(
            !xml.contains("_some-other-outstanding-request"),
            "must not echo the rewritten ID: {xml}"
        );
    }

    /// An IdP should not sign a weaker class than the SP's validated request
    /// demanded. The SP is expected to re-check on receipt, but an SP that
    /// omits that check has no other line of defence — and the proxy is not
    /// the only caller that reaches issuance.
    #[test]
    fn issue_response_refuses_a_class_the_request_does_not_accept() {
        let idp = idp_with(false, false);
        let sp = sp_descriptor(false);
        // The requirement must live in the private provenance, so this
        // validates a request that genuinely carries it rather than touching
        // the `pub` field — which issuance deliberately ignores.
        let req = parsed_authn_request_with_authn_context(RequestedAuthnContext {
            class_refs: vec![AuthnContextClassRef::MultiFactorAuth],
            comparison: AuthnContextComparison::Exact,
        });

        let err = issue_to(&idp, &sp, &req)
            .expect_err("PasswordProtectedTransport does not satisfy Exact(MFA)");
        assert!(matches!(err, Error::AuthnContextDowngrade), "got {err:?}");
    }

    /// Control: the same path issues normally when the class does satisfy the
    /// request, so the guard above is not simply refusing everything.
    #[test]
    fn issue_response_allows_a_class_the_request_accepts() {
        let idp = idp_with(false, false);
        let sp = sp_descriptor(false);
        let req = parsed_authn_request_with_authn_context(RequestedAuthnContext {
            class_refs: vec![AuthnContextClassRef::PasswordProtectedTransport],
            comparison: AuthnContextComparison::Exact,
        });

        issue_to(&idp, &sp, &req).expect("the emitted class satisfies the request");
    }

    #[test]
    fn issue_error_response_rejects_request_from_a_different_sp() {
        let idp = idp_with(false, false);
        let mut other_sp = sp_descriptor(false);
        other_sp.entity_id = "https://other-sp.example.com".to_owned();
        let parsed_req = parsed_authn_request_fixture();

        let err = idp
            .issue_error_response(IssueErrorResponse {
                sp: &other_sp,
                in_response_to: &parsed_req,
                status_code: SamlStatusCode::Responder,
                second_level_status_code: None,
                message: None,
                now: fixed_now(),
            })
            .expect_err("error responses correlate the same way");
        assert!(matches!(err, Error::IssuerMismatch { .. }));
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    #[test]
    fn artifact_issuance_requires_and_returns_a_trust_transaction() {
        let idp = artifact_idp();
        let mut sp = sp_descriptor(false);
        sp.assertion_consumer_services = vec![SsoResponseEndpoint::artifact(
            "https://sp.example.com/acs-artifact",
            9,
            true,
        )];
        let request = artifact_authn_request(&sp);
        let success_input = || IssueResponse {
            sp: &sp,
            in_response_to: &request,
            name_id: NameId::email("alice@example.com"),
            attributes: vec![],
            authn_instant: fixed_now(),
            session_index: "artifact-session".to_owned(),
            session_not_on_or_after: None,
            authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
            force_encrypt_assertion: Some(false),
            now: fixed_now(),
            assertion_lifetime: Duration::from_mins(10),
            subject_confirmation_lifetime: Duration::from_mins(5),
            holder_of_key_cert: None,
        };
        let error_input = || IssueErrorResponse {
            sp: &sp,
            in_response_to: &request,
            status_code: SamlStatusCode::Responder,
            second_level_status_code: None,
            message: Some("denied".to_owned()),
            now: fixed_now(),
        };

        assert!(matches!(
            idp.issue_response(success_input()),
            Err(Error::ArtifactTransactionRequired)
        ));
        assert!(matches!(
            idp.issue_error_response(error_input()),
            Err(Error::ArtifactTransactionRequired)
        ));

        let issued = idp
            .issue_error_response_with_artifact_transaction(error_input())
            .expect("the transaction-bearing error API supports Artifact");
        let IssuedResponse::Artifact(issued) = issued else {
            panic!("the Artifact ACS must receive an artifact dispatch")
        };
        assert_eq!(issued.transaction.artifact, issued.redirect.artifact);
        assert_eq!(issued.transaction.sp_entity_id, sp.entity_id);
    }

    #[test]
    fn issue_response_round_trips_via_parse_response() {
        use crate::response::parse::parse_response;
        let idp = idp_with(false, false);
        let sp = sp_descriptor(false);
        let parsed_req = parsed_authn_request_fixture();

        let dispatch = idp
            .issue_response(IssueResponse {
                sp: &sp,
                in_response_to: &parsed_req,
                name_id: NameId::persistent_for_sp("alice-id", &sp.entity_id),
                attributes: vec![Attribute::email("alice@example.com")],
                authn_instant: fixed_now(),
                session_index: "sess-1".into(),
                session_not_on_or_after: Some(fixed_now() + Duration::from_hours(1)),
                authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
                force_encrypt_assertion: Some(false),
                now: fixed_now(),
                assertion_lifetime: Duration::from_mins(10),
                subject_confirmation_lifetime: Duration::from_mins(5),
                holder_of_key_cert: None,
            })
            .expect("issue ok");

        let form = match dispatch {
            SsoResponseDispatch::Post(f) => f,
            other @ SsoResponseDispatch::Artifact(_) => {
                panic!("expected POST dispatch, got {other:?}")
            }
        };
        assert_eq!(form.action.as_str(), "https://sp.example.com/acs");
        assert_eq!(form.relay_state.as_deref(), Some("rs-token"));

        let decoded = crate::binding::post::decode(&form.saml_response, None).unwrap();
        let doc = Document::parse(&decoded.xml).unwrap();
        let (parsed_resp, _) = parse_response(&doc).expect("parse");
        let assertion = parsed_resp.assertion.expect("assertion");
        let crate::response::parse::AssertionWrapper::Cleartext(assertion_id) = assertion else {
            panic!("expected cleartext assertion")
        };
        let assertion_elem = doc.element(assertion_id).unwrap();
        let parsed_assertion =
            crate::response::parse::parse_assertion(assertion_elem).expect("parse assertion");
        assert_eq!(parsed_assertion.subject_name_id.value, "alice-id");
        assert_eq!(parsed_assertion.attributes.len(), 1);
    }

    #[test]
    fn issue_error_response_carries_status_code_chain() {
        let idp = idp_with(false, false);
        let sp = sp_descriptor(false);
        let parsed_req = parsed_authn_request_fixture();
        let dispatch = idp
            .issue_error_response(IssueErrorResponse {
                sp: &sp,
                in_response_to: &parsed_req,
                status_code: SamlStatusCode::AuthnFailed,
                second_level_status_code: Some(SamlStatusCode::InvalidNameIdPolicy),
                message: Some("policy denied".into()),
                now: fixed_now(),
            })
            .expect("issue error");
        let form = match dispatch {
            SsoResponseDispatch::Post(f) => f,
            other @ SsoResponseDispatch::Artifact(_) => {
                panic!("expected POST dispatch, got {other:?}")
            }
        };
        let decoded = crate::binding::post::decode(&form.saml_response, None).unwrap();
        let doc = Document::parse(&decoded.xml).unwrap();
        let response = doc.root();
        let status = response
            .child_element(Some(SAMLP_NS), "Status")
            .expect("status");
        let code = status
            .child_element(Some(SAMLP_NS), "StatusCode")
            .expect("status code");
        assert_eq!(
            code.attribute(None, "Value"),
            Some(SamlStatusCode::AuthnFailed.uri())
        );
        let nested = code
            .child_element(Some(SAMLP_NS), "StatusCode")
            .expect("nested status code");
        assert_eq!(
            nested.attribute(None, "Value"),
            Some(SamlStatusCode::InvalidNameIdPolicy.uri())
        );
    }

    // -------------------------------------------------------------------------
    // SLO consume / build / start
    // -------------------------------------------------------------------------

    #[cfg(feature = "slo")]
    fn build_signed_logout_request(id: &str) -> Vec<u8> {
        let nid = NameId::email("alice@example.com");
        let build = BuildLogoutRequest {
            id,
            issue_instant: fixed_now(),
            issuer_entity_id: "https://sp.example.com/saml",
            destination: Some("https://idp.example.com/slo"),
            not_on_or_after: None,
            reason: None,
            name_id: &nid,
            session_index: Some("sess-1"),
        };
        let element = crate::logout::request_build::build_logout_request_element(&build).unwrap();
        let stash = Document::new(element).unwrap();
        let kp = rsa_keypair_with_cert();
        let signed = crate::dsig::sign::sign_element(
            stash.root().clone(),
            &stash,
            crate::dsig::sign::SignOptions {
                signing_key: &kp,
                sig_alg: SignatureAlgorithm::RsaSha256,
                digest_alg: DigestAlgorithm::Sha256,
                c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                inclusive_namespaces: &[],
                include_x509_cert: true,
            },
        )
        .unwrap();
        let final_doc = Document::new(signed).unwrap();
        emit_document(&final_doc).unwrap().into_bytes()
    }

    #[cfg(feature = "slo")]
    #[test]
    fn consume_logout_request_signed_post_succeeds() {
        let mut idp = idp_with(false, false);
        idp.config.logout_want_signed.requests = true;
        let sp = sp_descriptor(false);
        let xml = build_signed_logout_request("_lo-req-1");
        let parsed = idp
            .consume_logout_request(
                &sp,
                ConsumeLogoutRequest {
                    peer_crypto_policy: None,
                    body: &xml,
                    binding: Binding::HttpPost,
                    detached_signature: None,
                    expected_destination: "https://idp.example.com/slo",
                    now: fixed_now(),
                    clock_skew: Duration::from_mins(1),
                },
            )
            .expect("consume ok");
        assert_eq!(parsed.id, "_lo-req-1");
        assert_eq!(parsed.name_id.value, "alice@example.com");
        assert_eq!(parsed.session_index, vec!["sess-1".to_string()]);
    }

    #[cfg(feature = "slo")]
    #[test]
    fn consume_logout_request_unsigned_rejected_when_required() {
        let mut idp = idp_with(false, false);
        idp.config.logout_want_signed.requests = true;
        let sp = sp_descriptor(false);

        let nid = NameId::email("alice@example.com");
        let xml = crate::logout::request_build::build_logout_request_xml(&BuildLogoutRequest {
            id: "_lo-req-2",
            issue_instant: fixed_now(),
            issuer_entity_id: "https://sp.example.com/saml",
            destination: Some("https://idp.example.com/slo"),
            not_on_or_after: None,
            reason: None,
            name_id: &nid,
            session_index: None,
        })
        .unwrap();

        let err = idp
            .consume_logout_request(
                &sp,
                ConsumeLogoutRequest {
                    peer_crypto_policy: None,
                    body: &xml,
                    binding: Binding::HttpPost,
                    detached_signature: None,
                    expected_destination: "https://idp.example.com/slo",
                    now: fixed_now(),
                    clock_skew: Duration::from_mins(1),
                },
            )
            .unwrap_err();
        assert!(matches!(err, Error::SignatureMissing));
    }

    /// Build a signed HTTP-Redirect LogoutRequest the SP would send to the
    /// IdP's `/slo` endpoint. Returns the decoded XML alongside the canonical
    /// signed-query slice and the detached `Signature` / `SigAlg` values, in
    /// the shape the IdP-side caller would extract from the inbound URL.
    #[cfg(feature = "slo")]
    fn build_signed_redirect_logout_request(id: &str) -> (Vec<u8>, String, Vec<u8>, String) {
        use crate::binding::redirect::{
            RedirectDirection, decode as redirect_decode, encode_signed,
        };

        let nid = NameId::email("alice@example.com");
        let xml = crate::logout::request_build::build_logout_request_xml(&BuildLogoutRequest {
            id,
            issue_instant: fixed_now(),
            issuer_entity_id: "https://sp.example.com/saml",
            destination: Some("https://idp.example.com/slo"),
            not_on_or_after: None,
            reason: None,
            name_id: &nid,
            session_index: Some("sess-1"),
        })
        .unwrap();

        let kp = rsa_keypair_with_cert();
        let sig_alg = SignatureAlgorithm::RsaSha256;
        let dest = url::Url::parse("https://idp.example.com/slo").unwrap();
        let dispatch = encode_signed(
            &dest,
            RedirectDirection::Request,
            &xml,
            None,
            sig_alg.uri(),
            |to_sign| crate::dsig::sign::sign_detached_query(to_sign, &kp, sig_alg),
        )
        .unwrap();
        let url = match dispatch {
            Dispatch::Redirect(u) => u,
            other @ Dispatch::Post(_) => panic!("expected Redirect dispatch, got {other:?}"),
        };
        let raw_query = url.query().unwrap().to_owned();
        let decoded = redirect_decode(&raw_query, RedirectDirection::Request).unwrap();

        // The signature and sig_alg come back URL-decoded from `decoded`,
        // but `DetachedSignature::signature` / `.sig_alg` are documented as
        // the raw query-parameter values. Re-extract from the raw query.
        let mut signature_raw = String::new();
        let mut sig_alg_raw = String::new();
        for pair in raw_query.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            match k {
                "Signature" => signature_raw = v.to_owned(),
                "SigAlg" => sig_alg_raw = v.to_owned(),
                _ => {}
            }
        }
        let signed_query_string = decoded
            .signed_query_string
            .expect("decoder returned canonical signed query string");

        // Percent-decode + base64-decode the Signature parameter —
        // `DetachedSignature::signature` carries raw signature bytes.
        let signature_b64 = percent_encoding::percent_decode_str(&signature_raw)
            .decode_utf8()
            .unwrap()
            .into_owned();
        let signature_bytes = BASE64.decode(signature_b64.as_bytes()).unwrap();
        let sig_alg_decoded = percent_encoding::percent_decode_str(&sig_alg_raw)
            .decode_utf8()
            .unwrap()
            .into_owned();

        (
            decoded.xml,
            signed_query_string,
            signature_bytes,
            sig_alg_decoded,
        )
    }

    #[cfg(feature = "slo")]
    #[test]
    fn consume_logout_request_signed_redirect_succeeds() {
        let mut idp = idp_with(false, false);
        idp.config.logout_want_signed.requests = true;
        let sp = sp_descriptor(false);
        let (xml, signed_qs, signature, sig_alg) =
            build_signed_redirect_logout_request("_lo-redir-1");

        let parsed = idp
            .consume_logout_request(
                &sp,
                ConsumeLogoutRequest {
                    peer_crypto_policy: None,
                    body: &xml,
                    binding: Binding::HttpRedirect,
                    detached_signature: Some(DetachedSignature {
                        signature: &signature,
                        sig_alg: &sig_alg,
                        raw_query_string: &signed_qs,
                    }),
                    expected_destination: "https://idp.example.com/slo",
                    now: fixed_now(),
                    clock_skew: Duration::from_mins(1),
                },
            )
            .expect("signed redirect logout request must verify");

        assert_eq!(parsed.id, "_lo-redir-1");
        assert_eq!(parsed.name_id.value, "alice@example.com");
        assert_eq!(parsed.session_index, vec!["sess-1".to_string()]);
    }

    #[cfg(feature = "slo")]
    #[test]
    fn consume_logout_request_redirect_without_detached_payload_rejected() {
        // Mimic the pre-fix API: caller omits `detached_signature`. With
        // `require_signed_requests` on the IdP must reject the request as
        // unsigned even though the wire really was signed.
        let mut idp = idp_with(false, false);
        idp.config.logout_want_signed.requests = true;
        let sp = sp_descriptor(false);
        let (xml, _signed_qs, _signature, _sig_alg) =
            build_signed_redirect_logout_request("_lo-redir-2");

        let err = idp
            .consume_logout_request(
                &sp,
                ConsumeLogoutRequest {
                    peer_crypto_policy: None,
                    body: &xml,
                    binding: Binding::HttpRedirect,
                    detached_signature: None,
                    expected_destination: "https://idp.example.com/slo",
                    now: fixed_now(),
                    clock_skew: Duration::from_mins(1),
                },
            )
            .unwrap_err();
        assert!(matches!(err, Error::SignatureMissing));
    }

    #[cfg(feature = "slo")]
    #[test]
    fn consume_logout_request_redirect_tampered_signature_rejected() {
        // Flip a byte in the canonical signed query string after signing.
        // Verification must reject; we don't want a false-positive accept
        // from any future short-circuit in the dispatch.
        let mut idp = idp_with(false, false);
        idp.config.logout_want_signed.requests = true;
        let sp = sp_descriptor(false);
        let (xml, signed_qs, signature, sig_alg) =
            build_signed_redirect_logout_request("_lo-redir-3");
        let tampered_qs = format!("{signed_qs}&Tamper=1");

        let err = idp
            .consume_logout_request(
                &sp,
                ConsumeLogoutRequest {
                    peer_crypto_policy: None,
                    body: &xml,
                    binding: Binding::HttpRedirect,
                    detached_signature: Some(DetachedSignature {
                        signature: &signature,
                        sig_alg: &sig_alg,
                        raw_query_string: &tampered_qs,
                    }),
                    expected_destination: "https://idp.example.com/slo",
                    now: fixed_now(),
                    clock_skew: Duration::from_mins(1),
                },
            )
            .unwrap_err();
        assert!(matches!(err, Error::SignatureVerification { .. }));
    }

    #[cfg(feature = "slo")]
    #[test]
    fn build_logout_response_xml_round_trips_via_parse() {
        use crate::logout::response_parse::parse_logout_response;
        let idp = idp_with(false, false);
        let sp = sp_descriptor(false);

        // Synthesize a ParsedLogoutRequest to echo.
        let nid = NameId::email("alice@example.com");
        let xml = crate::logout::request_build::build_logout_request_xml(&BuildLogoutRequest {
            id: "_lo-req-3",
            issue_instant: fixed_now(),
            issuer_entity_id: "https://sp.example.com/saml",
            destination: Some("https://idp.example.com/slo"),
            not_on_or_after: None,
            reason: None,
            name_id: &nid,
            session_index: None,
        })
        .unwrap();
        let doc = Document::parse(&xml).unwrap();
        let (parsed_req, _) = crate::logout::request_parse::parse_logout_request(&doc).unwrap();

        let dispatch = idp
            .build_logout_response(
                &sp,
                &parsed_req,
                LogoutStatus::Success,
                Some("rs"),
                Binding::HttpPost,
            )
            .expect("build ok");
        let form = match dispatch {
            Dispatch::Post(f) => f,
            other @ Dispatch::Redirect(_) => panic!("expected POST dispatch, got {other:?}"),
        };
        let saml_response = form.saml_response.expect("saml_response in POST form");
        let decoded = crate::binding::post::decode(&saml_response, Some("rs")).unwrap();
        let resp_doc = Document::parse(&decoded.xml).unwrap();
        let (parsed_resp, _) = parse_logout_response(&resp_doc).unwrap();
        assert_eq!(parsed_resp.in_response_to, "_lo-req-3");
        assert_eq!(
            parsed_resp.status_code,
            "urn:oasis:names:tc:SAML:2.0:status:Success"
        );
    }

    #[cfg(feature = "slo")]
    #[test]
    fn start_logout_produces_tracker_and_dispatch() {
        let idp = idp_with(false, false);
        let sp = sp_descriptor(false);
        let nid = NameId::email("alice@example.com");
        let dispatch = idp
            .start_logout(
                &sp,
                StartLogout {
                    name_id: &nid,
                    session_index: Some("sess-1"),
                    relay_state: Some("rs"),
                    reason: None,
                    binding: Binding::HttpPost,
                },
            )
            .expect("start ok");
        assert_eq!(
            dispatch.tracker.peer_entity_id,
            "https://sp.example.com/saml"
        );
        assert!(matches!(dispatch.dispatch, Dispatch::Post(_)));
    }

    // -------------------------------------------------------------------------
    // metadata_xml
    // -------------------------------------------------------------------------

    #[test]
    fn metadata_xml_round_trips_via_idp_descriptor() {
        let idp = idp_with(true, false);
        let xml = idp.metadata_xml(false).expect("emit metadata");
        let parsed = IdpDescriptor::from_metadata_xml(xml.as_bytes()).expect("parse metadata");
        assert_eq!(parsed.entity_id, "https://idp.example.com/saml");
        assert!(parsed.want_authn_requests_signed);
        // Two SSO endpoints: POST + Redirect.
        assert_eq!(parsed.sso_endpoints.len(), 2);
        // One SLO endpoint.
        assert_eq!(parsed.slo_endpoints.len(), 1);
        // Signing cert round-trips.
        assert_eq!(parsed.signing_certs.len(), 1);
        // NameID formats round-trip in order.
        assert_eq!(
            parsed.supported_name_id_formats,
            vec![NameIdFormat::Persistent, NameIdFormat::EmailAddress]
        );
    }

    #[test]
    fn metadata_xml_signed_carries_signature_child() {
        let idp = idp_with(true, false);
        let xml = idp.metadata_xml(true).expect("emit signed metadata");
        let doc = Document::parse(xml.as_bytes()).unwrap();
        let root = doc.root();
        // The first child of <EntityDescriptor> is a <ds:Signature>.
        let first_elem = root
            .children()
            .find_map(|n| match n {
                Node::Element(e) => Some(e),
                _ => None,
            })
            .expect("at least one child element");
        assert_eq!(first_elem.qname().namespace(), Some(DS_NS));
        assert_eq!(first_elem.qname().local(), "Signature");
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    #[test]
    fn pick_name_id_format_honors_supported_request() {
        let supported = vec![NameIdFormat::Persistent, NameIdFormat::EmailAddress];
        let default = NameIdFormat::Persistent;
        assert_eq!(
            pick_name_id_format(Some(&NameIdFormat::EmailAddress), &supported, &default)
                .expect("supported"),
            NameIdFormat::EmailAddress
        );
        // No request at all: the default applies.
        assert_eq!(
            pick_name_id_format(None, &supported, &default).expect("no request"),
            NameIdFormat::Persistent
        );
    }

    /// Core §3.4.1.1: an explicit format the IdP cannot produce is an error,
    /// not an invitation to substitute. Falling back to Persistent handed the
    /// SP a durable pseudonym where it asked for a Transient one, under a
    /// request it believed had been satisfied.
    #[test]
    fn pick_name_id_format_rejects_an_unsupported_explicit_request() {
        let supported = vec![NameIdFormat::Persistent, NameIdFormat::EmailAddress];
        let default = NameIdFormat::Persistent;

        let err = pick_name_id_format(Some(&NameIdFormat::Transient), &supported, &default)
            .expect_err("Transient is not supported here");
        assert!(
            matches!(err, Error::UnsupportedNameIdPolicy { .. }),
            "got {err:?}"
        );
    }

    // -------------------------------------------------------------------------
    // wire-level helpers (consume_*_wire)
    // -------------------------------------------------------------------------

    /// Encode an unsigned AuthnRequest as a Redirect-binding raw query string.
    fn build_unsigned_redirect_authn_request_raw_query(id: &str) -> String {
        use crate::binding::redirect::{RedirectDirection, encode_unsigned};

        let xml = build_unsigned_authn_request(id, true);
        let dest = url::Url::parse("https://idp.example.com/sso").unwrap();
        let dispatch = encode_unsigned(
            &dest,
            RedirectDirection::Request,
            &xml,
            Some("rs-wire-authn"),
        )
        .unwrap();
        let url = match dispatch {
            Dispatch::Redirect(u) => u,
            other @ Dispatch::Post(_) => panic!("expected Redirect dispatch, got {other:?}"),
        };
        url.query().unwrap().to_owned()
    }

    /// Encode a signed AuthnRequest as a Redirect-binding raw query string —
    /// what the IdP would see after `?` in the inbound URL.
    fn build_signed_redirect_authn_request_raw_query(id: &str) -> String {
        use crate::binding::redirect::{RedirectDirection, encode_signed};

        let xml = build_unsigned_authn_request(id, true);
        let kp = rsa_keypair_with_cert();
        let sig_alg = SignatureAlgorithm::RsaSha256;
        let dest = url::Url::parse("https://idp.example.com/sso").unwrap();
        let dispatch = encode_signed(
            &dest,
            RedirectDirection::Request,
            &xml,
            Some("rs-wire-authn"),
            sig_alg.uri(),
            |to_sign| crate::dsig::sign::sign_detached_query(to_sign, &kp, sig_alg),
        )
        .unwrap();
        let url = match dispatch {
            Dispatch::Redirect(u) => u,
            other @ Dispatch::Post(_) => panic!("expected Redirect dispatch, got {other:?}"),
        };
        url.query().unwrap().to_owned()
    }

    #[test]
    fn consume_authn_request_wire_matches_two_step_for_signed_redirect() {
        // The wire helper must produce the same `ParsedAuthnRequest` as the
        // explicit `decode_wire` + `consume_authn_request` two-step path.
        let idp = idp_with(true, false);
        let sp = sp_descriptor(false);
        let raw_query = build_signed_redirect_authn_request_raw_query("_wire-authn-1");

        // Two-step path.
        let decoded = crate::binding::decode_wire(
            raw_query.as_bytes(),
            Binding::HttpRedirect,
            crate::binding::WireDirection::Request,
        )
        .expect("decode_wire");
        let two_step = idp
            .consume_authn_request(ConsumeAuthnRequest {
                sp: &sp,
                peer_crypto_policy: None,
                saml_request: &decoded.xml,
                binding: Binding::HttpRedirect,
                relay_state: decoded.relay_state.as_deref(),
                detached_signature: decoded.as_detached_signature(),
                expected_destination: "https://idp.example.com/sso",
                now: fixed_now(),
                clock_skew: Duration::from_mins(1),
            })
            .expect("two-step consume must succeed");

        // Wire-helper path.
        let one_call = idp
            .consume_authn_request_wire(ConsumeAuthnRequestWire {
                sp: &sp,
                peer_crypto_policy: None,
                wire_body: raw_query.as_bytes(),
                binding: Binding::HttpRedirect,
                relay_state: None,
                expected_destination: "https://idp.example.com/sso",
                now: fixed_now(),
                clock_skew: Duration::from_mins(1),
            })
            .expect("wire helper must succeed");

        assert_eq!(one_call.id, two_step.id);
        assert_eq!(one_call.issuer, two_step.issuer);
        assert_eq!(one_call.relay_state, two_step.relay_state);
        assert_eq!(one_call.relay_state.as_deref(), Some("rs-wire-authn"));
        assert_eq!(
            one_call.assertion_consumer_service.url,
            two_step.assertion_consumer_service.url
        );
    }

    #[test]
    fn signed_redirect_rejects_xml_or_relay_state_not_covered_by_signature() {
        let idp = idp_with(true, false);
        let sp = sp_descriptor(false);
        let signed_query = build_signed_redirect_authn_request_raw_query("_signed-request");
        let decoded = crate::binding::decode_wire(
            signed_query.as_bytes(),
            Binding::HttpRedirect,
            crate::binding::WireDirection::Request,
        )
        .expect("decode signed query");

        let substituted_xml = build_unsigned_authn_request("_substituted-request", true);
        let err = idp
            .consume_authn_request(ConsumeAuthnRequest {
                sp: &sp,
                peer_crypto_policy: None,
                saml_request: &substituted_xml,
                binding: Binding::HttpRedirect,
                relay_state: decoded.relay_state.as_deref(),
                detached_signature: decoded.as_detached_signature(),
                expected_destination: "https://idp.example.com/sso",
                now: fixed_now(),
                clock_skew: Duration::from_mins(1),
            })
            .expect_err("a valid signature cannot be paired with different XML");
        assert!(matches!(err, Error::SignatureVerification { .. }));

        let err = idp
            .consume_authn_request(ConsumeAuthnRequest {
                sp: &sp,
                peer_crypto_policy: None,
                saml_request: &decoded.xml,
                binding: Binding::HttpRedirect,
                relay_state: Some("substituted-relay-state"),
                detached_signature: decoded.as_detached_signature(),
                expected_destination: "https://idp.example.com/sso",
                now: fixed_now(),
                clock_skew: Duration::from_mins(1),
            })
            .expect_err("a valid signature cannot be paired with different RelayState");
        assert!(matches!(err, Error::SignatureVerification { .. }));
    }

    #[test]
    fn wire_redirect_rejects_a_conflicting_relay_state_override() {
        let idp = idp_with(true, false);
        let sp = sp_descriptor(false);
        let raw_query = build_signed_redirect_authn_request_raw_query("_wire-relay-conflict");

        let err = idp
            .consume_authn_request_wire(ConsumeAuthnRequestWire {
                sp: &sp,
                peer_crypto_policy: None,
                wire_body: raw_query.as_bytes(),
                binding: Binding::HttpRedirect,
                relay_state: Some("different-state"),
                expected_destination: "https://idp.example.com/sso",
                now: fixed_now(),
                clock_skew: Duration::from_mins(1),
            })
            .expect_err("the decoded signed RelayState is authoritative");
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    #[test]
    fn consume_authn_request_wire_unsigned_redirect_when_not_required() {
        // The wire path must accept unsigned Redirect requests when the IdP
        // does not require signing — mirroring the two-step API.
        let idp = idp_with(false, false);
        let sp = sp_descriptor(false);
        let raw_query = build_unsigned_redirect_authn_request_raw_query("_wire-authn-unsigned");
        let parsed = idp
            .consume_authn_request_wire(ConsumeAuthnRequestWire {
                sp: &sp,
                peer_crypto_policy: None,
                wire_body: raw_query.as_bytes(),
                binding: Binding::HttpRedirect,
                relay_state: None,
                expected_destination: "https://idp.example.com/sso",
                now: fixed_now(),
                clock_skew: Duration::from_mins(1),
            })
            .expect("unsigned wire consume must succeed");
        assert_eq!(parsed.id, "_wire-authn-unsigned");
        assert_eq!(parsed.relay_state.as_deref(), Some("rs-wire-authn"));
    }

    /// Replace the `Signature=...` parameter value in a Redirect-bound raw
    /// query string with garbage that still parses as a valid base64 string
    /// but does not verify against the signer's key. The XML payload and the
    /// canonical signed-slice are left intact so the failure surfaces from
    /// the verifier, not the decoder.
    fn tamper_redirect_signature_param(raw_query: &str) -> String {
        let mut pieces: Vec<String> = Vec::new();
        for pair in raw_query.split('&') {
            if pair.starts_with("Signature=") {
                // Replace with an obviously-bogus but well-formed base64 blob
                // of the same shape (256 chars → 192-byte signature, same as
                // RSA-2048 RsaSha256). Any well-formed but wrong signature
                // suffices to drive the verifier to reject.
                let bogus = "A".repeat(256);
                pieces.push(format!("Signature={bogus}"));
            } else {
                pieces.push(pair.to_owned());
            }
        }
        pieces.join("&")
    }

    #[test]
    fn consume_authn_request_wire_signed_redirect_rejects_tampered_signature() {
        // Swap the detached signature bytes for a bogus blob: the wire helper
        // must surface a signature-verification failure, matching the
        // two-step path's behavior.
        let idp = idp_with(true, false);
        let sp = sp_descriptor(false);
        let raw_query = build_signed_redirect_authn_request_raw_query("_wire-authn-tamper");
        let tampered = tamper_redirect_signature_param(&raw_query);
        let err = idp
            .consume_authn_request_wire(ConsumeAuthnRequestWire {
                sp: &sp,
                peer_crypto_policy: None,
                wire_body: tampered.as_bytes(),
                binding: Binding::HttpRedirect,
                relay_state: None,
                expected_destination: "https://idp.example.com/sso",
                now: fixed_now(),
                clock_skew: Duration::from_mins(1),
            })
            .unwrap_err();
        assert!(matches!(err, Error::SignatureVerification { .. }));
    }

    #[cfg(feature = "slo")]
    fn build_signed_redirect_logout_request_raw_query(id: &str) -> String {
        use crate::binding::redirect::{RedirectDirection, encode_signed};

        let nid = NameId::email("alice@example.com");
        let xml = crate::logout::request_build::build_logout_request_xml(&BuildLogoutRequest {
            id,
            issue_instant: fixed_now(),
            issuer_entity_id: "https://sp.example.com/saml",
            destination: Some("https://idp.example.com/slo"),
            not_on_or_after: None,
            reason: None,
            name_id: &nid,
            session_index: Some("sess-1"),
        })
        .unwrap();
        let kp = rsa_keypair_with_cert();
        let sig_alg = SignatureAlgorithm::RsaSha256;
        let dest = url::Url::parse("https://idp.example.com/slo").unwrap();
        let dispatch = encode_signed(
            &dest,
            RedirectDirection::Request,
            &xml,
            None,
            sig_alg.uri(),
            |to_sign| crate::dsig::sign::sign_detached_query(to_sign, &kp, sig_alg),
        )
        .unwrap();
        let url = match dispatch {
            Dispatch::Redirect(u) => u,
            other @ Dispatch::Post(_) => panic!("expected Redirect dispatch, got {other:?}"),
        };
        url.query().unwrap().to_owned()
    }

    #[cfg(feature = "slo")]
    #[test]
    fn consume_logout_request_wire_matches_two_step_for_signed_redirect() {
        let mut idp = idp_with(false, false);
        idp.config.logout_want_signed.requests = true;
        let sp = sp_descriptor(false);
        let raw_query = build_signed_redirect_logout_request_raw_query("_wire-lo-req-1");

        // Two-step path: reuse the existing helper that returns the
        // post-decode pieces, then feed them to `consume_logout_request`.
        let (xml, signed_qs, signature, sig_alg) =
            build_signed_redirect_logout_request("_wire-lo-req-1");
        let two_step = idp
            .consume_logout_request(
                &sp,
                ConsumeLogoutRequest {
                    peer_crypto_policy: None,
                    body: &xml,
                    binding: Binding::HttpRedirect,
                    detached_signature: Some(DetachedSignature {
                        signature: &signature,
                        sig_alg: &sig_alg,
                        raw_query_string: &signed_qs,
                    }),
                    expected_destination: "https://idp.example.com/slo",
                    now: fixed_now(),
                    clock_skew: Duration::from_mins(1),
                },
            )
            .expect("two-step consume must succeed");

        // Wire-helper path.
        let one_call = idp
            .consume_logout_request_wire(ConsumeLogoutRequestWire {
                sp: &sp,
                peer_crypto_policy: None,
                wire_body: raw_query.as_bytes(),
                binding: Binding::HttpRedirect,
                expected_destination: "https://idp.example.com/slo",
                now: fixed_now(),
                clock_skew: Duration::from_mins(1),
            })
            .expect("wire helper must succeed");

        assert_eq!(one_call.id, two_step.id);
        assert_eq!(one_call.issuer, two_step.issuer);
        assert_eq!(one_call.name_id.value, two_step.name_id.value);
        assert_eq!(one_call.session_index, two_step.session_index);
    }

    #[cfg(feature = "slo")]
    #[test]
    fn consume_logout_request_wire_rejects_tampered_signed_redirect() {
        let mut idp = idp_with(false, false);
        idp.config.logout_want_signed.requests = true;
        let sp = sp_descriptor(false);
        let raw_query = build_signed_redirect_logout_request_raw_query("_wire-lo-req-2");
        let tampered = tamper_redirect_signature_param(&raw_query);
        let err = idp
            .consume_logout_request_wire(ConsumeLogoutRequestWire {
                sp: &sp,
                peer_crypto_policy: None,
                wire_body: tampered.as_bytes(),
                binding: Binding::HttpRedirect,
                expected_destination: "https://idp.example.com/slo",
                now: fixed_now(),
                clock_skew: Duration::from_mins(1),
            })
            .unwrap_err();
        assert!(matches!(err, Error::SignatureVerification { .. }));
    }

    #[cfg(feature = "slo")]
    fn build_signed_redirect_logout_response_raw_query(id: &str, in_response_to: &str) -> String {
        use crate::binding::redirect::{RedirectDirection, encode_signed};

        let xml = crate::logout::response_build::build_logout_response_xml(&BuildLogoutResponse {
            id,
            issue_instant: fixed_now(),
            issuer_entity_id: "https://sp.example.com/saml",
            destination: Some("https://idp.example.com/slo"),
            in_response_to,
            status: LogoutStatus::Success,
            status_message: None,
        })
        .unwrap();
        let kp = rsa_keypair_with_cert();
        let sig_alg = SignatureAlgorithm::RsaSha256;
        let dest = url::Url::parse("https://idp.example.com/slo").unwrap();
        let dispatch = encode_signed(
            &dest,
            RedirectDirection::Response,
            &xml,
            None,
            sig_alg.uri(),
            |to_sign| crate::dsig::sign::sign_detached_query(to_sign, &kp, sig_alg),
        )
        .unwrap();
        let url = match dispatch {
            Dispatch::Redirect(u) => u,
            other @ Dispatch::Post(_) => panic!("expected Redirect dispatch, got {other:?}"),
        };
        url.query().unwrap().to_owned()
    }

    #[cfg(feature = "slo")]
    #[test]
    fn consume_logout_response_wire_matches_two_step_for_signed_redirect() {
        let mut idp = idp_with(false, false);
        idp.config.logout_want_signed.responses = true;
        let sp = sp_descriptor(false);
        let in_response_to = "_wire-lo-resp-anchor";
        let tracker = LogoutTracker {
            request_id: in_response_to.to_owned(),
            issued_at: fixed_now(),
            peer_entity_id: sp.entity_id.clone(),
        };
        let raw_query =
            build_signed_redirect_logout_response_raw_query("_wire-lo-resp-1", in_response_to);

        // Two-step path: decode wire, then call consume_logout_response.
        let decoded = crate::binding::decode_wire(
            raw_query.as_bytes(),
            Binding::HttpRedirect,
            crate::binding::WireDirection::Response,
        )
        .expect("decode_wire response");
        let two_step = idp
            .consume_logout_response(
                &sp,
                ConsumeLogoutResponse {
                    peer_crypto_policy: None,
                    body: &decoded.xml,
                    binding: Binding::HttpRedirect,
                    detached_signature: decoded.as_detached_signature(),
                    tracker: &tracker,
                    expected_destination: "https://idp.example.com/slo",
                    now: fixed_now(),
                    clock_skew: Duration::from_mins(1),
                },
            )
            .expect("two-step consume_logout_response must succeed");

        // Wire-helper path.
        let one_call = idp
            .consume_logout_response_wire(ConsumeLogoutResponseWire {
                sp: &sp,
                peer_crypto_policy: None,
                wire_body: raw_query.as_bytes(),
                binding: Binding::HttpRedirect,
                tracker: &tracker,
                expected_destination: "https://idp.example.com/slo",
                now: fixed_now(),
                clock_skew: Duration::from_mins(1),
            })
            .expect("wire helper must succeed");

        assert!(matches!(one_call, LogoutOutcome::Success));
        assert!(matches!(two_step, LogoutOutcome::Success));
    }

    #[cfg(feature = "slo")]
    #[test]
    fn consume_logout_response_wire_rejects_tampered_signed_redirect() {
        let mut idp = idp_with(false, false);
        idp.config.logout_want_signed.responses = true;
        let sp = sp_descriptor(false);
        let in_response_to = "_wire-lo-resp-tamper-anchor";
        let tracker = LogoutTracker {
            request_id: in_response_to.to_owned(),
            issued_at: fixed_now(),
            peer_entity_id: sp.entity_id.clone(),
        };
        let raw_query =
            build_signed_redirect_logout_response_raw_query("_wire-lo-resp-tamper", in_response_to);
        let tampered = tamper_redirect_signature_param(&raw_query);
        let err = idp
            .consume_logout_response_wire(ConsumeLogoutResponseWire {
                sp: &sp,
                peer_crypto_policy: None,
                wire_body: tampered.as_bytes(),
                binding: Binding::HttpRedirect,
                tracker: &tracker,
                expected_destination: "https://idp.example.com/slo",
                now: fixed_now(),
                clock_skew: Duration::from_mins(1),
            })
            .unwrap_err();
        assert!(matches!(err, Error::SignatureVerification { .. }));
    }

    #[cfg(feature = "slo")]
    #[test]
    fn soap_envelope_round_trip_extracts_payload() {
        let saml = r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_x" Version="2.0" IssueInstant="2026-05-26T12:34:56Z" InResponseTo="_y"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">idp</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>"#;
        let envelope = wrap_soap_envelope(saml).unwrap();
        let unwrapped = unwrap_soap_envelope(envelope.as_bytes()).unwrap();
        // The unwrapped payload must re-parse as a LogoutResponse.
        let doc = Document::parse(&unwrapped).unwrap();
        assert_eq!(doc.root().qname().local(), "LogoutResponse");
    }
}
