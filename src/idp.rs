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

#[cfg(feature = "slo")]
use base64::Engine as _;
#[cfg(feature = "slo")]
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::attribute::Attribute;
use crate::authn::request_parse::parse_authn_request;
use crate::authn::request_validate::validate_authn_request;
use crate::authn_context::AuthnContextClassRef;
#[cfg(any(feature = "slo", test))]
use crate::binding::Dispatch;
use crate::binding::{Binding, Endpoint, SsoResponseDispatch};
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
    /// Maximum age of an inbound `<samlp:AuthnRequest>`, measured from its
    /// `IssueInstant` and widened by the call's `clock_skew`.
    ///
    /// SAML gives `AuthnRequest` no `NotOnOrAfter`, so unlike `LogoutRequest`
    /// there is no peer-supplied expiry to enforce — the IdP has to supply the
    /// bound. Without one a captured request stays replayable forever, which
    /// makes `want_authn_requests_signed` much weaker than it looks: the
    /// signature proves the SP authored the request, never that it authored it
    /// recently.
    ///
    /// This bounds the replay window; it does not close it. Rejecting a
    /// *repeat* within the window needs request-ID bookkeeping, which the
    /// caller owns.
    ///
    /// This is a required field with no automatic default —
    /// [`IdentityProviderConfig::DEFAULT_MAX_AUTHN_REQUEST_AGE`] is the
    /// recommended value to pass, not a fallback applied on your behalf.
    ///
    /// `Duration::MAX` disables *age* enforcement only. A request dated into
    /// the future is still rejected beyond the call's `clock_skew`: that
    /// bound comes from the skew, not from this field, and dropping it would
    /// make a future-dated request acceptable indefinitely — the same hole
    /// this setting exists to close, wearing a different sign.
    pub max_authn_request_age: Duration,
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

impl IdentityProviderConfig {
    /// Recommended [`max_authn_request_age`]: five minutes.
    ///
    /// A browser-mediated `AuthnRequest` is redirected on within seconds, so
    /// this is generous for real flows while keeping the replay window short.
    /// The field is required, so nothing applies this automatically — pass it
    /// explicitly, or a value your deployment justifies.
    ///
    /// [`max_authn_request_age`]: IdentityProviderConfig::max_authn_request_age
    pub const DEFAULT_MAX_AUTHN_REQUEST_AGE: Duration = Duration::from_mins(5);
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
    /// Overrides [`IdentityProviderConfig::max_authn_request_age`] for this
    /// call.
    ///
    /// Scoped per call for the same reason `peer_crypto_policy` is: an SP
    /// whose flow legitimately runs long should not force a wider window on
    /// every other SP. `None` uses the IdP default.
    pub max_authn_request_age: Option<Duration>,
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
            Binding::HttpRedirect => verify_redirect_request_signature(
                signature_required,
                input.detached_signature.as_ref(),
                &input.sp.signing_certs,
                &policy.allowed_signature_algorithms,
            )?,
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

        // 5. Freshness. Runs after the signature check so an unauthenticated
        //    sender the effective policy refuses cannot probe the accepted
        //    time window. That qualifier matters: when neither
        //    `want_authn_requests_signed` nor the SP's metadata requires a
        //    signature, unsigned requests are accepted and then judged on
        //    freshness, so such a sender *can* probe it. The ordering is still
        //    correct — it is simply not a probing defence on its own.
        //
        //    `AuthnRequest` carries no `NotOnOrAfter` (contrast
        //    `LogoutRequest`, whose peer-supplied expiry is enforced in
        //    `consume_logout_request`), so the bound comes from this IdP's
        //    `max_authn_request_age`. Both directions are checked: a
        //    future-dated request would otherwise stay valid for as long as
        //    its `IssueInstant` is ahead of us.
        let max_age = input
            .max_authn_request_age
            .unwrap_or(self.config.max_authn_request_age);
        if let Ok(ahead) = parsed.issue_instant.duration_since(input.now)
            && ahead > input.clock_skew
        {
            return Err(Error::AuthnRequestNotYetValid {
                ahead,
                clock_skew: input.clock_skew,
            });
        }
        let limit = max_age.saturating_add(input.clock_skew);
        if let Ok(age) = input.now.duration_since(parsed.issue_instant)
            && age > limit
        {
            return Err(Error::StaleAuthnRequest { age, limit });
        }

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
    ///     max_authn_request_age: None,
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
            max_authn_request_age: input.max_authn_request_age,
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
    /// Overrides [`IdentityProviderConfig::max_authn_request_age`] for this
    /// call.
    ///
    /// Scoped per call for the same reason `peer_crypto_policy` is: an SP
    /// whose flow legitimately runs long should not force a wider window on
    /// every other SP. `None` uses the IdP default.
    pub max_authn_request_age: Option<Duration>,
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

impl IdentityProvider {
    /// Mint and binding-encode a success `<samlp:Response>` for an SP.
    /// See RFC-004 §3.1.
    pub fn issue_response(&self, input: IssueResponse<'_>) -> Result<SsoResponseDispatch, Error> {
        ensure_request_belongs_to_sp(input.in_response_to, input.sp)?;
        ensure_authn_context_satisfies_request(
            input.in_response_to,
            &input.authn_context_class_ref,
        )?;
        // Canonical endpoint from the SP's metadata, not the `pub` field:
        // `SsoResponseEndpoint::index` is public too, and artifact issuance
        // names the endpoint by index.
        let acs_endpoint = input.in_response_to.validated_acs();
        let relay_state = input.in_response_to.validated_relay_state();

        // Resolve outbound `NameID` Format: honor the SP's requested format
        // when supported, otherwise fall back to the IdP's default. From the
        // validated provenance, not the caller-mutable `pub` copy.
        let chosen_format = pick_name_id_format(
            input.in_response_to.validated_name_id_format(),
            &self.config.supported_name_id_formats,
            &self.config.default_name_id_format,
        )?;
        let mut name_id = input.name_id;
        name_id.format = chosen_format;

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
            relay_state,
            holder_of_key_cert: input.holder_of_key_cert,
        };

        issue_response(inputs)
    }

    /// Mint and binding-encode an error `<samlp:Response>` for an SP. The
    /// shape mirrors a success Response (same Issuer, Destination, ACS,
    /// signing rules) but carries `Status != Success` and no Assertion.
    /// See RFC-004 §4.
    pub fn issue_error_response(
        &self,
        input: IssueErrorResponse<'_>,
    ) -> Result<SsoResponseDispatch, Error> {
        ensure_request_belongs_to_sp(input.in_response_to, input.sp)?;
        // Canonical endpoint from the SP's metadata, not the `pub` field:
        // `SsoResponseEndpoint::index` is public too, and artifact issuance
        // names the endpoint by index.
        let acs_endpoint = input.in_response_to.validated_acs();
        let relay_state = input.in_response_to.validated_relay_state();

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
            relay_state,
        };

        issue_error_response(inputs)
    }

    /// Parse an inbound `<samlp:ArtifactResolve>` SOAP envelope received at
    /// this IdP's `ArtifactResolutionService` endpoint. The caller looks up
    /// the artifact value in its store and constructs the response via
    /// [`IdentityProvider::build_artifact_response`].
    ///
    /// Verifies the requesting SP's issuer matches the supplied
    /// [`SpDescriptor`]; mismatches return [`Error::IssuerMismatch`].
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

    /// Build an outbound `<samlp:ArtifactResponse>` SOAP envelope wrapping
    /// `payload_xml` (typically the previously-stashed `<samlp:Response>`
    /// keyed by `request.artifact`). `request` must be the
    /// [`crate::binding::artifact::ArtifactResolveRequest`] returned from
    /// [`IdentityProvider::parse_artifact_resolve`].
    ///
    /// The returned SOAP envelope is ready to be served as the HTTP response
    /// body with `Content-Type: text/xml`.
    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    pub fn build_artifact_response(
        &self,
        request: &crate::binding::artifact::ArtifactResolveRequest,
        payload_xml: &str,
    ) -> Result<String, Error> {
        crate::binding::artifact::build_artifact_response(
            &self.config.entity_id,
            &request.request_id,
            payload_xml,
        )
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
    // Key material, not just identity.
    //
    // Issuance encrypts the assertion to `sp`'s encryption certificate, and
    // entity ID plus ACS do not pin that: a descriptor with the same identity
    // and a substituted certificate has the assertion encrypted to the
    // substituted key, and one with the certificate removed silently
    // downgrades opportunistic encryption to plaintext.
    let sealed = request.validated_encryption_cert_fingerprints();
    let current: Vec<[u8; 32]> = sp
        .encryption_certs
        .iter()
        .map(crate::crypto::cert::X509Certificate::fingerprint_sha256)
        .collect();
    if current != sealed {
        return Err(Error::SpKeyMaterialMismatch);
    }

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
    use crate::response::issue::SamlStatusCode;
    use crate::xml::emit::emit_document;
    use crate::xml::parse::Node;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

    fn idp_with(want_authn_requests_signed: bool, sign_responses: bool) -> IdentityProvider {
        IdentityProvider::new(idp_config_with(want_authn_requests_signed, sign_responses))
            .expect("idp config valid")
    }

    /// The config `idp_with` builds, exposed so tests can tweak one knob
    /// without restating every field.
    fn idp_config_with(
        want_authn_requests_signed: bool,
        sign_responses: bool,
    ) -> IdentityProviderConfig {
        IdentityProviderConfig {
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
            max_authn_request_age: IdentityProviderConfig::DEFAULT_MAX_AUTHN_REQUEST_AGE,
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
        }
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
                max_authn_request_age: None,
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

    // ---------- AuthnRequest freshness ----------

    /// Drive `consume_authn_request` with a signed request built at
    /// `fixed_now()`, evaluated as if the clock reads `now`.
    fn consume_at(
        idp: &IdentityProvider,
        now: SystemTime,
        clock_skew: Duration,
    ) -> Result<ParsedAuthnRequest, Error> {
        let sp = sp_descriptor(true);
        let xml = build_signed_authn_request("_req-fresh");
        idp.consume_authn_request(ConsumeAuthnRequest {
            sp: &sp,
            peer_crypto_policy: None,
            max_authn_request_age: None,
            saml_request: &xml,
            binding: Binding::HttpPost,
            relay_state: None,
            detached_signature: None,
            expected_destination: "https://idp.example.com/sso",
            now,
            clock_skew,
        })
    }

    #[test]
    fn stale_authn_request_is_rejected() {
        // A valid signature proves the SP authored the request, never that it
        // did so recently — without a bound, a captured request replays for
        // ever.
        let idp = idp_with(true, false);
        let skew = Duration::from_mins(1);
        let max_age = idp.config.max_authn_request_age;

        consume_at(&idp, fixed_now() + max_age + skew, skew)
            .expect("exactly at the limit is still fresh");

        let err = consume_at(
            &idp,
            fixed_now() + max_age + skew + Duration::from_secs(1),
            skew,
        )
        .expect_err("one second past the limit is stale");
        // A dedicated variant, not `Expired`: that one is documented as an
        // assertion's `Conditions/@NotOnOrAfter` having passed, and an
        // AuthnRequest carries no such attribute.
        assert!(
            matches!(err, Error::StaleAuthnRequest { limit, .. } if limit == max_age + skew),
            "got {err:?}"
        );
    }

    #[test]
    fn future_dated_authn_request_beyond_skew_is_rejected() {
        // Evaluating at a clock *behind* the IssueInstant is the same shape as
        // a request dated into the future. Without this leg such a request
        // stays acceptable for as long as it is dated ahead.
        let idp = idp_with(true, false);
        let skew = Duration::from_mins(1);

        consume_at(&idp, fixed_now() - skew, skew).expect("within tolerated skew");

        let err = consume_at(&idp, fixed_now() - skew - Duration::from_secs(1), skew)
            .expect_err("beyond tolerated skew");
        assert!(
            matches!(err, Error::AuthnRequestNotYetValid { clock_skew, .. } if clock_skew == skew),
            "got {err:?}"
        );
    }

    /// The per-call override must actually win over the IdP default, so one
    /// SP with a slow flow does not force a wider window on every other SP —
    /// the same scoping argument `peer_crypto_policy` exists for.
    #[test]
    fn per_call_max_age_overrides_the_idp_default() {
        let idp = idp_with(true, false);
        let sp = sp_descriptor(true);
        let xml = build_signed_authn_request("_req-fresh");
        let skew = Duration::from_mins(1);
        let default_max = idp.config.max_authn_request_age;
        // Comfortably past the IdP default, comfortably inside the override.
        let now = fixed_now() + default_max + skew + Duration::from_mins(10);

        let consume = |max_authn_request_age| {
            idp.consume_authn_request(ConsumeAuthnRequest {
                sp: &sp,
                peer_crypto_policy: None,
                max_authn_request_age,
                saml_request: &xml,
                binding: Binding::HttpPost,
                relay_state: None,
                detached_signature: None,
                expected_destination: "https://idp.example.com/sso",
                now,
                clock_skew: skew,
            })
        };

        let err = consume(None).expect_err("the IdP default rejects it");
        assert!(
            matches!(err, Error::StaleAuthnRequest { .. }),
            "got {err:?}"
        );

        consume(Some(default_max + Duration::from_hours(1)))
            .expect("a wider per-call window accepts the same request");

        assert_eq!(
            idp.config.max_authn_request_age, default_max,
            "the override must not have mutated the IdP default"
        );
    }

    /// `Duration::MAX` opts out of the *age* bound, not of future-dating.
    /// A request dated arbitrarily far ahead stays rejected, because that
    /// bound comes from `clock_skew`. Covered at both the config level and
    /// the per-call override, since either could have been wired to skip the
    /// whole check.
    #[test]
    fn max_duration_opt_out_still_rejects_future_dated_requests() {
        let skew = Duration::from_mins(1);
        let far_behind = fixed_now() - skew - Duration::from_hours(24);

        // Config-level opt-out.
        let mut cfg = idp_config_with(true, false);
        cfg.max_authn_request_age = Duration::MAX;
        let idp = IdentityProvider::new(cfg).expect("idp config valid");
        let err = consume_at(&idp, far_behind, skew)
            .expect_err("future-dated beyond skew is still refused");
        assert!(
            matches!(err, Error::AuthnRequestNotYetValid { .. }),
            "config opt-out: got {err:?}"
        );

        // Per-call opt-out.
        let idp = idp_with(true, false);
        let sp = sp_descriptor(true);
        let xml = build_signed_authn_request("_req-fresh");
        let err = idp
            .consume_authn_request(ConsumeAuthnRequest {
                sp: &sp,
                peer_crypto_policy: None,
                max_authn_request_age: Some(Duration::MAX),
                saml_request: &xml,
                binding: Binding::HttpPost,
                relay_state: None,
                detached_signature: None,
                expected_destination: "https://idp.example.com/sso",
                now: far_behind,
                clock_skew: skew,
            })
            .expect_err("per-call opt-out does not waive the skew bound either");
        assert!(
            matches!(err, Error::AuthnRequestNotYetValid { .. }),
            "per-call opt-out: got {err:?}"
        );
    }

    #[test]
    fn max_duration_disables_the_freshness_bound() {
        let mut cfg = idp_config_with(true, false);
        cfg.max_authn_request_age = Duration::MAX;
        let idp = IdentityProvider::new(cfg).expect("idp config valid");

        consume_at(
            &idp,
            fixed_now() + Duration::from_hours(24 * 365),
            Duration::from_mins(1),
        )
        .expect("Duration::MAX opts out without overflowing the skew addition");
    }

    #[test]
    fn freshness_is_checked_after_the_signature() {
        // A stale *and* unsigned request must surface the signature failure,
        // so a sender the effective policy refuses cannot probe the accepted
        // window. Where signing is optional, unsigned requests are accepted and
        // then judged on freshness, so the ordering does not stop probing there.
        let idp = idp_with(true, false);
        let sp = sp_descriptor(false);
        let xml = build_unsigned_authn_request("_req-stale-unsigned", true);
        let skew = Duration::from_mins(1);

        let err = idp
            .consume_authn_request(ConsumeAuthnRequest {
                sp: &sp,
                peer_crypto_policy: None,
                max_authn_request_age: None,
                saml_request: &xml,
                binding: Binding::HttpPost,
                relay_state: None,
                detached_signature: None,
                expected_destination: "https://idp.example.com/sso",
                now: fixed_now() + idp.config.max_authn_request_age + skew + Duration::from_secs(1),
                clock_skew: skew,
            })
            .expect_err("unsigned and stale");
        assert!(matches!(err, Error::SignatureMissing));
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
                max_authn_request_age: None,
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
                max_authn_request_age: None,
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
                max_authn_request_age: None,
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
                max_authn_request_age: None,
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

    /// `SsoResponseEndpoint::index` is public, and the artifact encodes the
    /// endpoint index in bytes 2..4. Issuance therefore takes the canonical
    /// endpoint from metadata, so a mutated index never reaches the wire.
    ///
    /// Exercised through the artifact binding specifically: under POST the
    /// index is unused, so a POST-based test would pass either way.
    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    #[test]
    fn mutating_the_acs_index_does_not_reach_the_artifact() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as BASE64;

        const CANONICAL_INDEX: u16 = 3;
        let idp = idp_with(false, false);
        let mut sp = sp_descriptor(false);
        sp.assertion_consumer_services = vec![SsoResponseEndpoint::artifact(
            "https://sp.example.com/acs-artifact",
            CANONICAL_INDEX,
            true,
        )];

        let mut parsed_req = ParsedAuthnRequest::for_proxy_reissue(
            &sp,
            "_req-artifact".into(),
            fixed_now(),
            sp.assertion_consumer_services[0].clone(),
            None,
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
            emitted_index, CANONICAL_INDEX,
            "the artifact must name the registered endpoint, not the mutated one"
        );
    }

    fn issue_to(
        idp: &IdentityProvider,
        sp: &SpDescriptor,
        req: &ParsedAuthnRequest,
    ) -> Result<SsoResponseDispatch, Error> {
        idp.issue_response(IssueResponse {
            sp,
            in_response_to: req,
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
                name_id: NameId::email("alice@example.com"),
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
        assert_eq!(parsed_assertion.subject_name_id.value, "alice@example.com");
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
                max_authn_request_age: None,
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
                max_authn_request_age: None,
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
                max_authn_request_age: None,
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
                max_authn_request_age: None,
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
