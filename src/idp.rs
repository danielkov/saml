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

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::attribute::Attribute;
use crate::authn::request_parse::parse_authn_request;
use crate::authn::request_validate::validate_authn_request;
use crate::authn_context::AuthnContextClassRef;
use crate::binding::{
    Binding, Endpoint, SsoResponseDispatch,
};
#[cfg(feature = "slo")]
use crate::binding::Dispatch;
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

#[cfg(any(feature = "slo", test))]
const SAMLP_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
#[cfg(feature = "slo")]
const SAML_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
#[cfg(feature = "slo")]
const SOAP_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";

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
        if config.entity_id.is_empty()
            || config.entity_id.chars().any(char::is_whitespace)
        {
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
                    &policy.allowed_signature_algorithms,
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

        parsed.relay_state = input.relay_state.map(str::to_owned);
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
        let resolved_relay_state = input.relay_state.or(decoded.relay_state.as_deref());
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
    allowed_algorithms: &[SignatureAlgorithm],
) -> Result<(), Error> {
    let sig_elem = root.child_element(Some(DS_NS), "Signature");
    match sig_elem {
        None if required => Err(Error::SignatureMissing),
        None => Ok(()),
        Some(sig) => {
            let verified =
                verify_signature(doc, sig, candidate_certs, allowed_algorithms)?;
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
        let acs_endpoint = &input.in_response_to.assertion_consumer_service;
        let relay_state = input.in_response_to.relay_state.as_deref();

        // Resolve outbound `NameID` Format: honor the SP's requested format
        // when supported, otherwise fall back to the IdP's default.
        let chosen_format = pick_name_id_format(
            input.in_response_to.requested_name_id_format.as_ref(),
            &self.config.supported_name_id_formats,
            &self.config.default_name_id_format,
        );
        let mut name_id = input.name_id;
        name_id.format = chosen_format;

        let inputs = IssueResponseInputs {
            sp: input.sp,
            idp_entity_id: &self.config.entity_id,
            in_response_to: Some(input.in_response_to.id.as_str()),
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
        let acs_endpoint = &input.in_response_to.assertion_consumer_service;
        let relay_state = input.in_response_to.relay_state.as_deref();

        let inputs = IssueErrorResponseInputs {
            idp_entity_id: &self.config.entity_id,
            in_response_to: Some(input.in_response_to.id.as_str()),
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

/// Pick the `NameID` Format for the outbound Assertion. The SP-requested
/// format wins iff it appears in our `supported_name_id_formats`; otherwise
/// we fall back to the IdP default. This matches the SAML 2.0 NameIDPolicy
/// negotiation rules (Core §3.4.1.1).
fn pick_name_id_format(
    requested: Option<&NameIdFormat>,
    supported: &[NameIdFormat],
    default: &NameIdFormat,
) -> NameIdFormat {
    match requested {
        Some(fmt) if supported.contains(fmt) => fmt.clone(),
        _ => default.clone(),
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
        if !self.config.slo.iter().any(|e| e.url == expected_destination) {
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
            &policy.allowed_signature_algorithms,
        )?;

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

        let id = generate_xml_id();
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
        let element = self.maybe_sign_outbound(element, self.config.logout_signing.sign_responses)?;
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
        let destination_endpoint = sp
            .slo_endpoint(opts.binding)
            .ok_or(Error::UnsupportedByPeer {
                binding: opts.binding,
            })?;

        let id = generate_xml_id();
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
                let element = self.maybe_sign_outbound(element, self.config.logout_signing.sign_requests)?;
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
        if !self.config.slo.iter().any(|e| e.url == expected_destination) {
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
            &policy.allowed_signature_algorithms,
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
            sp.slo_endpoint(Binding::Soap).ok_or(Error::UnsupportedByPeer {
                binding: Binding::Soap,
            })?;

        let id = generate_xml_id();
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
        let element = self.maybe_sign_outbound(element, self.config.logout_signing.sign_requests)?;
        let xml = serialize_element(element)?;
        let xml_str = std::str::from_utf8(&xml)
            .map_err(|_err| Error::XmlEmit("non-UTF-8 outbound XML".to_string()))?;
        let envelope = wrap_soap_envelope(xml_str);

        let request = HttpRequest {
            method: http::Method::POST,
            url: destination_endpoint.url.clone(),
            headers: vec![
                ("Content-Type".to_owned(), "text/xml".to_owned()),
                ("SOAPAction".to_owned(), "\"\"".to_owned()),
            ],
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
    fn maybe_sign_outbound(
        &self,
        element: Element,
        should_sign: bool,
    ) -> Result<Element, Error> {
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
    allowed_algorithms: &[SignatureAlgorithm],
) -> Result<(), Error> {
    match binding {
        Binding::HttpRedirect => verify_redirect_request_signature(
            required,
            detached,
            candidate_certs,
            allowed_algorithms,
        ),
        Binding::HttpPost | Binding::Soap => {
            let root = doc
                .element(root_id)
                .ok_or(Error::SignatureVerification {
                    reason: "could not locate root element for signature check",
                })?;
            verify_envelope_signature(
                required,
                doc,
                root,
                root_id,
                candidate_certs,
                allowed_algorithms,
            )
        }
        Binding::HttpArtifact => Err(Error::UnsupportedByPeer {
            binding: Binding::HttpArtifact,
        }),
    }
}

/// Wrap a SAML protocol message XML body in a SOAP 1.1 envelope.
#[cfg(feature = "slo")]
fn wrap_soap_envelope(saml_xml: &str) -> String {
    format!(
        r#"<soap:Envelope xmlns:soap="{SOAP_NS}"><soap:Body>{saml_xml}</soap:Body></soap:Envelope>"#
    )
}

/// Unwrap a SOAP 1.1 envelope and return the inner SAML protocol message
/// element re-serialized to XML bytes.
#[cfg(feature = "slo")]
fn unwrap_soap_envelope(envelope_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let doc = Document::parse(envelope_bytes)?;
    let envelope = doc.root();
    if envelope.qname().namespace() != Some(SOAP_NS) || envelope.qname().local() != "Envelope" {
        return Err(Error::XmlParse(
            "SOAP envelope root is not soap:Envelope".to_string(),
        ));
    }
    let body = envelope
        .child_element(Some(SOAP_NS), "Body")
        .ok_or_else(|| Error::XmlParse("SOAP envelope missing soap:Body".to_string()))?;
    let payload = body
        .child_elements()
        .find(|e| {
            let ns = e.qname().namespace();
            ns == Some(SAMLP_NS) || ns == Some(SAML_NS)
        })
        .ok_or_else(|| {
            Error::XmlParse("SOAP body contains no SAML payload element".to_string())
        })?;
    let serialized = crate::xml::emit::emit_element(payload)?;
    Ok(serialized.into_bytes())
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
            let envelope = wrap_soap_envelope(xml_str);
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

/// Generate a `_<32 hex>` XML `ID` value for outbound messages. Same shape as
/// `crate::response::issue::generate_xml_id` (kept local to avoid a
/// pub(crate) leak from `response::issue`).
#[cfg(feature = "slo")]
fn generate_xml_id() -> String {
    use rsa::rand_core::{OsRng, RngCore as _};
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = [0u8; 16];
    // `try_fill_bytes` failure is treated as catastrophic for ID minting; fall
    // back to a deterministic placeholder rather than `unwrap()` to keep this
    // call path panic-free. Returning a (very unlikely) zero-byte ID is
    // acceptable: callers treat the value as opaque and the surrounding
    // protocol layer never relies on entropy beyond uniqueness within the
    // session window.
    if OsRng.try_fill_bytes(&mut bytes).is_err() {
        bytes = [0u8; 16];
    }
    let mut out = String::with_capacity(33);
    out.push('_');
    for b in bytes {
        let hi = usize::from(b >> 4);
        let lo = usize::from(b & 0x0f);
        if let (Some(&h), Some(&l)) = (HEX.get(hi), HEX.get(lo)) {
            out.push(h as char);
            out.push(l as char);
        }
    }
    out
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
    use crate::authn_context::AuthnContextClassRef;
    use crate::binding::{Binding, Endpoint, SsoResponseDispatch, SsoResponseEndpoint};
    use crate::crypto::cert::X509Certificate;
    use crate::crypto::cert::test_vectors::{RSA_CERT_PEM, RSA_KEY_PKCS8_PEM};
    use crate::descriptor::IdpDescriptor;
    use crate::dsig::algorithms::{
        C14nAlgorithm, DigestAlgorithm, PeerCryptoPolicy, SignatureAlgorithm,
    };
    use crate::xml::emit::emit_document;
    #[cfg(feature = "slo")]
    use crate::logout::request_build::BuildLogoutRequest;
    #[cfg(feature = "slo")]
    use crate::logout::{LogoutOutcome, LogoutStatus, StartLogout};
    use crate::nameid::{NameId, NameIdFormat};
    use crate::response::issue::SamlStatusCode;
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

    fn idp_with(
        want_authn_requests_signed: bool,
        sign_responses: bool,
    ) -> IdentityProvider {
        IdentityProvider::new(IdentityProviderConfig {
            entity_id: "https://idp.example.com/saml".into(),
            sso: vec![
                Endpoint::post("https://idp.example.com/sso", 0, true),
                Endpoint::redirect("https://idp.example.com/sso", 1, false),
            ],
            slo: vec![Endpoint::post("https://idp.example.com/slo", 0, true)],
            artifact_resolution: vec![],
            supported_name_id_formats: vec![
                NameIdFormat::Persistent,
                NameIdFormat::EmailAddress,
            ],
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
            single_logout_services: vec![Endpoint::post(
                "https://sp.example.com/slo",
                0,
                true,
            )],
            signing_certs: vec![rsa_cert()],
            encryption_certs: vec![],
            supported_name_id_formats: vec![],
            want_assertions_signed: false,
            authn_requests_signed,
            valid_until: None,
            cache_duration: None,
        }
    }

    fn fixed_now() -> SystemTime {
        UNIX_EPOCH
            .checked_add(Duration::from_hours(494_388))
            .expect("static UNIX_EPOCH + bounded Duration cannot overflow")
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

    fn parsed_authn_request_fixture() -> ParsedAuthnRequest {
        use crate::authn::request_parse::parse_authn_request;
        let xml = build_unsigned_authn_request("_req-issue", true);
        let doc = Document::parse(&xml).unwrap();
        let (raw, _root) = parse_authn_request(&doc).unwrap();
        let sp = sp_descriptor(false);
        let sso_urls = vec!["https://idp.example.com/sso".to_string()];
        let mut parsed = validate_authn_request(raw, &sp, "https://idp.example.com/sso", &sso_urls)
            .expect("validate");
        parsed.relay_state = Some("rs-token".into());
        parsed
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
            })
            .expect("issue ok");

        let form = match dispatch {
            SsoResponseDispatch::Post(f) => f,
            other @ SsoResponseDispatch::Artifact(_) => panic!("expected POST dispatch, got {other:?}"),
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
            other @ SsoResponseDispatch::Artifact(_) => panic!("expected POST dispatch, got {other:?}"),
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
    fn build_signed_redirect_logout_request(
        id: &str,
    ) -> (Vec<u8>, String, Vec<u8>, String) {
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

        (decoded.xml, signed_query_string, signature_bytes, sig_alg_decoded)
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
        assert_eq!(dispatch.tracker.peer_entity_id, "https://sp.example.com/saml");
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
            pick_name_id_format(Some(&NameIdFormat::EmailAddress), &supported, &default),
            NameIdFormat::EmailAddress
        );
        assert_eq!(
            pick_name_id_format(Some(&NameIdFormat::Transient), &supported, &default),
            NameIdFormat::Persistent
        );
        assert_eq!(pick_name_id_format(None, &supported, &default), NameIdFormat::Persistent);
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
        let raw_query =
            build_signed_redirect_authn_request_raw_query("_wire-authn-tamper");
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
    fn build_signed_redirect_logout_response_raw_query(
        id: &str,
        in_response_to: &str,
    ) -> String {
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
        let raw_query = build_signed_redirect_logout_response_raw_query(
            "_wire-lo-resp-tamper",
            in_response_to,
        );
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
        let envelope = wrap_soap_envelope(saml);
        let unwrapped = unwrap_soap_envelope(envelope.as_bytes()).unwrap();
        // The unwrapped payload must re-parse as a LogoutResponse.
        let doc = Document::parse(&unwrapped).unwrap();
        assert_eq!(doc.root().qname().local(), "LogoutResponse");
    }
}
