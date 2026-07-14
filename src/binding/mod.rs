//! SAML 2.0 bindings (HTTP-Redirect, HTTP-POST, HTTP-Artifact, SOAP).
//!
//! See `docs/rfcs/RFC-003-service-provider.md` §2 for the type-level structure.

pub mod artifact;
#[cfg(feature = "ecp")]
pub mod ecp;
pub mod post;
pub mod redirect;
#[cfg(any(feature = "artifact-binding", feature = "slo", feature = "ecp"))]
pub mod soap;

use crate::error::Error;

// ── shared helpers ────────────────────────────────────────────────────

/// Generate a fresh XML `ID` value of the shape `_<32 hex chars>` (16 random
/// bytes, hex-encoded with a leading underscore so the value is a valid XML
/// `xs:ID`, which must start with a letter or `_`). The same shape is also a
/// valid PAOS `messageID` (ECP, Profiles §4.2).
///
/// This is the single XML-ID minter for the whole crate — IdP, SP, response,
/// metadata and binding code all route through it. It lives in this
/// always-compiled parent module so every caller (cfg-gated or not) shares one
/// implementation instead of carrying a copy. It is **fail-closed**: RNG
/// failures propagate as [`Error::InvalidConfiguration`] rather than emitting a
/// predictable ID built from uninitialized entropy (a colliding ID would
/// corrupt one-time-use replay detection and `InResponseTo` correlation).
pub(crate) fn random_xml_id() -> Result<String, Error> {
    use std::fmt::Write as _;

    use rsa::rand_core::{OsRng, RngCore as _};

    let mut bytes = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_err| Error::InvalidConfiguration {
            reason: "RNG failure generating random XML ID",
        })?;

    // Lowercase two-char hex per byte. `{:02x}` is total over `u8`, so there is
    // no fallible nibble lookup and no silent-truncation branch (and no
    // panicking slice index, which the workspace lints forbid). The only error
    // `write!` into a `String` can yield is a `fmt::Error`, surfaced via `?`.
    let mut out = String::with_capacity(1 + 32);
    out.push('_');
    for b in bytes {
        write!(out, "{b:02x}")
            .map_err(|_err| Error::XmlEmit("formatting XML ID hex".to_string()))?;
    }
    Ok(out)
}

/// Generate an opaque 256-bit RelayState value encoded as unpadded Base64url.
///
/// The 43-character result is safe to place in Redirect- and POST-binding
/// parameters and remains below SAML's 80-byte RelayState interoperability
/// limit. Applications should still retain it server-side and consume it
/// atomically when the matching response succeeds.
pub fn random_relay_state() -> Result<String, Error> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rsa::rand_core::{OsRng, RngCore as _};

    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_err| Error::InvalidConfiguration {
            reason: "RNG failure generating RelayState",
        })?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

// ── enums ─────────────────────────────────────────────────────────────

/// The four SAML 2.0 protocol bindings used by this crate.
///
/// URIs are defined by SAML 2.0 Bindings (`urn:oasis:names:tc:SAML:2.0:bindings:*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Binding {
    HttpRedirect,
    HttpPost,
    HttpArtifact,
    Soap,
}

impl Binding {
    /// Canonical SAML 2.0 binding URI.
    pub const fn uri(self) -> &'static str {
        match self {
            Binding::HttpRedirect => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            Binding::HttpPost => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            Binding::HttpArtifact => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
            Binding::Soap => "urn:oasis:names:tc:SAML:2.0:bindings:SOAP",
        }
    }

    /// Parse a SAML 2.0 binding URI into a `Binding`.
    ///
    /// Unknown URIs produce `Error::InvalidConfiguration`.
    pub fn from_uri(uri: &str) -> Result<Self, Error> {
        match uri {
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" => Ok(Binding::HttpRedirect),
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" => Ok(Binding::HttpPost),
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" => Ok(Binding::HttpArtifact),
            "urn:oasis:names:tc:SAML:2.0:bindings:SOAP" => Ok(Binding::Soap),
            _ => Err(Error::InvalidConfiguration {
                reason: "unknown binding URI",
            }),
        }
    }
}

/// Bindings legal for an SSO `<samlp:Response>` per SAML 2.0 Profiles §4.1.4
/// (Web Browser SSO). Type-level subset of `Binding` that cannot represent
/// Redirect or SOAP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SsoResponseBinding {
    HttpPost,
    HttpArtifact,
}

impl SsoResponseBinding {
    /// Lossless widening into the general `Binding` enum.
    pub const fn as_binding(self) -> Binding {
        match self {
            SsoResponseBinding::HttpPost => Binding::HttpPost,
            SsoResponseBinding::HttpArtifact => Binding::HttpArtifact,
        }
    }

    /// Fallible narrowing. Returns `None` for `HttpRedirect` / `Soap`.
    pub const fn from_binding(b: Binding) -> Option<Self> {
        match b {
            Binding::HttpPost => Some(SsoResponseBinding::HttpPost),
            Binding::HttpArtifact => Some(SsoResponseBinding::HttpArtifact),
            Binding::HttpRedirect | Binding::Soap => None,
        }
    }

    /// Canonical SAML 2.0 binding URI for the narrowed variant.
    pub const fn uri(self) -> &'static str {
        self.as_binding().uri()
    }

    /// Parse a SAML 2.0 binding URI into an `SsoResponseBinding`.
    ///
    /// Returns `Error::IllegalResponseBinding { requested }` if the URI parses
    /// to a `Binding` that is not legal for an SSO Response (Redirect / SOAP),
    /// and `Error::InvalidConfiguration` for unknown URIs.
    pub fn from_uri(uri: &str) -> Result<Self, Error> {
        let binding = Binding::from_uri(uri)?;
        Self::from_binding(binding).ok_or(Error::IllegalResponseBinding { requested: binding })
    }
}

// ── endpoints ─────────────────────────────────────────────────────────

/// General endpoint type — used for SSO endpoints, SLO endpoints, and
/// ArtifactResolutionService endpoints. All four bindings are representable.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Endpoint {
    pub url: String,
    pub binding: Binding,
    /// ACS index advertised in metadata. None for SLO endpoints (SAML doesn't
    /// index SLO endpoints the same way).
    pub index: Option<u16>,
    pub is_default: bool,
}

impl Endpoint {
    /// Build a Redirect-binding endpoint.
    pub fn redirect(url: impl Into<String>, index: u16, is_default: bool) -> Self {
        Self {
            url: url.into(),
            binding: Binding::HttpRedirect,
            index: Some(index),
            is_default,
        }
    }

    /// Build a POST-binding endpoint.
    pub fn post(url: impl Into<String>, index: u16, is_default: bool) -> Self {
        Self {
            url: url.into(),
            binding: Binding::HttpPost,
            index: Some(index),
            is_default,
        }
    }

    /// Build an Artifact-binding endpoint.
    pub fn artifact(url: impl Into<String>, index: u16, is_default: bool) -> Self {
        Self {
            url: url.into(),
            binding: Binding::HttpArtifact,
            index: Some(index),
            is_default,
        }
    }

    /// Build a SOAP-binding endpoint. Index is optional because SOAP endpoints
    /// (e.g. ArtifactResolutionService) are not always indexed.
    pub fn soap(url: impl Into<String>, index: Option<u16>, is_default: bool) -> Self {
        Self {
            url: url.into(),
            binding: Binding::Soap,
            index,
            is_default,
        }
    }
}

/// Type-narrowed endpoint for AssertionConsumerService. The binding is an
/// `SsoResponseBinding`, so by construction it CANNOT be `HttpRedirect` or
/// `Soap`. See RFC-003 §2 for rationale.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SsoResponseEndpoint {
    pub url: String,
    pub binding: SsoResponseBinding,
    pub index: Option<u16>,
    pub is_default: bool,
}

impl SsoResponseEndpoint {
    /// Build a POST-binding ACS endpoint.
    pub fn post(url: impl Into<String>, index: u16, is_default: bool) -> Self {
        Self {
            url: url.into(),
            binding: SsoResponseBinding::HttpPost,
            index: Some(index),
            is_default,
        }
    }

    /// Build an Artifact-binding ACS endpoint.
    pub fn artifact(url: impl Into<String>, index: u16, is_default: bool) -> Self {
        Self {
            url: url.into(),
            binding: SsoResponseBinding::HttpArtifact,
            index: Some(index),
            is_default,
        }
    }

    /// Lossless widening into the general `Endpoint`.
    pub fn as_endpoint(&self) -> Endpoint {
        Endpoint {
            url: self.url.clone(),
            binding: self.binding.as_binding(),
            index: self.index,
            is_default: self.is_default,
        }
    }

    /// Fallible narrowing from a general `Endpoint`. Used by SP metadata
    /// parsers to reject non-conformant SP descriptors.
    pub fn try_from_endpoint(e: Endpoint) -> Result<Self, Error> {
        let binding =
            SsoResponseBinding::from_binding(e.binding).ok_or(Error::InvalidConfiguration {
                reason: "ACS endpoint binding must be POST or Artifact",
            })?;
        Ok(Self {
            url: e.url,
            binding,
            index: e.index,
            is_default: e.is_default,
        })
    }
}

// ── dispatch ──────────────────────────────────────────────────────────

/// Dispatch for outbound SAML *requests* (AuthnRequest, LogoutRequest) and
/// outbound LogoutResponse. SLO permits all three of Redirect / POST / SOAP;
/// SOAP is handled separately. Web Browser SSO Response uses the
/// typed-subset `SsoResponseDispatch` below instead.
#[derive(Debug, Clone)]
pub enum Dispatch {
    /// HTTP 302 to this URL.
    Redirect(url::Url),
    /// Render an auto-submitting HTML form to this action URL.
    Post(PostForm),
}

/// Form payload for the HTTP-POST binding. Exactly one of `saml_request` and
/// `saml_response` is populated, depending on whether the dispatched message
/// is a request (AuthnRequest / LogoutRequest) or a LogoutResponse.
#[derive(Debug, Clone)]
pub struct PostForm {
    pub action: url::Url,
    /// `SAMLRequest` hidden input value for AuthnRequest / LogoutRequest.
    pub saml_request: Option<String>,
    /// `SAMLResponse` hidden input value for LogoutResponse.
    pub saml_response: Option<String>,
    pub relay_state: Option<String>,
}

/// Dispatch for outbound SSO `<samlp:Response>`. POST or Artifact only.
/// `Redirect` is not representable here — Web Browser SSO Responses over
/// Redirect are not legal per SAML 2.0 Profiles §4.1.4.
#[derive(Debug, Clone)]
pub enum SsoResponseDispatch {
    Post(SsoResponsePostForm),
    Artifact(ArtifactRedirect),
}

/// Form payload for an SSO Response delivered via HTTP-POST.
#[derive(Debug, Clone)]
pub struct SsoResponsePostForm {
    pub action: url::Url,
    /// `SAMLResponse` hidden input value (base64-encoded SAML XML).
    pub saml_response: String,
    pub relay_state: Option<String>,
}

/// Artifact redirect payload. The IdP MUST persist `response_xml` keyed by
/// `artifact` and serve it from its ArtifactResolutionService.
#[derive(Debug, Clone)]
pub struct ArtifactRedirect {
    /// Redirect the user agent here. URL contains `?SAMLart=...&RelayState=...`.
    pub redirect_to: url::Url,
    /// The artifact value embedded in `redirect_to`.
    pub artifact: String,
    /// The full `<samlp:Response>` XML to return when the SP resolves the
    /// artifact via SOAP. Library is stateless; persistence is the caller's
    /// responsibility.
    pub response_xml: String,
}

// ── wire decoder ──────────────────────────────────────────────────────

/// Direction of an inbound SAML wire payload. Selects whether the decoder
/// looks for a `SAMLRequest=…` (AuthnRequest / LogoutRequest) or a
/// `SAMLResponse=…` (Response / LogoutResponse) parameter when decoding a
/// Redirect-binding query string. Ignored for POST and SOAP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WireDirection {
    /// Inbound *request* — `SAMLRequest=…` for Redirect / POST.
    Request,
    /// Inbound *response* — `SAMLResponse=…` for Redirect / POST.
    Response,
}

/// Unified output of [`decode_wire`]. Carries the binding-decoded XML plus
/// any Redirect-only sidecar fields (detached signature material, canonical
/// signed query string). The Redirect-only fields are `None` for POST and
/// SOAP inputs.
#[derive(Debug, Clone)]
pub struct DecodedWire {
    /// The recovered SAML XML, ready to hand to
    /// [`crate::IdentityProvider::consume_authn_request`] /
    /// [`crate::ServiceProvider::consume_response`] / the SLO consume entry
    /// points.
    pub xml: Vec<u8>,
    /// `RelayState` parameter value, if present.
    pub relay_state: Option<String>,
    /// Redirect-only: detached signature bytes (base64-decoded from the
    /// `Signature=…` query parameter). Always `None` for POST / SOAP.
    pub detached_signature: Option<Vec<u8>>,
    /// Redirect-only: `SigAlg=…` URI from the query string. Always `None`
    /// for POST / SOAP.
    pub detached_sig_alg: Option<String>,
    /// Redirect-only: canonical signed query string per SAML 2.0 Bindings
    /// §3.4.4.1 — the byte sequence the signer covered. `None` when no
    /// `Signature=…` parameter was present, and always `None` for POST /
    /// SOAP.
    pub signed_query_string: Option<String>,
}

impl DecodedWire {
    /// Borrow the Redirect-binding detached signature material as a
    /// [`crate::idp::DetachedSignature`] view, ready to pass into the
    /// IdP-side `consume_*` entry points. Returns `None` when any of the
    /// three required pieces (signature, sig_alg, signed query string) is
    /// missing — i.e. for unsigned Redirect requests and for every POST /
    /// SOAP request.
    #[must_use]
    pub fn as_detached_signature(&self) -> Option<crate::idp::DetachedSignature<'_>> {
        Some(crate::idp::DetachedSignature {
            signature: self.detached_signature.as_deref()?,
            sig_alg: self.detached_sig_alg.as_deref()?,
            raw_query_string: self.signed_query_string.as_deref()?,
        })
    }
}

/// Decode the binding wire bytes of an inbound SAML message into XML plus
/// any Redirect-binding detached signature material.
///
/// `body` is the raw, binding-layer wire payload as it arrived:
///
/// - [`Binding::HttpRedirect`]: the exact, percent-encoded query string the
///   server received (everything after `?`, before `#`). The decoder splits
///   it on `&`, picks out `SAMLRequest` / `SAMLResponse` / `RelayState` /
///   `Signature` / `SigAlg`, base64-decodes the SAML payload, and DEFLATE-
///   inflates it. When a `Signature=…` pair is present, the canonical signed
///   query string is reconstructed in the field of the same name.
/// - [`Binding::HttpPost`]: the value of the `SAMLRequest` / `SAMLResponse`
///   form field, after form-URL decoding. The decoder base64-decodes it
///   into the SAML XML. Any `RelayState` form value should be threaded in
///   separately by the caller — the decoder cannot see it here.
/// - [`Binding::Soap`] / [`Binding::HttpArtifact`]: returns
///   [`Error::UnsupportedByPeer`] — those bindings have richer envelope
///   structures (SOAP) or require a back-channel exchange (Artifact) that
///   this single-shot helper deliberately does not cover.
///
/// `direction` selects between the `SAMLRequest=…` and `SAMLResponse=…`
/// parameter names for the Redirect binding (it is ignored for POST, which
/// is invoked on the bare form value).
///
/// This is the entry point IdP authors should call before handing XML to
/// [`crate::IdentityProvider::consume_authn_request`] (and equivalents for
/// the SLO consume methods). The SP-side `consume_*` calls binding-decode
/// internally; this exposes the same plumbing for symmetry.
///
/// # Examples
///
/// ```no_run
/// use saml::{Binding, WireDirection, decode_wire};
///
/// # fn run(raw_query_string: &str) -> Result<(), saml::Error> {
/// // /saml/sso GET handler — caller has the full URL query string.
/// let decoded = decode_wire(
///     raw_query_string.as_bytes(),
///     Binding::HttpRedirect,
///     WireDirection::Request,
/// )?;
/// let _xml: &[u8] = &decoded.xml;
/// let _relay_state: Option<&str> = decoded.relay_state.as_deref();
/// // For signed Redirect-bound requests, the detached signature material
/// // is plumbed through `decoded.detached_signature` / `.detached_sig_alg`
/// // / `.signed_query_string` to thread into a `DetachedSignature` struct.
/// # Ok(())
/// # }
/// ```
pub fn decode_wire(
    body: &[u8],
    binding: Binding,
    direction: WireDirection,
) -> Result<DecodedWire, Error> {
    match binding {
        Binding::HttpRedirect => {
            let qs = std::str::from_utf8(body).map_err(|_err| Error::Base64Decode)?;
            let redirect_direction = match direction {
                WireDirection::Request => redirect::RedirectDirection::Request,
                WireDirection::Response => redirect::RedirectDirection::Response,
            };
            let decoded = redirect::decode(qs, redirect_direction)?;
            Ok(DecodedWire {
                xml: decoded.xml,
                relay_state: decoded.relay_state,
                detached_signature: decoded.signature,
                detached_sig_alg: decoded.sig_alg,
                signed_query_string: decoded.signed_query_string,
            })
        }
        Binding::HttpPost => {
            let b64 = std::str::from_utf8(body).map_err(|_err| Error::Base64Decode)?;
            let decoded = post::decode(b64, None)?;
            Ok(DecodedWire {
                xml: decoded.xml,
                relay_state: decoded.relay_state,
                detached_signature: None,
                detached_sig_alg: None,
                signed_query_string: None,
            })
        }
        Binding::Soap | Binding::HttpArtifact => Err(Error::UnsupportedByPeer { binding }),
    }
}

// ── tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_states_are_random_unique_and_binding_safe() {
        use std::collections::HashSet;

        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let mut seen = HashSet::new();
        for _ in 0..64 {
            let relay_state = random_relay_state().expect("OS randomness");
            assert_eq!(relay_state.len(), 43);
            assert!(relay_state.len() <= 80);
            assert!(!relay_state.contains('='));
            assert_eq!(
                URL_SAFE_NO_PAD
                    .decode(&relay_state)
                    .expect("Base64url RelayState")
                    .len(),
                32
            );
            assert!(seen.insert(relay_state));
        }
    }

    #[test]
    fn binding_uri_roundtrip() {
        for b in [
            Binding::HttpRedirect,
            Binding::HttpPost,
            Binding::HttpArtifact,
            Binding::Soap,
        ] {
            let uri = b.uri();
            assert_eq!(Binding::from_uri(uri).unwrap(), b, "roundtrip for {b:?}");
        }
    }

    #[test]
    fn binding_uri_constants_match_spec() {
        assert_eq!(
            Binding::HttpRedirect.uri(),
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        );
        assert_eq!(
            Binding::HttpPost.uri(),
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        );
        assert_eq!(
            Binding::HttpArtifact.uri(),
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
        );
        assert_eq!(
            Binding::Soap.uri(),
            "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
        );
    }

    #[test]
    fn binding_from_unknown_uri_is_invalid_configuration() {
        let err = Binding::from_uri("urn:something:else").unwrap_err();
        match err {
            Error::InvalidConfiguration { reason } => {
                assert_eq!(reason, "unknown binding URI");
            }
            other => panic!("expected InvalidConfiguration, got {other:?}"),
        }
    }

    #[test]
    fn sso_response_binding_widen_narrow() {
        assert_eq!(SsoResponseBinding::HttpPost.as_binding(), Binding::HttpPost);
        assert_eq!(
            SsoResponseBinding::HttpArtifact.as_binding(),
            Binding::HttpArtifact
        );
        assert_eq!(
            SsoResponseBinding::from_binding(Binding::HttpPost),
            Some(SsoResponseBinding::HttpPost)
        );
        assert_eq!(
            SsoResponseBinding::from_binding(Binding::HttpArtifact),
            Some(SsoResponseBinding::HttpArtifact)
        );
        assert_eq!(
            SsoResponseBinding::from_binding(Binding::HttpRedirect),
            None
        );
        assert_eq!(SsoResponseBinding::from_binding(Binding::Soap), None);
    }

    #[test]
    fn sso_response_binding_from_uri_accepts_post_and_artifact() {
        assert_eq!(
            SsoResponseBinding::from_uri(Binding::HttpPost.uri()).unwrap(),
            SsoResponseBinding::HttpPost
        );
        assert_eq!(
            SsoResponseBinding::from_uri(Binding::HttpArtifact.uri()).unwrap(),
            SsoResponseBinding::HttpArtifact
        );
    }

    #[test]
    fn sso_response_binding_from_uri_rejects_redirect_and_soap() {
        let err = SsoResponseBinding::from_uri(Binding::HttpRedirect.uri()).unwrap_err();
        match err {
            Error::IllegalResponseBinding { requested } => {
                assert_eq!(requested, Binding::HttpRedirect);
            }
            other => panic!("expected IllegalResponseBinding, got {other:?}"),
        }

        let err = SsoResponseBinding::from_uri(Binding::Soap.uri()).unwrap_err();
        match err {
            Error::IllegalResponseBinding { requested } => {
                assert_eq!(requested, Binding::Soap);
            }
            other => panic!("expected IllegalResponseBinding, got {other:?}"),
        }
    }

    #[test]
    fn sso_response_binding_from_uri_rejects_unknown() {
        let err = SsoResponseBinding::from_uri("urn:bogus").unwrap_err();
        match err {
            Error::InvalidConfiguration { reason } => {
                assert_eq!(reason, "unknown binding URI");
            }
            other => panic!("expected InvalidConfiguration, got {other:?}"),
        }
    }

    #[test]
    fn endpoint_constructors_set_expected_fields() {
        let r = Endpoint::redirect("https://example.com/r", 1, false);
        assert_eq!(r.url, "https://example.com/r");
        assert_eq!(r.binding, Binding::HttpRedirect);
        assert_eq!(r.index, Some(1));
        assert!(!r.is_default);

        let p = Endpoint::post("https://example.com/p", 2, true);
        assert_eq!(p.binding, Binding::HttpPost);
        assert_eq!(p.index, Some(2));
        assert!(p.is_default);

        let a = Endpoint::artifact("https://example.com/a", 3, false);
        assert_eq!(a.binding, Binding::HttpArtifact);
        assert_eq!(a.index, Some(3));

        let s_indexed = Endpoint::soap("https://example.com/s", Some(7), true);
        assert_eq!(s_indexed.binding, Binding::Soap);
        assert_eq!(s_indexed.index, Some(7));
        assert!(s_indexed.is_default);

        let s_none = Endpoint::soap("https://example.com/s", None, false);
        assert_eq!(s_none.binding, Binding::Soap);
        assert_eq!(s_none.index, None);
    }

    #[test]
    fn sso_response_endpoint_constructors_and_widening() {
        let p = SsoResponseEndpoint::post("https://example.com/acs", 0, true);
        assert_eq!(p.binding, SsoResponseBinding::HttpPost);
        assert_eq!(p.index, Some(0));
        assert!(p.is_default);

        let widened = p.as_endpoint();
        assert_eq!(widened.url, "https://example.com/acs");
        assert_eq!(widened.binding, Binding::HttpPost);
        assert_eq!(widened.index, Some(0));
        assert!(widened.is_default);

        let a = SsoResponseEndpoint::artifact("https://example.com/acs-art", 1, false);
        assert_eq!(a.binding, SsoResponseBinding::HttpArtifact);
        assert_eq!(a.as_endpoint().binding, Binding::HttpArtifact);
    }

    #[test]
    fn sso_response_endpoint_try_from_post_and_artifact_succeeds() {
        let post = Endpoint::post("https://example.com/acs", 0, true);
        let narrowed = SsoResponseEndpoint::try_from_endpoint(post).unwrap();
        assert_eq!(narrowed.binding, SsoResponseBinding::HttpPost);
        assert_eq!(narrowed.url, "https://example.com/acs");
        assert_eq!(narrowed.index, Some(0));
        assert!(narrowed.is_default);

        let art = Endpoint::artifact("https://example.com/acs-art", 2, false);
        let narrowed = SsoResponseEndpoint::try_from_endpoint(art).unwrap();
        assert_eq!(narrowed.binding, SsoResponseBinding::HttpArtifact);
        assert_eq!(narrowed.index, Some(2));
        assert!(!narrowed.is_default);
    }

    #[test]
    fn sso_response_endpoint_try_from_redirect_rejected() {
        let redirect = Endpoint::redirect("https://example.com/r", 0, true);
        let err = SsoResponseEndpoint::try_from_endpoint(redirect).unwrap_err();
        match err {
            Error::InvalidConfiguration { reason } => {
                assert_eq!(reason, "ACS endpoint binding must be POST or Artifact");
            }
            other => panic!("expected InvalidConfiguration, got {other:?}"),
        }
    }

    #[test]
    fn sso_response_endpoint_try_from_soap_rejected() {
        let soap = Endpoint::soap("https://example.com/s", Some(0), true);
        let err = SsoResponseEndpoint::try_from_endpoint(soap).unwrap_err();
        match err {
            Error::InvalidConfiguration { reason } => {
                assert_eq!(reason, "ACS endpoint binding must be POST or Artifact");
            }
            other => panic!("expected InvalidConfiguration, got {other:?}"),
        }
    }

    // ── decode_wire ───────────────────────────────────────────────────

    #[test]
    fn decode_wire_post_round_trips_request() {
        // POST binding: form value is base64 of raw XML, no compression.
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as B64;

        let xml = b"<samlp:AuthnRequest ID=\"_r\"/>";
        let b64 = B64.encode(xml);
        let decoded = decode_wire(b64.as_bytes(), Binding::HttpPost, WireDirection::Request)
            .expect("decode_wire post");
        assert_eq!(decoded.xml, xml);
        assert!(decoded.relay_state.is_none());
        assert!(decoded.detached_signature.is_none());
        assert!(decoded.detached_sig_alg.is_none());
        assert!(decoded.signed_query_string.is_none());
    }

    #[test]
    fn decode_wire_post_round_trips_response() {
        // POST binding: `WireDirection::Response` is ignored for POST — the
        // decoder operates on the bare form value, not a query string.
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as B64;

        let xml = b"<samlp:Response ID=\"_x\"/>";
        let b64 = B64.encode(xml);
        let decoded = decode_wire(b64.as_bytes(), Binding::HttpPost, WireDirection::Response)
            .expect("decode_wire post response");
        assert_eq!(decoded.xml, xml);
    }

    #[test]
    fn decode_wire_redirect_round_trips_unsigned() {
        // Build a Redirect-encoded query string via the crate's own encoder
        // so we know it's valid; then verify `decode_wire` pulls the XML
        // (DEFLATE+base64 reversed) and RelayState back out.
        use url::Url;

        let xml = b"<samlp:AuthnRequest ID=\"_r1\"/>";
        let dest = Url::parse("https://idp.example.com/sso").unwrap();
        let dispatch = redirect::encode_unsigned(
            &dest,
            redirect::RedirectDirection::Request,
            xml,
            Some("rs-token"),
        )
        .unwrap();
        let Dispatch::Redirect(url) = dispatch else {
            panic!("expected redirect dispatch");
        };
        let query = url.query().expect("query");

        let decoded = decode_wire(
            query.as_bytes(),
            Binding::HttpRedirect,
            WireDirection::Request,
        )
        .expect("decode_wire redirect");
        assert_eq!(decoded.xml, xml);
        assert_eq!(decoded.relay_state.as_deref(), Some("rs-token"));
        // No `Signature=` parameter present → no detached material.
        assert!(decoded.detached_signature.is_none());
        assert!(decoded.detached_sig_alg.is_none());
        assert!(decoded.signed_query_string.is_none());
    }

    #[test]
    fn decode_wire_redirect_surfaces_detached_signature_fields() {
        // Build a *signed* Redirect dispatch; the canonical signed-query
        // bytes, base64-decoded signature bytes, and SigAlg URI MUST all
        // surface verbatim through `decode_wire` so an IdP author can fold
        // them into a `DetachedSignature` and pass to `consume_authn_request`.
        use url::Url;

        let xml = b"<samlp:AuthnRequest ID=\"_r2\"/>";
        let dest = Url::parse("https://idp.example.com/sso").unwrap();
        let sig_alg = "urn:test:alg";
        let raw_signature_bytes = vec![0x42u8; 16];
        let captured_signed_input: std::cell::RefCell<Option<Vec<u8>>> =
            std::cell::RefCell::new(None);

        let dispatch = redirect::encode_signed(
            &dest,
            redirect::RedirectDirection::Request,
            xml,
            Some("rs"),
            sig_alg,
            |signed_bytes| {
                *captured_signed_input.borrow_mut() = Some(signed_bytes.to_vec());
                Ok(raw_signature_bytes.clone())
            },
        )
        .unwrap();
        let Dispatch::Redirect(url) = dispatch else {
            panic!("expected redirect dispatch");
        };
        let query = url.query().expect("query");

        let decoded = decode_wire(
            query.as_bytes(),
            Binding::HttpRedirect,
            WireDirection::Request,
        )
        .expect("decode_wire signed redirect");
        assert_eq!(decoded.xml, xml);
        assert_eq!(decoded.relay_state.as_deref(), Some("rs"));
        assert_eq!(
            decoded.detached_signature.as_deref(),
            Some(raw_signature_bytes.as_slice()),
            "raw signature bytes round-trip"
        );
        assert_eq!(decoded.detached_sig_alg.as_deref(), Some(sig_alg));
        let signed_qs = decoded
            .signed_query_string
            .as_deref()
            .expect("signed_query_string set on signed payload");
        let captured = captured_signed_input.into_inner().expect("signer ran");
        assert_eq!(
            signed_qs.as_bytes(),
            captured.as_slice(),
            "canonical signed query string round-trips byte-for-byte",
        );
    }

    #[test]
    fn decode_wire_redirect_rejects_invalid_utf8_query() {
        // Redirect bodies must be UTF-8 (they're percent-encoded ASCII
        // query strings). Non-UTF-8 input is rejected as Base64Decode —
        // we reuse the same error variant as the percent / base64 path.
        let err = decode_wire(
            &[0xff, 0xfe, 0xfd],
            Binding::HttpRedirect,
            WireDirection::Request,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Base64Decode), "got {err:?}");
    }

    #[test]
    fn decode_wire_soap_unsupported() {
        let err = decode_wire(b"<x/>", Binding::Soap, WireDirection::Request).unwrap_err();
        match err {
            Error::UnsupportedByPeer { binding } => assert_eq!(binding, Binding::Soap),
            other => panic!("expected UnsupportedByPeer(Soap), got {other:?}"),
        }
    }

    #[test]
    fn decode_wire_artifact_unsupported() {
        let err = decode_wire(b"abc", Binding::HttpArtifact, WireDirection::Request).unwrap_err();
        match err {
            Error::UnsupportedByPeer { binding } => assert_eq!(binding, Binding::HttpArtifact),
            other => panic!("expected UnsupportedByPeer(HttpArtifact), got {other:?}"),
        }
    }
}
