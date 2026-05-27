//! SAML 2.0 bindings (HTTP-Redirect, HTTP-POST, HTTP-Artifact, SOAP).
//!
//! See `docs/rfcs/RFC-003-service-provider.md` §2 for the type-level structure.

pub mod artifact;
pub mod post;
pub mod redirect;

use crate::error::Error;

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
        let binding = SsoResponseBinding::from_binding(e.binding).ok_or(
            Error::InvalidConfiguration {
                reason: "ACS endpoint binding must be POST or Artifact",
            },
        )?;
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

// ── tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            SsoResponseBinding::HttpPost.as_binding(),
            Binding::HttpPost
        );
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
        assert_eq!(SsoResponseBinding::from_binding(Binding::HttpRedirect), None);
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
}
