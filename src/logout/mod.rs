//! Single Logout. See `docs/rfcs/RFC-007-single-logout.md`.

pub mod request_build;
pub mod request_parse;
pub mod response_build;
pub mod response_parse;

use crate::dsig::algorithms::PeerCryptoPolicy;
use crate::nameid::NameId;
use crate::xml::parse::QName;
use std::time::{Duration, SystemTime};

pub(crate) const SAMLP_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub(crate) const SAML_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

pub(crate) fn samlp_qname(local: &str) -> QName {
    QName::new(Some(SAMLP_NS.to_owned()), local)
}

pub(crate) fn saml_qname(local: &str) -> QName {
    QName::new(Some(SAML_NS.to_owned()), local)
}

/// Inputs to a `consume_logout_request` call. Shared by both
/// [`crate::sp::ServiceProvider::consume_logout_request`] and
/// [`crate::idp::IdentityProvider::consume_logout_request`] — the parameter
/// shape is identical on both sides of the SLO exchange (RFC-007 §5.1).
pub struct ConsumeLogoutRequest<'a> {
    /// Per-peer inbound crypto policy. `None` falls back to the role's
    /// `default_peer_crypto_policy`.
    pub peer_crypto_policy: Option<&'a PeerCryptoPolicy>,
    /// Binding-decoded SAML wire bytes. For HTTP-Redirect/POST the SP-side
    /// implementation decodes the form value internally; on the IdP side the
    /// caller hands already-decoded XML (see `crate::idp` module docs).
    pub body: &'a [u8],
    pub binding: crate::binding::Binding,
    pub expected_destination: &'a str,
    pub now: SystemTime,
    pub clock_skew: Duration,
}

/// Inputs to a `consume_logout_response` call. Shared by both
/// [`crate::sp::ServiceProvider::consume_logout_response`] and
/// [`crate::idp::IdentityProvider::consume_logout_response`] — the parameter
/// shape is identical on both sides of the SLO exchange (RFC-007 §5.2).
pub struct ConsumeLogoutResponse<'a> {
    /// Per-peer inbound crypto policy. `None` falls back to the role's
    /// `default_peer_crypto_policy`.
    pub peer_crypto_policy: Option<&'a PeerCryptoPolicy>,
    /// Binding-decoded SAML wire bytes. See [`ConsumeLogoutRequest::body`]
    /// for the SP-vs-IdP decoding distinction.
    pub body: &'a [u8],
    pub binding: crate::binding::Binding,
    /// The tracker recorded when the matching `<samlp:LogoutRequest>` was
    /// sent — provides the `InResponseTo` anchor (RFC-007 §5.2 step 6).
    pub tracker: &'a LogoutTracker,
    pub expected_destination: &'a str,
    pub now: SystemTime,
    pub clock_skew: Duration,
}

/// Inputs for initiating a Logout (sp.start_logout / idp.start_logout).
pub struct StartLogout<'a> {
    pub name_id: &'a NameId,
    pub session_index: Option<&'a str>,
    pub relay_state: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub binding: crate::binding::Binding,
}

/// Caller-side state retained between sending a `<samlp:LogoutRequest>` and
/// receiving the matching `<samlp:LogoutResponse>`. Serializable so it can be
/// stashed in a server-side session keyed by request ID.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogoutTracker {
    pub request_id: String,
    pub issued_at: SystemTime,
    pub peer_entity_id: String,
}

/// Output of `start_logout`: the wire dispatch plus the tracker needed to
/// later validate the matching `<samlp:LogoutResponse>` (RFC-007 §5.2 step 6).
#[derive(Debug)]
pub struct LogoutDispatch {
    pub tracker: LogoutTracker,
    pub dispatch: crate::binding::Dispatch,
}

/// Parsed view of an inbound `<samlp:LogoutRequest>`. Schema-required and
/// schema-optional fields are both surfaced so the caller can decide what to
/// echo into a chain-propagated request (proxy SLO).
#[derive(Debug, Clone)]
pub struct ParsedLogoutRequest {
    pub id: String,
    pub issuer: String,
    pub issue_instant: SystemTime,
    pub destination: Option<String>,
    pub not_on_or_after: Option<SystemTime>,
    pub reason: Option<String>,
    pub name_id: NameId,
    pub session_index: Vec<String>,
    pub relay_state: Option<String>,
}

/// Status to emit on outbound `<samlp:LogoutResponse>`.
///
/// SAML 2.0 status URIs come in two layers: a top-level status code (`Success`
/// / `Requester` / `Responder` / `VersionMismatch`) and an optional
/// second-level code (`PartialLogout`, `RequestDenied`, etc.). For SLO this
/// distinction matters: a `PartialLogout` means "we tried, some peers failed"
/// (the SP/IdP did do work and the user should be considered partially logged
/// out), versus `RequestDenied` which means "I refuse to do this" (the
/// session was untouched). Both are surfaced here as top-level variants so
/// callers can reason about them without learning the SAML two-level dance —
/// emitters expand each variant into the right `<samlp:StatusCode>` chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogoutStatus {
    Success,
    PartialLogout,
    RequestDenied,
    Requester,
    Responder,
}

impl LogoutStatus {
    /// Top-level `<samlp:StatusCode>` URI for this status, per SAML 2.0 Core
    /// §3.2.2.2 status code table.
    ///
    /// `PartialLogout` and `RequestDenied` are second-level codes in the spec;
    /// when emitting them the top-level code is `Responder` / `Requester`
    /// respectively, and the second-level code is the specific URI below.
    /// [`Self::uri`] returns the *most specific* URI — emitters select the
    /// top-level code separately via [`Self::top_level_uri`].
    pub fn uri(self) -> &'static str {
        match self {
            LogoutStatus::Success => "urn:oasis:names:tc:SAML:2.0:status:Success",
            LogoutStatus::PartialLogout => "urn:oasis:names:tc:SAML:2.0:status:PartialLogout",
            LogoutStatus::RequestDenied => "urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
            LogoutStatus::Requester => "urn:oasis:names:tc:SAML:2.0:status:Requester",
            LogoutStatus::Responder => "urn:oasis:names:tc:SAML:2.0:status:Responder",
        }
    }

    /// Top-level `<samlp:StatusCode>` URI to nest the specific status under.
    /// For `Success`, `Requester`, `Responder` this is `Self::uri`; for the
    /// second-level codes (`PartialLogout`, `RequestDenied`) it is `Responder`
    /// / `Requester` respectively. Used internally by `response_build`.
    pub(crate) fn top_level_uri(self) -> &'static str {
        match self {
            LogoutStatus::Success => "urn:oasis:names:tc:SAML:2.0:status:Success",
            LogoutStatus::PartialLogout | LogoutStatus::Responder => {
                "urn:oasis:names:tc:SAML:2.0:status:Responder"
            }
            LogoutStatus::RequestDenied | LogoutStatus::Requester => {
                "urn:oasis:names:tc:SAML:2.0:status:Requester"
            }
        }
    }

    /// Second-level `<samlp:StatusCode>` URI if this status uses nesting;
    /// `None` for top-level-only codes (`Success`, `Requester`, `Responder`).
    pub(crate) fn second_level_uri(self) -> Option<&'static str> {
        match self {
            LogoutStatus::PartialLogout => Some("urn:oasis:names:tc:SAML:2.0:status:PartialLogout"),
            LogoutStatus::RequestDenied => Some("urn:oasis:names:tc:SAML:2.0:status:RequestDenied"),
            LogoutStatus::Success | LogoutStatus::Requester | LogoutStatus::Responder => None,
        }
    }
}

/// Outcome of consuming an inbound `<samlp:LogoutResponse>`. The wire format
/// is two-level (top-level + optional second-level `StatusCode`); we collapse
/// to a three-variant view because the caller's only interesting question is
/// whether to consider the user fully / partially / not logged out.
#[derive(Debug, Clone)]
pub enum LogoutOutcome {
    Success,
    PartialLogout { message: Option<String> },
    Failure { status: String, message: Option<String> },
}
