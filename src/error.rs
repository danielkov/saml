//! Error type for the `saml` crate.
//!
//! Single, exhaustive enum mirroring `arctic-oauth::Error` in style: every
//! distinct validation rule has its own variant so callers can branch and log
//! specifically. See `docs/rfcs/RFC-001-architecture.md` §7.

use crate::binding::Binding;

/// Errors returned by the `saml` crate.
///
/// Marked `#[non_exhaustive]` so adding new variants is not a breaking change.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    // --- XML / wire format ---
    #[error("XML parse error: {0}")]
    XmlParse(String),
    #[error("XML emit error: {0}")]
    XmlEmit(String),
    #[error("Base64 decode failed")]
    Base64Decode,
    #[error("DEFLATE decode failed")]
    Inflate,

    // --- Signature / crypto ---
    #[error("XML signature verification failed: {reason}")]
    SignatureVerification { reason: &'static str },
    #[error("XML signature missing where required")]
    SignatureMissing,
    #[error("Disallowed signature algorithm: {alg}")]
    DisallowedAlgorithm { alg: String },
    #[error("Disallowed transform: {transform}")]
    DisallowedTransform { transform: String },
    #[error("Signature Reference URI does not resolve to a recognized element")]
    ReferenceResolution,
    #[error("X.509 parse failed")]
    X509Parse,
    #[error("XML-Enc decrypt failed: {reason}")]
    DecryptFailed { reason: &'static str },

    // --- SAML protocol ---
    #[error("Issuer mismatch: expected {expected}, got {got:?}")]
    IssuerMismatch {
        expected: String,
        got: Option<String>,
    },
    #[error("Destination mismatch")]
    DestinationMismatch,
    #[error("InResponseTo mismatch")]
    InResponseToMismatch,
    #[error("Audience restriction not satisfied")]
    AudienceMismatch,
    #[error("Assertion not yet valid (NotBefore in future)")]
    NotYetValid,
    #[error("Assertion expired (NotOnOrAfter passed)")]
    Expired,
    #[error("SubjectConfirmation Recipient mismatch")]
    RecipientMismatch,
    #[error("Status not Success: {code}")]
    StatusNotSuccess {
        code: String,
        message: Option<String>,
    },
    #[error("Unsolicited Response received but allow_unsolicited is false")]
    UnsolicitedNotAllowed,
    #[error("Requested AuthnContextClassRef not satisfied")]
    AuthnContextDowngrade,

    // --- Trust / metadata ---
    #[error("Unknown peer entity: {entity_id}")]
    UnknownEntity { entity_id: String },
    #[error("AssertionConsumerServiceURL not registered for SP {entity_id}")]
    UnregisteredAcs { entity_id: String },
    #[error("No signing cert found in peer metadata")]
    NoPeerSigningCert,
    #[error("Peer does not advertise the requested binding: {binding:?}")]
    UnsupportedByPeer { binding: Binding },
    #[error("AuthnRequest/@ProtocolBinding is not legal for SSO Response: {requested:?}")]
    IllegalResponseBinding { requested: Binding },

    // --- Configuration ---
    #[error("Invalid configuration: {reason}")]
    InvalidConfiguration { reason: &'static str },

    // --- Transport ---
    #[error("HTTP request failed: {0}")]
    Http(#[from] Box<dyn std::error::Error + Send + Sync>),
}
