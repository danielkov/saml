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
    #[error("decoded SAML message exceeds the {limit}-byte limit")]
    MessageTooLarge { limit: usize },
    #[error("DEFLATE decode failed")]
    Inflate,
    /// Structural-XSD-style schema mismatch on an inbound message. Surfaced
    /// from the `xsd-validate` first-pass walk that runs before any
    /// cryptographic or content-policy check (see `crate::schema`).
    ///
    /// `element` carries the offending element's expanded `{ns}local` name so
    /// callers can log which part of the wire tree was wrong; `reason` is a
    /// static description of the rule that fired (missing required attribute,
    /// unknown child, wrong child ordering, etc.) without leaking caller-
    /// supplied byte ranges.
    #[error("SAML schema violation at <{element}>: {reason}")]
    SchemaViolation {
        element: String,
        reason: &'static str,
    },

    // --- Signature / crypto ---
    #[error("XML signature verification failed: {reason}")]
    SignatureVerification { reason: &'static str },
    #[error("XML signature missing where required")]
    SignatureMissing,
    #[error("Disallowed cryptographic algorithm: {alg}")]
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
    /// A Holder-of-Key SubjectConfirmation (SAML V2.0 HoK SSO Profile) could
    /// not be confirmed. `reason` distinguishes the failure mode: the presenter
    /// key did not match the confirmation's `<ds:KeyInfo>`, no presenter cert
    /// was configured so HoK could not be checked, or the `<ds:KeyInfo>`
    /// carried no usable key material. Never returned when a bearer
    /// confirmation on the same assertion already satisfied all its
    /// constraints — HoK is only consulted as a fallback.
    #[error("Holder-of-Key SubjectConfirmation not confirmed: {reason}")]
    HolderOfKeyConfirmation { reason: &'static str },
    #[error("Status not Success: {code}")]
    StatusNotSuccess {
        code: String,
        message: Option<String>,
    },
    /// The peer answered a SOAP request with a `<soap:Fault>` (SOAP 1.1 §4.4)
    /// instead of the expected payload. `faultcode` is the QName-shaped fault
    /// code (e.g. `soap:Client`, `soap:Server`); `faultstring` is the
    /// human-readable description, when present. Surfaced by the SOAP
    /// back-channel envelope parser so callers can distinguish a transport-
    /// level SOAP refusal from a SAML-level non-Success status.
    #[error("SOAP Fault: {faultcode}{}", .faultstring.as_deref().map(|s| format!(" — {s}")).unwrap_or_default())]
    SoapFault {
        faultcode: String,
        faultstring: Option<String>,
    },
    #[error("Unsolicited Response received but allow_unsolicited is false")]
    UnsolicitedNotAllowed,
    #[error("Requested AuthnContextClassRef not satisfied")]
    AuthnContextDowngrade,

    // --- ECP / PAOS profile (SAML 2.0 Profiles §4.2, Bindings §3.3) ---
    /// **The** ECP security check (Profiles §4.2.4.2). The
    /// `AssertionConsumerServiceURL` the IdP returned in `<ecp:Response>`
    /// (step 4) does not equal the `responseConsumerURL` the SP supplied in
    /// `<paos:Request>` (step 2). A malicious IdP or man-in-the-middle is
    /// attempting to redirect the assertion to an attacker-controlled endpoint.
    /// The ECP client refuses to deliver the assertion and surfaces this error
    /// instead; `soap_fault` is the ready-to-POST `<soap:Fault>` envelope the
    /// client MUST send to `response_consumer_url` per §4.2.4.2. No assertion
    /// is ever placed in a deliverable envelope when this fires.
    #[error(
        "ECP AssertionConsumerServiceURL mismatch: IdP returned {assertion_consumer_service_url}, \
         SP requested {response_consumer_url} (SAML 2.0 Profiles §4.2.4.2)"
    )]
    EcpAcsUrlMismatch {
        response_consumer_url: String,
        assertion_consumer_service_url: String,
        soap_fault: String,
    },
    /// An ECP PAOS POST's `<paos:Response>/@refToMessageID` (step 6) did not
    /// match the `messageID` the SP issued in its `<paos:Request>` (step 2).
    /// Surfaced by
    /// [`SpEcp::consume_paos_response`](crate::binding::ecp::SpEcp::consume_paos_response)
    /// before the inner `<samlp:Response>` reaches the consume path.
    #[error("ECP PAOS refToMessageID does not match the issued messageID")]
    EcpMessageIdMismatch,
    /// A required ECP / PAOS SOAP header block (or one of its attributes) was
    /// missing from an ECP envelope. `header` names the absent block / attribute
    /// (e.g. `Request`, `Request/@responseConsumerURL`, `ecp:Response`).
    #[error("ECP message missing required PAOS/ECP header: {header}")]
    EcpMissingPaosHeader { header: &'static str },
    /// An ECP envelope carried more than one of a trust-bearing PAOS/ECP header
    /// block (e.g. two `<paos:Request>` or two `<ecp:Response>` blocks). A
    /// duplicate is malformed and would let a second, attacker-supplied value
    /// hide behind the first-match header read, so the envelope is rejected
    /// outright rather than silently taking the first block. `header` names the
    /// duplicated block.
    #[error("ECP message carries a duplicate PAOS/ECP header: {header}")]
    EcpDuplicatePaosHeader { header: &'static str },

    // --- IdP Discovery (`idp-disco` feature) ---
    /// An inbound discovery-service request query string violated the
    /// protocol: missing/empty `entityID`, a duplicated parameter, an
    /// unsupported `policy`, a non-boolean `isPassive`, or a `returnIDParam`
    /// that is not a plain URL-parameter token. Surfaced by
    /// [`parse_discovery_request_query`](crate::disco::parse_discovery_request_query)
    /// and the discovery request/response builders.
    #[error("IdP discovery request malformed: {reason}")]
    DiscoveryRequestMalformed { reason: &'static str },
    /// The discovery service's return redirect was malformed — currently
    /// only a duplicated chosen-IdP parameter, which is rejected outright so
    /// an attacker-appended second value can never win a first-match parse.
    /// Surfaced by
    /// [`parse_discovery_response_query`](crate::disco::parse_discovery_response_query).
    #[error("IdP discovery response malformed: {reason}")]
    DiscoveryResponseMalformed { reason: &'static str },
    /// **The** discovery-service trust check: the `return` URL in a
    /// discovery request does not match any `<idpdisc:DiscoveryResponse>`
    /// endpoint registered in the requesting SP's metadata. Redirecting
    /// there anyway would be an open redirect that hands the user agent (and
    /// the chosen IdP hint) to an attacker. Surfaced by
    /// [`validate_discovery_return_url`](crate::disco::validate_discovery_return_url).
    #[error("IdP discovery return URL not registered in SP metadata: {return_url}")]
    DiscoveryReturnUrlNotRegistered { return_url: String },
    /// The `_saml_idp` Common Domain Cookie value did not decode
    /// (percent-encoding, base64, or UTF-8 layer). Surfaced by
    /// [`CommonDomainCookie::parse`](crate::disco::CommonDomainCookie::parse).
    #[error("Common Domain Cookie malformed: {reason}")]
    CommonDomainCookieMalformed { reason: &'static str },

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

    // --- Replay protection (SAML 2.0 Core §2.5.1.5) ---
    /// Assertion ID was already present in the replay cache within its
    /// validity window. Surfaces from
    /// [`ServiceProvider::consume_response`](crate::sp::ServiceProvider::consume_response)
    /// when a caller-supplied [`ReplayCache`](crate::replay::ReplayCache)
    /// reports the id as previously consumed.
    #[error(
        "Assertion replay detected: assertion_id was already consumed within its validity window"
    )]
    AssertionReplay,
    /// In-memory replay cache hit its hard capacity ceiling. Bigger
    /// capacity, a TTL shorter than the assertion lifetime, or a
    /// distributed cache backend will resolve this.
    #[error("Replay cache full: refusing to evict live entries to make room")]
    ReplayCacheFull,
    /// Replay cache backend itself errored (e.g. a poisoned mutex, a
    /// Redis timeout). The static `reason` describes the specific
    /// failure mode without leaking caller data.
    #[error("Replay cache backend error: {reason}")]
    ReplayCache { reason: &'static str },

    // --- Transport ---
    #[error("HTTP request failed: {0}")]
    Http(#[from] Box<dyn std::error::Error + Send + Sync>),
}
