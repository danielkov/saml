//! Error type for the `saml` crate.
//!
//! Single, exhaustive enum mirroring `arctic-oauth::Error` in style: every
//! distinct validation rule has its own variant so callers can branch and log
//! specifically. See `docs/rfcs/RFC-001-architecture.md` §7.

use std::time::Duration;

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
    /// An inbound `<samlp:AuthnRequest>` was older than the IdP's accepted
    /// freshness window.
    ///
    /// Distinct from [`Error::Expired`], which is about an assertion's
    /// `Conditions/@NotOnOrAfter`. `AuthnRequest` carries no such attribute —
    /// the bound is the IdP's
    /// [`max_authn_request_age`](crate::IdentityProviderConfig::max_authn_request_age),
    /// widened by the call's `clock_skew`. Both figures are carried so a log
    /// line says how far outside the window the request fell.
    #[error("AuthnRequest is stale: IssueInstant is {age:?} old, limit is {limit:?}")]
    StaleAuthnRequest { age: Duration, limit: Duration },
    /// An inbound `<samlp:AuthnRequest>` was dated further into the future
    /// than the call's `clock_skew` tolerates.
    ///
    /// Distinct from [`Error::NotYetValid`], which is about an assertion's
    /// `Conditions/@NotBefore`. Without this bound a future-dated request
    /// would stay acceptable for as long as its `IssueInstant` runs ahead,
    /// which is the staleness hole wearing a different sign.
    #[error("AuthnRequest is dated {ahead:?} ahead, clock skew tolerance is {clock_skew:?}")]
    AuthnRequestNotYetValid {
        ahead: Duration,
        clock_skew: Duration,
    },
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
    /// Surfaced by `SpEcp::consume_paos_response` (feature `ecp`) before the
    /// inner `<samlp:Response>` reaches the consume path.
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
    /// `parse_discovery_request_query` (feature `idp-disco`) and the
    /// discovery request/response builders.
    #[error("IdP discovery request malformed: {reason}")]
    DiscoveryRequestMalformed { reason: &'static str },
    /// The discovery service's return redirect was malformed — currently
    /// only a duplicated chosen-IdP parameter, which is rejected outright so
    /// an attacker-appended second value can never win a first-match parse.
    /// Surfaced by
    /// `parse_discovery_response_query` (feature `idp-disco`).
    #[error("IdP discovery response malformed: {reason}")]
    DiscoveryResponseMalformed { reason: &'static str },
    /// **The** discovery-service trust check: the `return` URL in a
    /// discovery request does not match any `<idpdisc:DiscoveryResponse>`
    /// endpoint registered in the requesting SP's metadata. Redirecting
    /// there anyway would be an open redirect that hands the user agent (and
    /// the chosen IdP hint) to an attacker. Surfaced by
    /// `validate_discovery_return_url` (feature `idp-disco`).
    #[error("IdP discovery return URL not registered in SP metadata: {return_url}")]
    DiscoveryReturnUrlNotRegistered { return_url: String },
    /// The `_saml_idp` Common Domain Cookie value did not decode
    /// (percent-encoding, base64, or UTF-8 layer). Surfaced by
    /// `CommonDomainCookie::parse` (feature `idp-disco`).
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
    /// An `<samlp:ArtifactResolve>` came from a registered SP other than the
    /// one the artifact was minted for.
    ///
    /// Authenticating the resolver establishes *who* is asking; this is the
    /// separate question of whether they are entitled to *this* artifact.
    /// Without it, any registered SP could redeem another's leaked artifact —
    /// and artifacts travel in URL query parameters, so they leak readily.
    #[error("artifact was minted for {expected}, resolve came from {received}")]
    ArtifactRecipientMismatch { expected: String, received: String },
    /// An `<md:ArtifactResolutionService>` lacked the REQUIRED `index`, or two
    /// shared one.
    ///
    /// `ArtifactResolutionService` is an `IndexedEndpoint`: the index is what a
    /// type `0x0004` artifact carries to say which endpoint to resolve against,
    /// so it must identify exactly one. A missing index makes an endpoint
    /// unaddressable; a duplicate makes routing ambiguous, silently resolved by
    /// whichever entry happens to come first.
    #[error("ArtifactResolutionService index is missing or duplicated: {reason}")]
    AmbiguousArtifactEndpointIndex { reason: &'static str },
    /// An artifact was not a well-formed type `0x0004` value.
    #[error("malformed artifact: {reason}")]
    InvalidArtifact { reason: &'static str },
    /// A type `0x0004` artifact named an `<md:ArtifactResolutionService>`
    /// endpoint index the issuing IdP's metadata does not advertise.
    ///
    /// Resolving against some other endpoint instead would send the artifact
    /// somewhere its issuer never nominated, so this is refused rather than
    /// falling back to the default endpoint.
    #[error(
        "artifact names ArtifactResolutionService index {index}, which {entity_id} does not advertise"
    )]
    UnknownArtifactEndpointIndex { entity_id: String, index: u16 },
    #[error("AuthnRequest/@ProtocolBinding is not legal for SSO Response: {requested:?}")]
    IllegalResponseBinding { requested: Binding },
    /// A solicited Response arrived over a different binding than the ACS
    /// endpoint recorded in the `LoginTracker` when the `AuthnRequest` was
    /// issued. Both bindings are legal for SSO responses — they simply do not
    /// correlate, so this is distinct from [`Error::IllegalResponseBinding`].
    #[error("Response binding {received:?} does not match the tracked ACS binding {expected:?}")]
    ResponseBindingMismatch {
        expected: Binding,
        received: Binding,
    },

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
