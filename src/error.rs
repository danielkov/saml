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
    /// An inbound `SAMLart` value is not the exact 44-byte SAML 2.0 Type-4
    /// structure required by Bindings §3.6.4.
    #[error("Malformed SAML 2.0 Type-4 artifact: {reason}")]
    MalformedArtifact { reason: &'static str },
    /// A Type-4 artifact's `SourceID` is not SHA-1 of the IdP entity selected
    /// for this login transaction.
    #[error("artifact SourceID does not match the expected IdP entity")]
    ArtifactSourceIdMismatch,
    /// The Type-4 artifact names an ArtifactResolutionService index that was
    /// not pinned for the selected IdP when this login transaction began.
    #[error("artifact names an untrusted ArtifactResolutionService index {index}")]
    ArtifactResolutionServiceMismatch { index: u16 },
    /// HTTP-Artifact resolution cannot choose a back-channel destination
    /// safely without the transaction-time IdP metadata pinned in a tracker.
    #[error("artifact response resolution requires a LoginTracker")]
    ArtifactTrackerRequired,
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
    #[error("AuthnRequest/@ProtocolBinding is not legal for SSO Response: {requested:?}")]
    IllegalResponseBinding { requested: Binding },
    /// An [`UpstreamFlow`](crate::UpstreamFlow) was presented to a different
    /// `Proxy` than the one that produced it.
    ///
    /// A flow carries a trust decision — the context this proxy's codec
    /// authenticated, and the response validated against it. Honouring one
    /// from another instance would mean acting on that instance's codec, and
    /// a caller is free to construct a proxy whose codec authenticates
    /// nothing.
    #[error("UpstreamFlow belongs to a different Proxy instance")]
    ForeignProxyFlow,
    /// The `IdpDescriptor` supplied to
    /// [`Proxy::consume_upstream_response`](crate::Proxy::consume_upstream_response)
    /// carries signing certificates that were not trusted when the login
    /// began.
    ///
    /// The upstream `LoginTracker` correlates by entity ID, so a descriptor
    /// bearing the expected entity ID and a different signing key would
    /// otherwise validate an attacker-signed response into a genuine flow.
    #[error("upstream IdP signing certificates differ from those sealed at bounce")]
    UpstreamTrustRootMismatch,
    /// Direct SP response consumption received an IdP descriptor with no
    /// signing certificate, or one introducing a certificate that was not
    /// trusted when the login transaction began.
    #[error("IdP signing certificates differ from those pinned when login began")]
    IdpTrustRootMismatch,
    /// The `SpDescriptor` supplied to issuance carries different encryption
    /// key material than the one the request was validated against.
    ///
    /// Entity ID and ACS pin the SP's identity but not its keys. A substituted
    /// encryption certificate would have the assertion encrypted to that key;
    /// a removed one silently downgrades opportunistic encryption to
    /// plaintext.
    #[error("SP encryption certificates differ from those seen at validation")]
    SpKeyMaterialMismatch,
    /// The assertion carries `<saml:OneTimeUse>` but no replay cache was
    /// supplied, or [`ReplayMode::Off`](crate::ReplayMode) disabled the check.
    ///
    /// SAML 2.0 Core §2.5.1.5 makes single use a MUST: the asserting party has
    /// stated the assertion is good for exactly one consumption. With no
    /// atomic deduplication available there is no way to honour that, and
    /// accepting it anyway silently discards the directive.
    #[error("assertion is marked OneTimeUse but no replay cache is available to enforce it")]
    OneTimeUseUnenforceable,
    /// An authenticated proxy transaction was already redeemed by another
    /// valid upstream Response.
    #[error("proxy transaction was already redeemed")]
    ProxyTransactionReplay,
    /// The SP's `<samlp:NameIDPolicy>/@Format` names a format this IdP cannot
    /// produce.
    ///
    /// SAML 2.0 Core §3.4.1.1: when the IdP cannot honour the requested
    /// format, it must respond with `InvalidNameIDPolicy` rather than
    /// substituting one. Silently returning a different format hands the SP an
    /// identifier with different semantics — a persistent pseudonym where a
    /// transient one was asked for, say — under a request it believes was
    /// satisfied. Callers should map this to
    /// `SamlStatusCode::InvalidNameIdPolicy`.
    #[error("requested NameIDPolicy format {requested} is not supported")]
    UnsupportedNameIdPolicy { requested: String },
    /// The caller supplied a NameID whose declared format does not match the
    /// format negotiated from the validated request and IdP policy.
    ///
    /// A format is semantic, not cosmetic: relabelling an email address or a
    /// transient identifier as a persistent pseudonym makes a signed claim
    /// that the value generator did not produce. Callers and proxy transforms
    /// must mint the value for the negotiated format instead.
    #[error("NameID format mismatch: expected {expected}, got {got}")]
    NameIdFormatMismatch { expected: String, got: String },
    /// A persistent NameID is explicitly scoped to another service provider.
    #[error("persistent NameID is scoped to {got}, expected {expected}")]
    NameIdSpQualifierMismatch { expected: String, got: String },
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
