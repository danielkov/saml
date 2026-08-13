# RFC-003: Service Provider role

**Status**: Draft
**Date**: 2026-05-26

## Summary

This RFC defines the active SP-role surface: `ServiceProvider`, `ServiceProviderConfig`, the login-start flow, and the response-consume flow. The SP role is what an application uses when it delegates user authentication to one or more external IdPs.

---

## 1. Configuration

```rust
#[derive(Debug, Clone, Copy, Default)]
pub struct SpWantSigned {
    /// Require a signature over the Response element itself.
    pub response: bool,
    /// Require every Assertion to be signed.
    pub assertions: bool,
}

#[cfg(feature = "slo")]
#[derive(Debug, Clone, Copy, Default)]
pub struct SpLogoutSigning {
    pub sign_requests: bool,
    pub sign_responses: bool,
}

#[cfg(feature = "slo")]
#[derive(Debug, Clone, Copy, Default)]
pub struct SpLogoutWantSigned {
    pub requests: bool,
    pub responses: bool,
}

#[derive(Debug, Clone)]
pub struct ServiceProviderConfig {
    /// SP EntityID. Must be a non-empty, whitespace-free `xs:anyURI` value.
    /// Bare identifiers are legal; this is not required to parse as a URL.
    pub entity_id: String,

    /// AssertionConsumerService endpoints, in declaration order. Type-narrowed:
    /// ACS endpoints can only have POST or Artifact bindings. The first
    /// `is_default=true` entry, or the first entry if none is marked, is used
    /// when a login does not nominate an ACS by index or URL.
    pub acs: Vec<SsoResponseEndpoint>,

    /// SingleLogoutService endpoints. Empty disables SP-initiated logout.
    pub slo: Vec<Endpoint>,

    /// Accepted NameID formats, advertised in metadata. Most-preferred first.
    pub name_id_formats: Vec<NameIdFormat>,

    /// Signing keypair. Required if `sign_authn_requests` or either outbound
    /// logout signing flag is true, and when signed metadata is requested.
    pub signing_key: Option<KeyPair>,

    /// Decryption keypair. Required if SP advertises an encryption cert
    /// in metadata and IdPs may send EncryptedAssertion.
    pub decryption_key: Option<KeyPair>,

    /// If true, outbound AuthnRequest is signed.
    pub sign_authn_requests: bool,

    /// Inbound Response/Assertion signature requirements.
    pub want_signed: SpWantSigned,

    /// If true, allow IdP-initiated (unsolicited) Responses — i.e., Responses
    /// with no `InResponseTo` matching a tracker the caller supplied.
    pub allow_unsolicited: bool,

    /// Outbound logout signing flags. Present only with the `slo` feature.
    #[cfg(feature = "slo")]
    pub logout_signing: SpLogoutSigning,

    /// Inbound logout signature requirements. Present only with `slo`.
    #[cfg(feature = "slo")]
    pub logout_want_signed: SpLogoutWantSigned,

    /// Default inbound crypto policy when a consume call does not provide a
    /// peer-specific override. Legacy peers that require weak algorithms should
    /// be handled by passing a per-peer `PeerCryptoPolicy` on the consume input,
    /// not by weakening this default for every IdP the SP trusts.
    pub default_peer_crypto_policy: PeerCryptoPolicy,

    /// Outbound signing defaults for AuthnRequest and Logout messages.
    pub outbound_signature_algorithm: SignatureAlgorithm, // default RsaSha256
    pub outbound_digest_algorithm: DigestAlgorithm,       // default Sha256
}

impl ServiceProvider {
    pub fn new(config: ServiceProviderConfig) -> Result<Self, Error>;
}
```

Validation at construction time:

- `entity_id` is non-empty and contains no whitespace (the accepted
  `xs:anyURI` lexical space includes bare identifiers).
- `acs` is non-empty.
- If `sign_authn_requests` or either `logout_signing` flag is true,
  `signing_key` is `Some`. The logout legs are considered only when `slo` is
  enabled.

There is no construction-time warning based on `want_signed` and
`allow_unsolicited`; signature enforcement still happens during response
validation according to the grouped flags.

---

## 2. Endpoints and bindings

```rust
/// General endpoint type — used for SSO endpoints, SLO endpoints, and
/// ArtifactResolutionService endpoints. All four bindings are representable.
pub struct Endpoint {
    pub url: String,
    pub binding: Binding,
    /// ACS index advertised in metadata. None for SLO endpoints (SAML doesn't
    /// index SLO endpoints the same way).
    pub index: Option<u16>,
    pub is_default: bool,
}

impl Endpoint {
    pub fn redirect(url: impl Into<String>, index: u16, is_default: bool) -> Self;
    pub fn post(url: impl Into<String>, index: u16, is_default: bool) -> Self;
    pub fn artifact(url: impl Into<String>, index: u16, is_default: bool) -> Self;
    pub fn soap(url: impl Into<String>, index: Option<u16>, is_default: bool) -> Self;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    HttpRedirect,  // urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect
    HttpPost,      // urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST
    HttpArtifact,  // urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact
    Soap,          // urn:oasis:names:tc:SAML:2.0:bindings:SOAP
}

/// Bindings legal for an SSO `<samlp:Response>` per SAML 2.0 Profiles §4.1.4
/// (Web Browser SSO). The Response MAY be delivered via POST or Artifact and
/// MUST NOT be delivered via Redirect. This is a type-level subset of
/// `Binding` so that consume/emit APIs can encode the constraint in their
/// signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsoResponseBinding {
    HttpPost,
    HttpArtifact,
}

impl SsoResponseBinding {
    /// Lossless widening to the general `Binding` enum.
    pub fn as_binding(self) -> Binding;
    /// Fallible narrowing. Returns `None` for `HttpRedirect` / `Soap`.
    pub fn from_binding(b: Binding) -> Option<Self>;
}

/// Typed-narrowed endpoint for AssertionConsumerService. The binding is a
/// `SsoResponseBinding`, so by construction it CANNOT be `HttpRedirect` or
/// `Soap`. Use this everywhere ACS endpoints flow:
///   - `ServiceProviderConfig.acs`
///   - `SpDescriptor.assertion_consumer_services`
///   - `LoginTracker::acs_endpoint()`
///   - `AcsSelection` resolution result
///
/// This closes the gap where `Endpoint::redirect("...", 0, true)` could be
/// placed into an ACS list, causing the IdP to mint a Response over Redirect
/// at issue time. There is no `redirect` constructor on this type — the
/// constraint is structural, not runtime.
pub struct SsoResponseEndpoint {
    pub url: String,
    pub binding: SsoResponseBinding,
    pub index: Option<u16>,
    pub is_default: bool,
}

impl SsoResponseEndpoint {
    pub fn post(url: impl Into<String>, index: u16, is_default: bool) -> Self;
    pub fn artifact(url: impl Into<String>, index: u16, is_default: bool) -> Self;
    /// Widening to the general `Endpoint`. The reverse direction (narrowing)
    /// is a fallible `try_from(Endpoint) -> Result<Self, Error>` — used by
    /// SP metadata parsers in RFC-006 to reject non-conformant SP descriptors.
    pub fn as_endpoint(&self) -> Endpoint;
    pub fn try_from_endpoint(e: Endpoint) -> Result<Self, Error>;
}
```

---

## 3. Starting a login

```rust
pub struct StartLogin<'a> {
    /// Opaque CSRF / app-state token, round-tripped via RelayState.
    pub relay_state: Option<&'a str>,
    /// Which binding to use for the outbound AuthnRequest transport.
    pub binding: Binding,
    /// If true, request that the IdP not use a cached session (ForceAuthn).
    pub force_authn: bool,
    /// If true, request that the IdP not present any UI (IsPassive).
    pub is_passive: bool,
    /// Optional NameID format to request.
    pub requested_name_id_format: Option<NameIdFormat>,
    /// Optional AuthnContextClassRef to request (e.g., MFA).
    pub requested_authn_context: Option<RequestedAuthnContext>,
    /// Which of the SP's ACS endpoints to nominate. If None, the AuthnRequest
    /// omits ACS index/URL and the IdP uses the SP's default from metadata.
    pub acs_index: Option<u16>,
    /// Nominate a registered ACS by URL instead of index. Mutually exclusive
    /// with `acs_index`; an unregistered URL returns `Error::UnregisteredAcs`.
    pub acs_url: Option<&'a str>,
    /// Optional requested Response binding. If omitted, the selected ACS
    /// endpoint's binding is used. This is deliberately separate from
    /// `binding`, which is only the AuthnRequest transport.
    pub response_binding: Option<SsoResponseBinding>,
}

pub struct StartLoginResult {
    /// Caller persists this. Required at `consume_response` time to bind the
    /// Response back to this request.
    pub tracker: LoginTracker,
    pub dispatch: Dispatch,
}

#[derive(Debug, Clone)]
pub struct LoginTracker { /* private authoritative fields */ }

impl LoginTracker {
    pub fn request_id(&self) -> &str;
    pub fn issued_at(&self) -> SystemTime;
    pub fn idp_entity_id(&self) -> &str;
    pub fn acs_endpoint(&self) -> &SsoResponseEndpoint;
    pub fn requested_authn_context(&self) -> Option<&RequestedAuthnContext>;
    pub fn requested_name_id_format(&self) -> Option<&NameIdFormat>;
    pub fn idp_signing_cert_fingerprints(&self) -> &[[u8; 32]];
    pub fn idp_artifact_resolution_services(&self) -> &[Endpoint];
    pub fn to_payload(&self) -> LoginTrackerPayload;
    pub fn open(blob: &str, key: &[u8; 32], now: SystemTime, max_age: Duration)
        -> Result<Self, Error>;
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoginTrackerPayload {
    pub request_id: String,
    pub issued_at: SystemTime,
    pub idp_entity_id: String,
    pub acs_endpoint: SsoResponseEndpoint,
    pub requested_authn_context: Option<RequestedAuthnContext>,
    pub requested_name_id_format: Option<NameIdFormat>,
    pub idp_signing_cert_fingerprints: Vec<[u8; 32]>,
    #[serde(default)]
    pub idp_artifact_resolution_services: Vec<Endpoint>,
}

impl LoginTrackerPayload {
    pub fn seal(&self, key: &[u8; 32]) -> Result<String, Error>;
}

/// Dispatch for outbound SAML *requests* (AuthnRequest, LogoutRequest) and
/// outbound LogoutResponse. SLO permits all three of Redirect / POST / SOAP;
/// SOAP is handled separately via `send_soap_logout_request`. Web Browser SSO
/// Response uses the typed-subset `SsoResponseDispatch` below instead.
pub enum Dispatch {
    /// HTTP 302 to this URL.
    Redirect(url::Url),
    /// Render an auto-submitting HTML form to this action URL.
    Post(PostForm),
}

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
pub enum SsoResponseDispatch {
    Post(SsoResponsePostForm),
    Artifact(ArtifactRedirect),
}

pub struct SsoResponsePostForm {
    pub action: url::Url,
    /// `SAMLResponse` hidden input value (base64-encoded SAML XML).
    pub saml_response: String,
    pub relay_state: Option<String>,
}

pub struct ArtifactRedirect {
    /// Redirect the user agent here. URL contains `?SAMLart=...&RelayState=...`.
    pub redirect_to: url::Url,
    /// The artifact value embedded in `redirect_to`. The IdP MUST persist the
    /// associated `<samlp:Response>` XML keyed by this value and atomically
    /// take it when serving its ArtifactResolutionService.
    pub artifact: String,
    /// The full `<samlp:Response>` XML the IdP's ArtifactResolutionService
    /// must return when the SP later resolves the artifact via SOAP. Library
    /// is stateless; one-time persistence is the caller's responsibility.
    pub response_xml: String,
}

impl ServiceProvider {
    pub fn start_login(
        &self,
        idp: &IdpDescriptor,
        opts: StartLogin<'_>,
    ) -> Result<StartLoginResult, Error>;
}
```

For an Artifact response, `start_login` also pins the selected IdP metadata's
SOAP `ArtifactResolutionService` endpoints (unique, required indices) into the
tracker. Consumption base64-decodes an exact 44-byte Type-4 artifact, rejects a
type other than `0x0004`, verifies `SourceID == SHA-1(tracked IdP entityID)`, and
uses the embedded endpoint index to select only from that pinned snapshot. The
fresh descriptor supplied at response time never supplies the outbound ARS URL,
so metadata substitution cannot turn artifact resolution into SSRF. All these
checks run before the caller's HTTP client is invoked. Artifact resolution is a
solicited flow and therefore requires a `LoginTracker`.

Every authoritative tracker field is read-only. A tracker is obtained from
`start_login`, or by authenticating a sealed payload with `LoginTracker::open`.
The sealing-key holder is a tracker-issuing trust root: because the payload is
transparent, it can authorize arbitrary correlation and policy fields. This
protects an honest tracker while it crosses an untrusted cookie/session store;
it does not constrain an application that owns the key. The wire form is
`base64url(nonce_12 || ciphertext || tag_16)` using AES-256-GCM and a 32-byte
application key. `open` authenticates and deserializes it, rejects blobs older
than `max_age`, and rejects an `issued_at` more than five minutes in the future.
The payload itself is inert: response validation accepts only `LoginTracker`,
never a caller-constructed `LoginTrackerPayload`.

### 3.1 Build steps

- Canonicalize (sort and deduplicate) the SHA-256 fingerprints of
  `idp.signing_certs`, reject an empty set with `Error::NoPeerSigningCert`, and
  pin those fingerprints in the tracker.
- For an Artifact response, also require indexed SOAP
  `ArtifactResolutionService` endpoints and pin their canonical endpoint set.
- Look up `idp.sso_endpoint(opts.binding)`. If absent → `Error::UnsupportedByPeer`.
- Generate `request_id` = `"_"` + lowercase-hex(16 random bytes). SAML IDs must start with a non-digit; `_` is the conventional prefix.
- Reject setting both `opts.acs_index` and `opts.acs_url`. Resolve the selected
  ACS by index, by exact registered URL, or from the SP default. Resolve the
  requested Response binding as
  `opts.response_binding.unwrap_or(selected_acs.binding)` and reject if it
  does not match `selected_acs.binding`.
- Build `<samlp:AuthnRequest>` XML with: `ID`, `Version="2.0"`, `IssueInstant`,
  `Destination`; the selected `AssertionConsumerServiceURL` or
  `AssertionConsumerServiceIndex` (neither for the default case);
  `ProtocolBinding` set to the selected **Response** binding; `ForceAuthn` and
  `IsPassive` only when true; `Issuer`; optional `NameIDPolicy`; and optional
  `RequestedAuthnContext`.
- For `HttpPost`: embed enveloped XML-DSig if `sign_authn_requests` is true. Base64-encode the resulting XML.
- For `HttpRedirect`: produce detached signature in query string (`Signature` + `SigAlg`) per spec §3.4.4.1; DEFLATE-compress + base64 + URL-encode `SAMLRequest`. Detached signature covers the canonical query string per spec.

---

## 4. Consuming a Response

```rust
pub struct ConsumeResponse<'a> {
    pub idp: &'a IdpDescriptor,
    /// Peer-specific inbound crypto policy for this IdP. If absent, the SP's
    /// `default_peer_crypto_policy` is used. Use this for legacy IdPs requiring
    /// weak algorithms so the exception does not apply to every trusted IdP.
    pub peer_crypto_policy: Option<&'a PeerCryptoPolicy>,
    /// Raw bytes from the binding layer. For HTTP-POST: the base64-decoded
    /// `SAMLResponse` form value. For HTTP-Artifact: the resolved Response XML.
    pub saml_response: &'a [u8],
    /// Type-narrowed to POST / Artifact only; `Redirect` is not representable
    /// here per SAML 2.0 Profiles §4.1.4.
    pub binding: SsoResponseBinding,
    pub relay_state: Option<&'a str>,
    /// Tracker from the matching `start_login`. `None` only if
    /// `allow_unsolicited` is true AND the Response carries no `InResponseTo`.
    pub tracker: Option<&'a LoginTracker>,
    /// The SP ACS URL that received this Response. Used to check the
    /// Response's `Destination` and the assertion's `SubjectConfirmationData/Recipient`.
    /// An SP can advertise multiple ACS endpoints (multiple bindings or indices),
    /// so the library cannot infer which one received the message from `binding`
    /// alone. For solicited flows it must equal `tracker.acs_endpoint().url`; the
    /// library enforces that match.
    pub expected_destination: &'a str,
    pub now: SystemTime,
    pub clock_skew: Duration,
    pub replay_cache: Option<&'a dyn ReplayCache>,
    pub replay_mode: ReplayMode,
    pub holder_of_key_cert: Option<&'a X509Certificate>,
}

/// Read-only by construction: every field is private and reached through an
/// accessor. `Proxy::relay_to_downstream` mints a *signed* downstream
/// assertion from an `Identity`, so a mutable one is a signing oracle — a
/// caller could authenticate once, rewrite the subject or attributes, and
/// have the proxy sign the rewritten claims.
pub struct Identity { /* private fields */ }

impl Identity {
    pub fn name_id(&self) -> &NameId;
    pub fn session_index(&self) -> Option<&str>;
    pub fn authn_instant(&self) -> SystemTime;
    pub fn session_not_on_or_after(&self) -> Option<SystemTime>;
    pub fn subject_confirmation_not_on_or_after(&self) -> SystemTime;
    pub fn authn_context_class_ref(&self) -> Option<&str>;
    pub fn attributes(&self) -> &[Attribute];
    /// Assertion ID used by the library replay cache, or by a caller-owned
    /// replay store when `replay_cache` is absent.
    pub fn assertion_id(&self) -> &str;
    pub fn not_on_or_after(&self) -> SystemTime;
    /// Fingerprint of the cert that verified the signature.
    pub fn verifying_cert_fingerprint(&self) -> [u8; 32];
    pub fn is_one_time_use(&self) -> bool;
}

impl ServiceProvider {
    pub fn consume_response(&self, input: ConsumeResponse<'_>) -> Result<Identity, Error>;
}
```

### 4.1 Validation order

Each step short-circuits on error to a specific `Error` variant:

1. **Registered destination and tracker preflight**, before parsing the
   response (and, for Artifact, before making any HTTP request):
   - `expected_destination` MUST resolve to a registered ACS URL in `self.acs`. If not, `Error::InvalidConfiguration` (caller bug, not a wire-format issue).
   - If `tracker.is_some()`: `tracker.acs_endpoint().url` MUST equal `expected_destination`. → `Error::DestinationMismatch`.
   - If `tracker.is_some()`: `tracker.acs_endpoint().binding` MUST equal
     `input.binding`. → `Error::ResponseBindingMismatch`.
   - The supplied IdP descriptor MUST have the tracked entity ID, MUST retain
     at least one signing certificate, and may not introduce a certificate
     absent when `start_login` ran. Retiring an old root is allowed. →
     `Error::IssuerMismatch` / `Error::IdpTrustRootMismatch`.
2. Parse XML and require the `<samlp:Response>` root, including required `ID`,
   `Version="2.0"`, and parseable `IssueInstant`; hardening per RFC-002 §1.
3. **Wire destination**:
   - If `Response/@Destination` is present: it MUST equal `expected_destination`. → `Error::DestinationMismatch`.
4. Check `Response/Issuer` equals `idp.entity_id`. → `Error::IssuerMismatch`.
5. Check `Status/StatusCode/@Value` equals `urn:oasis:names:tc:SAML:2.0:status:Success`. Otherwise `Error::StatusNotSuccess { code, message }` carrying the StatusCode/StatusMessage from the response.
6. **`Response/@InResponseTo` binding** (the rule is strict, not "match-if-present" — that pattern lets replayed solicited responses re-enter as "unsolicited"):
   - If `tracker.is_some()`: `Response/@InResponseTo` MUST be present AND equal `tracker.request_id()`. Any other state → `Error::InResponseToMismatch`.
   - If `tracker.is_none()`: `allow_unsolicited` MUST be true AND `Response/@InResponseTo` MUST be absent. If `InResponseTo` is present, the response is claiming to be solicited and the caller has no tracker for it — reject with `Error::UnsolicitedNotAllowed`. If `allow_unsolicited` is false, reject with `Error::UnsolicitedNotAllowed` regardless of `InResponseTo`.
7. Locate `<saml:Assertion>` or `<saml:EncryptedAssertion>` children. Reject if not exactly one (multiple-assertion responses are out of scope for v0.1 and a known XSW vector).
8. Select `policy = input.peer_crypto_policy.unwrap_or(&self.default_peer_crypto_policy)`.
9. If `EncryptedAssertion`: decrypt per RFC-002 §7 using `decryption_key` and
   the policy's data-encryption, key-transport, OAEP message-digest, and OAEP
   MGF1-digest allow-lists.
10. **Signature verification**:
   - If `want_signed.response`: verify Response signature against `idp.signing_certs`, threading `policy.allowed_signature_algorithms`. The signed element MUST be the Response root.
   - If `want_signed.assertions`: verify Assertion signature with the same allow-list. The signed element MUST be the Assertion.
   - If neither flag is set: require at least one of the two signatures to be present and valid.
   - In all cases, the validated payload is extracted from the signed element by `ElementId`, not by re-lookup. (RFC-002 §3.2.)
11. Check `Assertion/Issuer` equals `idp.entity_id`.
12. Check `Conditions/@NotBefore` ≤ `now + clock_skew`. → `Error::NotYetValid`.
13. Check `Conditions/@NotOnOrAfter` > `now - clock_skew`. → `Error::Expired`.
14. Check `Conditions/AudienceRestriction/Audience` contains `self.entity_id`. Multiple `AudienceRestriction` elements: ALL must be satisfied. → `Error::AudienceMismatch`.
15. Locate a usable `Assertion/Subject/SubjectConfirmation`: bearer is always
    eligible; Holder-of-Key is eligible only when `holder_of_key_cert` was
    supplied and its public key matches the confirmation's `<ds:KeyInfo>`.
    Bearer candidates are tried first.
16. From the matching SubjectConfirmation's `SubjectConfirmationData`:
    - `@Recipient` equals `expected_destination`. → `Error::RecipientMismatch`.
    - `@NotOnOrAfter` > `now - clock_skew`. → `Error::Expired`.
    - If `@NotBefore` is present, it is ≤ `now + clock_skew`. →
      `Error::NotYetValid`.
    - **`@InResponseTo` binding** (mirrors step 6 — both must agree, neither alone is sufficient):
      - If `tracker.is_some()`: `@InResponseTo` MUST be present AND equal `tracker.request_id()`. → `Error::InResponseToMismatch`.
      - If `tracker.is_none()`: `@InResponseTo` MUST be absent. → `Error::UnsolicitedNotAllowed`.
17. If `tracker.requested_authn_context()` is set, the actual `AuthnStatement/AuthnContext/AuthnContextClassRef` must satisfy the comparator (default `exact`). → `Error::AuthnContextDowngrade`.
18. Extract `Identity` from the Assertion. If the tracker requested a NameID
    format, require the returned format to match. For a persistent NameID, a
    present `SPNameQualifier` must equal this SP's entity ID.
19. If `<OneTimeUse>` is present, a replay cache and an enabled replay mode are
    mandatory; otherwise fail with `Error::OneTimeUseUnenforceable`. When a
    replay check applies, atomic namespaced `check_and_insert(entries, now)` rejects duplicates with
    `Error::AssertionReplay`.

For HTTP-Artifact, these checks precede the shared XML validation: decode an
exact 44-byte Type-4 artifact, require SourceID = SHA-1 of the tracked IdP
entity, and resolve its EndpointIndex only through the transaction-pinned SOAP
ARS set. Malformed, cross-issuer, unknown-index, and substituted-metadata
inputs make no HTTP request. The SOAP back channel must authenticate both
peers: supply `ArtifactBackchannel` message signing/verification, or use
mutually authenticated TLS when its `backchannel` field is `None`.

### 4.2 What the caller does after

- **Replay defense**: supply a `ReplayCache` (recommended with
  `ReplayMode::All`) or dedupe ordinary assertions in an application store.
  `<OneTimeUse>` always fails closed unless the library can perform the atomic
  cache operation.
- **Application session**: create a session keyed off `identity.name_id()` + `identity.session_index()`.
- **Authorization**: apply policy to `identity.attributes()`.

---

## 5. SP-initiated logout

API summarized; details in RFC-007.

```rust
impl ServiceProvider {
    pub fn start_logout(&self, idp: &IdpDescriptor, opts: StartLogout<'_>) -> Result<LogoutDispatch, Error>;
    pub fn consume_logout_response(&self, /* ... */) -> Result<LogoutOutcome, Error>;
    pub fn consume_logout_request(&self, /* ... */) -> Result<ParsedLogoutRequest, Error>;
    pub fn build_logout_response(&self, /* ... */) -> Result<Dispatch, Error>;
    pub async fn send_soap_logout_request<H: HttpClient>(&self, http: &H, /* ... */) -> Result<LogoutOutcome, Error>;
}
```

---

## 6. Metadata

```rust
impl ServiceProvider {
    /// Emit SP-side EntityDescriptor XML, suitable for IdPs to consume.
    /// Optionally signed with `signing_key`.
    pub fn metadata_xml(&self, sign: bool) -> Result<String, Error>;
}
```

Details in RFC-006.

---

## 7. Example

```rust
let sp = ServiceProvider::new(ServiceProviderConfig {
    entity_id: "https://app.example.com/saml".into(),
    acs: vec![SsoResponseEndpoint::post("https://app.example.com/saml/acs", 0, true)],
    slo: vec![Endpoint::post("https://app.example.com/saml/slo", 0, true)],
    name_id_formats: vec![NameIdFormat::EmailAddress, NameIdFormat::Persistent],
    signing_key: Some(KeyPair::from_pkcs8_pem(SP_PRIV)?),
    decryption_key: Some(KeyPair::from_pkcs8_pem(SP_ENC_PRIV)?),
    sign_authn_requests: true,
    want_signed: SpWantSigned {
        response: false,
        assertions: true,
    },
    allow_unsolicited: false,
    logout_signing: SpLogoutSigning {
        sign_requests: true,
        sign_responses: true,
    },
    logout_want_signed: SpLogoutWantSigned {
        requests: true,
        responses: true,
    },
    default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
    outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
    outbound_digest_algorithm: DigestAlgorithm::Sha256,
})?;

let idp = IdpDescriptor::from_metadata_xml(idp_metadata_xml)?;

// --- /auth/login handler ---
let start = sp.start_login(&idp, StartLogin {
    relay_state: Some(&app_state_token),
    binding: Binding::HttpRedirect,
    force_authn: false,
    is_passive: false,
    requested_name_id_format: None,
    requested_authn_context: None,
    acs_index: None,
    acs_url: None,
    response_binding: None,
})?;
let sealed_tracker = start.tracker.to_payload().seal(&TRACKER_KEY)?;
session.put("saml_tracker", &sealed_tracker)?;
match start.dispatch {
    Dispatch::Redirect(url) => Redirect::to(url.as_str()),
    Dispatch::Post(form) => render_autosubmit(form),
}

// --- /saml/acs handler ---
let sealed_tracker: String = session.take("saml_tracker")?;
let tracker = LoginTracker::open(
    &sealed_tracker,
    &TRACKER_KEY,
    SystemTime::now(),
    Duration::from_mins(10),
)?;
let identity = sp.consume_response(ConsumeResponse {
    idp: &idp,
    peer_crypto_policy: None,
    saml_response: &decoded_form.saml_response,
    binding: SsoResponseBinding::HttpPost,
    relay_state: decoded_form.relay_state.as_deref(),
    tracker: Some(&tracker),
    expected_destination: "https://app.example.com/saml/acs", // the URL this handler serves
    now: SystemTime::now(),
    clock_skew: Duration::from_secs(60),
    replay_cache: Some(&replay_cache),
    replay_mode: ReplayMode::All,
    holder_of_key_cert: None,
})?;
// Create app session keyed off identity.name_id() + identity.session_index().
```

---

## 8. Security checks summary

| Check | Where |
| --- | --- |
| `expected_destination`, IdP, response binding, and trust roots match the registered/tracked transaction | §4.1 step 1 |
| Required Response protocol attributes parse and `Response/@Destination` matches | §4.1 steps 2–3 |
| `Response/Issuer` matches expected IdP EntityID | §4.1 step 4 |
| `Status` is `Success` | §4.1 step 5 |
| `Response/@InResponseTo` strictly matches solicited / unsolicited state | §4.1 step 6 |
| Exactly one Assertion (or EncryptedAssertion) | §4.1 step 7 |
| Effective peer crypto policy selected | §4.1 step 8 |
| EncryptedAssertion decrypts under all peer XML-Enc/OAEP allow-lists | §4.1 step 9 |
| Signature verified under peer signature allow-list; payload bound to signed `ElementId` | §4.1 step 10 (XSW-resistant) |
| `Conditions/NotBefore`, `Conditions/NotOnOrAfter` within clock skew | §4.1 steps 12–13 |
| `AudienceRestriction` includes our EntityID | §4.1 step 14 |
| Bearer or cryptographically proven Holder-of-Key SubjectConfirmation present | §4.1 step 15 |
| `SubjectConfirmationData/Recipient` = `expected_destination` | §4.1 step 16 |
| `SubjectConfirmationData/NotOnOrAfter` in future | §4.1 step 16 |
| `SubjectConfirmationData/InResponseTo` strictly matches solicited / unsolicited state | §4.1 step 16 |
| Requested AuthnContext non-downgrade | §4.1 step 17 |
| Requested NameID format and persistent `SPNameQualifier` binding | §4.1 step 18 |
| Atomic namespaced replay dedupe; fail closed for `<OneTimeUse>` | §4.1 step 19 |
