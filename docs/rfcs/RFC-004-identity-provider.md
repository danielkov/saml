# RFC-004: Identity Provider role

**Status**: Draft
**Date**: 2026-05-26

## Summary

This RFC defines the active IdP-role surface: `IdentityProvider`, `IdentityProviderConfig`, AuthnRequest validation, and Response issuance. The IdP role is what an application uses when it authenticates users on behalf of one or more downstream SPs.

The library is **not** an IdP framework — it does not provide user authentication, session management, MFA, consent flows, attribute storage, or admin UI. It provides only the SAML 2.0 protocol mechanics. The caller authenticates the user however it sees fit and then asks the library to mint an Assertion.

---

## 1. Configuration

```rust
pub struct IdentityProviderConfig {
    pub entity_id: String,

    /// SSO endpoints (where downstream SPs send AuthnRequests).
    pub sso: Vec<Endpoint>,
    /// SLO endpoints.
    pub slo: Vec<Endpoint>,
    /// Indexed SOAP ArtifactResolutionService endpoints; indices must be
    /// unique because Type-4 artifacts route by this value.
    pub artifact_resolution: Vec<Endpoint>,

    pub supported_name_id_formats: Vec<NameIdFormat>,
    /// Default Format when the SP did not request one.
    pub default_name_id_format: NameIdFormat,

    /// Required key material used when the configured signing flags request it.
    pub signing_key: KeyPair,
    /// Optional — currently used to decrypt EncryptedID on inbound
    /// LogoutRequest (rare in practice, with `xmlenc`).
    pub decryption_key: Option<KeyPair>,

    /// If true, AuthnRequests from SPs must be signed.
    pub want_authn_requests_signed: bool,
    /// Outbound Response / Assertion signing policy.
    pub assertion_signing: IdpAssertionSigning,
    /// If true, encrypt Assertions when the SP has an encryption cert in metadata.
    pub encrypt_assertions_when_possible: bool,

    // --- SLO signing policy — independent of SSO policy. `want_authn_requests_signed`
    //     is an SSO-side knob and does NOT apply to LogoutRequest validation.

    /// Outbound LogoutRequest / LogoutResponse signing policy (with `slo`).
    #[cfg(feature = "slo")]
    pub logout_signing: IdpLogoutSigning,
    /// Inbound LogoutRequest / LogoutResponse signature requirements (with `slo`).
    #[cfg(feature = "slo")]
    pub logout_want_signed: IdpLogoutWantSigned,

    pub default_session_duration: Duration,

    /// Default inbound crypto policy when a consume call does not provide a
    /// peer-specific override. Legacy SPs that require weak algorithms should
    /// be handled by passing a per-peer `PeerCryptoPolicy` on the consume input,
    /// not by weakening this default for every SP the IdP trusts.
    pub default_peer_crypto_policy: PeerCryptoPolicy,
    pub outbound_signature_algorithm: SignatureAlgorithm,             // default RsaSha256
    pub outbound_digest_algorithm: DigestAlgorithm,                   // default Sha256
    pub outbound_c14n: C14nAlgorithm,                                 // default ExclusiveCanonical
    // The encryption fields are present with the `xmlenc` feature.
    #[cfg(feature = "xmlenc")]
    pub outbound_data_encryption_algorithm: DataEncryptionAlgorithm,  // default Aes256Gcm
    #[cfg(feature = "xmlenc")]
    pub outbound_key_transport_algorithm: KeyTransportAlgorithm,      // default RsaOaep
}

pub struct IdpAssertionSigning {
    pub sign_responses: bool,
    pub sign_assertions: bool,
}

pub struct IdpLogoutSigning {
    pub sign_requests: bool,
    pub sign_responses: bool,
}

pub struct IdpLogoutWantSigned {
    pub requests: bool,
    pub responses: bool,
}

impl IdentityProvider {
    pub fn new(config: IdentityProviderConfig) -> Result<Self, Error>;
}
```

---

## 2. Consuming AuthnRequest

```rust
pub struct ConsumeAuthnRequest<'a> {
    pub sp: &'a SpDescriptor,
    /// Peer-specific inbound crypto policy for this SP. If absent, the IdP's
    /// `default_peer_crypto_policy` is used.
    pub peer_crypto_policy: Option<&'a PeerCryptoPolicy>,
    pub saml_request: &'a [u8],
    pub binding: Binding,
    pub relay_state: Option<&'a str>,
    /// For HTTP-Redirect binding: the detached `Signature` + `SigAlg` query
    /// values + the raw query string that was signed.
    pub detached_signature: Option<DetachedSignature<'a>>,
    /// The IdP SSO endpoint URL that received this AuthnRequest. The library
    /// uses this to validate `AuthnRequest/@Destination`. Necessary because an
    /// IdP can advertise multiple SSO endpoints (one per binding, or multiple
    /// per binding for ingress isolation) and the library cannot infer which
    /// one received the message from `binding` alone.
    pub expected_destination: &'a str,
    pub now: SystemTime,
    pub clock_skew: Duration,
}

pub struct DetachedSignature<'a> {
    pub signature: &'a [u8],   // already base64-decoded signature bytes
    pub sig_alg: &'a str,      // algorithm URI
    pub raw_query_string: &'a str,  // canonical query string per spec §3.4.4.1
}

pub struct ParsedAuthnRequest {
    pub id: String,
    pub issuer: String,
    pub issue_instant: SystemTime,
    pub destination: Option<String>,
    /// The ACS endpoint **resolved** against SP metadata. Always points at a
    /// registered `SsoResponseEndpoint`, never an SP-supplied URL. ACS-URL
    /// echoing is the canonical assertion-exfiltration vector; the resolved
    /// type makes echoing structurally impossible.
    pub assertion_consumer_service: SsoResponseEndpoint,
    /// What binding the SP requested for the Response. Validated at parse
    /// time to be POST or Artifact (`Redirect`/`SOAP` rejected with
    /// `Error::IllegalResponseBinding`), AND cross-checked against the
    /// resolved ACS endpoint's binding (§2.1 step 7a). `None` means the
    /// AuthnRequest carried no `@ProtocolBinding`; the resolved ACS endpoint's
    /// binding is authoritative.
    pub protocol_binding: Option<SsoResponseBinding>,
    /// The raw selection from the AuthnRequest, retained for logging /
    /// metrics. Resolution to a concrete `SsoResponseEndpoint` has already
    /// happened.
    pub assertion_consumer_service_selection: AcsSelection,
    pub force_authn: bool,
    pub is_passive: bool,
    pub requested_name_id_format: Option<NameIdFormat>,
    pub requested_authn_context: Option<RequestedAuthnContext>,
    pub relay_state: Option<String>,
}

pub enum AcsSelection {
    /// SP specified `AssertionConsumerServiceIndex`.
    Index(u16),
    /// SP specified `AssertionConsumerServiceURL`.
    Url(String),
    /// SP specified neither — IdP used SP metadata's default endpoint.
    Default,
}

impl IdentityProvider {
    pub fn consume_authn_request(
        &self,
        input: ConsumeAuthnRequest<'_>,
    ) -> Result<ParsedAuthnRequest, Error>;
}
```

The wire-derived request fields remain public for logging and diagnostics, but
issuance does not treat them as authority. A private provenance snapshot
records the SP, ACS, request ID, RelayState, requested NameID/AuthnContext
policies, encryption fingerprints, and SP signing fingerprints validated by
the role. Read-only `validated_*` accessors expose the non-signing provenance;
signing roots stay private and flow only into an opaque Artifact transaction.
Callers cannot reconstruct or rewrite the snapshot after validation.

### 2.1 Validation order

1. Decode the binding wire format (DEFLATE+base64 for Redirect, base64 for
   POST) before this low-level method, or call `consume_authn_request_wire` to
   do it. Bound input size; reject if oversized.
2. Parse XML; hardening per RFC-002 §1.
3. Check the root element is `<samlp:AuthnRequest>`.
4. Check `Issuer` equals `input.sp.entity_id`. → `Error::IssuerMismatch`.
5. **Destination binding**: `expected_destination` MUST resolve to a registered SSO endpoint URL in `self.sso`. If not, `Error::InvalidConfiguration` (caller bug). Then if `AuthnRequest/@Destination` is present, it MUST equal `expected_destination`. → `Error::DestinationMismatch`.
5a. **ProtocolBinding sanity**: if `AuthnRequest/@ProtocolBinding` is present, it MUST map to a `SsoResponseBinding` (POST or Artifact). `HTTP-Redirect` and `SOAP` are illegal for Web Browser SSO Responses (SAML 2.0 Profiles §4.1.4) and are rejected here with `Error::IllegalResponseBinding { requested }`. This guards against malformed or malicious AuthnRequests asking the IdP to deliver the SSO Response over Redirect, which would bypass the embedded XML-Signature path the POST profile mandates.
6. **Signature check** (security-critical). Select `policy = input.peer_crypto_policy.unwrap_or(&self.default_peer_crypto_policy)`. All paths thread `policy.allowed_signature_algorithms` into the verifier — the allow-list applies equally to XML-DSig and detached Redirect signatures, otherwise `weak-algos` would leak through the Redirect path:
   - If `self.want_authn_requests_signed` OR `input.sp.authn_requests_signed`:
     - For `Binding::HttpRedirect`: call `verify_detached_signature` (RFC-002 §3.3) over the canonical query string per spec §3.4.4.1, with `candidate_certs = input.sp.signing_certs` and `allowed_algorithms = policy.allowed_signature_algorithms`. → `Error::SignatureVerification` / `Error::DisallowedAlgorithm`.
     - For `Binding::HttpPost` or `Binding::Soap`: call `verify_signature` (RFC-002 §3) on the enveloped XML-DSig, with the same `candidate_certs` and `allowed_algorithms`.
     - After a Redirect signature verifies, decode its canonical signed query
       and require its XML and RelayState to exactly equal the separately
       supplied values. This prevents mixing a genuine signature with another
       request or application correlation token.
   - Else: signature optional; if present, verify with the same allow-list discipline; if absent, accept.
7. **Resolve ACS selection** (most dangerous SAML IdP bug class). The result is a `&SsoResponseEndpoint`, so by construction the resolved endpoint's binding is in {`HttpPost`, `HttpArtifact`}. Non-conformant SP metadata advertising a Redirect/SOAP ACS would have been rejected at `SpDescriptor::from_metadata_xml` time (RFC-006 §2).
   - `Index(n)`: look up in `input.sp.assertion_consumer_services` by index. If absent → `Error::UnregisteredAcs`.
   - `Url(u)`: look up in `input.sp.assertion_consumer_services` by URL. If absent → `Error::UnregisteredAcs`.
   - `Default`: pick `input.sp.default_acs()`. If SP has no default → `Error::UnregisteredAcs`.
   - **Never accept the SP-supplied URL without registry match.** This is non-configurable. Accepting an arbitrary `AssertionConsumerServiceURL` enables assertion exfiltration to an attacker-controlled endpoint.
7a. **ACS / ProtocolBinding consistency** (closes the gap where `@ProtocolBinding` was checked in isolation from the resolved ACS):
   - If `AuthnRequest/@ProtocolBinding` was specified (already narrowed to `SsoResponseBinding` in step 5a) AND the resolved ACS endpoint's binding differs from it: → `Error::IllegalResponseBinding { requested }`. The SP cannot ask for the Response on a binding the registered ACS endpoint does not support.
   - If `@ProtocolBinding` was not specified: the resolved ACS endpoint's binding is authoritative.
   - The pair `(resolved_acs.binding, requested_protocol_binding)` is what flows into `IssueResponse` and pins the outbound binding — there is no further negotiation after this step.
8. Build `ParsedAuthnRequest` with the resolved ACS (`SsoResponseEndpoint`), all flags, and the relay state.

### 2.2 Caller responsibility after consume

- **Replay defense on AuthnRequest ID**: optional; the threat is limited (no bearer credential is carried in AuthnRequest itself). The library exposes immutable `parsed.validated_request_id()` for the caller to dedupe if desired.
- **User authentication**: out of band. The library does not provide login UI, MFA, or session management.
- **Consent / attribute release decision**: out of band. The library accepts the final attribute set as input to `issue_response`.

---

## 3. Issuing a Response

```rust
pub struct IssueResponse<'a> {
    pub sp: &'a SpDescriptor,
    pub in_response_to: &'a ParsedAuthnRequest,
    pub name_id: NameId,
    pub attributes: Vec<Attribute>,
    pub authn_instant: SystemTime,
    pub session_index: String,
    pub session_not_on_or_after: Option<SystemTime>,
    pub authn_context_class_ref: AuthnContextClassRef,
    /// Override default behavior. `None` = encrypt only when SP has an
    /// encryption cert AND `config.encrypt_assertions_when_possible` is true.
    pub force_encrypt_assertion: Option<bool>,
    pub now: SystemTime,
    pub assertion_lifetime: Duration,
    pub subject_confirmation_lifetime: Duration,
    pub holder_of_key_cert: Option<&'a X509Certificate>,
}

impl IdentityProvider {
    pub fn issue_response(&self, input: IssueResponse<'_>) -> Result<SsoResponseDispatch, Error>;

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    pub fn issue_response_with_artifact_transaction(
        &self,
        input: IssueResponse<'_>,
    ) -> Result<IssuedResponse, Error>;
}
```

### 3.1 Build steps

1. Require `input.sp` to match the request's private validated provenance and
   resolve the ACS from `input.in_response_to.validated_acs()`. This determines
   the destination URL and response binding; mutable public request fields are
   never used for issuance.
2. Generate `response_id` and `assertion_id` = `"_"` + lowercase-hex(16 random bytes).
3. Build `<saml:Assertion>`:
   - `Issuer` = `self.entity_id`.
   - `Subject`:
     - `NameID` with the explicitly requested format when supported. An
       unsupported explicit request fails with `InvalidNameIDPolicy`; the IdP
       default is used only when no format was requested. The supplied
       `NameId` must already carry that resolved format; issuance refuses a
       mismatch rather than relabelling a value with different semantics.
     - For `NameIdFormat::Persistent`: reject a caller-supplied `SPNameQualifier` for another SP, then set an absent qualifier to `input.sp.entity_id` (privacy — prevents downstream SPs from correlating users).
     - `SubjectConfirmation @Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"` with:
       - `Recipient` = ACS URL (the one resolved in step 1).
       - `NotOnOrAfter` = `now + subject_confirmation_lifetime`.
       - `InResponseTo` = `input.in_response_to.validated_request_id()`.
   - `Conditions`:
     - `NotBefore` = `now - 1 minute` (clock-skew tolerance for downstream).
     - `NotOnOrAfter` = `now + assertion_lifetime`.
     - `AudienceRestriction/Audience` = `input.sp.entity_id`.
   - `AuthnStatement`:
     - `AuthnInstant` = `input.authn_instant`.
     - `SessionIndex` = `input.session_index`.
     - `SessionNotOnOrAfter` if set.
     - `AuthnContext/AuthnContextClassRef` = `input.authn_context_class_ref`.
   - `AttributeStatement` if `attributes` is non-empty.
4. If `self.assertion_signing.sign_assertions`: sign the Assertion (RFC-002 §6) with the chosen outbound algorithm and canonicalization method.
5. Build `<samlp:Response>`:
   - `Destination` = ACS URL.
   - `InResponseTo` = `input.in_response_to.validated_request_id()`.
   - `Issuer` = `self.entity_id`.
   - `Status/StatusCode @Value="urn:oasis:names:tc:SAML:2.0:status:Success"`.
   - Embed the Assertion. If
     - `force_encrypt_assertion == Some(true)`, OR
     - (`force_encrypt_assertion == None` AND `self.encrypt_assertions_when_possible` AND `input.sp.encryption_cert().is_some()`):
     wrap in `<saml:EncryptedAssertion>` (RFC-002 §7).
6. If `self.assertion_signing.sign_responses`: sign the Response root.
7. Encode for the binding in `input.in_response_to.validated_acs()`. For
   HTTP-Artifact, select an indexed SOAP `ArtifactResolutionService` from IdP
   configuration and encode that IdP ARS index—not the SP ACS index—in the
   Type-4 artifact.

`issue_response` returns POST and refuses an Artifact-capable request with
`ArtifactTransactionRequired`; its legacy result cannot carry the later trust
transaction. When the Artifact features are not compiled, the same request
returns `UnsupportedByPeer(HttpArtifact)` because the transaction-bearing API
is unavailable. The type system also forbids returning a Redirect for an SSO
Response.

For an Artifact-capable flow, call
`IdentityProvider::issue_response_with_artifact_transaction` (features
`artifact-binding` + `weak-algos`). Its Artifact
variant includes an opaque transaction binding the exact artifact, SP identity,
and SP signing-root fingerprints observed during AuthnRequest validation. The authenticated
`consume_artifact_resolve` path requires that transaction plus a linearizable
`ReplayCache`; it verifies the root signature against a descriptor whose roots
are still within the pinned set, then atomically reserves the SP-scoped
ArtifactResolve `@ID` before the caller takes the one-time artifact. Deployments
using the structural `parse_artifact_resolve` compatibility path for more than
an untrusted store lookup must make mutually authenticated TLS the explicit SP
trust root. The opaque transaction can be kept in memory or persisted using
its authenticated `seal` / `open` methods. Resolution also parses the Type-4
artifact and requires its SourceID and endpoint index to identify this IdP and
the exact receiving ARS URL. `clock_skew` must be positive: wire timestamps are
quantized and cannot reliably equal the receiver's higher-precision clock.
`IdentityProvider::build_artifact_response` signs the outer
`ArtifactResponse` with the configured IdP key so SPs can enable envelope
verification independently of validating the embedded Response/assertion.

---

## 4. Issuing an error Response

```rust
pub struct IssueErrorResponse<'a> {
    pub sp: &'a SpDescriptor,
    pub in_response_to: &'a ParsedAuthnRequest,
    pub status_code: SamlStatusCode,
    pub second_level_status_code: Option<SamlStatusCode>,
    pub message: Option<String>,
    pub now: SystemTime,
}

pub enum SamlStatusCode {
    Requester,           // urn:oasis:names:tc:SAML:2.0:status:Requester
    Responder,           // urn:oasis:names:tc:SAML:2.0:status:Responder
    VersionMismatch,
    AuthnFailed,
    InvalidAttrNameOrValue,
    InvalidNameIdPolicy,
    NoAuthnContext,
    NoAvailableIdp,
    NoPassive,
    NoSupportedIdp,
    PartialLogout,
    ProxyCountExceeded,
    RequestDenied,
    RequestUnsupported,
    RequestVersionDeprecated,
    RequestVersionTooHigh,
    RequestVersionTooLow,
    ResourceNotRecognized,
    TooManyResponses,
    UnknownAttrProfile,
    UnknownPrincipal,
    UnsupportedBinding,
    Custom(String),
}

impl IdentityProvider {
    pub fn issue_error_response(&self, input: IssueErrorResponse<'_>) -> Result<SsoResponseDispatch, Error>;
    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    pub fn issue_error_response_with_artifact_transaction(
        &self,
        input: IssueErrorResponse<'_>,
    ) -> Result<IssuedResponse, Error>;
}
```

Used when the user declined consent, MFA failed, the requested authentication strength is unavailable, or the AuthnRequest was malformed in a way the caller wants to surface to the SP.

---

## 5. IdP-side SLO

Mirror image of SP-side; details in RFC-007.

```rust
impl IdentityProvider {
    pub fn consume_logout_request(&self, /* ... */) -> Result<ParsedLogoutRequest, Error>;
    pub fn build_logout_response(&self, /* ... */) -> Result<Dispatch, Error>;
    pub fn start_logout(&self, /* ... */) -> Result<LogoutDispatch, Error>;
    pub fn consume_logout_response(&self, /* ... */) -> Result<LogoutOutcome, Error>;
    pub async fn send_soap_logout_request<H: HttpClient>(&self, http: &H, /* ... */) -> Result<LogoutOutcome, Error>;
}
```

---

## 6. Metadata

```rust
impl IdentityProvider {
    pub fn metadata_xml(&self, sign: bool) -> Result<String, Error>;
}
```

Emits `<md:EntityDescriptor>` containing `<md:IDPSSODescriptor>`. Details in RFC-006.

---

## 7. Example

```rust
let idp = IdentityProvider::new(IdentityProviderConfig {
    entity_id: "https://idp.example.com/saml".into(),
    sso: vec![
        Endpoint::redirect("https://idp.example.com/saml/sso", 0, true),
        Endpoint::post("https://idp.example.com/saml/sso", 1, false),
    ],
    slo: vec![Endpoint::post("https://idp.example.com/saml/slo", 0, true)],
    artifact_resolution: vec![Endpoint::soap(
        "https://idp.example.com/saml/artifact",
        Some(0),
        true,
    )],
    supported_name_id_formats: vec![NameIdFormat::Persistent, NameIdFormat::EmailAddress],
    default_name_id_format: NameIdFormat::Persistent,
    signing_key: KeyPair::from_pkcs8_pem(IDP_PRIV)?,
    decryption_key: None,
    want_authn_requests_signed: true,
    assertion_signing: IdpAssertionSigning {
        sign_responses: false,
        sign_assertions: true,
    },
    encrypt_assertions_when_possible: true,
    logout_signing: IdpLogoutSigning {
        sign_requests: true,
        sign_responses: true,
    },
    logout_want_signed: IdpLogoutWantSigned {
        requests: true,
        responses: true,
    },
    default_session_duration: Duration::from_secs(3600),
    default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
    outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
    outbound_digest_algorithm: DigestAlgorithm::Sha256,
    outbound_c14n: C14nAlgorithm::ExclusiveCanonical,
    outbound_data_encryption_algorithm: DataEncryptionAlgorithm::Aes256Gcm,
    outbound_key_transport_algorithm: KeyTransportAlgorithm::RsaOaep,
})?;

// --- /saml/sso handler (HTTP-Redirect or HTTP-POST binding) ---
let sp = sp_registry.lookup_by_entity_id(&issuer_from_request)?;
let parsed = idp.consume_authn_request_wire(ConsumeAuthnRequestWire {
    sp: &sp,
    peer_crypto_policy: None,
    wire_body: request.raw_query.as_bytes(),
    binding: Binding::HttpRedirect,
    // Redirect RelayState comes from the signed query. `None` preserves it;
    // a separately supplied disagreement is rejected.
    relay_state: None,
    expected_destination: "https://idp.example.com/saml/sso", // URL this handler serves
    now: SystemTime::now(),
    clock_skew: Duration::from_secs(60),
})?;

// Authenticate the user out of band.
let user = authn::login(...)?;

let dispatch = idp.issue_response_with_artifact_transaction(IssueResponse {
    sp: &sp,
    in_response_to: &parsed,
    name_id: NameId::persistent_for_sp(&user.opaque_id, &sp.entity_id),
    attributes: vec![
        Attribute::email(&user.email),
        Attribute::display_name(&user.display_name),
    ],
    authn_instant: user.authenticated_at,
    session_index: format!("sess-{}", user.session_id),
    session_not_on_or_after: Some(SystemTime::now() + Duration::from_secs(3600)),
    authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
    force_encrypt_assertion: None,
    now: SystemTime::now(),
    assertion_lifetime: Duration::from_secs(300),
    subject_confirmation_lifetime: Duration::from_secs(300),
    holder_of_key_cert: None,
})?;

match dispatch {
    IssuedResponse::Post(form) => render_autosubmit(form),
    IssuedResponse::Artifact(art) => {
        let redirect = &art.redirect;
        // Persist both the opaque trust transaction (directly or via
        // transaction.seal(server_key)) and XML. The ARS must
        // atomically take/delete the pair only after consume_artifact_resolve
        // authenticates and replay-reserves the request.
        artifact_store.put_once(
            &redirect.artifact,
            art.transaction,
            &redirect.response_xml,
        )?;
        Redirect::to(redirect.redirect_to.as_str())
    }
}
```

For HTTP-Artifact dispatch, the IdP must advertise at least one indexed SOAP
`ArtifactResolutionService`. Issuance selects the default endpoint (falling
back to the first), and encodes that IdP ARS index in bytes 2–3 of the Type-4
artifact. The SP's ACS index is unrelated and is never placed there. `SourceID`
is the mandated SHA-1 of the issuing IdP's entity ID; the remaining 20-byte
message handle is random.

---

## 8. Security checks summary

The IdP role does the heaviest lifting in security-sensitive validation. Library hard-enforces; no opt-out:

| Check | Enforcement |
| --- | --- |
| AuthnRequest `Issuer` matches caller-supplied `SpDescriptor.entity_id` | Hard |
| `AssertionConsumerServiceURL` / `AssertionConsumerServiceIndex` validated against SP metadata | Hard |
| AuthnRequest signature when `want_authn_requests_signed` (per-SP OR global) | Hard |
| Response `InResponseTo` populated with AuthnRequest ID | Hard |
| Assertion `AudienceRestriction/Audience` = SP entity ID | Hard |
| `SubjectConfirmationData/Recipient` = ACS URL (resolved from registry) | Hard |
| Persistent NameID `SPNameQualifier` = SP entity ID | Hard |
| Assertion signed when `assertion_signing.sign_assertions` is true | Hard |
| Assertion encrypted when SP has encryption cert AND `encrypt_assertions_when_possible` | Soft (caller can force-override per-response) |
| Outbound signature algorithm is the configured `outbound_signature_algorithm` | Hard |
| Emitted AuthnContext satisfies the immutable requested policy | Hard |
| Encryption certificates match validation-time fingerprints when encryption is selected | Hard |
| Replay defense on AuthnRequest ID | Caller's job (library exposes `validated_request_id()`) |
