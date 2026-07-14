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
    /// ArtifactResolutionService endpoints.
    pub artifact_resolution: Vec<Endpoint>,

    pub supported_name_id_formats: Vec<NameIdFormat>,
    /// Default Format when the SP did not request one.
    pub default_name_id_format: NameIdFormat,

    /// Required — IdP must sign Responses and/or Assertions.
    pub signing_key: KeyPair,
    /// Optional — for decrypting EncryptedID / EncryptedAttribute on inbound
    /// AuthnRequest / LogoutRequest (rare in practice).
    pub decryption_key: Option<KeyPair>,

    /// If true, AuthnRequests from SPs must be signed.
    pub want_authn_requests_signed: bool,
    /// If true, the outbound Response root is signed.
    pub sign_responses: bool,
    /// If true, each outbound Assertion is signed.
    pub sign_assertions: bool,
    /// If true, encrypt Assertions when the SP has an encryption cert in metadata.
    pub encrypt_assertions_when_possible: bool,

    // --- SLO signing policy — independent of SSO policy. `want_authn_requests_signed`
    //     is an SSO-side knob and does NOT apply to LogoutRequest validation.

    /// If true, outbound LogoutRequest (proxy chain propagation) is signed.
    pub sign_logout_requests: bool,
    /// If true, outbound LogoutResponse is signed.
    pub sign_logout_responses: bool,
    /// If true, reject inbound LogoutRequest from SPs unless it carries a valid signature.
    pub want_logout_requests_signed: bool,
    /// If true, reject inbound LogoutResponse from SPs unless it carries a valid signature.
    pub want_logout_responses_signed: bool,

    pub default_session_duration: Duration,

    /// Default inbound crypto policy when a consume call does not provide a
    /// peer-specific override. Legacy SPs that require weak algorithms should
    /// be handled by passing a per-peer `PeerCryptoPolicy` on the consume input,
    /// not by weakening this default for every SP the IdP trusts.
    pub default_peer_crypto_policy: PeerCryptoPolicy,
    pub outbound_signature_algorithm: SignatureAlgorithm,             // default RsaSha256
    pub outbound_digest_algorithm: DigestAlgorithm,                   // default Sha256
    pub outbound_data_encryption_algorithm: DataEncryptionAlgorithm,  // default Aes256Gcm
    pub outbound_key_transport_algorithm: KeyTransportAlgorithm,      // default RsaOaep
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
    pub signature: &'a str,    // base64-encoded sig
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

### 2.1 Validation order

1. Decode the binding wire format (DEFLATE+base64 for Redirect, base64 for POST). Bound input size; reject if oversized.
2. Parse XML; hardening per RFC-002 §1.
3. Check the root element is `<samlp:AuthnRequest>`.
4. Check `Issuer` equals `input.sp.entity_id`. → `Error::IssuerMismatch`.
5. **Destination binding**: `expected_destination` MUST resolve to a registered SSO endpoint URL in `self.sso`. If not, `Error::InvalidConfiguration` (caller bug). Then if `AuthnRequest/@Destination` is present, it MUST equal `expected_destination`. → `Error::DestinationMismatch`.
5a. **ProtocolBinding sanity**: if `AuthnRequest/@ProtocolBinding` is present, it MUST map to a `SsoResponseBinding` (POST or Artifact). `HTTP-Redirect` and `SOAP` are illegal for Web Browser SSO Responses (SAML 2.0 Profiles §4.1.4) and are rejected here with `Error::IllegalResponseBinding { requested }`. This guards against malformed or malicious AuthnRequests asking the IdP to deliver the SSO Response over Redirect, which would bypass the embedded XML-Signature path the POST profile mandates.
6. **Signature check** (security-critical). Select `policy = input.peer_crypto_policy.unwrap_or(&self.default_peer_crypto_policy)`. Detached Redirect verification receives `policy.allowed_signature_algorithms`; embedded POST XML-DSig verification receives the complete policy so its signature, Reference-digest, and canonicalization allow-lists are all enforced:
   - If `self.want_authn_requests_signed` OR `input.sp.authn_requests_signed`:
     - For `Binding::HttpRedirect`: call `verify_detached_signature` (RFC-002 §3.3) over the canonical query string per spec §3.4.4.1, with `candidate_certs = input.sp.signing_certs` and `allowed_algorithms = policy.allowed_signature_algorithms`. → `Error::SignatureVerification` / `Error::DisallowedAlgorithm`.
     - For `Binding::HttpPost`: call `verify_signature` (RFC-002 §3) on the enveloped XML-DSig, with the same `candidate_certs` and the complete `policy`.
   - Else: signature optional; if present, verify with the same per-binding policy discipline; if absent, accept.
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

- **Replay defense on AuthnRequest ID**: optional; the threat is limited (no bearer credential is carried in AuthnRequest itself). The library exposes `parsed.id` for the caller to dedupe if desired.
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
}

impl IdentityProvider {
    pub fn issue_response(&self, input: IssueResponse<'_>) -> Result<SsoResponseDispatch, Error>;
}
```

### 3.1 Build steps

1. Resolve the ACS endpoint = `input.in_response_to.assertion_consumer_service` → `input.sp.acs_endpoint(...)`. Already validated at consume time; this is a re-lookup. Determines the destination URL and binding for the Dispatch.
2. Generate `response_id` and `assertion_id` = `"_"` + lowercase-hex(16 random bytes).
3. Build `<saml:Assertion>`:
   - `Issuer` = `self.entity_id`.
   - `Subject`:
     - `NameID` with format = `input.in_response_to.requested_name_id_format` if supported, else `self.default_name_id_format`.
     - For `NameIdFormat::Persistent`: set `SPNameQualifier` = `input.sp.entity_id` (privacy — prevents downstream SPs from correlating users).
     - `SubjectConfirmation @Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"` with:
       - `Recipient` = ACS URL (the one resolved in step 1).
       - `NotOnOrAfter` = `now + subject_confirmation_lifetime`.
       - `InResponseTo` = `input.in_response_to.id`.
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
4. If `self.sign_assertions`: sign the Assertion (RFC-002 §6) with the chosen outbound algorithm.
5. Build `<samlp:Response>`:
   - `Destination` = ACS URL.
   - `InResponseTo` = `input.in_response_to.id`.
   - `Issuer` = `self.entity_id`.
   - `Status/StatusCode @Value="urn:oasis:names:tc:SAML:2.0:status:Success"`.
   - Embed the Assertion. If
     - `force_encrypt_assertion == Some(true)`, OR
     - (`force_encrypt_assertion == None` AND `self.encrypt_assertions_when_possible` AND `input.sp.encryption_cert().is_some()`):
     wrap in `<saml:EncryptedAssertion>` (RFC-002 §7).
6. If `self.sign_responses`: sign the Response root.
7. Encode for the resolved-ACS-endpoint binding, which by §2.1 step 7a is consistent with `input.in_response_to.protocol_binding` whenever the latter was specified. The resolved binding is read off `input.in_response_to.assertion_consumer_service.binding` (a `SsoResponseBinding`).

Return `SsoResponseDispatch::Post` (most common) or `SsoResponseDispatch::Artifact`. The type system forbids returning a Redirect for an SSO Response.

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
    artifact_resolution: vec![],
    supported_name_id_formats: vec![NameIdFormat::Persistent, NameIdFormat::EmailAddress],
    default_name_id_format: NameIdFormat::Persistent,
    signing_key: KeyPair::from_pkcs8_pem(IDP_PRIV)?,
    decryption_key: None,
    want_authn_requests_signed: true,
    sign_responses: false,
    sign_assertions: true,
    encrypt_assertions_when_possible: true,
    sign_logout_requests: true,
    sign_logout_responses: true,
    want_logout_requests_signed: true,
    want_logout_responses_signed: true,
    default_session_duration: Duration::from_secs(3600),
    default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
    outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
    outbound_digest_algorithm: DigestAlgorithm::Sha256,
    outbound_data_encryption_algorithm: DataEncryptionAlgorithm::Aes256Gcm,
    outbound_key_transport_algorithm: KeyTransportAlgorithm::RsaOaep,
})?;

// --- /saml/sso handler (HTTP-Redirect or HTTP-POST binding) ---
let sp = sp_registry.lookup_by_entity_id(&issuer_from_request)?;
let parsed = idp.consume_authn_request(ConsumeAuthnRequest {
    sp: &sp,
    peer_crypto_policy: None,
    saml_request: &body.saml_request,
    binding: Binding::HttpRedirect,
    relay_state: query.relay_state.as_deref(),
    detached_signature: Some(DetachedSignature {
        signature: &query.signature,
        sig_alg: &query.sig_alg,
        raw_query_string: &request.raw_query,
    }),
    expected_destination: "https://idp.example.com/saml/sso", // URL this handler serves
    now: SystemTime::now(),
    clock_skew: Duration::from_secs(60),
})?;

// Authenticate the user out of band.
let user = authn::login(...)?;

let dispatch = idp.issue_response(IssueResponse {
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
})?;

match dispatch {
    SsoResponseDispatch::Post(form) => render_autosubmit(form),
    SsoResponseDispatch::Artifact(art) => {
        // 1. Persist `art.response_xml` keyed by `art.artifact` for later
        //    ArtifactResolutionService SOAP resolution.
        // 2. Redirect the user agent to `art.redirect_to`.
        artifact_store.put(&art.artifact, &art.response_xml)?;
        Redirect::to(art.redirect_to.as_str())
    }
}
```

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
| Assertion signed when `sign_assertions` is true | Hard |
| Assertion encrypted when SP has encryption cert AND `encrypt_assertions_when_possible` | Soft (caller can force-override per-response) |
| Outbound signature algorithm is the configured `outbound_signature_algorithm` | Hard |
| Replay defense on AuthnRequest ID | Caller's job (library exposes ID) |
