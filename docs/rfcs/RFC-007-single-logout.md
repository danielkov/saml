# RFC-007: Single Logout

**Status**: Draft
**Date**: 2026-05-26

## Summary

SAML 2.0 Single Logout (SLO) lets a user log out of all participating SPs in a single session. It is famously fragile in practice: front-channel SLO requires sequential browser redirects to N downstream SPs (each may fail, redirect mid-chain, or hang); back-channel SLO uses SOAP and avoids the UX problem but requires every SP to be reachable from the IdP at request time. The library implements the protocol mechanics for both bindings in both directions and explicitly leaves chain orchestration to the caller.

---

## 1. Message shapes

Two message types:

- `<samlp:LogoutRequest>` — initiator → target.
- `<samlp:LogoutResponse>` — target → initiator (echo).

Both are SAML protocol messages with the standard envelope: `ID`, `Version`, `IssueInstant`, optional `Destination`, `<saml:Issuer>`, optional `<ds:Signature>`. `<samlp:LogoutRequest>` additionally carries `<saml:NameID>` (or `<saml:EncryptedID>`) identifying the principal to log out, plus zero-or-more `<samlp:SessionIndex>` elements scoping which sessions to terminate.

---

## 2. SP-side flows

```rust
pub struct StartLogout<'a> {
    pub name_id: &'a NameId,
    pub session_index: Option<&'a str>,
    pub relay_state: Option<&'a str>,
    pub reason: Option<&'a str>,  // optional URI per spec
    pub binding: Binding,
}

pub struct LogoutDispatch {
    pub tracker: LogoutTracker,
    pub dispatch: Dispatch,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct LogoutTracker {
    pub request_id: String,
    pub issued_at: SystemTime,
    pub peer_entity_id: String,
}

impl ServiceProvider {
    /// SP initiates SLO toward an IdP.
    pub fn start_logout(
        &self,
        idp: &IdpDescriptor,
        opts: StartLogout<'_>,
    ) -> Result<LogoutDispatch, Error>;

    /// SP consumes the LogoutResponse from the IdP.
    pub fn consume_logout_response(
        &self,
        idp: &IdpDescriptor,
        peer_crypto_policy: Option<&PeerCryptoPolicy>,
        body: &[u8],
        binding: Binding,
        tracker: &LogoutTracker,
        /// SP SLO URL that received this LogoutResponse. Must be a registered
        /// SLO endpoint in `self.slo`; used to validate `Destination`.
        expected_destination: &str,
        now: SystemTime,
        clock_skew: Duration,
    ) -> Result<LogoutOutcome, Error>;

    /// SP receives a LogoutRequest from the IdP (IdP-initiated SLO).
    pub fn consume_logout_request(
        &self,
        idp: &IdpDescriptor,
        peer_crypto_policy: Option<&PeerCryptoPolicy>,
        body: &[u8],
        binding: Binding,
        /// SP SLO URL that received this LogoutRequest.
        expected_destination: &str,
        now: SystemTime,
        clock_skew: Duration,
    ) -> Result<ParsedLogoutRequest, Error>;

    /// SP echoes a LogoutResponse to the IdP after terminating the local session.
    pub fn build_logout_response(
        &self,
        idp: &IdpDescriptor,
        in_response_to: &ParsedLogoutRequest,
        status: LogoutStatus,
        relay_state: Option<&str>,
        binding: Binding,
    ) -> Result<Dispatch, Error>;

    /// SP sends a LogoutRequest over the SOAP binding and waits synchronously
    /// for the LogoutResponse. Used for back-channel SLO.
    pub async fn send_soap_logout_request<H: HttpClient>(
        &self,
        http: &H,
        idp: &IdpDescriptor,
        peer_crypto_policy: Option<&PeerCryptoPolicy>,
        opts: StartLogout<'_>,
    ) -> Result<LogoutOutcome, Error>;
}
```

---

## 3. IdP-side flows

Mirror image:

```rust
impl IdentityProvider {
    /// IdP receives a LogoutRequest from an SP.
    pub fn consume_logout_request(
        &self,
        sp: &SpDescriptor,
        peer_crypto_policy: Option<&PeerCryptoPolicy>,
        body: &[u8],
        binding: Binding,
        /// IdP SLO URL that received this LogoutRequest.
        expected_destination: &str,
        now: SystemTime,
        clock_skew: Duration,
    ) -> Result<ParsedLogoutRequest, Error>;

    /// IdP echoes a LogoutResponse to the SP.
    pub fn build_logout_response(
        &self,
        sp: &SpDescriptor,
        in_response_to: &ParsedLogoutRequest,
        status: LogoutStatus,
        relay_state: Option<&str>,
        binding: Binding,
    ) -> Result<Dispatch, Error>;

    /// IdP initiates SLO toward an SP (typically for chain propagation).
    pub fn start_logout(
        &self,
        sp: &SpDescriptor,
        opts: StartLogout<'_>,
    ) -> Result<LogoutDispatch, Error>;

    /// IdP consumes a LogoutResponse from an SP.
    pub fn consume_logout_response(
        &self,
        sp: &SpDescriptor,
        peer_crypto_policy: Option<&PeerCryptoPolicy>,
        body: &[u8],
        binding: Binding,
        tracker: &LogoutTracker,
        /// IdP SLO URL that received this LogoutResponse.
        expected_destination: &str,
        now: SystemTime,
        clock_skew: Duration,
    ) -> Result<LogoutOutcome, Error>;

    /// IdP sends a LogoutRequest over the SOAP binding (back-channel SLO).
    pub async fn send_soap_logout_request<H: HttpClient>(
        &self,
        http: &H,
        sp: &SpDescriptor,
        peer_crypto_policy: Option<&PeerCryptoPolicy>,
        opts: StartLogout<'_>,
    ) -> Result<LogoutOutcome, Error>;
}
```

---

## 4. Parsed types

```rust
pub struct ParsedLogoutRequest {
    pub id: String,
    pub issuer: String,
    pub issue_instant: SystemTime,
    pub destination: Option<String>,
    pub not_on_or_after: Option<SystemTime>,
    pub reason: Option<String>,
    pub name_id: NameId,
    pub session_index: Vec<String>,  // schema allows zero or more
    pub relay_state: Option<String>,
}

pub enum LogoutStatus {
    Success,
    PartialLogout,
    RequestDenied,
    Requester,
    Responder,
}

pub enum LogoutOutcome {
    Success,
    PartialLogout { message: Option<String> },
    Failure { status: String, message: Option<String> },
}
```

---

## 5. Validation rules

SLO signature policy uses dedicated config knobs (`sign_logout_requests`, `sign_logout_responses`, `want_logout_requests_signed`, `want_logout_responses_signed` on both `ServiceProviderConfig` and `IdentityProviderConfig`). It is **not** derived from `want_authn_requests_signed` or `want_response_signed` / `want_assertions_signed`; the same process can legitimately want signed assertions but tolerate unsigned LogoutResponses (or any other mix), and conflating the policies would couple unrelated decisions and create silent acceptance of unsigned logout messages.

### 5.1 LogoutRequest (both directions)

1. XML parse, hardening per RFC-002 §1.
2. Decode binding wire format (DEFLATE+base64 for Redirect, base64 for POST, SOAP envelope unwrap for SOAP).
3. `Issuer` matches the peer's EntityID. → `Error::IssuerMismatch`.
4. **Destination binding**: `expected_destination` MUST resolve to a registered SLO endpoint URL in our `slo` list. If not, `Error::InvalidConfiguration` (caller bug). Then if `LogoutRequest/@Destination` is present, it MUST equal `expected_destination`. → `Error::DestinationMismatch`.
5. **Signature**. Select `policy = peer_crypto_policy.unwrap_or(&self.default_peer_crypto_policy)`. Detached Redirect signatures go through `verify_detached_signature` (RFC-002 §3.3) with `policy.allowed_signature_algorithms`; embedded POST/SOAP XML-DSig signatures go through `verify_signature` (RFC-002 §3) with the complete policy so Reference-digest and canonicalization allow-lists are enforced too.
   - If `self.want_logout_requests_signed` is true: a valid signature is required.
     - For `Binding::HttpRedirect`: detached query-string signature, verified via `verify_detached_signature` with `candidate_certs = peer.signing_certs`, `allowed_algorithms = policy.allowed_signature_algorithms`.
     - For `Binding::HttpPost` / `Binding::Soap`: enveloped XML-DSig, verified via `verify_signature` with the complete `policy`.
     - Missing signature → `Error::SignatureMissing`. Invalid signature → `Error::SignatureVerification`. Algorithm outside allow-list → `Error::DisallowedAlgorithm`.
   - If `self.want_logout_requests_signed` is false: a signature is optional; if present it MUST verify under the same per-binding policy discipline; if absent the message is accepted.
   - The SSO flags (`want_authn_requests_signed`, `want_response_signed`, `want_assertions_signed`) are not consulted here.
6. `NotOnOrAfter`, if present, > `now - clock_skew`. → `Error::Expired`.

### 5.2 LogoutResponse

1. XML parse, hardening.
2. Decode binding wire format.
3. `Issuer` matches the peer's EntityID.
4. **Destination binding**: same rule as §5.1 step 4.
5. **Signature**: select the effective peer policy the same way as §5.1 step 5, then use the same per-binding dispatch: `verify_detached_signature` receives `policy.allowed_signature_algorithms` for Redirect, while `verify_signature` receives the complete policy for POST/SOAP. The requirement is gated on `self.want_logout_responses_signed`.
6. `InResponseTo` matches `tracker.request_id`. → `Error::InResponseToMismatch`.
7. `Status/StatusCode @Value` mapped to `LogoutOutcome`:
   - `urn:oasis:names:tc:SAML:2.0:status:Success` → `LogoutOutcome::Success`.
   - `urn:oasis:names:tc:SAML:2.0:status:PartialLogout` → `LogoutOutcome::PartialLogout`.
   - Anything else → `LogoutOutcome::Failure`.

### 5.3 Outbound signing

- LogoutRequest is signed iff `self.sign_logout_requests` is true.
- LogoutResponse is signed iff `self.sign_logout_responses` is true.
- Signing key is `self.signing_key`; algorithm is the role's `outbound_signature_algorithm`; digest is `outbound_digest_algorithm`; canonicalization is Exclusive C14N. Both `ServiceProviderConfig` and `IdentityProviderConfig` define these outbound fields.
- For `Binding::HttpRedirect`, the signature is detached (query-string `Signature` + `SigAlg`); for `Binding::HttpPost` and `Binding::Soap`, the signature is embedded via XML-DSig.
- `send_soap_logout_request` sends outbound XML and then consumes the SOAP LogoutResponse internally, so it takes the same optional `peer_crypto_policy` as `consume_logout_response`; otherwise back-channel SLO would silently fall back to the role default for peer verification.

---

## 6. Front-channel vs back-channel

| Property | Front-channel (Redirect / POST) | Back-channel (SOAP) |
| --- | --- | --- |
| Browser involvement | Yes — user visits each SLO endpoint via redirect / form POST | No — server-to-server HTTP |
| UX impact | Visible chain of redirects; failure modes are visible to the user | Invisible |
| Failure handling | Caller must drive the chain state machine, handle redirects mid-flow, time out hung SPs | Simple request/response; failures returned synchronously |
| Reachability | Each SP must be reachable from the user's browser | Each SP must be reachable from the IdP at request time |
| Typical use | User-initiated logout from a single SP | Proxy SLO chain propagation; admin-initiated session revocation |

The library provides the same protocol primitives for both. Back-channel SLO uses `send_soap_logout_request` which goes through the `HttpClient` trait; front-channel SLO uses the regular `Dispatch` return type and the caller's web framework dispatches it.

---

## 7. Proxy SLO

Proxy SLO is the worst-case SAML flow. The library does not orchestrate the chain; it provides the building blocks:

```rust
// 1. SP-A sends LogoutRequest to proxy (proxy acts as IdP toward SP-A).
let req_from_a = idp.consume_logout_request(
    &sp_a,
    None,
    &body,
    Binding::HttpPost,
    "https://hub.example.com/saml/slo", // the URL this handler serves
    now,
    clock_skew,
)?;

// 2. Proxy queries its session registry: which SPs are in the same upstream
//    session as the principal in `req_from_a`?
//    Answer: SP-B, SP-C (caller-managed state).
let other_sps_in_session = session_registry.peers_of(&req_from_a.name_id, &req_from_a.session_index)?;

// 3. Proxy propagates to SP-B and SP-C via SOAP back-channel (no UX).
let outcomes: Vec<LogoutOutcome> = future::join_all(other_sps_in_session.iter().map(|sp_descriptor| {
    idp.send_soap_logout_request(
        &http,
        sp_descriptor,
        None,
        StartLogout {
            name_id: &req_from_a.name_id,
            session_index: req_from_a.session_index.first().map(String::as_str),
            relay_state: None,
            reason: None,
            binding: Binding::Soap,
        },
    )
})).await;

// 4. Proxy propagates to upstream IdP (the one that originally authenticated this session).
let upstream_outcome = sp.send_soap_logout_request(
    &http,
    &upstream_idp_descriptor,
    None,
    StartLogout {
        name_id: &req_from_a.name_id,
        session_index: Some(&upstream_session_index),
        relay_state: None,
        reason: None,
        binding: Binding::Soap,
    },
).await?;

// 5. Proxy echoes LogoutResponse back to SP-A.
let all_succeeded = outcomes.iter().all(|o| matches!(o, Ok(LogoutOutcome::Success)))
    && matches!(upstream_outcome, LogoutOutcome::Success);
let echo = idp.build_logout_response(
    &sp_a,
    &req_from_a,
    if all_succeeded { LogoutStatus::Success } else { LogoutStatus::PartialLogout },
    None,
    Binding::HttpPost,
)?;
```

The session registry, the chain loop, the retry policy, and the partial-failure handling all live in the caller. The library guarantees each protocol message is correctly built and validated.

---

## 8. Front-channel chain hooks

For callers who do want to drive a front-channel SLO chain (sequential redirects through downstream SPs), the library provides a small state-machine helper:

```rust
pub struct FrontChannelChain {
    /// Ordered list of (SP descriptor, NameID, session_index) tuples.
    pub targets: Vec<FrontChannelTarget>,
    pub state: FrontChannelState,
}

pub struct FrontChannelTarget {
    pub sp: SpDescriptor,
    pub peer_crypto_policy: Option<PeerCryptoPolicy>,
    pub name_id: NameId,
    pub session_index: Option<String>,
}

pub enum FrontChannelState {
    /// Next target to redirect to. Caller dispatches `next_dispatch`, then
    /// when that SP's LogoutResponse arrives, calls `chain.advance(response)`.
    NextTarget { index: usize, next_dispatch: Dispatch, tracker: LogoutTracker },
    /// Chain complete. `outcomes` parallels `targets`.
    Done { outcomes: Vec<Result<LogoutOutcome, Error>> },
}

impl FrontChannelChain {
    pub fn start(idp: &IdentityProvider, targets: Vec<FrontChannelTarget>) -> Result<Self, Error>;
    pub fn advance(
        &mut self,
        idp: &IdentityProvider,
        logout_response_body: &[u8],
        binding: Binding,
        now: SystemTime,
        clock_skew: Duration,
    ) -> Result<(), Error>;
}
```

The state machine is held in caller-side storage (typically a server-side session keyed by chain ID) and advanced as each downstream SP returns its `LogoutResponse`. `advance` verifies each response with that target's `peer_crypto_policy` when present, otherwise the IdP role default. The caller decides on timeout / give-up behavior.

This is opt-in; back-channel SOAP propagation is recommended where available.

---

## 9. Out-of-scope for v0.1.0

- Asynchronous queue-based out-of-process SLO propagation. Caller drives it via whichever message queue infrastructure they already operate.
- `LogoutNotification` (a non-standard extension some federations use).
- Name Identifier Management Service Protocol (separate spec entirely).
- Push notification of session termination outside of SLO (proprietary; usually a vendor REST API).
