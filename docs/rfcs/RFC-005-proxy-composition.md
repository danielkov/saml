# RFC-005: Proxy composition

**Status**: Draft
**Date**: 2026-05-26

## Summary

An identity proxy is a SAML entity that acts as an SP toward one set of IdPs and as an IdP toward another set of SPs. It bridges federations, normalizes attribute schemas, brokers between customer IdPs and SaaS apps, and acts as a federation hub.

The crate models proxy as **composition rather than a distinct role**: a `Proxy` borrows one `ServiceProvider` and one `IdentityProvider` plus exposes helpers to carry context across the round-trip statelessly. Library users can also build proxies without `Proxy` by wiring `ServiceProvider` and `IdentityProvider` themselves — `Proxy` is convenience, not gatekeeping.

---

## 1. Threat model

A proxy holds signing keys that mint identity for downstream SPs. Compromise of a proxy's IdP-side signing key = total compromise of every downstream SP that trusts the proxy. Therefore:

- The proxy must not silently accept weaker authentication from upstream than the downstream SP requested.
- The proxy must not echo SP-supplied URLs without validation (open redirect → assertion exfiltration).
- The proxy must scope persistent NameIDs per downstream SP (privacy: prevents downstream SPs from correlating users).
- The proxy must not leak upstream attributes to downstream SPs without filtering (data-minimization / GDPR / regulatory).

The library enforces the first two structurally (via RFC-003 and RFC-004 enforcement, inherited). The latter two are policy hooks with safe defaults — the API requires the caller to provide an explicit policy; the built-in `ReleaseNone` and `PersistentPerSpHmac` give safe starting points.

---

## 2. Proxy type

```rust
pub struct Proxy<'a> {
    sp: &'a ServiceProvider,
    idp: &'a IdentityProvider,
    context_codec: Box<dyn ProxyContextCodec>,
}

impl<'a> Proxy<'a> {
    pub fn new(
        sp: &'a ServiceProvider,
        idp: &'a IdentityProvider,
        context_codec: Box<dyn ProxyContextCodec>,
    ) -> Self;

    pub fn sp(&self) -> &ServiceProvider { self.sp }
    pub fn idp(&self) -> &IdentityProvider { self.idp }
}
```

`ProxyContextCodec` is a caller-supplied AEAD wrapper for the stateless context blob carried in `RelayState` across the upstream round-trip:

```rust
pub trait ProxyContextCodec: Send + Sync {
    fn encode(&self, context: &ProxyContext) -> Result<String, Error>;
    fn decode(&self, blob: &str) -> Result<ProxyContext, Error>;
}

pub struct Aes256GcmCodec {
    key: [u8; 32],
    /// Reject context blobs older than this. Default 10 minutes.
    pub max_age: Duration,
}

impl Aes256GcmCodec {
    pub fn new(key: [u8; 32]) -> Self;
    pub fn with_max_age(self, max_age: Duration) -> Self;
}

impl ProxyContextCodec for Aes256GcmCodec { /* ... */ }
```

The default implementation uses AES-256-GCM with a caller-supplied 32-byte key. The wire format is `base64url(nonce_12 || ciphertext || tag_16)` where the plaintext is the bincode-serialized `ProxyContext`. Callers can plug HMAC-only, signed-JWT-style, or HSM-backed codecs by implementing the trait.

### 2.1 Codec choice and RelayState size

The HTTP-POST binding has no practical size limit on `RelayState` (the form field is just an HTTP body parameter; SAML 2.0 §3.5.3 sets no upper bound for that binding). The HTTP-Redirect binding, however, fits everything in a URL — and **SAML 2.0 §3.4.3 specifies `RelayState` MUST NOT exceed 80 bytes** on this binding. Many IdPs enforce this at the byte level and silently truncate or reject longer values, and intermediate proxies / WAFs may truncate URLs anyway.

A bincode-serialized `ProxyContext` carrying the upstream tracker, the downstream request ID, the ACS endpoint, the requested AuthnContext, and the issued-at timestamp easily exceeds 80 bytes even before AEAD framing (12-byte nonce + 16-byte tag + base64url overhead pushes a "small" plaintext past the limit). `Aes256GcmCodec` is therefore appropriate for the POST binding outbound but unreliable for Redirect.

For Redirect-binding proxies, use `OpaqueHandleCodec`: a short random handle is the `RelayState`, and the actual context lives in a caller-supplied store keyed by that handle.

```rust
pub trait ProxyContextStore: Send + Sync {
    fn put(&self, handle: &str, context: &ProxyContext, ttl: Duration) -> Result<(), Error>;
    fn take(&self, handle: &str) -> Result<Option<ProxyContext>, Error>;
}

pub struct OpaqueHandleCodec<S: ProxyContextStore> {
    pub store: S,
    /// Bytes of entropy in the handle. Default 24 → 32 base64url chars,
    /// well under the 80-byte RelayState ceiling.
    pub handle_byte_len: usize,
    pub ttl: Duration,
}

impl<S: ProxyContextStore> ProxyContextCodec for OpaqueHandleCodec<S> {
    fn encode(&self, context: &ProxyContext) -> Result<String, Error> {
        let mut bytes = vec![0u8; self.handle_byte_len];
        rand::rng().fill_bytes(&mut bytes);
        let handle = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
        self.store.put(&handle, context, self.ttl)?;
        Ok(handle)
    }

    fn decode(&self, blob: &str) -> Result<ProxyContext, Error> {
        self.store.take(blob)?.ok_or(Error::InvalidConfiguration {
            reason: "proxy context not found (expired or replay)",
        })
    }
}
```

This trades the "fully stateless" promise for spec-compliant `RelayState` size. The trade is localized: only the proxy uses the store; SP and IdP roles remain stateless. Typical `ProxyContextStore` implementations are a Redis hash with `EXPIRE`, a database table with `expires_at`, or an in-memory `Mutex<HashMap>` for single-instance deployments. `take` semantics (one-shot consumption) double as replay defense for the proxy round-trip.

| Outbound upstream binding | Recommended codec | Notes |
| --- | --- | --- |
| `HttpPost` | `Aes256GcmCodec` | Stateless, no caller-side store. |
| `HttpRedirect` | `OpaqueHandleCodec` | 80-byte `RelayState` ceiling. |

Custom codecs (signed-JWT, KMS envelope encryption, HSM-backed) implement `ProxyContextCodec` directly.

---

## 3. ProxyContext

The opaque context carried across the upstream round-trip:

```rust
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxyContext {
    /// AuthnRequest ID we received from the downstream SP.
    pub downstream_request_id: String,
    /// Downstream SP's entity ID.
    pub downstream_sp_entity_id: String,
    /// Downstream SP's ACS endpoint (resolved at consume time).
    pub downstream_acs: Endpoint,
    /// Downstream SP's RelayState (if any), preserved for end-to-end propagation.
    pub downstream_relay_state: Option<String>,
    /// What the downstream requested. Preserved for non-downgrade enforcement.
    pub requested_authn_context: Option<RequestedAuthnContext>,
    pub requested_name_id_format: Option<NameIdFormat>,
    /// Upstream LoginTracker, stashed inside the context to avoid
    /// requiring `allow_unsolicited` on the SP side.
    pub upstream_tracker: LoginTracker,
    /// Issued-at timestamp. Used for context-blob age-limit enforcement
    /// by `ProxyContextCodec::decode`.
    pub issued_at: SystemTime,
}
```

Statelessness: the entire downstream round-trip state lives inside this blob. No proxy-side session store is required.

---

## 4. Flow

```
                                 ┌────────────┐
       downstream SP             │            │             upstream IdP
   AuthnRequest                  │   Proxy    │       AuthnRequest
   ───────────────────────────►  │            │  ───────────────────────────►
                                 │  acts as   │
                                 │   IdP ↑    │
                                 │   SP  ↓    │
                                 │            │
   ◄──────────── Response        │            │       Response  ◄─────────────
                                 └────────────┘
```

### 4.1 Bounce to upstream

```rust
pub struct BounceToUpstream<'a> {
    pub upstream_idp: &'a IdpDescriptor,
    pub downstream_request: &'a ParsedAuthnRequest,
    /// If true, propagate downstream's `ForceAuthn` / `IsPassive` upward.
    pub propagate_request_flags: bool,
    /// If true, propagate downstream's `RequestedAuthnContext` upward (recommended).
    pub propagate_authn_context: bool,
    /// If true, propagate downstream's `NameIDPolicy` upward.
    pub propagate_name_id_policy: bool,
    pub upstream_binding: Binding,
    pub now: SystemTime,
}

pub struct BounceResult {
    pub dispatch: Dispatch,
    /// Encoded context to inject as RelayState on the upstream redirect.
    /// Already URL-safe; callers serve it as-is.
    pub upstream_relay_state: String,
}

impl<'a> Proxy<'a> {
    pub fn bounce_to_upstream(
        &self,
        input: BounceToUpstream<'_>,
    ) -> Result<BounceResult, Error>;
}
```

Internally:

1. Build a `StartLogin` for the upstream IdP, propagating flags per `input`.
2. Call `self.sp.start_login(input.upstream_idp, ...)`.
3. Stash the returned `LoginTracker` inside `ProxyContext`.
4. Encode the `ProxyContext` via the codec → `upstream_relay_state`.
5. Return `BounceResult { dispatch, upstream_relay_state }`.

### 4.2 Relay to downstream

```rust
pub struct RelayToDownstream<'a> {
    pub context: &'a ProxyContext,
    pub upstream_identity: &'a Identity,
    /// Pluggable: which upstream attributes to release downstream, possibly
    /// rewritten / renamed.
    pub attribute_release: &'a dyn AttributeReleasePolicy,
    /// Pluggable: how to mint a NameID for the downstream SP from the upstream subject.
    pub name_id_transform: &'a dyn NameIdTransform,
    /// If true, set downstream AuthnContextClassRef = upstream's actual.
    /// If false, use the proxy's default policy (typically `PasswordProtectedTransport`).
    pub passthrough_authn_context: bool,
    pub now: SystemTime,
    pub session_lifetime: Duration,
    pub subject_confirmation_lifetime: Duration,
}

impl<'a> Proxy<'a> {
    pub fn relay_to_downstream(
        &self,
        input: RelayToDownstream<'_>,
    ) -> Result<SsoResponseDispatch, Error>;
}
```

Internally:

1. Look up the downstream SP descriptor by `context.downstream_sp_entity_id`. (Caller-managed registry; the library does not maintain one.) For ergonomics, the caller can pass a closure for SP lookup via `ProxyConfig` (future addition).
2. **Enforce AuthnContext non-downgrade** (§7) using `context.requested_authn_context` and `upstream_identity.authn_context_class_ref`. → `Error::AuthnContextDowngrade`.
3. Compute downstream attributes via `attribute_release.release(&upstream_identity.attributes, &downstream_sp)`.
4. Compute downstream NameID via `name_id_transform.transform(&upstream_identity.name_id, &downstream_sp)`.
5. Build a synthetic `ParsedAuthnRequest` from `context` (with `in_response_to: context.downstream_request_id`).
6. Call `self.idp.issue_response(...)` with the synthesized request and transformed identity.
7. Return the resulting `Dispatch`.

---

## 5. Attribute release policy

```rust
pub trait AttributeReleasePolicy: Send + Sync {
    /// Given the upstream attributes and the downstream SP, return the attributes
    /// to release downstream (possibly renamed, filtered, transformed).
    fn release(
        &self,
        upstream: &[Attribute],
        downstream_sp: &SpDescriptor,
    ) -> Vec<Attribute>;
}

/// Built-in: release nothing. Safest default; force the caller to opt-in.
pub struct ReleaseNone;

/// Built-in: release only attributes whose name matches the allow-list.
pub struct ReleaseAllowList {
    pub names: Vec<String>,
}

/// Built-in: release all attributes. For development only; logs a warning if
/// the `tracing` feature is enabled.
pub struct ReleaseAll;

/// Built-in: per-SP allow-list. Different attribute sets for different downstream
/// SPs, looked up by entity ID.
pub struct ReleasePerSp {
    pub allow_lists: std::collections::HashMap<String, Vec<String>>,
    pub default: Box<dyn AttributeReleasePolicy>,
}
```

Custom policies — for example, attribute renaming per downstream SP, or eduPerson schema normalization — are implemented by the caller as additional types.

---

## 6. NameID transformation

```rust
pub trait NameIdTransform: Send + Sync {
    fn transform(
        &self,
        upstream_subject: &NameId,
        downstream_sp: &SpDescriptor,
    ) -> Result<NameId, Error>;
}

/// Built-in: HMAC-SHA256 of (upstream_subject_value || downstream_sp_entity_id),
/// base64url-encoded. Produces an SP-scoped persistent ID that the downstream SP
/// cannot correlate with other SPs.
pub struct PersistentPerSpHmac {
    pub key: [u8; 32],
    pub format: NameIdFormat,  // typically Persistent
}

/// Built-in: passthrough — use the upstream subject verbatim.
/// Only use when proxy and downstream share a trust boundary (e.g., internal apps).
pub struct PassThroughNameId;

/// Built-in: replace with an attribute lifted from upstream `Identity.attributes`.
/// Useful when downstream SPs expect an email-format NameID and the upstream
/// IdP returns a separate `email` attribute.
pub struct NameIdFromAttribute {
    pub attribute_name: String,
    pub format: NameIdFormat,
}

/// Built-in: per-SP format selection. Different downstream SPs get different
/// NameID formats based on their declared `supported_name_id_formats`.
pub struct PerSpFormat {
    pub inner: Box<dyn NameIdTransform>,
}
```

---

## 7. AuthnContext non-downgrade

If `context.requested_authn_context` requested `MultiFactorAuth` and `upstream_identity.authn_context_class_ref` is `PasswordProtectedTransport`, the proxy must reject — silently downgrading authentication strength is a transitive trust violation.

Built into `relay_to_downstream` as:

```rust
pub(crate) fn enforce_authn_context_floor(
    requested: &RequestedAuthnContext,
    actual: Option<&str>,
) -> Result<(), Error>;
```

Comparison rules per SAML 2.0 §3.3.2.2.1 (`Comparison` attribute: `exact` / `minimum` / `maximum` / `better`). Default is `exact`. The library exposes the comparator function and accepts a caller override for non-standard hierarchies (some enterprise IdPs define custom AuthnContext class hierarchies).

```rust
pub trait AuthnContextComparator: Send + Sync {
    fn satisfies(&self, requested: &str, actual: &str) -> bool;
}

pub struct StandardComparator;  // built-in: exact + minimum + better per spec
```

---

## 8. What is NOT in `Proxy`

Explicitly punted to the caller:

- **Session registry** mapping upstream → downstream sessions (for SLO chain propagation). The library exposes session indices and request IDs; the caller stores the graph.
- **SLO chain orchestration loop**. Iterating through N downstream SPs via sequential browser redirects is a state-machine + UX problem, not a protocol problem. Library provides the primitives (`build LogoutRequest`, `parse LogoutResponse`) and a hook to drive the chain; the loop lives in the caller. Backchannel SOAP SLO is fully supported because it's just request/response.
- **Discovery** (when the proxy fronts multiple upstream IdPs). The caller picks the IdP before calling `bounce_to_upstream`.
- **Caching** of `IdpDescriptor` / `SpDescriptor` across requests. The library parses metadata XML on demand; whether the caller caches the parse result is up to them.
- **SP / IdP registry lookup** by entity ID. The caller maintains the registry and looks up by `context.downstream_sp_entity_id`.

---

## 9. Example

```rust
// Upstream redirect binding ⇒ use OpaqueHandleCodec (80-byte RelayState ceiling).
// For POST-bound upstreams, swap in Aes256GcmCodec for a fully stateless proxy.
let proxy = Proxy::new(
    &sp,
    &idp,
    Box::new(OpaqueHandleCodec {
        store: redis_store,
        handle_byte_len: 24,
        ttl: Duration::from_secs(600),
    }),
);

// --- /saml/sso handler (downstream SP → proxy) ---
let downstream_sp = sp_registry.lookup_by_entity_id(&issuer)?;
let parsed = idp.consume_authn_request(ConsumeAuthnRequest {
    sp: &downstream_sp,
    peer_crypto_policy: None,
    saml_request: &body.saml_request,
    binding: Binding::HttpPost,
    relay_state: form.relay_state.as_deref(),
    detached_signature: None,
    expected_destination: "https://hub.example.com/saml/sso", // proxy SSO URL this handler serves
    now: SystemTime::now(),
    clock_skew: Duration::from_secs(60),
})?;

let bounce = proxy.bounce_to_upstream(BounceToUpstream {
    upstream_idp: &upstream_idp_descriptor,
    downstream_request: &parsed,
    propagate_request_flags: true,
    propagate_authn_context: true,
    propagate_name_id_policy: true,
    upstream_binding: Binding::HttpRedirect,
    now: SystemTime::now(),
})?;
// Dispatch to upstream IdP, with `bounce.upstream_relay_state` injected as the
// RelayState query/form parameter. Carries downstream context across the round-trip.

// --- /saml/acs handler (upstream IdP → proxy) ---
let context: ProxyContext = proxy.context_codec().decode(&form.relay_state)?;
let upstream_identity = sp.consume_response(ConsumeResponse {
    idp: &upstream_idp_descriptor,
    peer_crypto_policy: None,
    saml_response: &form.saml_response,
    binding: SsoResponseBinding::HttpPost,
    relay_state: Some(&form.relay_state),
    tracker: Some(&context.upstream_tracker),
    expected_destination: "https://hub.example.com/saml/acs", // proxy ACS URL this handler serves
    now: SystemTime::now(),
    clock_skew: Duration::from_secs(60),
})?;

let dispatch = proxy.relay_to_downstream(RelayToDownstream {
    context: &context,
    upstream_identity: &upstream_identity,
    attribute_release: &ReleaseAllowList {
        names: vec!["email".into(), "displayName".into(), "groups".into()],
    },
    name_id_transform: &PersistentPerSpHmac {
        key: NAME_ID_HMAC_KEY,
        format: NameIdFormat::Persistent,
    },
    passthrough_authn_context: true,
    now: SystemTime::now(),
    session_lifetime: Duration::from_secs(3600),
    subject_confirmation_lifetime: Duration::from_secs(300),
})?;

match dispatch {
    SsoResponseDispatch::Post(form) => render_autosubmit(form),  // back to downstream SP's ACS
    SsoResponseDispatch::Artifact(art) => {
        artifact_store.put(&art.artifact, &art.response_xml)?;
        Redirect::to(art.redirect_to.as_str())
    }
}
```

---

## 10. Security checks summary

| Check | Enforcement |
| --- | --- |
| Downstream `Issuer` matches a known `SpDescriptor` | Hard (via IdP role) |
| Downstream `AssertionConsumerServiceURL` validated against SP metadata | Hard (via IdP role) |
| Upstream `Destination` / `Issuer` / `InResponseTo` checks | Hard (via SP role) |
| Upstream signature verified | Hard (via SP role) |
| AuthnContext non-downgrade | Hard (Proxy enforces in `relay_to_downstream`) |
| NameID scoped per downstream SP | Soft — caller chooses transform (`PersistentPerSpHmac` is the recommended built-in) |
| Attribute release filtered | Soft — caller chooses policy (`ReleaseNone` is the default-safe built-in) |
| ProxyContext authenticity | Hard via codec — AEAD for `Aes256GcmCodec`, one-shot lookup + TTL for `OpaqueHandleCodec`. |
| ProxyContext max-age | Hard (codec rejects expired blobs / handles). |
| Proxy-round-trip replay defense | `OpaqueHandleCodec.take` is one-shot; `Aes256GcmCodec` relies on `max_age` (caller can layer an external replay store if a shorter window is needed). |
