# RFC-005: Proxy composition

**Status**: Draft
**Date**: 2026-05-26

## Summary

An identity proxy is a SAML entity that acts as an SP toward one set of IdPs and as an IdP toward another set of SPs. It bridges federations, normalizes attribute schemas, brokers between customer IdPs and SaaS apps, and acts as a federation hub.

The crate models proxy as **composition rather than a distinct role**: a `Proxy` borrows one `ServiceProvider` and one `IdentityProvider` and exposes helpers to carry authenticated context across the upstream round-trip. `Aes256GcmCodec` carries that state in a client token; `OpaqueHandleCodec` keeps it in a server-side store. Library users can also build proxies without `Proxy` by wiring `ServiceProvider` and `IdentityProvider` themselves — `Proxy` is convenience, not gatekeeping.

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
    instance: ProxyInstance,
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

`ProxyContextCodec` authenticates the context represented by `RelayState`. The built-in AEAD codec carries it in the token; the opaque-handle codec authenticates it through a server-side lookup:

```rust
pub trait ProxyContextCodec: Send + Sync {
    /// Takes a crate-issued `SealingGrant`, not a bare payload — see below.
    fn encode(&self, grant: &SealingGrant<'_>) -> Result<String, Error>;
    fn decode(&self, blob: &str) -> Result<ProxyContextPayload, Error>;
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

The codec deals in `ProxyContextPayload`: a transparent `Serialize`/`Deserialize` struct with public fields, so callers can implement their own codec. It carries no authority on its own.

`Proxy::relay_to_downstream` instead requires an `UpstreamFlow`, obtainable only from `Proxy::consume_upstream_response`, which authenticates the relay token and validates the upstream Response against *that context's* tracker in one step and records the `Proxy` instance that did so. `ProxyContext` — an opaque wrapper with no public constructor, no public fields and no `Deserialize` impl — is what the codec's authentication yields, via `Proxy::decode_context`. The split exists because relay mints a *signed* downstream assertion from the context: every check it performs reads the context, so a caller-supplied one would mean comparing caller-controlled input against caller-supplied metadata and then signing the result. An authentic identity could otherwise be paired with an invented context naming any registered SP and ACS.

The built-in AEAD implementation uses AES-256-GCM with a caller-supplied 32-byte key. The wire format is `base64url(nonce_12 || ciphertext || tag_16)` where the plaintext is the postcard-serialized `ProxyContextPayload`. Callers can plug HMAC-only, signed-JWT-style, or HSM-backed codecs by implementing the trait.

### 2.1 Codec choice and RelayState size

The HTTP-POST binding has no practical size limit on `RelayState` (the form field is just an HTTP body parameter; SAML 2.0 §3.5.3 sets no upper bound for that binding). The HTTP-Redirect binding, however, fits everything in a URL — and **SAML 2.0 §3.4.3 specifies `RelayState` MUST NOT exceed 80 bytes** on this binding. Many IdPs enforce this at the byte level and silently truncate or reject longer values, and intermediate proxies / WAFs may truncate URLs anyway.

A postcard-serialized `ProxyContextPayload` carrying the upstream tracker, the downstream request ID, the ACS endpoint, the requested AuthnContext, and the issued-at timestamp easily exceeds 80 bytes even before AEAD framing (12-byte nonce + 16-byte tag + base64url overhead pushes a "small" plaintext past the limit). `Aes256GcmCodec` is therefore appropriate for the POST binding outbound but unreliable for Redirect.

For Redirect-binding proxies, use `OpaqueHandleCodec`: a short random handle is the `RelayState`, and the actual context lives in a caller-supplied store keyed by that handle.

```rust
pub trait ProxyContextStore: Send + Sync {
    /// Takes a crate-issued `SealingGrant`, not a bare payload: the caller
    /// owns the store, so a `put` accepting a payload would let them insert an
    /// invented context under a handle of their choosing and redeem it.
    fn put(&self, handle: &str, grant: &SealingGrant<'_>, ttl: Duration) -> Result<(), Error>;
    /// Read without consuming. The authenticated proxy transaction is
    /// atomically reserved in the mandatory ReplayCache only after response
    /// validation succeeds.
    fn get(&self, handle: &str) -> Result<Option<ProxyContextPayload>, Error>;
}

pub struct OpaqueHandleCodec<S: ProxyContextStore> {
    pub store: S,
    /// Bytes of entropy in the handle. A typical value of 24 produces 32
    /// base64url characters,
    /// well under the 80-byte RelayState ceiling. Minimum 16; sealing fails
    /// below that, since the handle is a bearer credential in a URL.
    pub handle_byte_len: usize,
    pub ttl: Duration,
}

impl<S: ProxyContextStore> ProxyContextCodec for OpaqueHandleCodec<S> {
    fn encode(&self, grant: &SealingGrant<'_>) -> Result<String, Error> {
        const MIN_HANDLE_BYTE_LEN: usize = 16;
        const PROXY_CONTEXT_LIFETIME: Duration = Duration::from_secs(10 * 60);

        if self.handle_byte_len < MIN_HANDLE_BYTE_LEN {
            return Err(Error::InvalidConfiguration {
                reason: "OpaqueHandleCodec.handle_byte_len must be at least 16 bytes",
            });
        }
        if self.ttl > PROXY_CONTEXT_LIFETIME {
            return Err(Error::InvalidConfiguration {
                reason: "OpaqueHandleCodec.ttl must not exceed the proxy context lifetime",
            });
        }
        let remaining_lifetime = grant
            .payload()
            .expires_at
            .duration_since(SystemTime::now())
            .map_err(|_| Error::InvalidConfiguration {
                reason: "cannot store an already-expired proxy context",
            })?;
        let effective_ttl = self.ttl.min(remaining_lifetime);

        let mut bytes = vec![0u8; self.handle_byte_len];
        rand::rng().fill_bytes(&mut bytes);
        let handle = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
        self.store.put(&handle, grant, effective_ttl)?;
        Ok(handle)
    }

    fn decode(&self, blob: &str) -> Result<ProxyContextPayload, Error> {
        self.store.get(blob)?.ok_or(Error::InvalidConfiguration {
            reason: "proxy context not found (expired or replay)",
        })
    }
}
```

The codec refuses fewer than 16 bytes of handle entropy, refuses a configured TTL beyond the universal ten-minute proxy-context lifetime, refuses a context whose `expires_at` is already past, and passes `min(configured_ttl, expires_at - now)` to the store. `ProxyContextStore::put` MUST enforce that effective TTL, and `get` MUST stop returning the payload no later than that deadline. A Redis implementation should set the value and expiry in the same write; a database implementation should store and enforce an absolute expiry. `get` deliberately does not delete a live entry: otherwise anyone who learns a handle can destroy a valid login by presenting it with an invalid Response.

The handle store and the replay cache have separate jobs. The codec generates an unguessable handle and the store authenticates its lookup and bounds its lifetime; neither makes the authenticated login one-shot. After the upstream Response validates, `consume_upstream_response` requires `ReplayCache::check_and_insert` to atomically and linearizably reserve the namespaced proxy-transaction tombstone through `context.expires_at`. A conflict inserts nothing, and a backend error fails closed. This ordering prevents invalid Responses from consuming a transaction while ensuring a second valid Response—even one with a fresh assertion ID—cannot authorize another downstream assertion.

| Outbound upstream binding | Recommended codec | Notes |
| --- | --- | --- |
| `HttpPost` | `Aes256GcmCodec` | Stateless, no caller-side store. |
| `HttpRedirect` | `OpaqueHandleCodec` | 80-byte `RelayState` ceiling. |

Custom codecs (signed-JWT, KMS envelope encryption, HSM-backed) implement `ProxyContextCodec` directly.

---

## 3. ProxyContext

Two types, deliberately:

- **`ProxyContextPayload`** — the transparent wire form below. `Serialize`/`Deserialize` with public fields so callers can implement their own codec. It carries no authority.
- **`ProxyContext`** — opaque: no public constructor, no public fields, no `Deserialize`. Obtainable only from `Proxy::decode_context`, which runs the configured codec's authentication first.
- **`UpstreamFlow`** — a `ProxyContext` together with the `Identity` validated against *its* tracker, plus the identity of the `Proxy` that produced it. Only `Proxy::consume_upstream_response` makes one, and `relay_to_downstream` accepts nothing else.

Attesting the context and the identity separately says nothing about the pair: `Identity` records no issuer, tracker or request ID, so identity B could be relayed under context A and authenticate the wrong subject into A's transaction. Binding the flow to its originating `Proxy` closes the matching gap for the *instance* — a second `Proxy` over the same roles, with a codec of the caller's choosing, otherwise produces flows the production proxy would honour.

The split exists because relay mints a *signed* downstream assertion from the context. Every check it performs reads the context, so a caller-supplied one would mean comparing caller-controlled input against caller-supplied metadata and then signing the result — an authentic identity could be paired with an invented context naming any registered SP and ACS. For the same reason `encode` takes a `SealingGrant` — a type with no public constructor, issued only by `bounce_to_upstream`. Removing `Proxy`'s codec accessor was not enough on its own: `Aes256GcmCodec` is public and the caller supplies its key, so a second instance over the same key is trivial to build.

This closes the API route, not the underlying one. Whoever holds the AEAD key can reimplement the wire format described in §2 and mint blobs without this crate at all — inherent to sealing state into a client-carried token. Where the application's own key material is in scope, use `OpaqueHandleCodec`, whose token is an opaque handle with the context held server-side.

Because `ProxyContextCodec` is a public trait, a custom implementation **is** the proxy's trust anchor: whatever its `decode` returns is what gets attested and signed from. Implementations must authenticate rather than merely parse, bind the blob to the deployment's key or store, and reject stale blobs.

The opaque context carried across the upstream round-trip:

```rust
/// The transparent wire form. Carries no authority on its own — see §3.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxyContextPayload {
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
    /// Transparent upstream tracker payload, stashed inside the authenticated
    /// proxy context to avoid
    /// requiring `allow_unsolicited` on the SP side.
    pub upstream_tracker: LoginTrackerPayload,
    /// Issued-at timestamp. Used for context-blob age-limit enforcement
    /// by `ProxyContextCodec::decode`.
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
    pub transaction_id: [u8; 16],
    pub downstream_encryption_cert_fingerprints: Vec<[u8; 32]>,
    pub upstream_signing_cert_fingerprints: Vec<[u8; 32]>,
}
```

With `Aes256GcmCodec`, the payload is carried in the token and no context store is required. With `OpaqueHandleCodec`, the payload lives in the server-side handle store. Both modes still require the replay cache used by `consume_upstream_response`.

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
    /// Encoded context, already injected into `dispatch` as RelayState.
    /// Exposed separately for correlation and logging.
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

1. Reject a signed upstream Redirect request: the tracker-dependent proxy
   RelayState does not exist until after `start_login` signs its query. Use
   POST or an unsigned Redirect AuthnRequest.
2. Build a `StartLogin` for the upstream IdP, propagating flags per `input`,
   and call `self.sp.start_login(input.upstream_idp, ...)`.
3. Create a ten-minute context with a random 128-bit transaction ID; preserve
   the validated downstream provenance, the tracker payload, downstream
   encryption-key fingerprints, and upstream signing-key fingerprints.
4. Encode the payload through a crate-issued `SealingGrant`.
5. Inject the encoded RelayState into the returned POST form or unsigned
   Redirect URL, then return `BounceResult`. The dispatch is already complete;
   callers must not append RelayState a second time.

### 4.2 Consume upstream response

```rust
pub struct ConsumeUpstreamResponse<'a> {
    pub relay_state: &'a str,
    pub upstream_idp: &'a IdpDescriptor,
    pub peer_crypto_policy: Option<&'a PeerCryptoPolicy>,
    pub saml_response: &'a [u8],
    pub binding: SsoResponseBinding,
    pub expected_destination: &'a str,
    pub now: SystemTime,
    pub clock_skew: Duration,
    /// Mandatory on the proxy path.
    pub replay_cache: &'a dyn ReplayCache,
    pub holder_of_key_cert: Option<&'a X509Certificate>,
}

impl<'a> Proxy<'a> {
    pub fn consume_upstream_response(
        &self,
        input: ConsumeUpstreamResponse<'_>,
    ) -> Result<UpstreamFlow, Error>;
}
```

This authenticates the RelayState through the configured codec, rejects an
expired context, and rejects an upstream descriptor that introduces signing
certificates not pinned at bounce time. It then validates the Response against
the tracker embedded in that exact context. On success, the required replay
cache atomically reserves the namespaced proxy transaction using the same
`input.now` clock used for validation and retains it through
`context.expires_at`. A concurrent or later response for that transaction
fails with `ProxyTransactionReplay`, even if the IdP uses a different assertion
ID. The method returns the inseparable `UpstreamFlow { context, identity }`
bound to the `Proxy` instance that made the trust decision.

### 4.3 Relay to downstream

```rust
pub struct RelayToDownstream<'a> {
    /// From `Proxy::consume_upstream_response` — the only source of one.
    /// Carries the context, the identity validated under it, and the `Proxy`
    /// instance that produced both.
    pub flow: UpstreamFlow,
    /// Downstream SP descriptor. The context must belong to it; relay refuses
    /// the pairing otherwise.
    pub downstream_sp: &'a SpDescriptor,
    /// Pluggable: which upstream attributes to release downstream, possibly
    /// rewritten / renamed.
    pub attribute_release: &'a dyn AttributeReleasePolicy,
    /// Pluggable: how to mint a NameID for the downstream SP from the upstream subject.
    pub name_id_transform: &'a dyn NameIdTransform,
    /// If true, set downstream AuthnContextClassRef = upstream's actual.
    /// If false — or upstream asserted none — emit `Unspecified`, which claims
    /// nothing. Not `PasswordProtectedTransport`: that outranks plain
    /// Password, so defaulting to it would assert more than upstream attested.
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

1. Verify that the by-value flow belongs to this `Proxy`, that the supplied SP
   is the one bound into the context, that its encryption certificate set has
   not changed, and that the full ACS endpoint remains registered. These checks
   precede caller callbacks.
2. **Select the class the response will advertise**, then **enforce AuthnContext non-downgrade** (§7) against *that* value using `flow.context().payload().requested_authn_context`. → `Error::AuthnContextDowngrade`. Where there is nothing to pass through, the emitted class is `Unspecified` rather than a synthesized `PasswordProtectedTransport`, which would claim more than upstream attested.
3. Cap the downstream session, assertion and subject-confirmation deadlines at
   the earliest of upstream Conditions `NotOnOrAfter`,
   `SessionNotOnOrAfter`, and the selected `SubjectConfirmationData` expiry;
   preflight all timestamp arithmetic before callbacks.
4. Resolve the downstream NameID policy before callbacks. An unsupported
   explicit format fails without running either callback.
5. Compute downstream NameID via `name_id_transform.transform(flow.context().payload().upstream_tracker.idp_entity_id.as_str(), flow.identity().name_id(), flow.identity().attributes(), downstream_sp)`. The upstream IdP entity ID comes from the authenticated flow, never caller-supplied metadata. Require the transform's declared format to equal the resolved policy and reject a Persistent NameID whose present `SPNameQualifier` names another SP, all before attribute release.
6. Compute downstream attributes via `attribute_release.release(flow.identity().attributes(), downstream_sp)`.
7. Build a synthetic `ParsedAuthnRequest` from authenticated context provenance
   and canonical downstream metadata.
8. Call `self.idp.issue_response(...)` and return its POST dispatch. The current
   proxy relay result has no slot for `ArtifactResolveTransaction`, so an
   Artifact downstream ACS is refused with `ArtifactTransactionRequired`
   before either callback runs.

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

/// Built-in: release all attributes. For development only.
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
        /// Authenticated issuer provenance from the upstream login tracker.
        upstream_idp_entity_id: &str,
        upstream_subject: &NameId,
        /// Upstream attributes, so a transform can derive the downstream
        /// NameID from one (e.g. a directory UUID) rather than the subject.
        upstream_attributes: &[Attribute],
        downstream_sp: &SpDescriptor,
    ) -> Result<NameId, Error>;
}

/// Built-in: HMAC-SHA256 over a versioned domain separator followed by
/// fixed-width-length-prefixed upstream IdP entity ID, upstream subject value,
/// and downstream SP entity ID. It is base64url-encoded and produces an IdP-
/// and SP-scoped persistent ID. Framing prevents distinct input tuples from
/// aliasing, and users at different upstream IdPs cannot collide merely because
/// their IdPs chose the same local subject value.
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

/// Compatibility wrapper. Delegates to `inner`; the inner transform chooses
/// the value and format.
pub struct PerSpFormat {
    pub inner: Box<dyn NameIdTransform>,
}
```

---

## 7. AuthnContext non-downgrade

If `context.payload().requested_authn_context` requested `MultiFactorAuth` and the response would advertise `PasswordProtectedTransport`, the proxy must reject — silently downgrading authentication strength is a transitive trust violation.

`relay_to_downstream` selects the class the downstream response will advertise **first**, then evaluates that exact class against the downstream request. The order matters: validating the upstream class and then emitting a different one proves nothing about what the downstream SP receives. With passthrough disabled it emits truthful `Unspecified`, not a fabricated stronger class.

Comparison rules per SAML 2.0 §3.3.2.2.1 (`Comparison` attribute: `exact` / `minimum` / `maximum` / `better`). Default is `exact`. `relay_to_downstream` applies `StandardComparator` unconditionally — the `AuthnContextComparator` trait is public, but there is no override plumbed through `RelayToDownstream`, so a deployment with a custom AuthnContext hierarchy cannot substitute its own today. Both `NotSatisfied` and `NotComparable` collapse to `Error::AuthnContextDowngrade`, i.e. fail closed.

```rust
pub trait AuthnContextComparator: Send + Sync {
    fn satisfies(&self, requested: &str, actual: &str) -> bool;
}

pub struct StandardComparator;  // built-in: exact / minimum / maximum / better
```

`StandardComparator` ranks the standard class refs and treats anything else as unrankable. An ordered comparison (`minimum` / `maximum` / `better`) whose requested set contains *any* unrankable class returns `NotComparable` rather than deciding on the rankable remainder — nothing places a vendor-defined class in the standard hierarchy, so no ordered verdict against it is sound.

---

## 8. What is NOT in `Proxy`

Explicitly punted to the caller:

- **Session registry** mapping upstream → downstream sessions (for SLO chain propagation). The library exposes session indices and request IDs; the caller stores the graph.
- **Session-graph selection for SLO**. The caller decides which downstream sessions belong to an upstream session. Once the caller supplies ordered targets, the `FrontChannelChain` helper drives sequential Redirect LogoutRequest/LogoutResponse round trips and records per-target outcomes; see RFC-007 §8.
- **Discovery** (when the proxy fronts multiple upstream IdPs). The caller picks the IdP before calling `bounce_to_upstream`.
- **Caching** of `IdpDescriptor` / `SpDescriptor` across requests. The library parses metadata XML on demand; whether the caller caches the parse result is up to them.
- **SP / IdP registry lookup** by entity ID. The caller maintains the registry and looks up by `context.downstream_sp_entity_id()`.

---

## 9. Example

```rust
// Upstream redirect binding ⇒ use OpaqueHandleCodec (80-byte RelayState ceiling).
// For POST-bound upstreams, swap in Aes256GcmCodec to avoid a context store.
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
    max_authn_request_age: None,   // use the IdP default
    // Already decoded from the binding's base64 form value.
    saml_request: &decoded_authn_request_xml,
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
// Dispatch to the upstream IdP. `bounce.dispatch` already contains the proxy
// RelayState; `upstream_relay_state` is exposed for correlation/logging only.

// --- /saml/acs handler (upstream IdP → proxy) ---
// One call: authenticate the RelayState blob through the configured codec and
// validate the Response against *that* context's tracker. They come back
// coupled, and tagged with this `Proxy` instance, so relay cannot be handed a
// pairing — or a trust decision — made anywhere else. Sealing is gated behind
// a crate-issued `SealingGrant`, so neither the codec nor the store will seal
// a payload the caller assembled.
let flow = proxy.consume_upstream_response(ConsumeUpstreamResponse {
    relay_state: &form.relay_state,
    upstream_idp: &upstream_idp_descriptor,
    peer_crypto_policy: None,
    // Already decoded from the binding's base64 form value.
    saml_response: &decoded_saml_response_xml,
    binding: SsoResponseBinding::HttpPost,
    expected_destination: "https://hub.example.com/saml/acs", // proxy ACS URL this handler serves
    now: SystemTime::now(),
    clock_skew: Duration::from_secs(60),
    replay_cache: &replay_cache,
    holder_of_key_cert: None,
})?;

let dispatch = proxy.relay_to_downstream(RelayToDownstream {
    flow,
    // Required: the context must belong to this SP, or relay refuses.
    downstream_sp: &downstream_sp,
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
    SsoResponseDispatch::Artifact(_) => unreachable!(
        "Proxy relay refuses Artifact until its public result can carry the trust transaction"
    ),
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
| NameID scoped per downstream SP | Hard for Persistent NameIDs: a conflicting `SPNameQualifier` is rejected; caller still chooses the value transform (`PersistentPerSpHmac` recommended). |
| Attribute release filtered | Soft — caller chooses policy (`ReleaseNone` is the default-safe built-in) |
| ProxyContext authenticity | Hard via codec — AEAD for `Aes256GcmCodec`, authenticated lookup for `OpaqueHandleCodec`; a custom codec/store is itself a trust anchor. |
| ProxyContext lifetime | Hard: universal ten-minute `expires_at`; AEAD also checks `max_age`; opaque handles require ≥128-bit entropy and store TTL is capped at the smaller of configured TTL and remaining context lifetime. |
| Proxy-round-trip replay defense | Mandatory `ReplayCache`; after validation, `consume_upstream_response` atomically and linearly reserves the namespaced transaction tombstone through context expiry using the validation clock. The handle store is not the replay store, and a fresh assertion ID cannot redeem one transaction twice. |
