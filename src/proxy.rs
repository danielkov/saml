//! Identity proxy composition: act as SP toward upstream IdPs and IdP toward
//! downstream SPs, with a stateless context codec carrying state across the
//! round trip.
//!
//! See `docs/rfcs/RFC-005-proxy-composition.md`.

use std::time::{Duration, SystemTime};

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use rand::RngCore as _;
use sha2::Sha256;

use crate::attribute::Attribute;
use crate::authn::request_validate::ParsedAuthnRequest;
use crate::authn_context::{
    AuthnContextClassRef, AuthnContextComparison, ComparatorOutcome, RequestedAuthnContext,
};
// Re-export the canonical comparator under `crate::proxy::StandardComparator`
// so the historical `saml::StandardComparator` re-export path (lib.rs) keeps
// resolving without the proxy carrying its own (now-deleted) implementation.
pub use crate::authn_context::StandardComparator;
use crate::binding::{
    Binding, Dispatch, Endpoint, PostForm, SsoResponseDispatch, SsoResponseEndpoint,
};
use crate::descriptor::{IdpDescriptor, SpDescriptor};
use crate::error::Error;
use crate::idp::{IdentityProvider, IssueResponse};
#[cfg(feature = "slo")]
use crate::logout::{ConsumeLogoutResponse, LogoutOutcome, LogoutTracker, StartLogout};
use crate::nameid::{NameId, NameIdFormat};
use crate::response::Identity;
use crate::sp::{LoginTracker, ServiceProvider, StartLogin};

// =============================================================================
// Proxy type
// =============================================================================

/// Identity proxy: SP toward upstream IdPs, IdP toward downstream SPs. See
/// RFC-005 §2.
pub struct Proxy<'a> {
    sp: &'a ServiceProvider,
    idp: &'a IdentityProvider,
    context_codec: Box<dyn ProxyContextCodec>,
    /// Distinguishes this proxy from any other in the process.
    ///
    /// An [`UpstreamFlow`] records the instance that produced it, and
    /// [`relay_to_downstream`](Self::relay_to_downstream) refuses one from
    /// elsewhere. Without this the wrapper is opaque but transferable: a
    /// caller can stand up a second `Proxy` over the same roles with a codec
    /// of their choosing — a custom one that authenticates nothing — obtain a
    /// flow there, and hand it to the production proxy, which would then act
    /// on another instance's trust decision.
    instance: ProxyInstance,
}

/// Opaque per-`Proxy` identity. Random rather than a counter so it cannot be
/// predicted or reconstructed, and `PartialEq` only — there is nothing to
/// order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProxyInstance(u128);

impl ProxyInstance {
    fn new() -> Self {
        let mut bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut bytes);
        Self(u128::from_be_bytes(bytes))
    }
}

impl<'a> Proxy<'a> {
    /// Construct a proxy from borrowed SP + IdP roles and an owned codec.
    pub fn new(
        sp: &'a ServiceProvider,
        idp: &'a IdentityProvider,
        context_codec: Box<dyn ProxyContextCodec>,
    ) -> Self {
        Self {
            sp,
            idp,
            context_codec,
            instance: ProxyInstance::new(),
        }
    }

    /// Borrow the SP role.
    pub fn sp(&self) -> &ServiceProvider {
        self.sp
    }

    /// Borrow the IdP role.
    pub fn idp(&self) -> &IdentityProvider {
        self.idp
    }
}

// =============================================================================
// ProxyContextPayload + codec trait
// =============================================================================

/// AEAD wrapper for the stateless context blob carried in `RelayState` across
/// the upstream round-trip. See RFC-005 §2.
///
/// # Security-critical
///
/// An implementation of this trait **is** the proxy's trust anchor. Whatever
/// [`decode`](Self::decode) returns is what [`Proxy::decode_context`] attests
/// and [`Proxy::relay_to_downstream`] then signs a downstream assertion from.
/// Wrapping the result in a [`ProxyContext`] is not independent evidence of
/// authenticity — it records that *this codec* vouched for the blob, nothing
/// more.
///
/// A correct implementation must therefore:
///
/// - Authenticate the blob, not merely parse it. An unauthenticated
///   deserialize (`decode -> Ok(payload)` for any well-formed input) hands an
///   attacker the ability to name any registered SP and ACS.
/// - Bind the blob to this deployment's key or store, so a token minted
///   elsewhere is refused.
/// - Reject stale blobs. [`ProxyContextPayload::issued_at`] exists for this;
///   [`Aes256GcmCodec`] enforces a `max_age`.
///
/// [`Aes256GcmCodec`] (AEAD over a caller-supplied key) and
/// [`OpaqueHandleCodec`] (server-side store lookup) both satisfy this. Prefer
/// them to a hand-rolled codec.
pub trait ProxyContextCodec: Send + Sync {
    /// Seal the granted payload into a blob.
    ///
    /// Takes a [`SealingGrant`] rather than a bare [`ProxyContextPayload`]
    /// because the payload type is public and constructible: if this method
    /// accepted one, a caller could build a context naming any registered SP
    /// and ACS, seal it, and pass the blob to [`Proxy::decode_context`] for a
    /// genuine attestation. A grant has no public constructor, so only
    /// [`Proxy::bounce_to_upstream`] can produce the input this needs.
    ///
    /// Implementations read the payload via [`SealingGrant::payload`].
    fn encode(&self, grant: &SealingGrant<'_>) -> Result<String, Error>;
    /// Authenticate a blob and return the payload it carries.
    fn decode(&self, blob: &str) -> Result<ProxyContextPayload, Error>;
}

/// Permission to seal one payload, issued only by
/// [`Proxy::bounce_to_upstream`].
///
/// # What this does and does not buy
///
/// It closes the *API* route to sealing. Without it, `encode` is a public
/// method on public types such as [`Aes256GcmCodec`], so removing
/// `Proxy`'s codec accessor achieved nothing: a caller could construct a
/// second codec over the same key and seal whatever they liked.
///
/// It does **not** make a stateless keyed codec unforgeable. Whoever holds
/// the AEAD key can reimplement the wire format — it is documented in
/// RFC-005 §2 — and mint blobs without going through this crate at all. That
/// is inherent to sealing state into a token the client carries: the key is
/// the only thing standing between an attacker and a valid blob, and with
/// [`Aes256GcmCodec`] the application holds that key.
///
/// If the application's own key material is part of your threat model, use
/// [`OpaqueHandleCodec`]: the token is an opaque handle and the context lives
/// server-side, so forging one means guessing a random handle rather than
/// holding a key.
pub struct SealingGrant<'a> {
    payload: &'a ProxyContextPayload,
    /// Denies struct-literal construction outside this crate. That is the
    /// entire mechanism.
    #[expect(
        dead_code,
        reason = "never read: its purpose is to make the type externally \
                  unconstructible, which a read would not demonstrate"
    )]
    issued: IssuedByCrate,
}

/// Zero-sized proof that a [`SealingGrant`] came from this crate.
struct IssuedByCrate;

impl<'a> SealingGrant<'a> {
    /// Issue a grant. Crate-internal: `bounce_to_upstream` is the only
    /// legitimate reason to seal a context.
    pub(crate) fn issue(payload: &'a ProxyContextPayload) -> Self {
        Self {
            payload,
            issued: IssuedByCrate,
        }
    }

    /// The payload to seal.
    #[must_use]
    pub fn payload(&self) -> &ProxyContextPayload {
        self.payload
    }
}

/// The serialized body of a proxy relay token. See RFC-005 §3.
///
/// This is the wire form: a [`ProxyContextCodec`] turns it into an opaque blob
/// and back. It is deliberately transparent so callers can implement their own
/// codec — and correspondingly carries no authority. Only
/// [`Proxy::decode_context`] produces the [`ProxyContext`] that
/// [`Proxy::relay_to_downstream`] will act on.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxyContextPayload {
    /// AuthnRequest ID we received from the downstream SP.
    pub downstream_request_id: String,
    /// Downstream SP's entity ID.
    pub downstream_sp_entity_id: String,
    /// Downstream SP's ACS endpoint (resolved at consume time).
    pub downstream_acs: Endpoint,
    /// Downstream SP's RelayState, preserved end-to-end.
    pub downstream_relay_state: Option<String>,
    /// What the downstream requested. Preserved for non-downgrade enforcement.
    pub requested_authn_context: Option<RequestedAuthnContext>,
    pub requested_name_id_format: Option<NameIdFormat>,
    /// Upstream LoginTracker, stashed inside the context.
    pub upstream_tracker: crate::sp::LoginTrackerPayload,
    /// Issued-at timestamp. Codec rejects blobs older than its `max_age`.
    pub issued_at: SystemTime,
    /// SHA-256 fingerprints of the *downstream* SP's encryption certificates
    /// as seen when its AuthnRequest was validated.
    ///
    /// `for_proxy_reissue` builds its synthetic request from the descriptor
    /// supplied at relay time, so the issuance-side key check compares that
    /// descriptor against itself — tautological. Carrying the fingerprints in
    /// the sealed context is what makes the comparison mean something: they
    /// come from the request the downstream SP actually sent.
    pub downstream_encryption_cert_fingerprints: Vec<[u8; 32]>,
    /// SHA-256 fingerprints of the upstream IdP signing certificates that
    /// were trusted when this login was started.
    ///
    /// The `LoginTracker` correlates the upstream response by entity ID
    /// alone, and `consume_upstream_response` takes a fresh `IdpDescriptor`
    /// from the caller. Without this, a descriptor bearing the expected entity
    /// ID and an attacker's signing certificate validates an attacker-signed
    /// response and yields a genuine `UpstreamFlow` — the trust root is
    /// substituted after the transaction began.
    pub upstream_signing_cert_fingerprints: Vec<[u8; 32]>,
}

/// A relay token that this crate has seen come back out of an authenticated
/// [`ProxyContextCodec`]. See RFC-005 §3.
///
/// # Why this is not just [`ProxyContextPayload`]
///
/// [`Proxy::relay_to_downstream`] mints a signed downstream assertion from the
/// context paired with an upstream [`Identity`]. Every check it performs —
/// which SP the context belongs to, which ACS to deliver at, what
/// authentication context was requested — reads the context. If a caller could
/// supply that value directly, all of those checks would compare
/// caller-controlled input against caller-supplied metadata, and the proxy
/// would sign the result: an authentic identity could be paired with an
/// invented context naming any registered SP and ACS.
///
/// So the payload is transparent and inert, and this type is opaque and
/// authoritative. It has no public constructor, no public fields and no
/// `Deserialize` impl; the only way to obtain one is
/// [`Proxy::decode_context`], which runs the configured codec's authentication
/// first.
///
/// ```compile_fail
/// # use saml::proxy::{ProxyContext, ProxyContextPayload};
/// fn forge(payload: ProxyContextPayload) -> ProxyContext {
///     ProxyContext { payload, attested: unimplemented!() }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ProxyContext {
    payload: ProxyContextPayload,
    /// Zero-sized proof the payload came back from an authenticated decode.
    #[expect(
        dead_code,
        reason = "never read: it exists to deny struct-literal construction \
                  outside this crate, which is the whole guarantee"
    )]
    attested: AttestedContext,
}

/// Zero-sized proof that a [`ProxyContext`] came from an authenticated decode.
#[derive(Debug, Clone)]
struct AttestedContext;

impl ProxyContext {
    /// Wrap an authenticated payload. Crate-internal: only
    /// [`Proxy::decode_context`] may vouch for one.
    pub(crate) fn attested(payload: ProxyContextPayload) -> Self {
        Self {
            payload,
            attested: AttestedContext,
        }
    }

    /// The authenticated payload, read-only.
    #[must_use]
    pub fn payload(&self) -> &ProxyContextPayload {
        &self.payload
    }

    /// AuthnRequest ID received from the downstream SP.
    #[must_use]
    pub fn downstream_request_id(&self) -> &str {
        &self.payload.downstream_request_id
    }

    /// Downstream SP's entity ID.
    #[must_use]
    pub fn downstream_sp_entity_id(&self) -> &str {
        &self.payload.downstream_sp_entity_id
    }

    /// Downstream SP's RelayState.
    #[must_use]
    pub fn downstream_relay_state(&self) -> Option<&str> {
        self.payload.downstream_relay_state.as_deref()
    }
}

// =============================================================================
// AES-256-GCM codec (RFC-005 §2.1)
// =============================================================================

/// How far ahead of local time a context's `issued_at` may be.
///
/// Clock disagreement between cooperating hosts is seconds; anything beyond
/// this is a caller stamping a future date to evade `max_age`, since
/// `BounceToUpstream::now` is caller-supplied.
const MAX_CONTEXT_CLOCK_SKEW: Duration = Duration::from_mins(5);

/// Stateless AEAD codec: postcard-serialized `ProxyContextPayload` sealed with
/// AES-256-GCM, base64url-encoded for `RelayState`.
pub struct Aes256GcmCodec {
    key: [u8; 32],
    /// Reject context blobs older than this. Default 10 minutes.
    pub max_age: Duration,
}

impl Aes256GcmCodec {
    /// Construct with the default `max_age` of 10 minutes.
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            max_age: Duration::from_mins(10),
        }
    }

    /// Override the default `max_age`.
    pub fn with_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = max_age;
        self
    }
}

impl ProxyContextCodec for Aes256GcmCodec {
    fn encode(&self, grant: &SealingGrant<'_>) -> Result<String, Error> {
        let context = grant.payload();
        let plaintext =
            postcard::to_allocvec(context).map_err(|_err| Error::InvalidConfiguration {
                reason: "proxy context serialize",
            })?;

        let cipher =
            Aes256Gcm::new_from_slice(&self.key).map_err(|_err| Error::InvalidConfiguration {
                reason: "AES-256-GCM key size mismatch",
            })?;

        // Random 12-byte nonce.
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

        let ct_with_tag = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &plaintext,
                    aad: &[],
                },
            )
            .map_err(|_err| Error::DecryptFailed {
                reason: "proxy context",
            })?;

        let mut buf = Vec::with_capacity(12usize.saturating_add(ct_with_tag.len()));
        buf.extend_from_slice(&nonce_bytes);
        buf.extend_from_slice(&ct_with_tag);
        Ok(URL_SAFE_NO_PAD.encode(&buf))
    }

    fn decode(&self, blob: &str) -> Result<ProxyContextPayload, Error> {
        let bytes =
            URL_SAFE_NO_PAD
                .decode(blob.as_bytes())
                .map_err(|_err| Error::DecryptFailed {
                    reason: "proxy context",
                })?;
        if bytes.len() < 12 + 16 {
            return Err(Error::DecryptFailed {
                reason: "proxy context",
            });
        }
        let (nonce_bytes, ct_with_tag) = bytes.split_at(12);

        let cipher =
            Aes256Gcm::new_from_slice(&self.key).map_err(|_err| Error::InvalidConfiguration {
                reason: "AES-256-GCM key size mismatch",
            })?;
        let plaintext = cipher
            .decrypt(
                aes_gcm::Nonce::from_slice(nonce_bytes),
                Payload {
                    msg: ct_with_tag,
                    aad: &[],
                },
            )
            .map_err(|_err| Error::DecryptFailed {
                reason: "proxy context",
            })?;

        let context: ProxyContextPayload =
            postcard::from_bytes(&plaintext).map_err(|_err| Error::InvalidConfiguration {
                reason: "proxy context deserialize",
            })?;

        // Enforce max_age in both directions.
        //
        // Treating any future-dated context as age zero made `max_age` soft:
        // `BounceToUpstream::now` is caller-supplied and sealed verbatim, so a
        // context stamped a year ahead stayed valid for a year plus `max_age`.
        // Real clock disagreement between hosts is seconds, not months, so a
        // bounded skew tolerance keeps legitimate deployments working while
        // making the limit actually hard.
        let now = SystemTime::now();
        match now.duration_since(context.issued_at) {
            Ok(age) => {
                if age > self.max_age {
                    return Err(Error::InvalidConfiguration {
                        reason: "proxy context expired",
                    });
                }
            }
            Err(ahead) => {
                if ahead.duration() > MAX_CONTEXT_CLOCK_SKEW {
                    return Err(Error::InvalidConfiguration {
                        reason: "proxy context is dated too far in the future",
                    });
                }
            }
        }

        Ok(context)
    }
}

// =============================================================================
// Opaque-handle codec for Redirect binding (RFC-005 §2.1)
// =============================================================================

/// Caller-supplied storage for the opaque-handle codec. `take` is one-shot.
pub trait ProxyContextStore: Send + Sync {
    /// Store the granted payload under `handle`.
    ///
    /// Takes a [`SealingGrant`] for the same reason
    /// [`ProxyContextCodec::encode`] does. With a plain payload this method is
    /// a sealing oracle in its own right: a caller holding the store — which
    /// they must, since they construct it — could insert an invented context
    /// under a handle of their choosing and hand that handle to
    /// [`Proxy::decode_context`]. No AEAD key and no dishonest codec required.
    ///
    /// # Contract
    ///
    /// Implementations MUST:
    ///
    /// - **Honour `ttl`.** An entry that outlives it extends the window in
    ///   which a leaked `RelayState` is redeemable. [`Aes256GcmCodec`]
    ///   enforces its age limit itself; here the store is the only thing that
    ///   can.
    /// - **Make [`take`](Self::take) atomic and one-shot.** Returning the same
    ///   handle twice makes the proxy round-trip replayable. A check-then-
    ///   delete that is not atomic is a race, not a one-shot.
    ///
    /// Neither property is checkable from inside this crate, which is why they
    /// are stated as obligations rather than assumed.
    fn put(&self, handle: &str, grant: &SealingGrant<'_>, ttl: Duration) -> Result<(), Error>;
    /// Remove and return the payload stored under `handle`, if any.
    ///
    /// Must be atomic and one-shot — see the contract on [`put`](Self::put).
    ///
    /// Whatever this returns is what [`Proxy::decode_context`] attests and
    /// [`Proxy::relay_to_downstream`] then signs a downstream assertion from.
    /// Under [`OpaqueHandleCodec`] the store *is* the trust anchor, exactly as
    /// a custom [`ProxyContextCodec`] would be: the grant on
    /// [`put`](Self::put) constrains what this crate will hand you, not what
    /// your implementation chooses to return. An implementation that returns a
    /// payload it was never given — or one belonging to a different handle —
    /// forges a context, and nothing downstream can tell.
    fn take(&self, handle: &str) -> Result<Option<ProxyContextPayload>, Error>;
}

/// Minimum handle entropy, in bytes. 128 bits — the handle is a bearer
/// credential redeemable by anyone who presents it, and it travels in a URL.
const MIN_HANDLE_BYTE_LEN: usize = 16;

/// Short random handle as `RelayState`; context lives in a caller-supplied
/// store. See RFC-005 §2.1.
pub struct OpaqueHandleCodec<S: ProxyContextStore> {
    pub store: S,
    /// Bytes of entropy in the handle. Default 24 → 32 base64url chars.
    /// Must be at least 16; sealing fails otherwise.
    pub handle_byte_len: usize,
    pub ttl: Duration,
}

impl<S: ProxyContextStore> ProxyContextCodec for OpaqueHandleCodec<S> {
    fn encode(&self, grant: &SealingGrant<'_>) -> Result<String, Error> {
        // The handle *is* the credential: anyone presenting it redeems the
        // context. This codec is the one recommended when the token must be
        // unforgeable, so a short handle here is worse than the AEAD it was
        // chosen over — `0` would hand every caller the same empty handle.
        if self.handle_byte_len < MIN_HANDLE_BYTE_LEN {
            return Err(Error::InvalidConfiguration {
                reason: "OpaqueHandleCodec.handle_byte_len must be at least 16 bytes",
            });
        }
        let mut bytes = vec![0u8; self.handle_byte_len];
        rand::rng().fill_bytes(&mut bytes);
        let handle = URL_SAFE_NO_PAD.encode(&bytes);
        // Forward the grant rather than the payload: `put` is public, so a
        // caller who could call it with a bare payload would not need this
        // codec at all.
        self.store.put(&handle, grant, self.ttl)?;
        Ok(handle)
    }

    fn decode(&self, blob: &str) -> Result<ProxyContextPayload, Error> {
        let ctx = self.store.take(blob)?.ok_or(Error::InvalidConfiguration {
            reason: "proxy context not found (expired or replay)",
        })?;
        Ok(ctx)
    }
}

// =============================================================================
// Bounce + relay flows (RFC-005 §4)
// =============================================================================

/// Inputs for [`Proxy::bounce_to_upstream`]. See RFC-005 §4.1.
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

/// Result of [`Proxy::bounce_to_upstream`].
pub struct BounceResult {
    pub dispatch: Dispatch,
    /// Encoded context — already URL-safe; serve as-is on the wire.
    pub upstream_relay_state: String,
}

/// Inputs for [`Proxy::consume_upstream_response`].
///
/// Mirrors [`ConsumeResponse`](crate::ConsumeResponse) minus `tracker`, which
/// is taken from the authenticated context rather than supplied — that
/// substitution is the entire point of routing through this method.
pub struct ConsumeUpstreamResponse<'a> {
    /// The `RelayState` blob the upstream IdP returned.
    pub relay_state: &'a str,
    /// Descriptor of the upstream IdP whose signature must verify.
    pub upstream_idp: &'a IdpDescriptor,
    pub peer_crypto_policy: Option<&'a crate::dsig::algorithms::PeerCryptoPolicy>,
    /// Raw `<samlp:Response>` XML, already base64-decoded by the binding layer.
    pub saml_response: &'a [u8],
    pub binding: crate::binding::SsoResponseBinding,
    /// The proxy's own ACS URL that received this Response.
    pub expected_destination: &'a str,
    pub now: SystemTime,
    pub clock_skew: Duration,
    pub replay_cache: Option<&'a dyn crate::replay::ReplayCache>,
    pub replay_mode: crate::replay::ReplayMode,
    pub holder_of_key_cert: Option<&'a crate::crypto::cert::X509Certificate>,
}

/// An upstream `Identity` together with the context it was validated under.
///
/// # Why these travel as one value
///
/// [`Proxy::relay_to_downstream`] used to take a [`ProxyContext`] and an
/// [`Identity`] as separate arguments. Both were individually attested — the
/// context by the codec, the identity by response validation — and neither
/// carried anything tying it to the other. `Identity` records no issuer, no
/// request or tracker ID, no trust root. So a caller could pair identity B
/// with context A and the proxy would mint a downstream assertion
/// authenticating B's subject into A's transaction, with every individual
/// check passing.
///
/// [`Proxy::consume_upstream_response`] authenticates the context and
/// validates the response against *that context's* upstream tracker in one
/// step, and returns this. Relay accepts only this type, so the pairing cannot
/// be chosen by the caller.
pub struct UpstreamFlow {
    context: ProxyContext,
    identity: Identity,
    /// The proxy that produced this flow. See [`Proxy::instance`].
    instance: ProxyInstance,
}

impl UpstreamFlow {
    /// The authenticated context this response was validated against.
    #[must_use]
    pub fn context(&self) -> &ProxyContext {
        &self.context
    }

    /// The validated upstream identity.
    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
}

/// Inputs for [`Proxy::relay_to_downstream`]. See RFC-005 §4.2.
pub struct RelayToDownstream<'a> {
    /// From [`Proxy::consume_upstream_response`] — the only source of one.
    ///
    /// Taken **by value**. One upstream authentication authorizes one
    /// downstream assertion: borrowing let a caller call relay repeatedly on
    /// the same flow, minting a fresh signed assertion and re-running the
    /// attribute-release and NameID callbacks each time. Moving it makes the
    /// single use a type-level fact rather than a caller obligation.
    pub flow: UpstreamFlow,
    /// Downstream SP descriptor (caller looks it up from
    /// `flow.context().downstream_sp_entity_id()`).
    pub downstream_sp: &'a SpDescriptor,
    /// Pluggable: which upstream attributes to release downstream.
    pub attribute_release: &'a dyn AttributeReleasePolicy,
    /// Pluggable: how to mint a NameID for the downstream SP.
    pub name_id_transform: &'a dyn NameIdTransform,
    /// If true, set the downstream AuthnContextClassRef to the upstream's
    /// actual class. If false — or if upstream asserted none — the emitted
    /// class is `Unspecified`, which claims nothing. It is deliberately not
    /// `PasswordProtectedTransport`: that outranks plain Password, so
    /// defaulting to it signed a *stronger* claim than upstream attested.
    pub passthrough_authn_context: bool,
    pub now: SystemTime,
    pub session_lifetime: Duration,
    pub subject_confirmation_lifetime: Duration,
}

impl Proxy<'_> {
    /// Build an upstream AuthnRequest from the downstream one, stash the
    /// downstream-round-trip state in `RelayState`, and return the dispatch.
    /// See RFC-005 §4.1.
    pub fn bounce_to_upstream(&self, input: BounceToUpstream<'_>) -> Result<BounceResult, Error> {
        let downstream = input.downstream_request;

        // A signed Redirect request cannot carry a RelayState this proxy only
        // learns afterwards.
        //
        // `start_login` signs the canonical query — SAMLRequest, RelayState,
        // SigAlg in that order (Bindings §3.4.4.1) — and the proxy's
        // RelayState is the encoded context, which embeds the `LoginTracker`
        // that `start_login` itself produces. So it cannot be supplied before
        // signing, and appending it afterwards changes both the content and
        // the ordering of what a receiver reconstructs: the signature is then
        // unverifiable by any conforming peer.
        //
        // Emitting a request that cannot verify is worse than refusing to
        // emit one. Pair Redirect upstream with an unsigned request, or use
        // POST, where RelayState is a separate form field outside the
        // signature.
        if input.upstream_binding == Binding::HttpRedirect && self.sp.config().sign_authn_requests {
            return Err(Error::InvalidConfiguration {
                reason: "signed Redirect upstream cannot carry the proxy context RelayState; \
                         use POST upstream or disable AuthnRequest signing",
            });
        }

        // 1. Build StartLogin honoring propagate flags.
        //
        //    These flags decide what the *upstream* IdP is asked for. They
        //    must not touch what the context records about the downstream
        //    request: that is the authoritative statement of what the
        //    downstream SP required, and relay enforces non-downgrade against
        //    it. Folding the flags into the stored values erased the
        //    requirement — `propagate_authn_context: false` left the context
        //    with no requested context at all, so relay skipped the
        //    non-downgrade check entirely and a proxy that merely declined to
        //    forward the request upstream silently stopped enforcing it.
        let force_authn = input.propagate_request_flags && downstream.validated_force_authn();
        let is_passive = input.propagate_request_flags && downstream.validated_is_passive();
        let upstream_name_id_format = if input.propagate_name_id_policy {
            downstream.validated_name_id_format().cloned()
        } else {
            None
        };
        let upstream_authn_context = if input.propagate_authn_context {
            downstream.validated_authn_context().cloned()
        } else {
            None
        };

        let result = self.sp.start_login(
            input.upstream_idp,
            StartLogin {
                // We replace RelayState below with the encoded ProxyContextPayload.
                relay_state: None,
                binding: input.upstream_binding,
                force_authn,
                is_passive,
                requested_name_id_format: upstream_name_id_format,
                requested_authn_context: upstream_authn_context,
                acs_index: None,
                acs_url: None,
                response_binding: None,
            },
        )?;

        // 2. Build the ProxyContextPayload from the parsed downstream request.
        // Seal the provenance the validator established, not the `pub`
        // wire-derived copies. Those are caller-mutable: validate against
        // SP-A, rewrite `issuer` and `assertion_consumer_service` to SP-B,
        // then bounce, and the proxy would preserve the rewritten values into
        // a context downstream treats as authenticated — laundering a mutation
        // into a trusted binding.
        let context = ProxyContextPayload {
            downstream_request_id: downstream.validated_request_id().to_owned(),
            downstream_sp_entity_id: downstream.validated_sp().to_owned(),
            downstream_acs: downstream.validated_acs().as_endpoint(),
            downstream_relay_state: downstream.validated_relay_state().map(str::to_owned),
            // Unconditionally what downstream asked for — see step 1 — and
            // from the private provenance, not the caller-mutable `pub` copies.
            requested_authn_context: downstream.validated_authn_context().cloned(),
            requested_name_id_format: downstream.validated_name_id_format().cloned(),
            upstream_tracker: result.tracker.to_payload(),
            issued_at: input.now,
            downstream_encryption_cert_fingerprints: downstream
                .validated_encryption_cert_fingerprints()
                .to_vec(),
            upstream_signing_cert_fingerprints: input
                .upstream_idp
                .signing_certs
                .iter()
                .map(crate::crypto::cert::X509Certificate::fingerprint_sha256)
                .collect(),
        };

        // 3. Encode the context for the wire.
        let upstream_relay_state = self.context_codec.encode(&SealingGrant::issue(&context))?;

        // 4. Inject the encoded RelayState into the dispatch. For POST we set
        //    the form field; for Redirect we append to the URL query. NOTE
        //    (RFC-005 §2.1): for *signed* Redirect outbound the appended
        //    RelayState falls outside the signature. v0.1 ships this and
        //    documents the constraint; production proxies should pair Redirect
        //    upstream with `OpaqueHandleCodec` (small handle) and a signed
        //    binding that re-signs the canonical query string at the wire
        //    layer.
        let dispatch = inject_relay_state(result.dispatch, &upstream_relay_state);

        Ok(BounceResult {
            dispatch,
            upstream_relay_state,
        })
    }

    /// Authenticate the relay token and validate the upstream Response
    /// against *that* context, in one step.
    ///
    /// This is the only way to obtain an [`UpstreamFlow`], and therefore the
    /// only way to reach [`relay_to_downstream`](Self::relay_to_downstream).
    /// Doing the two together is what couples them: the `LoginTracker` the
    /// response is correlated against comes from the context just
    /// authenticated, not from an argument, so the caller cannot pair a
    /// response with a context it was never validated under.
    ///
    /// # Errors
    ///
    /// Whatever the codec returns for a blob it will not vouch for, or
    /// whatever response validation rejects.
    pub fn consume_upstream_response(
        &self,
        input: ConsumeUpstreamResponse<'_>,
    ) -> Result<UpstreamFlow, Error> {
        let context = self.decode_context(input.relay_state)?;

        // The descriptor validating this response must be the trust root the
        // login was started against. The tracker correlates on entity ID only,
        // so without this a caller could supply a descriptor carrying the
        // expected entity ID and their own signing certificate, and an
        // attacker-signed response would produce a genuine flow.
        //
        // Subset rather than equality: retiring a key mid-flow is ordinary
        // rotation, introducing one is the attack.
        let sealed = &context.payload().upstream_signing_cert_fingerprints;
        if !input
            .upstream_idp
            .signing_certs
            .iter()
            .all(|cert| sealed.contains(&cert.fingerprint_sha256()))
        {
            return Err(Error::UpstreamTrustRootMismatch);
        }

        let identity = self.sp.consume_response(crate::sp::ConsumeResponse {
            idp: input.upstream_idp,
            peer_crypto_policy: input.peer_crypto_policy,
            saml_response: input.saml_response,
            binding: input.binding,
            relay_state: Some(input.relay_state),
            // From the context, never from the caller — this is the coupling.
            tracker: Some(&LoginTracker::from_payload(
                context.payload().upstream_tracker.clone(),
            )),
            expected_destination: input.expected_destination,
            now: input.now,
            clock_skew: input.clock_skew,
            replay_cache: input.replay_cache,
            replay_mode: input.replay_mode,
            holder_of_key_cert: input.holder_of_key_cert,
        })?;
        Ok(UpstreamFlow {
            context,
            identity,
            instance: self.instance,
        })
    }

    /// Authenticate a relay token and return the context it carries.
    ///
    /// This is the only way to obtain a [`ProxyContext`], and therefore the
    /// only way to reach [`relay_to_downstream`](Self::relay_to_downstream).
    /// The configured [`ProxyContextCodec`] performs the authentication —
    /// AEAD decryption for [`Aes256GcmCodec`], a store lookup for a
    /// handle-based codec — and the result is wrapped so the rest of the
    /// crate can tell an authenticated context from a caller-supplied one.
    ///
    /// # Errors
    ///
    /// Whatever the codec returns for a blob it will not vouch for: tampered,
    /// expired, unknown, or malformed.
    ///
    /// # The sealing side is not reachable through this crate
    ///
    /// Authentication establishes that a blob came from whoever holds the
    /// key. If a caller could also *seal* a blob, that would be everyone:
    /// they would build a payload naming any registered SP and ACS, encode
    /// it, and decode it straight back into an authoritative context.
    ///
    /// Removing `Proxy`'s codec accessor is not sufficient on its own —
    /// [`Aes256GcmCodec`] is public and the caller supplies its key, so a
    /// second instance is trivial to build. [`ProxyContextCodec::encode`]
    /// therefore requires a [`SealingGrant`], which has no public
    /// constructor. Neither of these compiles:
    ///
    /// ```compile_fail
    /// # use saml::{Aes256GcmCodec, ProxyContextCodec, ProxyContextPayload};
    /// // Retain the key, build your own codec — `encode` still wants a grant.
    /// fn forge(key: [u8; 32], payload: &ProxyContextPayload) -> String {
    ///     Aes256GcmCodec::new(key).encode(payload).unwrap()
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// # use saml::proxy::SealingGrant;
    /// # use saml::ProxyContextPayload;
    /// fn grant(payload: &ProxyContextPayload) -> SealingGrant<'_> {
    ///     SealingGrant::issue(payload)
    /// }
    /// ```
    ///
    /// The store behind [`OpaqueHandleCodec`] is the same authority wearing a
    /// different hat — the caller owns it, so inserting an invented context
    /// under a handle of their choosing would be a sealing oracle needing no
    /// key at all. [`ProxyContextStore::put`] therefore takes a grant too:
    ///
    /// ```compile_fail
    /// # use saml::{ProxyContextPayload, ProxyContextStore};
    /// # use std::time::Duration;
    /// fn forge<S: ProxyContextStore>(store: &S, payload: &ProxyContextPayload) {
    ///     store.put("handle-i-picked", payload, Duration::from_secs(600)).unwrap();
    /// }
    /// ```
    ///
    /// What this does **not** do is make [`Aes256GcmCodec`] unforgeable:
    /// whoever holds the AEAD key can reimplement the wire format and mint
    /// blobs without this crate. That is inherent to sealing state into a
    /// client-carried token. Where the application's own key material is in
    /// scope, use [`OpaqueHandleCodec`].
    pub fn decode_context(&self, blob: &str) -> Result<ProxyContext, Error> {
        let payload = self.context_codec.decode(blob)?;
        Ok(ProxyContext::attested(payload))
    }

    /// Translate an upstream `Identity` into a downstream `<samlp:Response>`,
    /// applying attribute release, NameID transformation, and AuthnContext
    /// non-downgrade. See RFC-005 §4.2.
    ///
    /// # Errors
    ///
    /// If the context does not belong to `downstream_sp`, if its ACS is not
    /// registered, if the upstream AuthnContext is a downgrade of what the
    /// downstream requested, if an issuance deadline overflows, or if
    /// issuance itself fails.
    pub fn relay_to_downstream(
        &self,
        input: RelayToDownstream<'_>,
    ) -> Result<SsoResponseDispatch, Error> {
        // 0. The flow must have come from *this* proxy.
        //
        //    `UpstreamFlow` is opaque, but opacity only stops a caller from
        //    fabricating one — not from obtaining a genuine one elsewhere. A
        //    second `Proxy` over the same roles, with a codec that
        //    authenticates nothing, produces structurally identical flows.
        //    Checked first: nothing else here means anything if the trust
        //    decision was made by an instance the caller controls.
        if input.flow.instance != self.instance {
            return Err(Error::ForeignProxyFlow);
        }

        // 0aa. The downstream SP's key material must be the one whose request
        //      we sealed.
        //
        //      Issuance re-checks this, but from a synthetic request built out
        //      of the descriptor passed here — so that comparison is against
        //      itself. The sealed fingerprints come from the AuthnRequest the
        //      downstream SP actually sent, which is the only non-circular
        //      reference available at relay time. Compared as a set, since
        //      metadata ordering carries no meaning.
        {
            let mut sealed = input
                .flow
                .context()
                .payload()
                .downstream_encryption_cert_fingerprints
                .clone();
            let mut current: Vec<[u8; 32]> = input
                .downstream_sp
                .encryption_certs
                .iter()
                .map(crate::crypto::cert::X509Certificate::fingerprint_sha256)
                .collect();
            sealed.sort_unstable();
            current.sort_unstable();
            if sealed != current {
                return Err(Error::SpKeyMaterialMismatch);
            }
        }

        // 0a. The context must belong to the SP being relayed to.
        //
        //    Without this an authentic SP-A context can be paired with SP-B —
        //    they may legitimately share an ACS URL and binding — and
        //    `for_proxy_reissue` below would then stamp SP-B's provenance onto
        //    it, replacing the binding rather than carrying it. Checked before
        //    any attribute release or NameID transformation, so nothing is
        //    computed for a pairing that will be refused.
        if input.flow.context().downstream_sp_entity_id() != input.downstream_sp.entity_id {
            return Err(Error::IssuerMismatch {
                expected: input.flow.context().downstream_sp_entity_id().to_owned(),
                got: Some(input.downstream_sp.entity_id.clone()),
            });
        }

        // 0b. Resolve the downstream ACS before any caller callback runs.
        //
        //     Attribute release and NameID transformation are caller-supplied
        //     and may touch a database, a directory, or a pseudonym store. An
        //     invalid or stale context must not drive those side effects only
        //     to fail afterwards on `UnregisteredAcs`. `for_proxy_reissue`
        //     re-resolves the same endpoint below; doing it here first costs a
        //     lookup and makes the failure ordering observable.
        let downstream_acs = SsoResponseEndpoint::try_from_endpoint(
            input.flow.context().payload().downstream_acs.clone(),
        )?;
        if !input
            .downstream_sp
            .assertion_consumer_services
            .iter()
            .any(|e| {
                e.url == downstream_acs.url
                    && e.binding == downstream_acs.binding
                    && e.index == downstream_acs.index
            })
        {
            return Err(Error::UnregisteredAcs {
                entity_id: input.downstream_sp.entity_id.clone(),
            });
        }

        // 1. Decide the class this response will actually advertise, then
        //    enforce non-downgrade against *that*.
        //
        //    Order matters. Validating the upstream class and emitting a
        //    different one proves nothing about what downstream receives:
        //    with `passthrough_authn_context: false` an upstream MFA identity
        //    satisfied a downstream `Exact(MultiFactorAuth)` request, and the
        //    signed assertion then advertised PasswordProtectedTransport. The
        //    check has to bind to the emitted value.
        //    Where there is nothing to pass through — upstream asserted no
        //    class, or the caller disabled passthrough — the emitted value is
        //    `Unspecified`. It previously defaulted to
        //    PasswordProtectedTransport, which is *stronger* than plain
        //    Password: an upstream Password result was signed downstream as
        //    PPT, inventing evidence rather than merely losing it.
        //    `Unspecified` claims nothing, and because it ranks lowest it
        //    satisfies no stronger request — so a downstream SP that required
        //    something specific is refused below rather than misled.
        let downstream_class_ref = if input.passthrough_authn_context {
            input.flow.identity().authn_context_class_ref().map_or(
                AuthnContextClassRef::Unspecified,
                AuthnContextClassRef::from_uri,
            )
        } else {
            AuthnContextClassRef::Unspecified
        };

        //    The set-aggregating semantics — in particular, `Better` requires
        //    the class to be strictly stronger than the *max* of the requested
        //    set, per SAML 2.0 Core §3.3.2.2.1 — live in
        //    [`crate::authn_context::StandardComparator`]. Both `NotSatisfied`
        //    and `NotComparable` collapse to `AuthnContextDowngrade`
        //    (fail-closed), matching the SP-side response validator.
        if let Some(requested) = &input.flow.context().payload().requested_authn_context {
            match StandardComparator.evaluate(requested, downstream_class_ref.as_uri()) {
                ComparatorOutcome::Satisfied => {}
                ComparatorOutcome::NotSatisfied | ComparatorOutcome::NotComparable => {
                    return Err(Error::AuthnContextDowngrade);
                }
            }
        }

        // 1b. Verify the assertion can actually be issued, before any
        //     caller callback runs.
        //
        //     Attribute release and NameID transformation are caller-supplied
        //     and may write to a pseudonym store, a directory, or an audit
        //     log. If issuance then fails, those side effects have happened
        //     for a response that will never exist.
        //
        //     This goes through the same `issuance_instants` the assertion
        //     builder uses, so the preflight cannot drift from the real thing.
        //     An earlier version checked only the additions and so missed
        //     `now = UNIX_EPOCH`, where `NotBefore = now - 1min` underflows,
        //     and missed the formatting failures entirely.
        // The downstream assertion cannot outlive the upstream authentication
        // it rests on. Without a cap, a proxy re-issues a 1-hour downstream
        // session from an upstream assertion with five minutes left — and can
        // keep doing so, laundering a short-lived authentication into an
        // indefinite one.
        let upstream_expiry = input.flow.identity().not_on_or_after();
        if upstream_expiry <= input.now {
            return Err(Error::Expired);
        }
        let session_not_on_or_after = input
            .now
            .checked_add(input.session_lifetime)
            .ok_or(Error::InvalidConfiguration {
                reason: "session_not_on_or_after overflow",
            })?
            .min(upstream_expiry);
        let effective_session_lifetime = session_not_on_or_after
            .duration_since(input.now)
            .unwrap_or(Duration::ZERO);
        let effective_subject_confirmation_lifetime = input
            .subject_confirmation_lifetime
            .min(effective_session_lifetime);
        crate::response::issue::issuance_instants(
            input.now,
            effective_session_lifetime,
            effective_subject_confirmation_lifetime,
            input.flow.identity().authn_instant(),
            Some(session_not_on_or_after),
        )?;

        // 2. Attribute release.
        let attributes = input
            .attribute_release
            .release(input.flow.identity().attributes(), input.downstream_sp);

        // 3. NameID transformation.
        let downstream_name_id = input.name_id_transform.transform(
            input.flow.identity().name_id(),
            input.flow.identity().attributes(),
            input.downstream_sp,
        )?;

        // 5. Build a synthetic ParsedAuthnRequest from the proxy context.
        //    The `assertion_consumer_service` field is type-narrowed to
        //    `SsoResponseEndpoint`; narrow the stashed `Endpoint` accordingly.
        let acs_endpoint = downstream_acs;
        // The sanctioned construction path: it re-resolves the ACS against the
        // downstream SP's metadata and records the provenance binding that
        // issuance correlates on. A struct literal cannot be used here — the
        // binding is private precisely so a synthetic request cannot claim an
        // SP it was never checked against.
        let synthetic = ParsedAuthnRequest::for_proxy_reissue(
            input.downstream_sp,
            input.flow.context().payload().downstream_request_id.clone(),
            input.flow.context().payload().issued_at,
            acs_endpoint,
            input
                .flow
                .context()
                .payload()
                .requested_name_id_format
                .clone(),
            input
                .flow
                .context()
                .payload()
                .requested_authn_context
                .clone(),
            input
                .flow
                .context()
                .payload()
                .downstream_relay_state
                .clone(),
        )?;

        // 6. Hand off to the IdP role for `<samlp:Response>` issuance.
        //    Every deadline was validated at step 1b, before any callback ran.
        let session_index = make_session_index();
        self.idp.issue_response(IssueResponse {
            sp: input.downstream_sp,
            in_response_to: &synthetic,
            name_id: downstream_name_id,
            attributes,
            authn_instant: input.flow.identity().authn_instant(),
            session_index,
            session_not_on_or_after: Some(session_not_on_or_after),
            authn_context_class_ref: downstream_class_ref,
            force_encrypt_assertion: None,
            now: input.now,
            assertion_lifetime: effective_session_lifetime,
            subject_confirmation_lifetime: effective_subject_confirmation_lifetime,
            holder_of_key_cert: None,
        })
    }
}

/// Replace the `RelayState` slot on a `Dispatch` with a freshly-encoded value.
/// For POST we mutate the form field; for Redirect we append to the URL
/// query.
fn inject_relay_state(dispatch: Dispatch, relay_state: &str) -> Dispatch {
    match dispatch {
        Dispatch::Post(form) => Dispatch::Post(PostForm {
            action: form.action,
            saml_request: form.saml_request,
            saml_response: form.saml_response,
            relay_state: Some(relay_state.to_string()),
        }),
        Dispatch::Redirect(mut url) => {
            // Use `url::form_urlencoded` to percent-encode the value
            // consistently with the binding layer.
            let encoded =
                url::form_urlencoded::byte_serialize(relay_state.as_bytes()).collect::<String>();
            // Splice `RelayState=<encoded>` into the existing query. The
            // SP-emitted query never carries RelayState (we passed None), so
            // a plain append is safe.
            let existing = url.query().unwrap_or_default();
            let new_query = if existing.is_empty() {
                format!("RelayState={encoded}")
            } else {
                format!("{existing}&RelayState={encoded}")
            };
            url.set_query(Some(&new_query));
            Dispatch::Redirect(url)
        }
    }
}

/// Generate a `_<hex16>` SessionIndex for the downstream Assertion. The
/// IdP role's `issue_response` requires a non-empty session index; the value
/// itself is opaque to SPs (used for SLO targeting).
fn make_session_index() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    let mut out = String::with_capacity(33);
    out.push('_');
    for b in bytes {
        out.push(hex_nibble(b >> 4));
        out.push(hex_nibble(b & 0x0f));
    }
    out
}

/// Convert a 0..=15 nibble to its lowercase hex character. Callers always
/// pass a masked nibble; values out of range fall back to `'0'`.
fn hex_nibble(nibble: u8) -> char {
    core::char::from_digit(u32::from(nibble), 16).unwrap_or('0')
}

// =============================================================================
// Attribute release (RFC-005 §5)
// =============================================================================

/// Filter / rewrite upstream attributes for a given downstream SP.
pub trait AttributeReleasePolicy: Send + Sync {
    fn release(&self, upstream: &[Attribute], downstream_sp: &SpDescriptor) -> Vec<Attribute>;
}

/// Release nothing — safest default.
pub struct ReleaseNone;

impl AttributeReleasePolicy for ReleaseNone {
    fn release(&self, _upstream: &[Attribute], _downstream_sp: &SpDescriptor) -> Vec<Attribute> {
        Vec::new()
    }
}

/// Release only attributes whose name appears in `names`.
pub struct ReleaseAllowList {
    pub names: Vec<String>,
}

impl AttributeReleasePolicy for ReleaseAllowList {
    fn release(&self, upstream: &[Attribute], _downstream_sp: &SpDescriptor) -> Vec<Attribute> {
        upstream
            .iter()
            .filter(|a| self.names.iter().any(|n| n == &a.name))
            .cloned()
            .collect()
    }
}

/// Release everything. Development only.
pub struct ReleaseAll;

impl AttributeReleasePolicy for ReleaseAll {
    fn release(&self, upstream: &[Attribute], _downstream_sp: &SpDescriptor) -> Vec<Attribute> {
        upstream.to_vec()
    }
}

/// Per-SP allow-list with a fallback policy.
pub struct ReleasePerSp {
    pub allow_lists: std::collections::HashMap<String, Vec<String>>,
    pub default: Box<dyn AttributeReleasePolicy>,
}

impl AttributeReleasePolicy for ReleasePerSp {
    fn release(&self, upstream: &[Attribute], downstream_sp: &SpDescriptor) -> Vec<Attribute> {
        match self.allow_lists.get(&downstream_sp.entity_id) {
            Some(names) => upstream
                .iter()
                .filter(|a| names.iter().any(|n| n == &a.name))
                .cloned()
                .collect(),
            None => self.default.release(upstream, downstream_sp),
        }
    }
}

// =============================================================================
// NameID transformation (RFC-005 §6)
// =============================================================================

/// Mint a downstream NameID from the upstream subject + attribute bag.
///
/// The attribute bag is passed alongside the subject so transforms can lift
/// values out of `upstream_identity.attributes` (see
/// [`NameIdFromAttribute`]).
pub trait NameIdTransform: Send + Sync {
    fn transform(
        &self,
        upstream_subject: &NameId,
        upstream_attributes: &[Attribute],
        downstream_sp: &SpDescriptor,
    ) -> Result<NameId, Error>;
}

/// HMAC-SHA256(upstream_value || downstream_sp_entity_id), base64url-encoded.
/// Produces an SP-scoped persistent ID that downstream SPs cannot correlate.
pub struct PersistentPerSpHmac {
    pub key: [u8; 32],
    pub format: NameIdFormat,
}

impl NameIdTransform for PersistentPerSpHmac {
    fn transform(
        &self,
        upstream_subject: &NameId,
        _upstream_attributes: &[Attribute],
        downstream_sp: &SpDescriptor,
    ) -> Result<NameId, Error> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.key).map_err(|_err| {
            Error::InvalidConfiguration {
                reason: "HMAC-SHA256 key size mismatch",
            }
        })?;
        mac.update(upstream_subject.value.as_bytes());
        mac.update(downstream_sp.entity_id.as_bytes());
        let digest = mac.finalize().into_bytes();
        let value = URL_SAFE_NO_PAD.encode(digest);
        Ok(NameId {
            value,
            format: self.format.clone(),
            name_qualifier: None,
            sp_name_qualifier: Some(downstream_sp.entity_id.clone()),
            sp_provided_id: None,
        })
    }
}

/// Passthrough — emit the upstream subject verbatim downstream. Only use
/// when proxy and downstream share a trust boundary.
pub struct PassThroughNameId;

impl NameIdTransform for PassThroughNameId {
    fn transform(
        &self,
        upstream_subject: &NameId,
        _upstream_attributes: &[Attribute],
        _downstream_sp: &SpDescriptor,
    ) -> Result<NameId, Error> {
        Ok(upstream_subject.clone())
    }
}

/// Replace the NameID with the value of a named upstream attribute (e.g.
/// lifting an `email` attribute into an `EmailAddress`-format NameID).
pub struct NameIdFromAttribute {
    pub attribute_name: String,
    pub format: NameIdFormat,
}

impl NameIdTransform for NameIdFromAttribute {
    fn transform(
        &self,
        _upstream_subject: &NameId,
        upstream_attributes: &[Attribute],
        downstream_sp: &SpDescriptor,
    ) -> Result<NameId, Error> {
        let attr = upstream_attributes
            .iter()
            .find(|a| a.name == self.attribute_name)
            .ok_or(Error::InvalidConfiguration {
                reason: "NameIdFromAttribute: named attribute not present",
            })?;
        let value = attr
            .values
            .first()
            .cloned()
            .ok_or(Error::InvalidConfiguration {
                reason: "NameIdFromAttribute: attribute has no values",
            })?;
        Ok(NameId {
            value,
            format: self.format.clone(),
            name_qualifier: None,
            sp_name_qualifier: Some(downstream_sp.entity_id.clone()),
            sp_provided_id: None,
        })
    }
}

/// Per-SP format selection. Delegates to `inner` for the value; the format
/// chosen is whatever `inner` returns (callers compose this with a base
/// transform to swap formats per SP via `inner` itself).
pub struct PerSpFormat {
    pub inner: Box<dyn NameIdTransform>,
}

impl NameIdTransform for PerSpFormat {
    fn transform(
        &self,
        upstream_subject: &NameId,
        upstream_attributes: &[Attribute],
        downstream_sp: &SpDescriptor,
    ) -> Result<NameId, Error> {
        self.inner
            .transform(upstream_subject, upstream_attributes, downstream_sp)
    }
}

// =============================================================================
// AuthnContext comparator (RFC-005 §7)
// =============================================================================

/// Compare a requested AuthnContextClassRef URI against an actual one under a
/// given comparison strategy.
///
/// This trait is a caller-supplied extension point for non-standard
/// AuthnContext hierarchies (e.g. enterprise IdPs with custom class refs); the
/// proxy's spec-conformant evaluation uses
/// [`crate::authn_context::StandardComparator::evaluate`] directly, which
/// honors the full set-aggregating SAML 2.0 §3.3.2.2.1 semantics that a
/// per-URI predicate cannot express.
pub trait AuthnContextComparator: Send + Sync {
    fn satisfies(&self, requested: &str, actual: &str) -> bool;
}

impl AuthnContextComparator for StandardComparator {
    fn satisfies(&self, requested: &str, actual: &str) -> bool {
        // Single-URI surface: degenerate to `Exact` against a one-element
        // requested set. Set-aggregating comparisons (`Minimum` / `Maximum` /
        // `Better`) require the full `RequestedAuthnContext` and route through
        // `StandardComparator::evaluate` instead.
        let requested_set = RequestedAuthnContext {
            class_refs: vec![AuthnContextClassRef::from_uri(requested)],
            comparison: AuthnContextComparison::Exact,
        };
        self.is_satisfied(&requested_set, actual)
    }
}

// =============================================================================
// Front-channel SLO chain (RFC-007 §8)
// =============================================================================

/// State-machine helper for sequential front-channel SLO. See RFC-007 §8.
#[cfg(feature = "slo")]
pub struct FrontChannelChain {
    pub targets: Vec<FrontChannelTarget>,
    pub state: FrontChannelState,
    /// Accumulated per-target outcomes. Materialized into `state` when the
    /// chain transitions to `Done`. Not part of the public RFC enum surface.
    pending_outcomes: Vec<Result<LogoutOutcome, Error>>,
}

/// One step in the chain: which SP to log out, with that SP's effective
/// crypto policy and the session-targeting metadata.
#[cfg(feature = "slo")]
pub struct FrontChannelTarget {
    pub sp: SpDescriptor,
    pub peer_crypto_policy: Option<crate::dsig::algorithms::PeerCryptoPolicy>,
    pub name_id: NameId,
    pub session_index: Option<String>,
}

/// Chain state — either "next dispatch waiting for the user-agent round trip"
/// or "all targets exercised, here are the per-target outcomes".
#[cfg(feature = "slo")]
pub enum FrontChannelState {
    NextTarget {
        index: usize,
        next_dispatch: Box<Dispatch>,
        tracker: LogoutTracker,
    },
    Done {
        outcomes: Vec<Result<LogoutOutcome, Error>>,
    },
}

#[cfg(feature = "slo")]
impl FrontChannelChain {
    /// Build the LogoutRequest for the first target (Redirect binding).
    /// Empty `targets` collapses immediately to `Done { outcomes: [] }`.
    pub fn start(idp: &IdentityProvider, targets: Vec<FrontChannelTarget>) -> Result<Self, Error> {
        if targets.is_empty() {
            return Ok(Self {
                targets,
                state: FrontChannelState::Done { outcomes: vec![] },
                pending_outcomes: vec![],
            });
        }
        let first = targets.first().ok_or(Error::InvalidConfiguration {
            reason: "FrontChannelChain: targets unexpectedly empty",
        })?;
        let logout = idp.start_logout(
            &first.sp,
            StartLogout {
                name_id: &first.name_id,
                session_index: first.session_index.as_deref(),
                relay_state: None,
                reason: None,
                binding: Binding::HttpRedirect,
            },
        )?;
        Ok(Self {
            targets,
            state: FrontChannelState::NextTarget {
                index: 0,
                next_dispatch: Box::new(logout.dispatch),
                tracker: logout.tracker,
            },
            pending_outcomes: Vec::new(),
        })
    }

    /// Consume a LogoutResponse from the current target, record its outcome,
    /// and either advance to the next target or transition to `Done`.
    pub fn advance(
        &mut self,
        idp: &IdentityProvider,
        logout_response_body: &[u8],
        binding: Binding,
        now: SystemTime,
        clock_skew: Duration,
    ) -> Result<(), Error> {
        let (index, tracker) = match &self.state {
            FrontChannelState::NextTarget { index, tracker, .. } => (*index, tracker.clone()),
            FrontChannelState::Done { .. } => {
                return Err(Error::InvalidConfiguration {
                    reason: "FrontChannelChain::advance called after Done",
                });
            }
        };

        let target = self.targets.get(index).ok_or(Error::InvalidConfiguration {
            reason: "FrontChannelChain: target index out of range",
        })?;
        let expected_destination =
            idp.config()
                .slo
                .first()
                .map(|e| e.url.clone())
                .ok_or(Error::InvalidConfiguration {
                    reason: "FrontChannelChain: IdP has no SLO endpoint",
                })?;

        // Record this target's outcome (errors collapse to an `Err` so the
        // caller still gets a parallel-shaped `outcomes` vector at Done).
        let outcome = idp.consume_logout_response(
            &target.sp,
            ConsumeLogoutResponse {
                peer_crypto_policy: target.peer_crypto_policy.as_ref(),
                body: logout_response_body,
                binding,
                detached_signature: None,
                tracker: &tracker,
                expected_destination: &expected_destination,
                now,
                clock_skew,
            },
        );
        self.pending_outcomes.push(outcome);

        let next_index = index.checked_add(1).ok_or(Error::InvalidConfiguration {
            reason: "FrontChannelChain: target index overflow",
        })?;
        if next_index >= self.targets.len() {
            self.state = FrontChannelState::Done {
                outcomes: std::mem::take(&mut self.pending_outcomes),
            };
            return Ok(());
        }

        let next = self
            .targets
            .get(next_index)
            .ok_or(Error::InvalidConfiguration {
                reason: "FrontChannelChain: next target index out of range",
            })?;
        let logout = idp.start_logout(
            &next.sp,
            StartLogout {
                name_id: &next.name_id,
                session_index: next.session_index.as_deref(),
                relay_state: None,
                reason: None,
                binding: Binding::HttpRedirect,
            },
        )?;
        self.state = FrontChannelState::NextTarget {
            index: next_index,
            next_dispatch: Box::new(logout.dispatch),
            tracker: logout.tracker,
        };
        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cert::X509Certificate;
    use crate::crypto::cert::test_vectors::{RSA_CERT_PEM, RSA_KEY_PKCS8_PEM};
    use crate::crypto::keypair::KeyPair;
    use crate::descriptor::{IdpDescriptor, SpDescriptor};
    use crate::dsig::algorithms::{
        C14nAlgorithm, DigestAlgorithm, PeerCryptoPolicy, SignatureAlgorithm,
    };
    use crate::idp::{IdentityProvider, IdentityProviderConfig};
    use crate::sp::{ServiceProvider, ServiceProviderConfig};
    use std::collections::HashMap;
    use std::sync::Mutex;

    // ---------- Fixtures ----------

    fn rsa_keypair() -> KeyPair {
        let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).unwrap();
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        kp.with_certificate(cert)
    }

    fn rsa_cert() -> X509Certificate {
        X509Certificate::from_pem(RSA_CERT_PEM).unwrap()
    }

    /// SP role for the proxy (acts as SP toward upstream IdP).
    fn proxy_sp() -> ServiceProvider {
        ServiceProvider::new(ServiceProviderConfig {
            entity_id: "https://proxy.example.com/sp".into(),
            acs: vec![SsoResponseEndpoint::post(
                "https://proxy.example.com/acs",
                0,
                true,
            )],
            slo: vec![],
            name_id_formats: vec![NameIdFormat::Persistent, NameIdFormat::EmailAddress],
            signing_key: None,
            decryption_key: None,
            sign_authn_requests: false,
            want_signed: crate::sp::SpWantSigned::default(),
            allow_unsolicited: false,
            #[cfg(feature = "slo")]
            logout_signing: crate::sp::SpLogoutSigning::default(),
            #[cfg(feature = "slo")]
            logout_want_signed: crate::sp::SpLogoutWantSigned::default(),
            default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
            outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
            outbound_digest_algorithm: DigestAlgorithm::Sha256,
        })
        .unwrap()
    }

    /// IdP role for the proxy (acts as IdP toward downstream SP).
    fn proxy_idp() -> IdentityProvider {
        IdentityProvider::new(IdentityProviderConfig {
            entity_id: "https://proxy.example.com/idp".into(),
            sso: vec![Endpoint::post("https://proxy.example.com/sso", 0, true)],
            slo: vec![Endpoint::redirect("https://proxy.example.com/slo", 0, true)],
            artifact_resolution: vec![],
            supported_name_id_formats: vec![NameIdFormat::Persistent, NameIdFormat::EmailAddress],
            default_name_id_format: NameIdFormat::Persistent,
            signing_key: rsa_keypair(),
            decryption_key: None,
            want_authn_requests_signed: false,
            assertion_signing: crate::idp::IdpAssertionSigning {
                sign_responses: false,
                sign_assertions: true,
            },
            encrypt_assertions_when_possible: false,
            #[cfg(feature = "slo")]
            logout_signing: crate::idp::IdpLogoutSigning::default(),
            #[cfg(feature = "slo")]
            logout_want_signed: crate::idp::IdpLogoutWantSigned::default(),
            default_session_duration: Duration::from_hours(1),
            default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
            outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
            outbound_digest_algorithm: DigestAlgorithm::Sha256,
            outbound_c14n: C14nAlgorithm::ExclusiveCanonical,
            #[cfg(feature = "xmlenc")]
            outbound_data_encryption_algorithm:
                crate::xmlenc::algorithms::DataEncryptionAlgorithm::Aes256Gcm,
            #[cfg(feature = "xmlenc")]
            outbound_key_transport_algorithm:
                crate::xmlenc::algorithms::KeyTransportAlgorithm::RsaOaep,
        })
        .unwrap()
    }

    fn upstream_idp_descriptor() -> IdpDescriptor {
        IdpDescriptor {
            entity_id: "https://upstream-idp.example.com".into(),
            sso_endpoints: vec![
                Endpoint::redirect("https://upstream-idp.example.com/sso", 0, true),
                Endpoint::post("https://upstream-idp.example.com/sso/post", 1, false),
            ],
            slo_endpoints: vec![],
            artifact_resolution_endpoints: vec![],
            signing_certs: vec![rsa_cert()],
            encryption_certs: vec![],
            supported_name_id_formats: vec![],
            want_authn_requests_signed: false,
            valid_until: None,
            cache_duration: None,
        }
    }

    fn downstream_sp_descriptor() -> SpDescriptor {
        SpDescriptor {
            entity_id: "https://downstream-sp.example.com".into(),
            assertion_consumer_services: vec![SsoResponseEndpoint::post(
                "https://downstream-sp.example.com/acs",
                0,
                true,
            )],
            single_logout_services: vec![Endpoint::redirect(
                "https://downstream-sp.example.com/slo",
                0,
                true,
            )],
            signing_certs: vec![rsa_cert()],
            encryption_certs: vec![],
            supported_name_id_formats: vec![NameIdFormat::Persistent, NameIdFormat::EmailAddress],
            want_assertions_signed: false,
            authn_requests_signed: false,
            valid_until: None,
            cache_duration: None,
            #[cfg(feature = "idp-disco")]
            discovery_response_endpoints: vec![],
        }
    }

    /// Couple a context and an identity for tests.
    ///
    /// Production code can only get an `UpstreamFlow` from
    /// `consume_upstream_response`, which validates the response against the
    /// context's own tracker. These tests exercise relay's logic downstream of
    /// that, so they assemble the pair directly — which is possible here only
    /// because this module is inside the crate.
    fn flow(proxy: &Proxy<'_>, context: ProxyContextPayload, identity: Identity) -> UpstreamFlow {
        UpstreamFlow {
            context: ProxyContext::attested(context),
            identity,
            instance: proxy.instance,
        }
    }

    fn sample_context() -> ProxyContextPayload {
        let tracker_issued_at = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_hours(494_388))
            .expect("tracker issued_at within representable range");
        ProxyContextPayload {
            downstream_request_id: "_req-downstream".into(),
            downstream_sp_entity_id: "https://downstream-sp.example.com".into(),
            downstream_acs: Endpoint::post("https://downstream-sp.example.com/acs", 0, true),
            downstream_relay_state: Some("opaque-downstream-state".into()),
            requested_authn_context: Some(RequestedAuthnContext {
                class_refs: vec![AuthnContextClassRef::PasswordProtectedTransport],
                comparison: AuthnContextComparison::Minimum,
            }),
            requested_name_id_format: Some(NameIdFormat::Persistent),
            downstream_encryption_cert_fingerprints: vec![],
            upstream_signing_cert_fingerprints: vec![],
            upstream_tracker: crate::sp::LoginTrackerPayload {
                request_id: "_upstream-1".into(),
                issued_at: tracker_issued_at,
                idp_entity_id: "https://upstream-idp.example.com".into(),
                acs_endpoint: SsoResponseEndpoint::post("https://proxy.example.com/acs", 0, true),
                requested_authn_context: None,
                requested_name_id_format: None,
            },
            issued_at: SystemTime::now(),
        }
    }

    // ---------- Aes256GcmCodec ----------

    #[test]
    fn aes_gcm_codec_round_trip() {
        let codec = Aes256GcmCodec::new([7u8; 32]);
        let context = sample_context();
        let blob = codec
            .encode(&SealingGrant::issue(&context))
            .expect("encode");
        let decoded = codec.decode(&blob).expect("decode");
        assert_eq!(decoded.downstream_request_id, context.downstream_request_id);
        assert_eq!(
            decoded.downstream_relay_state.as_deref(),
            Some("opaque-downstream-state"),
        );
        assert_eq!(
            decoded.upstream_tracker.request_id,
            context.upstream_tracker.request_id,
        );
    }

    #[test]
    fn aes_gcm_codec_rejects_tampered_blob() {
        let codec = Aes256GcmCodec::new([7u8; 32]);
        let context = sample_context();
        let blob = codec.encode(&SealingGrant::issue(&context)).unwrap();

        // Flip a byte in the middle (covers ciphertext / tag region).
        let mut tampered = URL_SAFE_NO_PAD.decode(blob.as_bytes()).unwrap();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0x01;
        let tampered_b64 = URL_SAFE_NO_PAD.encode(&tampered);

        let err = codec.decode(&tampered_b64).unwrap_err();
        match err {
            Error::DecryptFailed { reason } => assert_eq!(reason, "proxy context"),
            other => panic!("expected DecryptFailed, got {other:?}"),
        }
    }

    #[test]
    fn aes_gcm_codec_rejects_expired_blob() {
        let codec = Aes256GcmCodec::new([7u8; 32]).with_max_age(Duration::from_secs(1));
        let mut context = sample_context();
        // Pretend the context was issued 10 minutes ago.
        context.issued_at = SystemTime::now()
            .checked_sub(Duration::from_mins(10))
            .expect("now - 10min within range");
        let blob = codec.encode(&SealingGrant::issue(&context)).unwrap();
        let err = codec.decode(&blob).unwrap_err();
        match err {
            Error::InvalidConfiguration { reason } => {
                assert_eq!(reason, "proxy context expired");
            }
            other => panic!("expected InvalidConfiguration, got {other:?}"),
        }
    }

    #[test]
    fn aes_gcm_codec_rejects_truncated_blob() {
        let codec = Aes256GcmCodec::new([7u8; 32]);
        let err = codec.decode("AAAA").unwrap_err();
        assert!(matches!(err, Error::DecryptFailed { .. }));
    }

    // ---------- OpaqueHandleCodec ----------

    struct InMemoryStore {
        inner: Mutex<HashMap<String, (ProxyContextPayload, SystemTime)>>,
    }

    impl InMemoryStore {
        fn new() -> Self {
            Self {
                inner: Mutex::new(HashMap::new()),
            }
        }
    }

    impl ProxyContextStore for InMemoryStore {
        fn put(&self, handle: &str, grant: &SealingGrant<'_>, ttl: Duration) -> Result<(), Error> {
            let expires_at =
                SystemTime::now()
                    .checked_add(ttl)
                    .ok_or(Error::InvalidConfiguration {
                        reason: "InMemoryStore: expires_at overflow",
                    })?;
            let mut guard = self
                .inner
                .lock()
                .map_err(|_err| Error::InvalidConfiguration {
                    reason: "InMemoryStore: lock poisoned",
                })?;
            guard.insert(handle.to_string(), (grant.payload().clone(), expires_at));
            Ok(())
        }

        fn take(&self, handle: &str) -> Result<Option<ProxyContextPayload>, Error> {
            let mut guard = self
                .inner
                .lock()
                .map_err(|_err| Error::InvalidConfiguration {
                    reason: "InMemoryStore: lock poisoned",
                })?;
            match guard.remove(handle) {
                Some((ctx, expires_at)) if expires_at > SystemTime::now() => Ok(Some(ctx)),
                Some(_) | None => Ok(None), // expired or absent
            }
        }
    }

    #[test]
    fn opaque_handle_codec_round_trip_and_one_shot() {
        let codec = OpaqueHandleCodec {
            store: InMemoryStore::new(),
            handle_byte_len: 24,
            ttl: Duration::from_mins(10),
        };
        let context = sample_context();
        let handle = codec.encode(&SealingGrant::issue(&context)).unwrap();
        assert!(handle.len() >= 32, "handle len: {}", handle.len());

        let decoded = codec.decode(&handle).unwrap();
        assert_eq!(decoded.downstream_request_id, context.downstream_request_id);

        // Second decode: one-shot consumption returns None.
        let err = codec.decode(&handle).unwrap_err();
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    #[test]
    fn opaque_handle_codec_expired_entry() {
        let codec = OpaqueHandleCodec {
            store: InMemoryStore::new(),
            handle_byte_len: 24,
            ttl: Duration::from_millis(1),
        };
        let context = sample_context();
        let handle = codec.encode(&SealingGrant::issue(&context)).unwrap();
        std::thread::sleep(Duration::from_millis(10));
        let err = codec.decode(&handle).unwrap_err();
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    // ---------- bounce_to_upstream ----------

    fn synthetic_downstream_request() -> ParsedAuthnRequest {
        // Goes through the sanctioned constructor like production code does;
        // the provenance binding is private, so a struct literal is not
        // available here either.
        let sp = SpDescriptor {
            entity_id: "https://downstream-sp.example.com".into(),
            assertion_consumer_services: vec![SsoResponseEndpoint::post(
                "https://downstream-sp.example.com/acs",
                0,
                true,
            )],
            single_logout_services: vec![],
            signing_certs: vec![],
            encryption_certs: vec![],
            supported_name_id_formats: vec![],
            want_assertions_signed: false,
            authn_requests_signed: false,
            #[cfg(feature = "idp-disco")]
            discovery_response_endpoints: vec![],
            valid_until: None,
            cache_duration: None,
        };
        ParsedAuthnRequest::for_proxy_reissue(
            &sp,
            "_req-downstream".into(),
            SystemTime::now(),
            SsoResponseEndpoint::post("https://downstream-sp.example.com/acs", 0, true),
            Some(NameIdFormat::Persistent),
            Some(RequestedAuthnContext {
                class_refs: vec![AuthnContextClassRef::PasswordProtectedTransport],
                comparison: AuthnContextComparison::Minimum,
            }),
            Some("downstream-rs".into()),
        )
        .expect("the fixture ACS is registered on the fixture SP")
    }

    /// The `pub` policy fields are caller-mutable after validation, so the
    /// context must be sealed from the private provenance instead. Clearing
    /// `requested_authn_context` here previously erased an `Exact` requirement
    /// on its way into the authoritative context.
    #[test]
    fn context_seals_validated_policies_not_the_mutable_copies() {
        let sp = proxy_sp();
        let idp = proxy_idp();
        let proxy = Proxy::new(&sp, &idp, Box::new(Aes256GcmCodec::new([12u8; 32])));
        let upstream = upstream_idp_descriptor();

        let mut downstream = synthetic_downstream_request();
        // Post-validation tampering: weaken the policy the SP actually sent.
        downstream.requested_authn_context = None;
        downstream.requested_name_id_format = None;

        let bounce = proxy
            .bounce_to_upstream(BounceToUpstream {
                upstream_idp: &upstream,
                downstream_request: &downstream,
                propagate_request_flags: true,
                propagate_authn_context: true,
                propagate_name_id_policy: true,
                upstream_binding: Binding::HttpRedirect,
                now: SystemTime::now(),
            })
            .expect("bounce ok");

        let context = proxy
            .decode_context(&bounce.upstream_relay_state)
            .expect("decode context");
        let payload = context.payload();

        assert!(
            payload.requested_authn_context.is_some(),
            "the validated requirement must survive tampering with the pub field"
        );
        assert_eq!(
            payload.requested_name_id_format,
            Some(NameIdFormat::Persistent),
            "the validated NameIDPolicy must survive tampering with the pub field"
        );
    }

    /// A flow is opaque, but opacity only prevents fabrication — not
    /// obtaining a genuine one from a proxy the caller controls. A second
    /// `Proxy` over the same roles with a codec that authenticates nothing
    /// produces structurally identical flows, so the production proxy must
    /// refuse them.
    #[test]
    fn relay_refuses_a_flow_from_another_proxy_instance() {
        let sp = proxy_sp();
        let idp = proxy_idp();
        let production = Proxy::new(&sp, &idp, Box::new(Aes256GcmCodec::new([1u8; 32])));
        let attacker = Proxy::new(&sp, &idp, Box::new(Aes256GcmCodec::new([2u8; 32])));
        let downstream_sp = downstream_sp_descriptor();
        let identity = make_upstream_identity(
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
        );

        // A flow produced by the *other* proxy, otherwise entirely well-formed.
        let foreign = flow(&attacker, sample_context(), identity);

        let err = production
            .relay_to_downstream(RelayToDownstream {
                flow: foreign,
                downstream_sp: &downstream_sp,
                attribute_release: &ReleaseAll,
                name_id_transform: &PassThroughNameId,
                passthrough_authn_context: true,
                now: SystemTime::now(),
                session_lifetime: Duration::from_hours(1),
                subject_confirmation_lifetime: Duration::from_mins(5),
            })
            .expect_err("a flow from another Proxy must be refused");
        assert!(matches!(err, Error::ForeignProxyFlow), "got {err:?}");
    }

    /// Without an upstream claim, or with passthrough disabled, there is
    /// nothing to assert. Emitting PasswordProtectedTransport invented a
    /// *stronger* claim than upstream made — an upstream Password result was
    /// signed downstream as PPT.
    #[test]
    fn relay_does_not_invent_a_stronger_class_than_upstream_attested() {
        let sp = proxy_sp();
        let idp = proxy_idp();
        let proxy = Proxy::new(&sp, &idp, Box::new(Aes256GcmCodec::new([11u8; 32])));
        let downstream_sp = downstream_sp_descriptor();

        // Downstream asked for nothing, so issuance is not blocked and we can
        // observe the class actually emitted.
        let mut context = sample_context();
        context.requested_authn_context = None;

        // Upstream attested plain Password — weaker than PPT.
        let identity = make_upstream_identity(AuthnContextClassRef::Password.as_uri());

        let dispatch = proxy
            .relay_to_downstream(RelayToDownstream {
                flow: flow(&proxy, context, identity),
                downstream_sp: &downstream_sp,
                attribute_release: &ReleaseAll,
                name_id_transform: &PassThroughNameId,
                passthrough_authn_context: false,
                now: SystemTime::now(),
                session_lifetime: Duration::from_hours(1),
                subject_confirmation_lifetime: Duration::from_mins(5),
            })
            .expect("relay ok");

        let SsoResponseDispatch::Post(form) = dispatch else {
            panic!("expected Post");
        };
        let decoded = crate::binding::post::decode(&form.saml_response, None).expect("decode");
        let xml = String::from_utf8(decoded.xml).expect("utf8");

        assert!(
            xml.contains(AuthnContextClassRef::Unspecified.as_uri()),
            "no passthrough must emit Unspecified, got: {xml}"
        );
        assert!(
            !xml.contains(AuthnContextClassRef::PasswordProtectedTransport.as_uri()),
            "must not invent a stronger class than upstream attested: {xml}"
        );
    }

    /// The propagate flags govern what the *upstream* IdP is asked for. The
    /// context is the authoritative record of what the downstream SP required,
    /// and relay enforces non-downgrade against it — so folding the flags into
    /// the stored values erased the requirement. With
    /// `propagate_authn_context: false` the context carried no requested
    /// context at all, and relay skipped non-downgrade entirely: a proxy that
    /// merely declined to forward the request upstream silently stopped
    /// enforcing what downstream asked for.
    #[test]
    fn context_preserves_downstream_requirements_when_propagation_is_off() {
        let sp = proxy_sp();
        let idp = proxy_idp();
        let proxy = Proxy::new(&sp, &idp, Box::new(Aes256GcmCodec::new([7u8; 32])));
        let upstream = upstream_idp_descriptor();
        let downstream = synthetic_downstream_request();

        let bounce = proxy
            .bounce_to_upstream(BounceToUpstream {
                upstream_idp: &upstream,
                downstream_request: &downstream,
                propagate_request_flags: false,
                propagate_authn_context: false,
                propagate_name_id_policy: false,
                upstream_binding: Binding::HttpRedirect,
                now: SystemTime::now(),
            })
            .expect("bounce ok");

        let context = proxy
            .decode_context(&bounce.upstream_relay_state)
            .expect("decode context");
        let payload = context.payload();

        assert_eq!(
            payload
                .requested_authn_context
                .as_ref()
                .map(|r| &r.class_refs),
            Some(&vec![AuthnContextClassRef::PasswordProtectedTransport]),
            "downstream's requested AuthnContext must survive propagate_authn_context: false"
        );
        assert_eq!(
            payload.requested_name_id_format,
            Some(NameIdFormat::Persistent),
            "downstream's NameIDPolicy must survive propagate_name_id_policy: false"
        );
    }

    /// Non-downgrade must bind to the class the response will *advertise*, not
    /// the one the upstream asserted. With `passthrough_authn_context: false`
    /// the emitted class is PasswordProtectedTransport regardless of upstream,
    /// so a downstream `Exact(MultiFactorAuth)` request must be refused —
    /// previously the upstream MFA identity satisfied the check and the signed
    /// assertion then advertised the weaker class.
    #[test]
    fn non_downgrade_binds_to_the_emitted_class_not_the_upstream_one() {
        let sp = proxy_sp();
        let idp = proxy_idp();
        let proxy = Proxy::new(&sp, &idp, Box::new(Aes256GcmCodec::new([8u8; 32])));
        let downstream_sp = downstream_sp_descriptor();

        let mut context = sample_context();
        context.requested_authn_context = Some(RequestedAuthnContext {
            class_refs: vec![AuthnContextClassRef::MultiFactorAuth],
            comparison: AuthnContextComparison::Exact,
        });
        // Upstream genuinely did MFA.
        // Via the constant: the URI is `...MultiFactorAuthentication`, and a
        // literal that drifts parses as a Custom class, which is unrankable.
        let identity = make_upstream_identity(AuthnContextClassRef::MultiFactorAuth.as_uri());

        let err = proxy
            .relay_to_downstream(RelayToDownstream {
                flow: flow(&proxy, context.clone(), identity.clone()),
                downstream_sp: &downstream_sp,
                attribute_release: &ReleaseAll,
                name_id_transform: &PassThroughNameId,
                // ...but the response will advertise PasswordProtectedTransport.
                passthrough_authn_context: false,
                now: SystemTime::now(),
                session_lifetime: Duration::from_hours(1),
                subject_confirmation_lifetime: Duration::from_mins(5),
            })
            .expect_err("the emitted class does not satisfy Exact(MultiFactorAuth)");
        assert!(matches!(err, Error::AuthnContextDowngrade), "got {err:?}");

        // Control: with passthrough on, the emitted class *is* MFA and it passes.
        proxy
            .relay_to_downstream(RelayToDownstream {
                flow: flow(&proxy, context, identity.clone()),
                downstream_sp: &downstream_sp,
                attribute_release: &ReleaseAll,
                name_id_transform: &PassThroughNameId,
                passthrough_authn_context: true,
                now: SystemTime::now(),
                session_lifetime: Duration::from_hours(1),
                subject_confirmation_lifetime: Duration::from_mins(5),
            })
            .expect("passthrough emits MFA, which satisfies the request");
    }

    /// The handle is a bearer credential in a URL; a short one is worse than
    /// the AEAD codec this is chosen over. `0` produced an empty handle shared
    /// by every caller.
    #[test]
    fn opaque_handle_codec_rejects_insufficient_entropy() {
        let context = sample_context();
        let grant = SealingGrant::issue(&context);

        for len in [0usize, 1, 8, 15] {
            let codec = OpaqueHandleCodec {
                store: InMemoryStore::new(),
                handle_byte_len: len,
                ttl: Duration::from_mins(10),
            };
            let err = codec
                .encode(&grant)
                .expect_err("handle_byte_len below the minimum must be refused");
            assert!(
                matches!(err, Error::InvalidConfiguration { .. }),
                "len {len}: got {err:?}"
            );
        }

        // 16 bytes is the boundary and must be accepted.
        let codec = OpaqueHandleCodec {
            store: InMemoryStore::new(),
            handle_byte_len: 16,
            ttl: Duration::from_mins(10),
        };
        let handle = codec.encode(&grant).expect("16 bytes is sufficient");
        assert!(!handle.is_empty());
    }

    #[test]
    fn bounce_to_upstream_returns_dispatch_and_encoded_relay_state() {
        let sp = proxy_sp();
        let idp = proxy_idp();
        let codec = Box::new(Aes256GcmCodec::new([3u8; 32]));
        let proxy = Proxy::new(&sp, &idp, codec);

        let upstream = upstream_idp_descriptor();
        let downstream = synthetic_downstream_request();

        let bounce = proxy
            .bounce_to_upstream(BounceToUpstream {
                upstream_idp: &upstream,
                downstream_request: &downstream,
                propagate_request_flags: true,
                propagate_authn_context: true,
                propagate_name_id_policy: true,
                upstream_binding: Binding::HttpRedirect,
                now: SystemTime::now(),
            })
            .expect("bounce ok");

        // Dispatch is a Redirect with RelayState appended.
        match &bounce.dispatch {
            Dispatch::Redirect(url) => {
                let q = url.query().expect("query");
                assert!(q.contains("SAMLRequest="), "query: {q}");
                assert!(q.contains("RelayState="), "query: {q}");
            }
            other @ Dispatch::Post(_) => panic!("expected Redirect, got {other:?}"),
        }

        // The encoded RelayState round-trips through the codec.
        let decoded = proxy
            .decode_context(&bounce.upstream_relay_state)
            .expect("decode context");
        let decoded = decoded.payload();
        assert_eq!(decoded.downstream_request_id, "_req-downstream");
        assert_eq!(
            decoded.downstream_relay_state.as_deref(),
            Some("downstream-rs")
        );
        assert_eq!(
            decoded.downstream_sp_entity_id,
            "https://downstream-sp.example.com",
        );
    }

    #[test]
    fn bounce_to_upstream_post_binding_injects_relay_state_on_form() {
        let sp = proxy_sp();
        let idp = proxy_idp();
        let codec = Box::new(Aes256GcmCodec::new([4u8; 32]));
        let proxy = Proxy::new(&sp, &idp, codec);

        let upstream = upstream_idp_descriptor();
        let downstream = synthetic_downstream_request();

        let bounce = proxy
            .bounce_to_upstream(BounceToUpstream {
                upstream_idp: &upstream,
                downstream_request: &downstream,
                propagate_request_flags: true,
                propagate_authn_context: true,
                propagate_name_id_policy: true,
                upstream_binding: Binding::HttpPost,
                now: SystemTime::now(),
            })
            .expect("bounce ok");

        match &bounce.dispatch {
            Dispatch::Post(form) => {
                assert_eq!(
                    form.relay_state.as_deref(),
                    Some(bounce.upstream_relay_state.as_str()),
                );
            }
            other @ Dispatch::Redirect(_) => panic!("expected Post, got {other:?}"),
        }
    }

    // ---------- relay_to_downstream ----------

    fn make_upstream_identity(class_ref_uri: &str) -> Identity {
        make_upstream_identity_expiring(class_ref_uri, SystemTime::now())
    }

    /// As above, but with the upstream validity window anchored at `anchor`.
    /// Relay caps downstream deadlines at the upstream expiry, so a test that
    /// runs at an unusual `now` needs an identity that is live at that `now`.
    fn make_upstream_identity_expiring(class_ref_uri: &str, anchor: SystemTime) -> Identity {
        let now = anchor;
        let session_not_on_or_after = now
            .checked_add(Duration::from_hours(1))
            .expect("session_not_on_or_after within range");
        let not_on_or_after = now
            .checked_add(Duration::from_mins(5))
            .expect("not_on_or_after within range");
        Identity::new(
            NameId::email("alice@example.com"),
            Some("upstream-sess-1".into()),
            now,
            Some(session_not_on_or_after),
            Some(class_ref_uri.to_string()),
            vec![
                Attribute::email("alice@example.com"),
                Attribute::display_name("Alice Anderson"),
                Attribute::single("department", "platform"),
            ],
            "_a-upstream".into(),
            not_on_or_after,
            [0u8; 32],
            false,
        )
    }

    /// Attribute release and NameID transformation are caller-supplied and
    /// may write to a pseudonym store or an audit log. These spies record
    /// whether they ran.
    #[derive(Default)]
    struct SpyRelease {
        called: std::sync::atomic::AtomicBool,
    }

    impl AttributeReleasePolicy for SpyRelease {
        fn release(&self, attributes: &[Attribute], _sp: &SpDescriptor) -> Vec<Attribute> {
            self.called.store(true, std::sync::atomic::Ordering::SeqCst);
            attributes.to_vec()
        }
    }

    #[derive(Default)]
    struct SpyNameId {
        called: std::sync::atomic::AtomicBool,
    }

    impl NameIdTransform for SpyNameId {
        fn transform(
            &self,
            name_id: &NameId,
            _attributes: &[Attribute],
            _sp: &SpDescriptor,
        ) -> Result<NameId, Error> {
            self.called.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(name_id.clone())
        }
    }

    /// A `session_lifetime` that overflows `now` makes issuance impossible.
    /// That must be discovered *before* the callbacks run — otherwise the
    /// pseudonym store has already been written for a response that will
    /// never exist.
    #[test]
    fn relay_validates_time_bounds_before_running_callbacks() {
        let sp = proxy_sp();
        let idp = proxy_idp();
        let proxy = Proxy::new(&sp, &idp, Box::new(Aes256GcmCodec::new([5u8; 32])));
        let downstream_sp = downstream_sp_descriptor();
        let context = sample_context();
        let identity = make_upstream_identity(
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
        );
        let release = SpyRelease::default();
        let transform = SpyNameId::default();

        let err = proxy
            .relay_to_downstream(RelayToDownstream {
                flow: flow(&proxy, context.clone(), identity.clone()),
                downstream_sp: &downstream_sp,
                attribute_release: &release,
                name_id_transform: &transform,
                passthrough_authn_context: true,
                now: SystemTime::now(),
                session_lifetime: Duration::MAX,
                subject_confirmation_lifetime: Duration::from_mins(5),
            })
            .expect_err("session_lifetime of Duration::MAX cannot be added to now");

        assert!(
            matches!(err, Error::InvalidConfiguration { .. }),
            "got {err:?}"
        );
        assert!(
            !release.called.load(std::sync::atomic::Ordering::SeqCst),
            "attribute release ran despite an unsatisfiable time bound"
        );
        assert!(
            !transform.called.load(std::sync::atomic::Ordering::SeqCst),
            "NameID transformation ran despite an unsatisfiable time bound"
        );
    }

    /// At `now = UNIX_EPOCH` every addition succeeds, so an overflow-only
    /// preflight let both callbacks run — and issuance then failed on
    /// `Conditions/@NotBefore = now - 1 minute`.
    ///
    /// This is also the portable half of the *formatting* regression:
    /// `checked_sub` succeeds here on every platform, and it is
    /// `format_xs_datetime` that rejects the pre-epoch result. A preflight
    /// doing arithmetic alone fails this test everywhere.
    #[test]
    fn relay_validates_not_before_underflow_before_callbacks() {
        let sp = proxy_sp();
        let idp = proxy_idp();
        let proxy = Proxy::new(&sp, &idp, Box::new(Aes256GcmCodec::new([5u8; 32])));
        let downstream_sp = downstream_sp_descriptor();
        let context = sample_context();
        let identity = make_upstream_identity(
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
        );
        let release = SpyRelease::default();
        let transform = SpyNameId::default();

        let err = proxy
            .relay_to_downstream(RelayToDownstream {
                flow: flow(&proxy, context.clone(), identity.clone()),
                downstream_sp: &downstream_sp,
                attribute_release: &release,
                name_id_transform: &transform,
                passthrough_authn_context: true,
                // Additions from here all succeed; the subtraction does not.
                now: SystemTime::UNIX_EPOCH,
                session_lifetime: Duration::from_hours(1),
                subject_confirmation_lifetime: Duration::from_mins(5),
            })
            .expect_err("NotBefore is pre-epoch at the epoch");

        // `checked_sub` succeeds — `SystemTime` represents pre-epoch instants
        // fine — and `format_xs_datetime` is what rejects it. That is exactly
        // why the preflight has to format, not just do the arithmetic.
        assert!(
            matches!(err, Error::XmlEmit(_)),
            "expected the pre-epoch formatting failure, got {err:?}"
        );
        assert!(
            !release.called.load(std::sync::atomic::Ordering::SeqCst),
            "attribute release ran despite an unissuable assertion"
        );
        assert!(
            !transform.called.load(std::sync::atomic::Ordering::SeqCst),
            "NameID transformation ran despite an unissuable assertion"
        );
    }

    /// The other formatting failure: a civil date outside the representable
    /// range, rather than a pre-epoch one.
    ///
    /// Unix-only. Windows models `SystemTime` as a `FILETIME`, whose range
    /// ends around year 30828 — far short of where `civil_from_days` gives
    /// up — so no such instant is constructible there and `checked_add`
    /// returns `None`. The pre-epoch test above covers formatting on every
    /// platform; this one adds the second path where it is reachable.
    #[cfg(not(windows))]
    #[test]
    fn relay_validates_timestamp_formatting_before_callbacks() {
        let sp = proxy_sp();
        let idp = proxy_idp();
        let proxy = Proxy::new(&sp, &idp, Box::new(Aes256GcmCodec::new([5u8; 32])));
        let downstream_sp = downstream_sp_descriptor();
        let context = sample_context();
        let release = SpyRelease::default();
        let transform = SpyNameId::default();

        // Constructible, and the additions below succeed, but the civil date
        // is outside the representable range.
        let now = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(100_000_000_000_000_000))
            .expect("constructible");
        // Live at that `now`, so the expiry cap does not short-circuit before
        // the formatting step this test is about.
        let identity = make_upstream_identity_expiring(
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
            now,
        );

        let err = proxy
            .relay_to_downstream(RelayToDownstream {
                flow: flow(&proxy, context.clone(), identity.clone()),
                downstream_sp: &downstream_sp,
                attribute_release: &release,
                name_id_transform: &transform,
                passthrough_authn_context: true,
                now,
                session_lifetime: Duration::from_hours(1),
                subject_confirmation_lifetime: Duration::from_mins(5),
            })
            .expect_err("this instant cannot be formatted as xs:dateTime");

        assert!(
            matches!(err, Error::XmlEmit(_)),
            "expected a formatting failure, got {err:?}"
        );
        assert!(
            !release.called.load(std::sync::atomic::Ordering::SeqCst),
            "attribute release ran despite an unformattable timestamp"
        );
        assert!(
            !transform.called.load(std::sync::atomic::Ordering::SeqCst),
            "NameID transformation ran despite an unformattable timestamp"
        );
    }

    /// A downstream assertion cannot outlive the upstream authentication it
    /// rests on, and an already-expired upstream must not reach the callbacks
    /// at all — re-issuing from one would launder a dead authentication into a
    /// live downstream session.
    ///
    /// This replaces a subject-confirmation overflow test. That bound is now
    /// clamped to the session bound, so it can no longer overflow on its own;
    /// keeping the old assertion would have been asserting nothing.
    #[test]
    fn relay_refuses_an_expired_upstream_before_callbacks() {
        let sp = proxy_sp();
        let idp = proxy_idp();
        let proxy = Proxy::new(&sp, &idp, Box::new(Aes256GcmCodec::new([13u8; 32])));
        let downstream_sp = downstream_sp_descriptor();
        let release = SpyRelease::default();
        let transform = SpyNameId::default();

        // Upstream window anchored an hour ago, so it has already closed.
        let past = SystemTime::now()
            .checked_sub(Duration::from_hours(1))
            .expect("representable");
        let identity = make_upstream_identity_expiring(
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
            past,
        );

        let err = proxy
            .relay_to_downstream(RelayToDownstream {
                flow: flow(&proxy, sample_context(), identity),
                downstream_sp: &downstream_sp,
                attribute_release: &release,
                name_id_transform: &transform,
                passthrough_authn_context: true,
                now: SystemTime::now(),
                session_lifetime: Duration::from_hours(1),
                subject_confirmation_lifetime: Duration::from_mins(5),
            })
            .expect_err("an expired upstream cannot authorize a downstream assertion");

        assert!(matches!(err, Error::Expired), "got {err:?}");
        assert!(
            !release.called.load(std::sync::atomic::Ordering::SeqCst),
            "attribute release ran for an expired upstream"
        );
        assert!(
            !transform.called.load(std::sync::atomic::Ordering::SeqCst),
            "NameID transformation ran for an expired upstream"
        );
    }

    #[test]
    fn relay_to_downstream_end_to_end_returns_post_dispatch() {
        let sp = proxy_sp();
        let idp = proxy_idp();
        let codec = Box::new(Aes256GcmCodec::new([5u8; 32]));
        let proxy = Proxy::new(&sp, &idp, codec);

        let downstream_sp = downstream_sp_descriptor();
        let context = sample_context();
        let identity = make_upstream_identity(
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
        );

        let dispatch = proxy
            .relay_to_downstream(RelayToDownstream {
                flow: flow(&proxy, context.clone(), identity.clone()),
                downstream_sp: &downstream_sp,
                attribute_release: &ReleaseAllowList {
                    names: vec!["urn:oid:0.9.2342.19200300.100.1.3".into()],
                },
                name_id_transform: &PersistentPerSpHmac {
                    key: [9u8; 32],
                    format: NameIdFormat::Persistent,
                },
                passthrough_authn_context: true,
                now: SystemTime::now(),
                session_lifetime: Duration::from_hours(1),
                subject_confirmation_lifetime: Duration::from_mins(5),
            })
            .expect("relay ok");

        // Verify POST dispatch points back at the downstream ACS with the
        // downstream RelayState preserved.
        match dispatch {
            SsoResponseDispatch::Post(form) => {
                assert_eq!(
                    form.action.as_str(),
                    "https://downstream-sp.example.com/acs",
                );
                assert_eq!(form.relay_state.as_deref(), Some("opaque-downstream-state"),);
                // The body is a base64-encoded Response; we just smoke-check
                // non-empty here (full parse coverage lives in idp.rs).
                assert!(!form.saml_response.is_empty());
            }
            other @ SsoResponseDispatch::Artifact(_) => {
                panic!("expected Post, got {other:?}")
            }
        }
    }

    #[test]
    fn relay_to_downstream_rejects_authn_context_downgrade() {
        let sp = proxy_sp();
        let idp = proxy_idp();
        let codec = Box::new(Aes256GcmCodec::new([5u8; 32]));
        let proxy = Proxy::new(&sp, &idp, codec);

        let downstream_sp = downstream_sp_descriptor();
        // Downstream requested PasswordProtectedTransport (minimum), upstream
        // returned plain Password — downgrade.
        let context = sample_context();
        let identity = make_upstream_identity("urn:oasis:names:tc:SAML:2.0:ac:classes:Password");

        let err = proxy
            .relay_to_downstream(RelayToDownstream {
                flow: flow(&proxy, context.clone(), identity.clone()),
                downstream_sp: &downstream_sp,
                attribute_release: &ReleaseAll,
                name_id_transform: &PassThroughNameId,
                passthrough_authn_context: true,
                now: SystemTime::now(),
                session_lifetime: Duration::from_hours(1),
                subject_confirmation_lifetime: Duration::from_mins(5),
            })
            .unwrap_err();
        assert!(matches!(err, Error::AuthnContextDowngrade));
    }

    // ---------- Attribute release ----------

    #[test]
    fn release_none_drops_everything() {
        let sp = downstream_sp_descriptor();
        let attrs = vec![Attribute::email("x@example.com")];
        let out = ReleaseNone.release(&attrs, &sp);
        assert!(out.is_empty());
    }

    #[test]
    fn release_allow_list_filters() {
        let sp = downstream_sp_descriptor();
        let attrs = vec![
            Attribute::email("x@example.com"),
            Attribute::display_name("X"),
            Attribute::single("dept", "platform"),
        ];
        let policy = ReleaseAllowList {
            names: vec!["urn:oid:0.9.2342.19200300.100.1.3".into()],
        };
        let out = policy.release(&attrs, &sp);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "urn:oid:0.9.2342.19200300.100.1.3");
    }

    #[test]
    fn release_all_returns_clone() {
        let sp = downstream_sp_descriptor();
        let attrs = vec![
            Attribute::email("x@example.com"),
            Attribute::display_name("X"),
        ];
        let out = ReleaseAll.release(&attrs, &sp);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn release_per_sp_falls_back_to_default() {
        let sp = downstream_sp_descriptor();
        let mut allow_lists = HashMap::new();
        allow_lists.insert(
            "https://other-sp.example.com".to_string(),
            vec!["only-this".to_string()],
        );
        let policy = ReleasePerSp {
            allow_lists,
            default: Box::new(ReleaseNone),
        };
        let attrs = vec![Attribute::email("x@example.com")];
        let out = policy.release(&attrs, &sp);
        assert!(out.is_empty(), "default ReleaseNone should drop all");
    }

    #[test]
    fn release_per_sp_uses_specific_allow_list() {
        let sp = downstream_sp_descriptor();
        let mut allow_lists = HashMap::new();
        allow_lists.insert(
            sp.entity_id.clone(),
            vec!["urn:oid:0.9.2342.19200300.100.1.3".to_string()],
        );
        let policy = ReleasePerSp {
            allow_lists,
            default: Box::new(ReleaseAll),
        };
        let attrs = vec![
            Attribute::email("x@example.com"),
            Attribute::display_name("X"),
        ];
        let out = policy.release(&attrs, &sp);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "urn:oid:0.9.2342.19200300.100.1.3");
    }

    // ---------- NameID transforms ----------

    #[test]
    fn persistent_per_sp_hmac_is_stable_and_sp_scoped() {
        let upstream = NameId::email("alice@example.com");
        let sp_a = downstream_sp_descriptor();
        let mut sp_b = downstream_sp_descriptor();
        sp_b.entity_id = "https://other-sp.example.com".to_string();

        let transform = PersistentPerSpHmac {
            key: [11u8; 32],
            format: NameIdFormat::Persistent,
        };

        let a1 = transform.transform(&upstream, &[], &sp_a).unwrap();
        let a2 = transform.transform(&upstream, &[], &sp_a).unwrap();
        let b1 = transform.transform(&upstream, &[], &sp_b).unwrap();

        // Stable across calls for the same (subject, SP).
        assert_eq!(a1.value, a2.value);
        // Different SP → different value.
        assert_ne!(a1.value, b1.value);
        // Format honored.
        assert_eq!(a1.format, NameIdFormat::Persistent);
        // SP qualifier set.
        assert_eq!(
            a1.sp_name_qualifier.as_deref(),
            Some(sp_a.entity_id.as_str())
        );
    }

    #[test]
    fn passthrough_name_id_clones_upstream() {
        let upstream = NameId::email("alice@example.com");
        let sp = downstream_sp_descriptor();
        let out = PassThroughNameId.transform(&upstream, &[], &sp).unwrap();
        assert_eq!(out, upstream);
    }

    #[test]
    fn name_id_from_attribute_lifts_value() {
        let upstream = NameId::new("opaque", NameIdFormat::Transient);
        let sp = downstream_sp_descriptor();
        let attrs = vec![Attribute::email("alice@example.com")];
        let transform = NameIdFromAttribute {
            attribute_name: "urn:oid:0.9.2342.19200300.100.1.3".into(),
            format: NameIdFormat::EmailAddress,
        };
        let out = transform.transform(&upstream, &attrs, &sp).unwrap();
        assert_eq!(out.value, "alice@example.com");
        assert_eq!(out.format, NameIdFormat::EmailAddress);
    }

    #[test]
    fn name_id_from_attribute_missing_attribute_errors() {
        let upstream = NameId::new("opaque", NameIdFormat::Transient);
        let sp = downstream_sp_descriptor();
        let transform = NameIdFromAttribute {
            attribute_name: "nope".into(),
            format: NameIdFormat::EmailAddress,
        };
        let err = transform.transform(&upstream, &[], &sp).unwrap_err();
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    // ---------- AuthnContext comparator (trait surface only) ----------
    //
    // The full set-aggregating semantics of `StandardComparator::evaluate`
    // are covered in `authn_context::tests`. Here we only verify the
    // `AuthnContextComparator` trait wrapper that exposes the per-URI shim
    // used by callers plugging in custom hierarchies.

    #[test]
    fn authn_context_comparator_trait_satisfies_uses_exact_semantics() {
        let c = StandardComparator;
        assert!(c.satisfies(
            AuthnContextClassRef::Password.as_uri(),
            AuthnContextClassRef::Password.as_uri(),
        ));
        assert!(!c.satisfies(
            AuthnContextClassRef::Password.as_uri(),
            AuthnContextClassRef::PasswordProtectedTransport.as_uri(),
        ));
    }

    // ---------- relay_to_downstream: spec-bug regression for `Better` ----------
    //
    // SAML 2.0 Core §3.3.2.2.1 defines `Better` as "stronger than each of the
    // requested" — i.e. strictly greater than the MAX of the requested set.
    // The previous in-proxy implementation iterated `requested.class_refs`
    // with `any()` and short-circuited on the first match, which accepted
    // `actual > min(requested)` — too permissive. These tests pin the fixed
    // behavior to the canonical comparator.

    fn context_with_requested(refs: Vec<AuthnContextClassRef>) -> ProxyContextPayload {
        let mut ctx = sample_context();
        ctx.requested_authn_context = Some(RequestedAuthnContext {
            class_refs: refs,
            comparison: AuthnContextComparison::Better,
        });
        ctx
    }

    #[test]
    fn relay_to_downstream_better_rejects_actual_between_requested_set_bounds() {
        // Requested {Password (2), Smartcard (6)} with `Better`. Spec demands
        // `actual > max(requested) == 6`. Kerberos has strength 5, so it sits
        // *between* the min and max — the legacy `any()` fold returned true
        // because `5 > 2`. Post-fix it must be rejected.
        let sp = proxy_sp();
        let idp = proxy_idp();
        let codec = Box::new(Aes256GcmCodec::new([5u8; 32]));
        let proxy = Proxy::new(&sp, &idp, codec);

        let downstream_sp = downstream_sp_descriptor();
        let context = context_with_requested(vec![
            AuthnContextClassRef::Password,
            AuthnContextClassRef::Smartcard,
        ]);
        let identity = make_upstream_identity(AuthnContextClassRef::Kerberos.as_uri());

        let err = proxy
            .relay_to_downstream(RelayToDownstream {
                flow: flow(&proxy, context.clone(), identity.clone()),
                downstream_sp: &downstream_sp,
                attribute_release: &ReleaseAll,
                name_id_transform: &PassThroughNameId,
                passthrough_authn_context: true,
                now: SystemTime::now(),
                session_lifetime: Duration::from_hours(1),
                subject_confirmation_lifetime: Duration::from_mins(5),
            })
            .expect_err("Better must compare against max(requested), not min");
        assert!(matches!(err, Error::AuthnContextDowngrade));
    }

    #[test]
    fn relay_to_downstream_better_accepts_actual_strictly_above_max() {
        // Same requested set {Password, Smartcard}; actual MultiFactorAuth (8)
        // is strictly above the max (6) → satisfied.
        let sp = proxy_sp();
        let idp = proxy_idp();
        let codec = Box::new(Aes256GcmCodec::new([5u8; 32]));
        let proxy = Proxy::new(&sp, &idp, codec);

        let downstream_sp = downstream_sp_descriptor();
        let context = context_with_requested(vec![
            AuthnContextClassRef::Password,
            AuthnContextClassRef::Smartcard,
        ]);
        let identity = make_upstream_identity(AuthnContextClassRef::MultiFactorAuth.as_uri());

        proxy
            .relay_to_downstream(RelayToDownstream {
                flow: flow(&proxy, context.clone(), identity.clone()),
                downstream_sp: &downstream_sp,
                attribute_release: &ReleaseAll,
                name_id_transform: &PassThroughNameId,
                passthrough_authn_context: true,
                now: SystemTime::now(),
                session_lifetime: Duration::from_hours(1),
                subject_confirmation_lifetime: Duration::from_mins(5),
            })
            .expect("MultiFactorAuth > max(Password, Smartcard) under Better");
    }

    /// End-to-end laundering regression: rewriting the `pub` wire fields and
    /// then bouncing must not carry the mutation into the sealed context.
    ///
    /// The proxy seals what downstream is later trusted to be, so if it read
    /// the mutable copies a caller could validate against SP-A, rewrite both
    /// fields to SP-B, bounce, and have the proxy launder the rewrite into a
    /// context that downstream treats as authenticated. Decoding the sealed
    /// blob is what makes this end-to-end — asserting on the request's own
    /// accessors would pass whatever the proxy did with them.
    #[test]
    fn bouncing_does_not_launder_mutated_wire_fields_into_the_context() {
        let sp = proxy_sp();
        let idp = proxy_idp();
        let codec = Box::new(Aes256GcmCodec::new([9u8; 32]));
        let proxy = Proxy::new(&sp, &idp, codec);
        let upstream = upstream_idp_descriptor();

        let mut downstream = synthetic_downstream_request();
        let real_sp = downstream.validated_sp().to_owned();
        let real_acs_url = downstream.validated_acs().url.clone();

        // Everything a caller can reach.
        downstream.issuer = "https://attacker-sp.example.com".into();
        downstream.assertion_consumer_service =
            SsoResponseEndpoint::post("https://attacker-sp.example.com/acs", 7, true);

        let bounce = proxy
            .bounce_to_upstream(BounceToUpstream {
                upstream_idp: &upstream,
                downstream_request: &downstream,
                propagate_request_flags: true,
                propagate_authn_context: true,
                propagate_name_id_policy: true,
                upstream_binding: Binding::HttpRedirect,
                now: SystemTime::now(),
            })
            .expect("bounce ok");

        let sealed = proxy
            .decode_context(&bounce.upstream_relay_state)
            .expect("decode context");
        let sealed = sealed.payload();

        assert_eq!(
            sealed.downstream_sp_entity_id, real_sp,
            "the sealed context must carry validated provenance, not the rewritten issuer"
        );
        assert_eq!(
            sealed.downstream_acs.url, real_acs_url,
            "the sealed context must carry the canonical ACS, not the rewritten one"
        );
    }

    /// Caller callbacks must not run for a context that will be rejected.
    ///
    /// Attribute release and NameID transformation are caller-supplied and may
    /// hit a directory or a pseudonym store. A stale or invalid context
    /// driving those side effects — and only then failing on
    /// `UnregisteredAcs` — is a real defect, so ACS validation is ordered
    /// ahead of them and this test spies on the callbacks to prove it.
    #[test]
    fn callbacks_do_not_run_when_the_acs_is_unregistered() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct SpyRelease(AtomicUsize);
        impl AttributeReleasePolicy for SpyRelease {
            fn release(&self, upstream: &[Attribute], _sp: &SpDescriptor) -> Vec<Attribute> {
                self.0.fetch_add(1, Ordering::SeqCst);
                upstream.to_vec()
            }
        }
        struct SpyTransform(AtomicUsize);
        impl NameIdTransform for SpyTransform {
            fn transform(
                &self,
                upstream_subject: &NameId,
                _upstream_attributes: &[Attribute],
                _downstream_sp: &SpDescriptor,
            ) -> Result<NameId, Error> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(upstream_subject.clone())
            }
        }

        let sp = proxy_sp();
        let idp = proxy_idp();
        let codec = Box::new(Aes256GcmCodec::new([11u8; 32]));
        let proxy = Proxy::new(&sp, &idp, codec);

        // Context names an ACS this SP does not register.
        let mut context = sample_context();
        context.downstream_acs =
            SsoResponseEndpoint::post("https://downstream-sp.example.com/not-registered", 0, true)
                .as_endpoint();

        let release = SpyRelease(AtomicUsize::new(0));
        let transform = SpyTransform(AtomicUsize::new(0));
        let identity = make_upstream_identity(AuthnContextClassRef::Password.as_uri());

        let err = proxy
            .relay_to_downstream(RelayToDownstream {
                flow: flow(&proxy, context.clone(), identity.clone()),
                downstream_sp: &downstream_sp_descriptor(),
                attribute_release: &release,
                name_id_transform: &transform,
                passthrough_authn_context: true,
                now: SystemTime::now(),
                session_lifetime: Duration::from_hours(1),
                subject_confirmation_lifetime: Duration::from_mins(5),
            })
            .expect_err("the ACS is not registered for this SP");

        assert!(matches!(err, Error::UnregisteredAcs { .. }), "got {err:?}");
        assert_eq!(release.0.load(Ordering::SeqCst), 0, "attribute release ran");
        assert_eq!(
            transform.0.load(Ordering::SeqCst),
            0,
            "NameID transform ran"
        );
    }

    /// An authentic context for SP-A must not be relayable to SP-B, even when
    /// the two legitimately share an ACS URL and binding. Without the check,
    /// `for_proxy_reissue` would stamp SP-B's provenance onto SP-A's context —
    /// replacing the binding rather than carrying it forward.
    #[test]
    fn relay_refuses_a_context_belonging_to_another_sp() {
        let sp = proxy_sp();
        let idp = proxy_idp();
        let codec = Box::new(Aes256GcmCodec::new([7u8; 32]));
        let proxy = Proxy::new(&sp, &idp, codec);

        // Same ACS as the real downstream SP; only the entity ID differs.
        let mut twin = downstream_sp_descriptor();
        twin.entity_id = "https://twin-sp.example.com".into();

        let context = sample_context();
        let identity = make_upstream_identity(AuthnContextClassRef::Password.as_uri());

        let err = proxy
            .relay_to_downstream(RelayToDownstream {
                flow: flow(&proxy, context.clone(), identity.clone()),
                downstream_sp: &twin,
                attribute_release: &ReleaseAll,
                name_id_transform: &PassThroughNameId,
                passthrough_authn_context: true,
                now: SystemTime::now(),
                session_lifetime: Duration::from_hours(1),
                subject_confirmation_lifetime: Duration::from_mins(5),
            })
            .expect_err("the context was minted for a different SP");
        assert!(
            matches!(err, Error::IssuerMismatch { ref got, .. }
                if got.as_deref() == Some("https://twin-sp.example.com")),
            "got {err:?}"
        );
    }

    #[test]
    fn relay_to_downstream_custom_actual_under_ordered_comparison_fails_closed() {
        // Non-rankable actual URI under a strength-ordered comparison must
        // collapse to AuthnContextDowngrade (NotComparable → fail-closed).
        let sp = proxy_sp();
        let idp = proxy_idp();
        let codec = Box::new(Aes256GcmCodec::new([5u8; 32]));
        let proxy = Proxy::new(&sp, &idp, codec);

        let downstream_sp = downstream_sp_descriptor();
        let context = context_with_requested(vec![AuthnContextClassRef::Password]);
        let identity = make_upstream_identity("urn:example:vendor:opaque");

        let err = proxy
            .relay_to_downstream(RelayToDownstream {
                flow: flow(&proxy, context.clone(), identity.clone()),
                downstream_sp: &downstream_sp,
                attribute_release: &ReleaseAll,
                name_id_transform: &PassThroughNameId,
                passthrough_authn_context: true,
                now: SystemTime::now(),
                session_lifetime: Duration::from_hours(1),
                subject_confirmation_lifetime: Duration::from_mins(5),
            })
            .expect_err("non-rankable actual must fail closed under Better");
        assert!(matches!(err, Error::AuthnContextDowngrade));
    }
}
