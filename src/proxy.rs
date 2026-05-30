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
use crate::authn::request_validate::{AcsSelection, ParsedAuthnRequest};
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

    /// Borrow the context codec.
    pub fn context_codec(&self) -> &dyn ProxyContextCodec {
        &*self.context_codec
    }
}

// =============================================================================
// ProxyContext + codec trait
// =============================================================================

/// AEAD wrapper for the stateless context blob carried in `RelayState` across
/// the upstream round-trip. See RFC-005 §2.
pub trait ProxyContextCodec: Send + Sync {
    fn encode(&self, context: &ProxyContext) -> Result<String, Error>;
    fn decode(&self, blob: &str) -> Result<ProxyContext, Error>;
}

/// Opaque context carried across the upstream round-trip. See RFC-005 §3.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxyContext {
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
    pub upstream_tracker: LoginTracker,
    /// Issued-at timestamp. Codec rejects blobs older than its `max_age`.
    pub issued_at: SystemTime,
}

// =============================================================================
// AES-256-GCM codec (RFC-005 §2.1)
// =============================================================================

/// Stateless AEAD codec: postcard-serialized `ProxyContext` sealed with
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
    fn encode(&self, context: &ProxyContext) -> Result<String, Error> {
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

    fn decode(&self, blob: &str) -> Result<ProxyContext, Error> {
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

        let context: ProxyContext =
            postcard::from_bytes(&plaintext).map_err(|_err| Error::InvalidConfiguration {
                reason: "proxy context deserialize",
            })?;

        // Enforce max_age. We tolerate small backward clock skew (a context
        // dated in the future is treated as `now`).
        let age = SystemTime::now()
            .duration_since(context.issued_at)
            .unwrap_or(Duration::ZERO);
        if age > self.max_age {
            return Err(Error::InvalidConfiguration {
                reason: "proxy context expired",
            });
        }

        Ok(context)
    }
}

// =============================================================================
// Opaque-handle codec for Redirect binding (RFC-005 §2.1)
// =============================================================================

/// Caller-supplied storage for the opaque-handle codec. `take` is one-shot.
pub trait ProxyContextStore: Send + Sync {
    fn put(&self, handle: &str, context: &ProxyContext, ttl: Duration) -> Result<(), Error>;
    fn take(&self, handle: &str) -> Result<Option<ProxyContext>, Error>;
}

/// Short random handle as `RelayState`; context lives in a caller-supplied
/// store. See RFC-005 §2.1.
pub struct OpaqueHandleCodec<S: ProxyContextStore> {
    pub store: S,
    /// Bytes of entropy in the handle. Default 24 → 32 base64url chars.
    pub handle_byte_len: usize,
    pub ttl: Duration,
}

impl<S: ProxyContextStore> ProxyContextCodec for OpaqueHandleCodec<S> {
    fn encode(&self, context: &ProxyContext) -> Result<String, Error> {
        let mut bytes = vec![0u8; self.handle_byte_len];
        rand::rng().fill_bytes(&mut bytes);
        let handle = URL_SAFE_NO_PAD.encode(&bytes);
        self.store.put(&handle, context, self.ttl)?;
        Ok(handle)
    }

    fn decode(&self, blob: &str) -> Result<ProxyContext, Error> {
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

/// Inputs for [`Proxy::relay_to_downstream`]. See RFC-005 §4.2.
pub struct RelayToDownstream<'a> {
    pub context: &'a ProxyContext,
    pub upstream_identity: &'a Identity,
    /// Downstream SP descriptor (caller looks it up from
    /// `context.downstream_sp_entity_id`).
    pub downstream_sp: &'a SpDescriptor,
    /// Pluggable: which upstream attributes to release downstream.
    pub attribute_release: &'a dyn AttributeReleasePolicy,
    /// Pluggable: how to mint a NameID for the downstream SP.
    pub name_id_transform: &'a dyn NameIdTransform,
    /// If true, set downstream AuthnContextClassRef = upstream's actual.
    /// If false, fall back to `PasswordProtectedTransport`.
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

        // 1. Build StartLogin honoring propagate flags.
        let force_authn = input.propagate_request_flags && downstream.force_authn;
        let is_passive = input.propagate_request_flags && downstream.is_passive;
        let requested_name_id_format = if input.propagate_name_id_policy {
            downstream.requested_name_id_format.clone()
        } else {
            None
        };
        let requested_authn_context = if input.propagate_authn_context {
            downstream.requested_authn_context.clone()
        } else {
            None
        };

        let result = self.sp.start_login(
            input.upstream_idp,
            StartLogin {
                // We replace RelayState below with the encoded ProxyContext.
                relay_state: None,
                binding: input.upstream_binding,
                force_authn,
                is_passive,
                requested_name_id_format: requested_name_id_format.clone(),
                requested_authn_context: requested_authn_context.clone(),
                acs_index: None,
                acs_url: None,
                response_binding: None,
            },
        )?;

        // 2. Build the ProxyContext from the parsed downstream request.
        let context = ProxyContext {
            downstream_request_id: downstream.id.clone(),
            downstream_sp_entity_id: downstream.issuer.clone(),
            downstream_acs: downstream.assertion_consumer_service.as_endpoint(),
            downstream_relay_state: downstream.relay_state.clone(),
            requested_authn_context,
            requested_name_id_format,
            upstream_tracker: result.tracker,
            issued_at: input.now,
        };

        // 3. Encode the context for the wire.
        let upstream_relay_state = self.context_codec.encode(&context)?;

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

    /// Translate an upstream `Identity` into a downstream `<samlp:Response>`,
    /// applying attribute release, NameID transformation, and AuthnContext
    /// non-downgrade. See RFC-005 §4.2.
    pub fn relay_to_downstream(
        &self,
        input: RelayToDownstream<'_>,
    ) -> Result<SsoResponseDispatch, Error> {
        // 1. Enforce AuthnContext non-downgrade (§7). The set-aggregating
        //    semantics — in particular, `Better` requires the actual class ref
        //    to be strictly stronger than the *max* of the requested set, per
        //    SAML 2.0 Core §3.3.2.2.1 — live in
        //    [`crate::authn_context::StandardComparator`]. We collapse both
        //    `NotSatisfied` and `NotComparable` to `AuthnContextDowngrade`
        //    (fail-closed), matching the SP-side response validator.
        if let Some(requested) = &input.context.requested_authn_context {
            let actual = input
                .upstream_identity
                .authn_context_class_ref
                .as_deref()
                .ok_or(Error::AuthnContextDowngrade)?;
            match StandardComparator.evaluate(requested, actual) {
                ComparatorOutcome::Satisfied => {}
                ComparatorOutcome::NotSatisfied | ComparatorOutcome::NotComparable => {
                    return Err(Error::AuthnContextDowngrade);
                }
            }
        }

        // 2. Attribute release.
        let attributes = input
            .attribute_release
            .release(&input.upstream_identity.attributes, input.downstream_sp);

        // 3. NameID transformation.
        let downstream_name_id = input.name_id_transform.transform(
            &input.upstream_identity.name_id,
            &input.upstream_identity.attributes,
            input.downstream_sp,
        )?;

        // 4. Decide downstream AuthnContextClassRef.
        let downstream_class_ref = if input.passthrough_authn_context {
            input
                .upstream_identity
                .authn_context_class_ref
                .as_deref()
                .map_or(
                    AuthnContextClassRef::PasswordProtectedTransport,
                    AuthnContextClassRef::from_uri,
                )
        } else {
            AuthnContextClassRef::PasswordProtectedTransport
        };

        // 5. Build a synthetic ParsedAuthnRequest from the proxy context.
        //    The `assertion_consumer_service` field is type-narrowed to
        //    `SsoResponseEndpoint`; narrow the stashed `Endpoint` accordingly.
        let acs_endpoint =
            SsoResponseEndpoint::try_from_endpoint(input.context.downstream_acs.clone())?;
        let protocol_binding = Some(acs_endpoint.binding);
        let synthetic = ParsedAuthnRequest {
            id: input.context.downstream_request_id.clone(),
            issuer: input.context.downstream_sp_entity_id.clone(),
            issue_instant: input.context.issued_at,
            destination: None,
            assertion_consumer_service: acs_endpoint,
            protocol_binding,
            assertion_consumer_service_selection: AcsSelection::Default,
            force_authn: false,
            is_passive: false,
            requested_name_id_format: input.context.requested_name_id_format.clone(),
            requested_authn_context: input.context.requested_authn_context.clone(),
            relay_state: input.context.downstream_relay_state.clone(),
        };

        // 6. Hand off to the IdP role for `<samlp:Response>` issuance.
        let session_index = make_session_index();
        let session_not_on_or_after =
            input
                .now
                .checked_add(input.session_lifetime)
                .ok_or(Error::InvalidConfiguration {
                    reason: "session_not_on_or_after overflow",
                })?;
        self.idp.issue_response(IssueResponse {
            sp: input.downstream_sp,
            in_response_to: &synthetic,
            name_id: downstream_name_id,
            attributes,
            authn_instant: input.upstream_identity.authn_instant,
            session_index,
            session_not_on_or_after: Some(session_not_on_or_after),
            authn_context_class_ref: downstream_class_ref,
            force_encrypt_assertion: None,
            now: input.now,
            assertion_lifetime: input.session_lifetime,
            subject_confirmation_lifetime: input.subject_confirmation_lifetime,
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
    use crate::binding::SsoResponseBinding;
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
        }
    }

    fn sample_context() -> ProxyContext {
        let tracker_issued_at = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_hours(494_388))
            .expect("tracker issued_at within representable range");
        ProxyContext {
            downstream_request_id: "_req-downstream".into(),
            downstream_sp_entity_id: "https://downstream-sp.example.com".into(),
            downstream_acs: Endpoint::post("https://downstream-sp.example.com/acs", 0, true),
            downstream_relay_state: Some("opaque-downstream-state".into()),
            requested_authn_context: Some(RequestedAuthnContext {
                class_refs: vec![AuthnContextClassRef::PasswordProtectedTransport],
                comparison: AuthnContextComparison::Minimum,
            }),
            requested_name_id_format: Some(NameIdFormat::Persistent),
            upstream_tracker: LoginTracker {
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
        let blob = codec.encode(&context).expect("encode");
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
        let blob = codec.encode(&context).unwrap();

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
        let blob = codec.encode(&context).unwrap();
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
        inner: Mutex<HashMap<String, (ProxyContext, SystemTime)>>,
    }

    impl InMemoryStore {
        fn new() -> Self {
            Self {
                inner: Mutex::new(HashMap::new()),
            }
        }
    }

    impl ProxyContextStore for InMemoryStore {
        fn put(&self, handle: &str, context: &ProxyContext, ttl: Duration) -> Result<(), Error> {
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
            guard.insert(handle.to_string(), (context.clone(), expires_at));
            Ok(())
        }

        fn take(&self, handle: &str) -> Result<Option<ProxyContext>, Error> {
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
        let handle = codec.encode(&context).unwrap();
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
        let handle = codec.encode(&context).unwrap();
        std::thread::sleep(Duration::from_millis(10));
        let err = codec.decode(&handle).unwrap_err();
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    // ---------- bounce_to_upstream ----------

    fn synthetic_downstream_request() -> ParsedAuthnRequest {
        ParsedAuthnRequest {
            id: "_req-downstream".into(),
            issuer: "https://downstream-sp.example.com".into(),
            issue_instant: SystemTime::now(),
            destination: Some("https://proxy.example.com/sso".into()),
            assertion_consumer_service: SsoResponseEndpoint::post(
                "https://downstream-sp.example.com/acs",
                0,
                true,
            ),
            protocol_binding: Some(SsoResponseBinding::HttpPost),
            assertion_consumer_service_selection: AcsSelection::Default,
            force_authn: false,
            is_passive: false,
            requested_name_id_format: Some(NameIdFormat::Persistent),
            requested_authn_context: Some(RequestedAuthnContext {
                class_refs: vec![AuthnContextClassRef::PasswordProtectedTransport],
                comparison: AuthnContextComparison::Minimum,
            }),
            relay_state: Some("downstream-rs".into()),
        }
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
            .context_codec()
            .decode(&bounce.upstream_relay_state)
            .expect("decode context");
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
        let now = SystemTime::now();
        let session_not_on_or_after = now
            .checked_add(Duration::from_hours(1))
            .expect("session_not_on_or_after within range");
        let not_on_or_after = now
            .checked_add(Duration::from_mins(5))
            .expect("not_on_or_after within range");
        Identity {
            name_id: NameId::email("alice@example.com"),
            session_index: Some("upstream-sess-1".into()),
            authn_instant: now,
            session_not_on_or_after: Some(session_not_on_or_after),
            authn_context_class_ref: Some(class_ref_uri.to_string()),
            attributes: vec![
                Attribute::email("alice@example.com"),
                Attribute::display_name("Alice Anderson"),
                Attribute::single("department", "platform"),
            ],
            assertion_id: "_a-upstream".into(),
            not_on_or_after,
            verifying_cert_fingerprint: [0u8; 32],
            is_one_time_use: false,
        }
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
                context: &context,
                upstream_identity: &identity,
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
                context: &context,
                upstream_identity: &identity,
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

    fn context_with_requested(refs: Vec<AuthnContextClassRef>) -> ProxyContext {
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
                context: &context,
                upstream_identity: &identity,
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
                context: &context,
                upstream_identity: &identity,
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
                context: &context,
                upstream_identity: &identity,
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
