//! End-to-end proxy flow test.
//!
//! Drives a four-role chain end-to-end:
//!   downstream SP -> proxy (IdP face) -> proxy (SP face) -> upstream IdP
//!                <-                  <-                  <-
//!
//! Asserts that attribute release filters the upstream attribute bag, and
//! that the downstream NameID is scoped to the downstream SP via
//! `SPNameQualifier` (the privacy property that prevents cross-SP correlation).

#[path = "common/mod.rs"]
mod common;

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use saml::attribute::Attribute;
use saml::authn_context::AuthnContextClassRef;
use saml::binding::{Binding, Dispatch, SsoResponseBinding, SsoResponseDispatch};
use saml::idp::{ConsumeAuthnRequest, IssueResponse};
use saml::nameid::{NameId, NameIdFormat};
use saml::proxy::{
    Aes256GcmCodec, BounceToUpstream, PersistentPerSpHmac, Proxy, ProxyContext, RelayToDownstream,
    ReleaseAllowList,
};
use saml::replay::ReplayMode;
use saml::sp::{ConsumeResponse, StartLogin};

// Downstream SP — the relying app.
const DOWN_SP_ENTITY_ID: &str = "https://app.example.com/saml";
const DOWN_SP_ACS_URL: &str = "https://app.example.com/saml/acs";

// Proxy — wears both hats.
const PROXY_IDP_ENTITY_ID: &str = "https://hub.example.com/saml/idp";
const PROXY_IDP_SSO_URL: &str = "https://hub.example.com/saml/sso";
const PROXY_SP_ENTITY_ID: &str = "https://hub.example.com/saml/sp";
const PROXY_SP_ACS_URL: &str = "https://hub.example.com/saml/acs";

// Upstream IdP — the real authority.
const UP_IDP_ENTITY_ID: &str = "https://idp.example.com/saml";
const UP_IDP_SSO_URL: &str = "https://idp.example.com/saml/sso";

const USER_EMAIL: &str = "alice@example.com";
const USER_DISPLAY: &str = "Alice Example";

#[test]
fn proxy_round_trip_releases_attributes_and_scopes_name_id() {
    // ---- Build all four roles. -----------------------------------------
    let downstream_sp =
        common::make_sp(DOWN_SP_ENTITY_ID, DOWN_SP_ACS_URL, false).expect("downstream sp builds");
    let proxy_idp =
        common::make_idp(PROXY_IDP_ENTITY_ID, PROXY_IDP_SSO_URL).expect("proxy idp builds");
    let proxy_sp =
        common::make_sp(PROXY_SP_ENTITY_ID, PROXY_SP_ACS_URL, false).expect("proxy sp builds");
    let upstream_idp =
        common::make_idp(UP_IDP_ENTITY_ID, UP_IDP_SSO_URL).expect("upstream idp builds");

    // Descriptors via metadata round-trip — same wire-level handshake a
    // real deployment would use.
    let downstream_sp_descriptor =
        common::sp_descriptor(&downstream_sp).expect("downstream sp descriptor");
    let proxy_idp_descriptor = common::idp_descriptor(&proxy_idp).expect("proxy idp descriptor");
    let proxy_sp_descriptor = common::sp_descriptor(&proxy_sp).expect("proxy sp descriptor");
    let upstream_idp_descriptor =
        common::idp_descriptor(&upstream_idp).expect("upstream idp descriptor");
    let now = common::fixed_now().expect("fixed_now");

    // Proxy composes the proxy_sp + proxy_idp roles. Use the in-memory
    // AEAD codec so the test has no extra storage dependency. The codec's
    // `decode` enforces `max_age` against `SystemTime::now()` (real wall
    // clock); our test mints `ProxyContext.issued_at` from `fixed_now()`
    // which is pinned, so widen the window to swallow that delta — a
    // century is more than enough.
    let codec =
        Aes256GcmCodec::new([0x42u8; 32]).with_max_age(Duration::from_hours(100 * 365 * 24));
    let proxy = Proxy::new(&proxy_sp, &proxy_idp, Box::new(codec));

    // ---- 1. Downstream SP starts login against the proxy. ---------------
    let downstream_start = downstream_sp
        .start_login(
            &proxy_idp_descriptor,
            StartLogin {
                relay_state: Some("downstream-relay"),
                binding: Binding::HttpPost,
                force_authn: false,
                is_passive: false,
                requested_name_id_format: Some(NameIdFormat::Persistent),
                requested_authn_context: None,
                acs_index: None,
                acs_url: None,
                response_binding: Some(SsoResponseBinding::HttpPost),
            },
        )
        .expect("downstream start_login");

    let downstream_authn_request = match downstream_start.dispatch {
        Dispatch::Post(form) => BASE64
            .decode(
                form.saml_request
                    .expect("SAMLRequest present in downstream dispatch")
                    .as_bytes(),
            )
            .expect("base64"),
        Dispatch::Redirect(_) => panic!("expected POST from downstream start_login"),
    };

    // ---- 2. Proxy (IdP face) consumes the downstream AuthnRequest. ------
    let parsed_downstream_request = proxy_idp
        .consume_authn_request(ConsumeAuthnRequest {
            sp: &downstream_sp_descriptor,
            peer_crypto_policy: None,
            saml_request: &downstream_authn_request,
            binding: Binding::HttpPost,
            relay_state: Some("downstream-relay"),
            detached_signature: None,
            expected_destination: PROXY_IDP_SSO_URL,
            now,
            clock_skew: Duration::from_mins(2),
        })
        .expect("proxy idp consume_authn_request");

    // ---- 3. Proxy bounces to the upstream IdP. --------------------------
    let bounce = proxy
        .bounce_to_upstream(BounceToUpstream {
            upstream_idp: &upstream_idp_descriptor,
            downstream_request: &parsed_downstream_request,
            propagate_request_flags: true,
            propagate_authn_context: true,
            propagate_name_id_policy: true,
            upstream_binding: Binding::HttpPost,
            now,
        })
        .expect("proxy bounce_to_upstream");

    // Pull the upstream AuthnRequest out of the bounce dispatch so the
    // upstream IdP can consume it. RelayState carries the encoded proxy
    // context.
    let (upstream_authn_request_xml, upstream_relay_state) = match bounce.dispatch {
        Dispatch::Post(form) => {
            let xml = BASE64
                .decode(form.saml_request.expect("upstream SAMLRequest").as_bytes())
                .expect("base64");
            let relay = form
                .relay_state
                .expect("upstream RelayState carries proxy context");
            (xml, relay)
        }
        Dispatch::Redirect(_) => panic!("expected POST from upstream bounce"),
    };
    assert_eq!(
        upstream_relay_state, bounce.upstream_relay_state,
        "bounce dispatch RelayState matches the encoded ProxyContext blob",
    );

    // ---- 4. Upstream IdP consumes the AuthnRequest. ---------------------
    let parsed_upstream_request = upstream_idp
        .consume_authn_request(ConsumeAuthnRequest {
            sp: &proxy_sp_descriptor,
            peer_crypto_policy: None,
            saml_request: &upstream_authn_request_xml,
            binding: Binding::HttpPost,
            relay_state: Some(&upstream_relay_state),
            detached_signature: None,
            expected_destination: UP_IDP_SSO_URL,
            now,
            clock_skew: Duration::from_mins(2),
        })
        .expect("upstream consume_authn_request");

    // ---- 5. Upstream IdP issues a Response. -----------------------------
    let upstream_dispatch = upstream_idp
        .issue_response(IssueResponse {
            sp: &proxy_sp_descriptor,
            in_response_to: &parsed_upstream_request,
            // Persistent ID minted by the upstream — the proxy will re-mint
            // this per downstream SP via PersistentPerSpHmac (step 7).
            name_id: NameId::persistent_for_sp("upstream-uid-7", PROXY_SP_ENTITY_ID),
            attributes: vec![
                Attribute::email(USER_EMAIL),
                Attribute::display_name(USER_DISPLAY),
                // Extra attribute the allow-list will drop downstream.
                Attribute::single("groups", "admins"),
                Attribute::single("internalSecret", "do-not-release"),
            ],
            authn_instant: now,
            session_index: "sess-upstream-1".to_owned(),
            session_not_on_or_after: Some(
                now.checked_add(Duration::from_hours(1))
                    .expect("session_not_on_or_after fits"),
            ),
            authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
            force_encrypt_assertion: None,
            now,
            assertion_lifetime: Duration::from_mins(10),
            subject_confirmation_lifetime: Duration::from_mins(5),
            holder_of_key_cert: None,
        })
        .expect("upstream issue_response");

    let upstream_response_xml = match upstream_dispatch {
        SsoResponseDispatch::Post(form) => BASE64
            .decode(form.saml_response.as_bytes())
            .expect("base64"),
        SsoResponseDispatch::Artifact(_) => panic!("expected POST"),
    };

    // ---- 6. Proxy (SP face) consumes the upstream Response. -------------
    let proxy_context: ProxyContext = proxy
        .context_codec()
        .decode(&upstream_relay_state)
        .expect("proxy context decodes");

    let upstream_identity = proxy_sp
        .consume_response(ConsumeResponse {
            idp: &upstream_idp_descriptor,
            peer_crypto_policy: None,
            saml_response: &upstream_response_xml,
            binding: SsoResponseBinding::HttpPost,
            relay_state: Some(&upstream_relay_state),
            tracker: Some(&proxy_context.upstream_tracker),
            expected_destination: PROXY_SP_ACS_URL,
            now,
            clock_skew: Duration::from_mins(2),
            replay_cache: None,
            replay_mode: ReplayMode::All,
            holder_of_key_cert: None,
        })
        .expect("proxy sp consume_response");

    // The proxy saw all four upstream attributes.
    assert_eq!(upstream_identity.attributes.len(), 4);

    // ---- 7. Proxy relays the identity downstream. -----------------------
    let release_policy = ReleaseAllowList {
        names: vec![
            // `email` and `displayName` get their canonical OIDs from
            // Attribute::email / Attribute::display_name.
            Attribute::email("").name,
            Attribute::display_name("").name,
            "groups".to_owned(),
        ],
    };
    let name_id_transform = PersistentPerSpHmac {
        key: [0x99u8; 32],
        format: NameIdFormat::Persistent,
    };

    let downstream_dispatch = proxy
        .relay_to_downstream(RelayToDownstream {
            context: &proxy_context,
            upstream_identity: &upstream_identity,
            downstream_sp: &downstream_sp_descriptor,
            attribute_release: &release_policy,
            name_id_transform: &name_id_transform,
            passthrough_authn_context: true,
            now,
            session_lifetime: Duration::from_hours(1),
            subject_confirmation_lifetime: Duration::from_mins(5),
        })
        .expect("proxy relay_to_downstream");

    let downstream_form = match downstream_dispatch {
        SsoResponseDispatch::Post(form) => form,
        SsoResponseDispatch::Artifact(_) => panic!("expected POST"),
    };

    // Proxy preserved the downstream RelayState across the round-trip.
    assert_eq!(
        downstream_form.relay_state.as_deref(),
        Some("downstream-relay"),
    );
    assert_eq!(downstream_form.action.as_str(), DOWN_SP_ACS_URL);

    let downstream_response_xml = BASE64
        .decode(downstream_form.saml_response.as_bytes())
        .expect("base64");

    // ---- 8. Downstream SP consumes the final Response. ------------------
    let downstream_identity = downstream_sp
        .consume_response(ConsumeResponse {
            idp: &proxy_idp_descriptor,
            peer_crypto_policy: None,
            saml_response: &downstream_response_xml,
            binding: SsoResponseBinding::HttpPost,
            relay_state: Some("downstream-relay"),
            tracker: Some(&downstream_start.tracker),
            expected_destination: DOWN_SP_ACS_URL,
            now,
            clock_skew: Duration::from_mins(2),
            replay_cache: None,
            replay_mode: ReplayMode::All,
            holder_of_key_cert: None,
        })
        .expect("downstream consume_response");

    // ---- Assertions: attribute release worked. --------------------------
    assert_eq!(
        downstream_identity.attributes.len(),
        3,
        "internalSecret was filtered by the allow-list (4 upstream → 3 downstream)",
    );
    assert!(
        downstream_identity
            .attributes
            .iter()
            .all(|a| a.name != "internalSecret"),
        "internalSecret never reaches the downstream SP",
    );
    let email_attr = downstream_identity
        .attributes
        .iter()
        .find(|a| a.friendly_name.as_deref() == Some("mail"))
        .expect("mail attribute released");
    assert_eq!(email_attr.values, vec![USER_EMAIL.to_owned()]);

    // ---- Assertions: NameID is scoped to the downstream SP. -------------
    assert_eq!(downstream_identity.name_id.format, NameIdFormat::Persistent,);
    assert_eq!(
        downstream_identity.name_id.sp_name_qualifier.as_deref(),
        Some(DOWN_SP_ENTITY_ID),
        "downstream NameID carries SPNameQualifier = downstream SP entityID",
    );
    // Re-minted: HMAC output, not the verbatim upstream value.
    assert_ne!(
        downstream_identity.name_id.value, "upstream-uid-7",
        "proxy must NOT pass the upstream subject through verbatim",
    );

    // The downstream identity carries the upstream authn context (passthrough).
    assert_eq!(
        downstream_identity.authn_context_class_ref.as_deref(),
        Some(AuthnContextClassRef::PasswordProtectedTransport.as_uri()),
    );
}
