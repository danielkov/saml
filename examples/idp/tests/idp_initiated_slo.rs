//! In-process IdP-initiated Single Logout round trip.
//!
//! Proves the wiring added to the IdP example for IdP-initiated SLO without
//! binding any ports (unlike the gated `e2e_loop.rs`):
//!
//!   1. A logged-in IdP session POSTs `/logout-everywhere`. The example
//!      builds a signed `<samlp:LogoutRequest>` to the registered SP and
//!      dispatches it over the SP's preferred SLO binding (HTTP-POST here).
//!   2. The demo SP's `consume_logout_request` accepts the LogoutRequest.
//!   3. The SP builds a `<samlp:LogoutResponse>` (Success).
//!   4. That response is POSTed back to the IdP `/saml/slo`, which binds it
//!      to the stashed tracker via `consume_logout_response` and clears the
//!      IdP session cookie.
//!
//! Both roles are driven in-process: the IdP example's HTTP handlers run via
//! `tower::ServiceExt::oneshot`, and the SP role is the `saml` crate's
//! `ServiceProvider` (built by the demo crate) called directly.

use std::time::SystemTime;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use saml::{Binding, ConsumeLogoutRequest, IdpDescriptor, LogoutStatus, SpDescriptor};
use saml_demo as demo;
use saml_idp_example as idp;
use tower::ServiceExt as _;

const IDP_BASE: &str = "http://idp.test";
const SP_BASE: &str = "http://sp.test";

#[tokio::test]
async fn idp_initiated_slo_round_trip_clears_session() {
    // --- Build the IdP role + example AppState. ---
    let idp_cfg = idp::AppConfig {
        bind_addr: "127.0.0.1:0".parse().expect("addr"),
        idp_entity_id: format!("{IDP_BASE}/saml/idp"),
        idp_base_url: IDP_BASE.to_owned(),
        session_signing_key: [0x42u8; 32],
        users_toml_path: None,
        sps_toml_path: None,
    };
    let identity = idp::build_identity_provider(&idp_cfg).expect("build idp");
    let idp_metadata = identity.metadata_xml(true).expect("idp metadata");

    let users_file = idp::load_users(None).expect("load users");
    let users = idp::auth::UserStore::from_users_file(&users_file).expect("hash users");

    // --- Build the SP role (demo crate) + cross-register descriptors. ---
    let sp_cfg = demo::AppConfig {
        sp_entity_id: "saml-axum-demo".to_owned(),
        sp_base_url: SP_BASE.to_owned(),
        ..demo::AppConfig::from_env()
    };
    let sp = demo::build_service_provider(&sp_cfg).expect("build sp");
    let sp_metadata = sp.metadata_xml(false).expect("sp metadata");

    let sp_descriptor = SpDescriptor::from_metadata_xml(sp_metadata.as_bytes()).expect("sp desc");
    let idp_descriptor =
        IdpDescriptor::from_metadata_xml(idp_metadata.as_bytes()).expect("idp desc");

    let sp_entry = idp::SpEntry {
        config: idp::SpEntryConfig {
            entity_id: sp_descriptor.entity_id.clone(),
            acs_url: format!("{SP_BASE}/saml/acs"),
            acs_binding: "HTTP-POST".to_owned(),
            slo_url: Some(format!("{SP_BASE}/saml/slo")),
            slo_binding: "HTTP-POST".to_owned(),
            metadata_url: format!("{SP_BASE}/metadata"),
            idp_entity_id_override: None,
        },
        sp: std::sync::Arc::new(sp_descriptor),
        label: "Saml Axum Demo".to_owned(),
    };

    let state = idp::AppState::new(idp_cfg.clone(), identity, users, vec![sp_entry], Vec::new());

    // --- Mint a logged-in IdP session cookie for alice. ---
    let now_unix = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let session = idp::session::Session {
        user_id: "alice".to_owned(),
        email: "alice@saml-demo.local".to_owned(),
        display_name: "Alice Anderson".to_owned(),
        session_index: "sess-it-1".to_owned(),
        authn_instant_unix: now_unix,
        issued_at_unix: now_unix,
    };
    let cookie_value =
        idp::session::encode(&session, &idp_cfg.session_signing_key).expect("encode session");
    let cookie_header = format!("{}={cookie_value}", idp::session::COOKIE_NAME);

    // --- Step 1: POST /logout-everywhere. The IdP builds + dispatches a
    //     signed LogoutRequest to the SP over its preferred binding. ---
    let resp = idp::build_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/logout-everywhere")
                .header(header::COOKIE, &cookie_header)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("logout-everywhere");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "step 1: POST-binding dispatch renders a 200 auto-submit form",
    );
    // The IdP must NOT clear its cookie yet — it waits for the SP's
    // LogoutResponse to confirm.
    assert!(
        resp.headers().get(header::SET_COOKIE).is_none(),
        "step 1: IdP must not clear its session before the LogoutResponse lands",
    );
    let html = body_text(resp).await;
    let action = extract_form_action(&html).expect("step 1: form action");
    assert!(
        action.contains("/saml/slo"),
        "step 1: LogoutRequest should target the SP's SLO endpoint, got {action}",
    );
    let saml_request =
        extract_hidden_value(&html, "SAMLRequest").expect("step 1: SAMLRequest present");

    // --- Step 2: the SP consumes the LogoutRequest. ---
    let sp_slo_url = format!("{SP_BASE}/saml/slo");
    let parsed = sp
        .consume_logout_request(
            &idp_descriptor,
            ConsumeLogoutRequest {
                peer_crypto_policy: None,
                body: saml_request.as_bytes(),
                binding: Binding::HttpPost,
                detached_signature: None,
                expected_destination: &sp_slo_url,
                now: SystemTime::now(),
                clock_skew: std::time::Duration::from_mins(2),
            },
        )
        .expect("step 2: SP accepts the IdP's LogoutRequest");
    assert_eq!(
        parsed.issuer, idp_cfg.idp_entity_id,
        "step 2: LogoutRequest issuer is the IdP",
    );

    // --- Step 3: the SP builds a Success LogoutResponse. ---
    let sp_dispatch = sp
        .build_logout_response(
            &idp_descriptor,
            &parsed,
            LogoutStatus::Success,
            None,
            Binding::HttpPost,
        )
        .expect("step 3: SP builds LogoutResponse");
    let saml_response = match sp_dispatch {
        saml::Dispatch::Post(form) => form
            .saml_response
            .expect("step 3: POST LogoutResponse carries SAMLResponse"),
        saml::Dispatch::Redirect(_) => panic!("step 3: expected POST-binding LogoutResponse"),
    };

    // --- Step 4: POST the LogoutResponse back to the IdP /saml/slo. The
    //     IdP binds it to the tracker and clears the session. ---
    let form_body = format!("SAMLResponse={}", urlencode(&saml_response));
    let resp = idp::build_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/saml/slo")
                .header(header::COOKIE, &cookie_header)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form_body))
                .expect("request"),
        )
        .await
        .expect("POST /saml/slo");
    assert!(
        matches!(resp.status(), StatusCode::SEE_OTHER | StatusCode::FOUND),
        "step 4: IdP should redirect after consuming the LogoutResponse, got {}",
        resp.status(),
    );
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("step 4: Location header");
    assert!(
        location.contains("msg=signed-out"),
        "step 4: should land on the signed-out landing page, got {location}",
    );
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .expect("step 4: Set-Cookie clearing the session");
    assert!(
        set_cookie.contains(idp::session::COOKIE_NAME) && set_cookie.contains("Max-Age=0"),
        "step 4: IdP session cookie must be cleared, got {set_cookie}",
    );

    // --- Step 5: the tracker is single-use — a replayed LogoutResponse no
    //     longer matches a pending request. ---
    let form_body = format!("SAMLResponse={}", urlencode(&saml_response));
    let resp = idp::build_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/saml/slo")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form_body))
                .expect("request"),
        )
        .await
        .expect("replayed POST /saml/slo");
    assert_eq!(
        resp.status(),
        StatusCode::GONE,
        "step 5: a replayed LogoutResponse has no pending tracker",
    );
}

// =============================================================================
// Helpers
// =============================================================================

async fn body_text(resp: axum::response::Response) -> String {
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    String::from_utf8(bytes.to_vec()).expect("utf8 body")
}

fn extract_form_action(html: &str) -> Option<String> {
    let needle = "action=\"";
    let start = html.find(needle)? + needle.len();
    let rest = html.get(start..)?;
    let end = rest.find('"')?;
    Some(rest.get(..end)?.to_owned())
}

fn extract_hidden_value(html: &str, name: &str) -> Option<String> {
    let needle = format!("name=\"{name}\"");
    let pos = html.find(&needle)?;
    let after = html.get(pos..)?;
    let value_marker = "value=\"";
    let v_start = after.find(value_marker)? + value_marker.len();
    let rest = after.get(v_start..)?;
    let end = rest.find('"')?;
    Some(rest.get(..end)?.to_owned())
}

/// Minimal `application/x-www-form-urlencoded` value encoder. The base64
/// SAMLResponse can contain `+`, `/`, and `=`; percent-encode the ones that
/// matter so axum's form extractor recovers the original bytes.
fn urlencode(value: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}
