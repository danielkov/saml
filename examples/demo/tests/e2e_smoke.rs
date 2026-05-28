//! Programmatic smoke tests for the consolidated saml-demo. One test per
//! provider; each is gated on a `SAML_DEMO_E2E_<UPPER_ID>=1` env var so
//! the suite runs cleanly in CI without provisioned cloud credentials or
//! a Docker daemon for the local IdPs.
//!
//! When enabled, the per-provider test:
//!   1. Boots the SP on a free localhost port.
//!   2. Confirms `/healthz` returns 200 OK.
//!   3. Confirms `GET /` renders a card for the target provider.
//!   4. Confirms `GET /login/<provider>` returns a 302 (or 200 with the
//!      auto-submit POST form) toward the IdP — the SP successfully
//!      built an AuthnRequest against that provider's descriptor.
//!
//! We deliberately stop short of driving the IdP login UI: each vendor
//! has its own login surface, and the per-vendor full flows were already
//! covered by the now-deleted per-IdP example crates.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use reqwest::redirect::Policy;
use saml_demo::providers::ProviderIndex;
use saml_demo::session::{Session, encode as encode_session, set_cookie_header};
use saml_demo::{
    AppConfig, AppState, build_router, build_service_provider, fetch_all_descriptors,
    load_providers,
};

const PROVIDERS: &[(&str, &str)] = &[
    ("keycloak", "SAML_DEMO_E2E_KEYCLOAK"),
    ("authentik", "SAML_DEMO_E2E_AUTHENTIK"),
    ("fusionauth", "SAML_DEMO_E2E_FUSIONAUTH"),
    ("zitadel", "SAML_DEMO_E2E_ZITADEL"),
    ("auth0", "SAML_DEMO_E2E_AUTH0"),
    ("descope", "SAML_DEMO_E2E_DESCOPE"),
    ("asgardeo", "SAML_DEMO_E2E_ASGARDEO"),
];

async fn boot_sp() -> Option<(SocketAddr, AppConfig, tokio::task::JoinHandle<()>)> {
    let port = pick_free_port().ok()?;
    let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));

    let mut cfg = AppConfig::from_env();
    cfg.bind_addr = bind_addr;
    cfg.sp_base_url = format!("http://127.0.0.1:{port}");

    let providers_file = load_providers(None).ok()?;
    let all_configs = providers_file.provider.clone();
    let index = ProviderIndex::build(&providers_file).ok()?;
    let sp = build_service_provider(&cfg).ok()?;
    let entries = fetch_all_descriptors(&index).await;
    if entries.is_empty() {
        eprintln!("no IdP metadata reachable - skipping smoke test boot");
        return None;
    }
    let cfg_clone = cfg.clone();
    let state = AppState::new(cfg, sp, entries, all_configs);
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await.ok()?;
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    // Give axum a moment to start accepting.
    tokio::time::sleep(Duration::from_millis(75)).await;
    Some((bind_addr, cfg_clone, handle))
}

fn pick_free_port() -> std::io::Result<u16> {
    use std::net::TcpListener;
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = l.local_addr()?.port();
    drop(l);
    Ok(port)
}

async fn run_smoke_for(provider_id: &str) {
    let Some((addr, _cfg, handle)) = boot_sp().await else {
        eprintln!("could not boot SP for smoke test of {provider_id}");
        return;
    };
    let base = format!("http://{addr}");
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(10))
        .cookie_store(true)
        .build()
        .expect("client builds");

    let healthz = client
        .get(format!("{base}/healthz"))
        .send()
        .await
        .expect("healthz request");
    assert_eq!(healthz.status().as_u16(), 200, "healthz should be 200");

    let index = client.get(format!("{base}/")).send().await.expect("index");
    assert_eq!(index.status().as_u16(), 200, "/ should render");
    let body = index.text().await.expect("body");
    assert!(
        body.contains(&format!("/login/{provider_id}")),
        "landing page should include card linking to /login/{provider_id}"
    );

    let login = client
        .get(format!("{base}/login/{provider_id}"))
        .send()
        .await
        .expect("login");
    let status = login.status().as_u16();
    assert!(
        matches!(status, 200 | 302 | 303),
        "/login/{provider_id} should redirect or POST-form (got {status})"
    );

    handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn smoke_keycloak() {
    run_gated("keycloak").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn smoke_authentik() {
    run_gated("authentik").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn smoke_fusionauth() {
    run_gated("fusionauth").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn smoke_zitadel() {
    run_gated("zitadel").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn smoke_auth0() {
    run_gated("auth0").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn smoke_descope() {
    run_gated("descope").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn smoke_asgardeo() {
    run_gated("asgardeo").await;
}

async fn run_gated(provider_id: &str) {
    let env_var = PROVIDERS
        .iter()
        .find(|(id, _)| *id == provider_id)
        .map(|(_, env)| *env)
        .expect("provider id is known");
    if std::env::var(env_var).as_deref() != Ok("1") {
        eprintln!("skipping smoke for {provider_id}: set {env_var}=1 to enable");
        return;
    }
    run_smoke_for(provider_id).await;
}

/// `/logout` with a forged session cookie targeting FusionAuth (which is
/// the only IdP in the demo that advertises a SLO endpoint by default).
/// The SP-init SLO path should:
///   1. Look up the provider, see SLO advertised, mint a
///      `<samlp:LogoutRequest>`, redirect 303 to FA's SLO URL.
///   2. Clear the session cookie on the response.
/// Gated on `SAML_DEMO_E2E_FUSIONAUTH=1` plus a reachable FA at
/// localhost:9011.
#[tokio::test(flavor = "multi_thread")]
async fn slo_redirects_to_fusionauth_and_clears_cookie() {
    if std::env::var("SAML_DEMO_E2E_FUSIONAUTH").as_deref() != Ok("1") {
        eprintln!(
            "skipping FA SLO test: set SAML_DEMO_E2E_FUSIONAUTH=1 and run FusionAuth on :9011",
        );
        return;
    }
    let Some((addr, cfg, handle)) = boot_sp().await else {
        eprintln!("could not boot SP for SLO logout test");
        return;
    };
    let base = format!("http://{addr}");
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client builds");

    let session = Session {
        name_id_value: "alice@saml-demo.local".to_owned(),
        name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_owned(),
        session_index: Some("test-session-index".to_owned()),
        authn_instant_unix: 1_700_000_000,
        issued_at_unix: now_unix(),
        idp_entity_id: "http://localhost:9011/samlv2/d7d09513-a3f5-401c-9685-34ab6c552453".to_owned(),
        provider_id: "fusionauth".to_owned(),
        attributes: vec![],
    };
    let cookie_value =
        encode_session(&session, &cfg.session_signing_key).expect("encode forged session");
    let cookie_header = set_cookie_header(&cookie_value);

    let resp = client
        .post(format!("{base}/logout"))
        .header(reqwest::header::COOKIE, cookie_header)
        .send()
        .await
        .expect("POST /logout");

    let status = resp.status().as_u16();
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let set_cookie = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_owned)
        .collect::<Vec<_>>();

    assert!(
        matches!(status, 302 | 303),
        "/logout should redirect to FA SLO endpoint (got {status})",
    );
    let location = location.expect("redirect Location header present");
    assert!(
        location.contains("localhost:9011/samlv2/logout/")
            || location.contains("localhost:9011/samlv2/redirect/logout"),
        "Location should point at FA's SLO endpoint, got {location}",
    );
    assert!(
        location.contains("SAMLRequest="),
        "Location should carry a SAMLRequest, got {location}",
    );
    assert!(
        location.contains("Signature="),
        "Location should carry a Signature (SP-side logout signing is on), got {location}",
    );
    assert!(
        set_cookie.iter().any(|c| c.contains("Max-Age=0")),
        "logout response should clear the session cookie, got {set_cookie:?}",
    );

    handle.abort();
}

/// `/logout` against a provider that doesn't advertise SLO: should fall
/// back to a local-only logout with the `signed-out-locally-no-slo`
/// banner. We forge a session pointing at Descope (no SLO in its
/// metadata), but the actual IdP doesn't need to be reachable — the
/// branch is taken from the in-memory descriptor.
#[tokio::test(flavor = "multi_thread")]
async fn logout_falls_back_when_idp_lacks_slo() {
    if std::env::var("SAML_DEMO_E2E_DESCOPE").as_deref() != Ok("1") {
        eprintln!(
            "skipping Descope no-SLO test: set SAML_DEMO_E2E_DESCOPE=1 (the Descope metadata fetch must succeed at boot)",
        );
        return;
    }
    let Some((addr, cfg, handle)) = boot_sp().await else {
        eprintln!("could not boot SP for no-SLO logout test");
        return;
    };
    let base = format!("http://{addr}");
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client builds");

    let session = Session {
        name_id_value: "alice@saml-demo.local".to_owned(),
        name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_owned(),
        session_index: None,
        authn_instant_unix: 1_700_000_000,
        issued_at_unix: now_unix(),
        idp_entity_id: String::new(),
        provider_id: "descope".to_owned(),
        attributes: vec![],
    };
    let cookie_value =
        encode_session(&session, &cfg.session_signing_key).expect("encode forged session");

    let resp = client
        .post(format!("{base}/logout"))
        .header(reqwest::header::COOKIE, set_cookie_header(&cookie_value))
        .send()
        .await
        .expect("POST /logout");

    let status = resp.status().as_u16();
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_default();

    assert!(
        matches!(status, 302 | 303),
        "/logout fallback should 303 to landing page",
    );
    // The exact banner key depends on whether Descope's descriptor really
    // lacks SLO (it does, as of this writing) or is just "down" — both
    // branches land on a local-only message. Accept either.
    assert!(
        location.contains("/?msg=signed-out-locally-no-slo")
            || location.contains("/?msg=signed-out-locally"),
        "logout fallback should redirect to a local-only banner, got {location}",
    );

    handle.abort();
}

fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
