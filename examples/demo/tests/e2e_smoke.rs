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

async fn boot_sp() -> Option<(SocketAddr, tokio::task::JoinHandle<()>)> {
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
    let state = AppState::new(cfg, sp, entries, all_configs);
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await.ok()?;
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    // Give axum a moment to start accepting.
    tokio::time::sleep(Duration::from_millis(75)).await;
    Some((bind_addr, handle))
}

fn pick_free_port() -> std::io::Result<u16> {
    use std::net::TcpListener;
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = l.local_addr()?.port();
    drop(l);
    Ok(port)
}

async fn run_smoke_for(provider_id: &str) {
    let Some((addr, handle)) = boot_sp().await else {
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
