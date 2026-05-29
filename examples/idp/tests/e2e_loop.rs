//! End-to-end SAML 2.0 Web Browser SSO + SLO loop, demo SP ↔ this IdP.
//!
//! Boots both halves on free ports, drives the full flow programmatically
//! with `reqwest`:
//!
//!   1. SP `/login/rust-idp` → 302/303 toward IdP `/saml/sso?SAMLRequest=…`
//!   2. Follow → IdP renders the login form (200 HTML with username +
//!      password fields).
//!   3. POST `/login` → 200 auto-submit form posting SAMLResponse to SP.
//!   4. Submit that → 303 to `/dashboard`.
//!   5. GET `/dashboard` → confirms "Welcome back, Alice" + email + via
//!      Rust IdP badge.
//!   6. POST `/logout` → 302/303/200 toward IdP `/saml/slo?…` with signed
//!      LogoutRequest.
//!   7. Follow → IdP echoes LogoutResponse back to SP via the binding the
//!      SP advertised.
//!   8. SP redirects to `/?msg=signed-out` and clears the cookie.
//!   9. Re-`GET /login/rust-idp` → IdP renders the LOGIN form again
//!      (proves the IdP session was actually terminated by the SLO call).
//!
//! Gated on `SAML_DEMO_E2E_RUST_IDP=1` so default `cargo test` doesn't
//! try to bind ports.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use reqwest::Client;
use reqwest::redirect::Policy;

use saml_demo as demo;
use saml_demo::providers::ProviderIndex;
use saml_idp_example as idp;

#[tokio::test(flavor = "multi_thread")]
async fn rust_idp_loop_with_demo_sp() {
    if std::env::var("SAML_DEMO_E2E_RUST_IDP").as_deref() != Ok("1") {
        eprintln!("skipping rust-idp e2e loop: set SAML_DEMO_E2E_RUST_IDP=1 to enable",);
        return;
    }

    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_test_writer()
        .try_init();

    // Pick two free ports. Reserve the listeners, then drop them just
    // before binding so the kernel doesn't keep them tied up.
    let idp_port = pick_free_port().expect("free port for IdP");
    let sp_port = pick_free_port().expect("free port for SP");

    let sp_base = format!("http://127.0.0.1:{sp_port}");
    let idp_base = format!("http://127.0.0.1:{idp_port}");

    // Boot the IdP first so the SP can fetch its metadata. We pass the
    // bind/base config directly rather than going through env vars,
    // because the test crate has `unsafe_code = "forbid"` and
    // `std::env::set_var` is `unsafe` under Rust 2024.
    let idp_handle = boot_idp(idp_port, &idp_base, &sp_base)
        .await
        .expect("IdP boots");

    // The IdP can't fetch the SP metadata until the SP is up — boot the
    // SP next, then both halves resolve each other on first request.
    let sp_handle = boot_sp(sp_port, &idp_base).await.expect("SP boots");

    for _ in 0..40 {
        if reqwest::get(format!("{sp_base}/healthz"))
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let entries = idp::fetch_all_sps(&idp_handle.sps_file).await;
    assert!(
        !entries.is_empty(),
        "IdP must register the SP descriptor before driving the flow",
    );
    idp_handle.state.replace_sps(entries);

    let client = Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(15))
        .cookie_store(true)
        .build()
        .expect("client builds");

    // --- Step 1: SP /login/rust-idp ---
    let resp = client
        .get(format!("{sp_base}/login/rust-idp"))
        .send()
        .await
        .expect("/login/rust-idp");
    assert!(
        matches!(resp.status().as_u16(), 302 | 303),
        "step 1: /login/rust-idp should redirect, got {}",
        resp.status(),
    );
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("step 1: Location header")
        .to_owned();
    assert!(
        location.starts_with(&idp_base),
        "step 1: should redirect to IdP, got {location}",
    );
    assert!(
        location.contains("SAMLRequest="),
        "step 1: redirect should carry SAMLRequest, got {location}",
    );
    eprintln!("step 1 ok: SP → IdP redirect {location}");

    // --- Step 2: follow the redirect to /saml/sso ---
    let resp = client.get(&location).send().await.expect("/saml/sso");
    assert!(
        matches!(resp.status().as_u16(), 302 | 303),
        "step 2: /saml/sso should bounce to login form (got {})",
        resp.status(),
    );
    let login_location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("step 2: Location")
        .to_owned();
    assert!(
        login_location.contains("/saml/sso/login?request_id="),
        "step 2: should bounce to login form with request_id, got {login_location}",
    );
    let request_id_query = login_location
        .split_once("request_id=")
        .expect("step 2: request_id present")
        .1
        .to_owned();
    eprintln!("step 2 ok: IdP → login form with request_id={request_id_query}");

    // --- Step 2b: fetch login form, confirm fields ---
    let login_target = if login_location.starts_with("http") {
        login_location.clone()
    } else {
        format!("{idp_base}{login_location}")
    };
    let resp = client.get(&login_target).send().await.expect("login form");
    assert_eq!(resp.status().as_u16(), 200, "step 2b: login form 200");
    let html = resp.text().await.expect("login form body");
    assert!(
        html.contains("name=\"username\""),
        "step 2b: username field"
    );
    assert!(
        html.contains("name=\"password\""),
        "step 2b: password field"
    );
    assert!(
        html.contains(&request_id_query),
        "step 2b: hidden request_id present",
    );
    eprintln!("step 2b ok: login form renders with creds + hidden request_id");

    // --- Step 3: POST /login with alice's creds ---
    let resp = client
        .post(format!("{idp_base}/login"))
        .form(&[
            ("request_id", request_id_query.as_str()),
            ("username", "alice@saml-demo.local"),
            ("password", "password"),
        ])
        .send()
        .await
        .expect("POST /login");
    assert!(
        matches!(resp.status().as_u16(), 302 | 303),
        "step 3: POST /login should redirect to /saml/sso/continue (got {})",
        resp.status(),
    );
    let continue_location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("step 3: Location")
        .to_owned();
    assert!(
        continue_location.contains("/saml/sso/continue?request_id="),
        "step 3: should bounce to /saml/sso/continue, got {continue_location}",
    );
    eprintln!("step 3 ok: POST /login → {continue_location}");

    // --- Step 4: follow to /saml/sso/continue, IdP mints SAMLResponse ---
    let continue_target = if continue_location.starts_with("http") {
        continue_location
    } else {
        format!("{idp_base}{continue_location}")
    };
    let resp = client
        .get(&continue_target)
        .send()
        .await
        .expect("GET /saml/sso/continue");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "step 4: continue returns 200 auto-form",
    );
    let html = resp.text().await.expect("continue body");
    assert!(
        html.contains("name=\"SAMLResponse\""),
        "step 4: SAMLResponse field present",
    );
    let action = extract_form_action(&html).expect("step 4: form action");
    let saml_response =
        extract_hidden_value(&html, "SAMLResponse").expect("step 4: SAMLResponse value");
    let relay_state = extract_hidden_value(&html, "RelayState");
    assert!(
        action.starts_with(&sp_base) && action.contains("/saml/acs"),
        "step 4: action should point at SP's ACS, got {action}",
    );
    eprintln!("step 4 ok: IdP → ACS form, action={action}");

    // --- Step 5: POST SAMLResponse to SP /saml/acs ---
    let mut form_fields: Vec<(&str, &str)> = vec![("SAMLResponse", &saml_response)];
    if let Some(rs) = relay_state.as_deref() {
        form_fields.push(("RelayState", rs));
    }
    let resp = client
        .post(&action)
        .form(&form_fields)
        .send()
        .await
        .expect("POST /saml/acs");
    assert!(
        matches!(resp.status().as_u16(), 302 | 303),
        "step 5: ACS should 303 to /dashboard (got {})",
        resp.status(),
    );
    let dashboard_loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("step 5: Location")
        .to_owned();
    assert!(
        dashboard_loc.contains("/dashboard"),
        "step 5: ACS → /dashboard, got {dashboard_loc}",
    );
    eprintln!("step 5 ok: ACS → {dashboard_loc}");

    // --- Step 6: GET /dashboard, confirm identity is bound ---
    let dashboard_target = if dashboard_loc.starts_with("http") {
        dashboard_loc
    } else {
        format!("{sp_base}{dashboard_loc}")
    };
    let resp = client
        .get(&dashboard_target)
        .send()
        .await
        .expect("GET /dashboard");
    assert_eq!(resp.status().as_u16(), 200, "step 6: dashboard 200");
    let html = resp.text().await.expect("dashboard body");
    assert!(
        html.contains("Welcome back"),
        "step 6: dashboard greeting missing",
    );
    assert!(
        html.contains("Alice"),
        "step 6: dashboard should show display name",
    );
    assert!(
        html.contains("alice@saml-demo.local"),
        "step 6: dashboard should show email",
    );
    assert!(
        html.contains("Rust IdP") || html.contains("rust-idp"),
        "step 6: dashboard should show rust-idp badge",
    );
    eprintln!("step 6 ok: dashboard rendered with rust-idp identity");

    // --- Step 7: POST /logout ---
    let resp = client
        .post(format!("{sp_base}/logout"))
        .send()
        .await
        .expect("POST /logout");
    let status = resp.status().as_u16();
    let logout_target = match status {
        302 | 303 => resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .expect("step 7: Location on redirect")
            .to_owned(),
        200 => {
            // POST-binding logout: HTML auto-submit form. Pull action +
            // hidden SAMLRequest and submit it.
            let html = resp.text().await.expect("step 7: HTML body");
            let action = extract_form_action(&html).expect("step 7: form action");
            let saml_request =
                extract_hidden_value(&html, "SAMLRequest").expect("step 7: SAMLRequest value");
            let relay = extract_hidden_value(&html, "RelayState");
            let mut fields: Vec<(&str, &str)> = vec![("SAMLRequest", &saml_request)];
            if let Some(r) = relay.as_deref() {
                fields.push(("RelayState", r));
            }
            let post_resp = client
                .post(&action)
                .form(&fields)
                .send()
                .await
                .expect("step 7: POST LogoutRequest");
            let post_status = post_resp.status().as_u16();
            assert!(
                matches!(post_status, 200 | 302 | 303),
                "step 7: POST LogoutRequest should return 200 or 3xx (got {post_status})",
            );
            // The IdP will echo a LogoutResponse via POST-binding too.
            if post_status == 200 {
                let html = post_resp.text().await.expect("step 7b: HTML body");
                let action = extract_form_action(&html).expect("step 7b: action");
                let saml_response =
                    extract_hidden_value(&html, "SAMLResponse").expect("step 7b: SAMLResponse");
                let relay = extract_hidden_value(&html, "RelayState");
                let mut fields: Vec<(&str, &str)> = vec![("SAMLResponse", &saml_response)];
                if let Some(r) = relay.as_deref() {
                    fields.push(("RelayState", r));
                }
                let resp = client
                    .post(&action)
                    .form(&fields)
                    .send()
                    .await
                    .expect("step 7b: POST LogoutResponse to SP");
                assert!(
                    matches!(resp.status().as_u16(), 302 | 303),
                    "step 7b: SP should 303 after LogoutResponse",
                );
                resp.headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .expect("step 7b: Location")
                    .to_owned()
            } else {
                post_resp
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .expect("step 7: redirect Location")
                    .to_owned()
            }
        }
        other => panic!("step 7: unexpected status {other}"),
    };
    eprintln!("step 7 ok: logout chain landed on {logout_target}");

    // --- Step 8: dispatch the IdP's response (if not already handled above) ---
    let landed_target =
        if logout_target.starts_with(&sp_base) && logout_target.contains("/?msg=signed-out") {
            logout_target
        } else if logout_target.starts_with(&idp_base) {
            // Redirect-binding LogoutRequest to the IdP. Follow it.
            let resp = client.get(&logout_target).send().await.expect("IdP slo");
            let status = resp.status().as_u16();
            if status == 200 {
                // POST-binding LogoutResponse back to the SP.
                let html = resp.text().await.expect("logout response body");
                let action = extract_form_action(&html).expect("logout: action");
                let saml_response =
                    extract_hidden_value(&html, "SAMLResponse").expect("logout: SAMLResponse");
                let relay = extract_hidden_value(&html, "RelayState");
                let mut fields: Vec<(&str, &str)> = vec![("SAMLResponse", &saml_response)];
                if let Some(r) = relay.as_deref() {
                    fields.push(("RelayState", r));
                }
                let resp = client
                    .post(&action)
                    .form(&fields)
                    .send()
                    .await
                    .expect("POST LogoutResponse");
                assert!(
                    matches!(resp.status().as_u16(), 302 | 303),
                    "step 8: SP should 303 after LogoutResponse",
                );
                resp.headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .expect("step 8: Location")
                    .to_owned()
            } else if matches!(status, 302 | 303) {
                // Redirect-binding LogoutResponse to SP.
                let next = resp
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .expect("step 8: Location")
                    .to_owned();
                let resp = client.get(&next).send().await.expect("SP slo redirect");
                assert!(
                    matches!(resp.status().as_u16(), 302 | 303),
                    "step 8: SP should 303 after redirect LogoutResponse (got {})",
                    resp.status(),
                );
                resp.headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .expect("step 8: Location after SP slo")
                    .to_owned()
            } else {
                panic!("step 8: unexpected IdP /saml/slo status {status}");
            }
        } else {
            logout_target
        };
    assert!(
        landed_target.contains("/?msg=signed-out") || landed_target.contains("?msg=signed-out"),
        "step 8: should land on /?msg=signed-out, got {landed_target}",
    );
    eprintln!("step 8 ok: landed on {landed_target}");

    // --- Step 9: re-attempt /login/rust-idp; the IdP must prompt for
    //     credentials again, proving the IdP session was actually
    //     terminated by the SLO call. ---
    let resp = client
        .get(format!("{sp_base}/login/rust-idp"))
        .send()
        .await
        .expect("step 9: /login/rust-idp re-entry");
    assert!(
        matches!(resp.status().as_u16(), 302 | 303),
        "step 9: /login/rust-idp 3xx",
    );
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("step 9: Location")
        .to_owned();
    let resp = client
        .get(&loc)
        .send()
        .await
        .expect("step 9: follow to IdP");
    let status = resp.status().as_u16();
    // The IdP should send us BACK to the login form, not directly to
    // continue. So 3xx with /saml/sso/login? or 200 of the login page
    // are both proof that the IdP no longer recognises a session.
    let bounce = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    if matches!(status, 302 | 303) {
        let loc = bounce.expect("step 9: Location");
        assert!(
            loc.contains("/saml/sso/login?"),
            "step 9: IdP should bounce to login form, got {loc}",
        );
        // Follow + verify the form is there.
        let form_url = if loc.starts_with("http") {
            loc
        } else {
            format!("{idp_base}{loc}")
        };
        let resp = client
            .get(&form_url)
            .send()
            .await
            .expect("step 9: login form");
        assert_eq!(resp.status().as_u16(), 200, "step 9: login form 200");
        let html = resp.text().await.expect("step 9: body");
        assert!(
            html.contains("name=\"password\""),
            "step 9: must render password field again",
        );
    } else {
        panic!("step 9: expected redirect to login form, got {status}");
    }
    eprintln!("step 9 ok: IdP requires fresh login after SLO");

    idp_handle.shutdown();
    sp_handle.shutdown();
}

// =============================================================================
// Boot helpers
// =============================================================================

struct ServerHandle {
    handle: tokio::task::JoinHandle<()>,
}

impl ServerHandle {
    fn shutdown(self) {
        self.handle.abort();
    }
}

struct IdpHandle {
    handle: tokio::task::JoinHandle<()>,
    state: idp::AppState,
    sps_file: idp::SpsFile,
}

impl IdpHandle {
    fn shutdown(self) {
        self.handle.abort();
    }
}

async fn boot_idp(port: u16, idp_base: &str, sp_base: &str) -> Result<IdpHandle, String> {
    // Build the IdP config in-process. The AppState's `by_entity_id`
    // map uses interior mutability so we can populate it once the SP
    // listener comes up.
    let mut cfg = idp::AppConfig::from_env();
    cfg.bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    cfg.idp_base_url = idp_base.to_owned();
    cfg.idp_entity_id = format!("{idp_base}/saml/idp");
    cfg.users_toml_path = None;
    cfg.sps_toml_path = None;

    let users_file = idp::load_users(None).map_err(|e| format!("load users: {e}"))?;
    let users = idp::auth::UserStore::from_users_file(&users_file)
        .map_err(|e| format!("hash users: {e}"))?;

    let mut sps_file = idp::load_sps(None).map_err(|e| format!("load sps: {e}"))?;
    for sp in &mut sps_file.sp {
        if sp.entity_id == "saml-axum-demo" {
            sp.metadata_url = format!("{sp_base}/metadata");
            sp.acs_url = format!("{sp_base}/saml/acs");
            sp.slo_url = Some(format!("{sp_base}/saml/slo"));
        }
    }
    let all_sp_configs = sps_file.sp.clone();
    let identity = idp::build_identity_provider(&cfg).map_err(|e| format!("build idp: {e}"))?;

    let bind = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|e| format!("bind idp: {e}"))?;

    let state = idp::AppState::new(cfg, identity, users, vec![], all_sp_configs);
    let app = idp::build_router(state.clone());

    let serve_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    Ok(IdpHandle {
        handle: serve_handle,
        state,
        sps_file,
    })
}

async fn boot_sp(port: u16, idp_base: &str) -> Result<ServerHandle, String> {
    let mut cfg = demo::AppConfig::from_env();
    cfg.bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    cfg.sp_base_url = format!("http://127.0.0.1:{port}");

    let mut providers_file = demo::load_providers(cfg.providers_toml_path.as_deref())
        .map_err(|e| format!("load providers: {e}"))?;
    // Re-point rust-idp at our test IdP.
    for p in &mut providers_file.provider {
        if p.id == "rust-idp" {
            p.metadata_url = format!("{idp_base}/metadata");
        }
    }
    let all_configs = providers_file.provider.clone();
    let index = ProviderIndex::build(&providers_file).map_err(|e| format!("build index: {e}"))?;
    let sp = demo::build_service_provider(&cfg).map_err(|e| format!("build sp: {e}"))?;
    let entries = demo::fetch_all_descriptors(&index).await;

    let bind = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|e| format!("bind sp: {e}"))?;

    let state = demo::AppState::new(cfg, sp, entries, all_configs);
    let app = demo::build_router(state);
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(ServerHandle { handle })
}

fn pick_free_port() -> std::io::Result<u16> {
    use std::net::TcpListener;
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = l.local_addr()?.port();
    drop(l);
    Ok(port)
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
