//! Standalone Rust SAML 2.0 IdP example.
//!
//! Run:
//!   cp examples/idp/.env.example examples/idp/.env  # optional
//!   cargo run -p saml-idp-example
//!   open http://localhost:3001
//!
//! Then point the demo SP at this IdP (already configured as the
//! "rust-idp" provider in examples/demo/config/providers.toml):
//!   cargo run -p saml-demo
//!   open http://localhost:3000

use saml_idp_example::auth::UserStore;
use saml_idp_example::{
    AppConfig, AppState, build_identity_provider, build_router, fetch_all_sps, load_sps,
    load_users,
};
use tracing::{info, warn};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,tower_http=info")),
        )
        .compact()
        .init();

    let config = AppConfig::from_env();
    info!(?config.bind_addr, idp_entity_id = %config.idp_entity_id, "starting saml-idp-example");

    let users_file = load_users(config.users_toml_path.as_deref())?;
    let users = UserStore::from_users_file(&users_file)?;
    info!(seed_users = users.len(), "loaded users.toml");

    let sps_file = load_sps(config.sps_toml_path.as_deref())?;
    let all_sp_configs = sps_file.sp.clone();
    info!(sp_count = sps_file.sp.len(), "loaded sps.toml");

    let idp = build_identity_provider(&config)?;

    // Start serving immediately with an empty SP registry. The SP demo
    // fetches the IdP's metadata at startup; if we blocked here on the
    // SP's metadata, the SP couldn't reach us and we'd deadlock the
    // whole flow. Once the SP comes up, the background task below
    // populates the registry.
    let state = AppState::new(config.clone(), idp, users, vec![], all_sp_configs);
    let app = build_router(state.clone());

    let sps_for_refresh = sps_file;
    let state_for_refresh = state.clone();
    tokio::spawn(async move {
        loop {
            let entries = fetch_all_sps(&sps_for_refresh).await;
            if !entries.is_empty() {
                info!(live = entries.len(), "SP metadata fetched; registry populated");
                for e in &entries {
                    info!(sp = %e.sp.entity_id, "live");
                }
                state_for_refresh.replace_sps(entries);
                return;
            }
            warn!(
                "no SP metadata reachable yet; will keep retrying every 5s. \
                 The IdP is up and serving /metadata so SPs can still wire \
                 themselves in."
            );
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    info!(listening_on = ?listener.local_addr()?, "open http://localhost:3001");
    axum::serve(listener, app).await?;
    Ok(())
}
