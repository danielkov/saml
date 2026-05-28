//! Consolidated multi-IdP SAML 2.0 SP demo.
//!
//! Run:
//!   cp examples/demo/.env.example examples/demo/.env  # optional
//!   cargo run -p saml-demo
//!   open http://localhost:3000

use saml_demo::providers::ProviderIndex;
use saml_demo::{
    AppConfig, AppState, build_router, build_service_provider, fetch_all_descriptors,
    load_providers,
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
    info!(?config.bind_addr, sp_entity_id = %config.sp_entity_id, "starting saml-demo");

    let providers_file = load_providers(config.providers_toml_path.as_deref())?;
    let all_configs: Vec<_> = providers_file.provider.clone();
    let index = ProviderIndex::build(&providers_file)?;
    info!(provider_count = index.len(), "providers.toml loaded");

    let sp = build_service_provider(&config)?;

    info!("fetching IdP metadata for all providers in parallel");
    let entries = fetch_all_descriptors(&index).await;
    if entries.is_empty() {
        warn!(
            "no IdP metadata reachable - the SP will boot, but every /login will return an error"
        );
    } else {
        info!(live = entries.len(), "ready providers");
        for e in &entries {
            info!(provider = %e.config.id, entity_id = %e.idp.entity_id, "live");
        }
    }

    let state = AppState::new(config.clone(), sp, entries, all_configs);
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    info!(listening_on = ?listener.local_addr()?, "open http://localhost:3000");
    axum::serve(listener, app).await?;
    Ok(())
}
