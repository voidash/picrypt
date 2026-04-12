use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use tracing_subscriber::EnvFilter;

use picrypt_server::api;
use picrypt_server::config::ServerConfig;
use picrypt_server::hardening;
use picrypt_server::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Apply process hardening before touching any key material.
    hardening::apply();

    let config = ServerConfig::load().context("failed to load server configuration")?;
    let addr: SocketAddr = config
        .listen_addr
        .parse()
        .context(format!("invalid listen address: {}", config.listen_addr))?;

    let state = Arc::new(AppState::new(config)?);

    // Start dead man's switch if configured.
    let dms_timeout = state.config.dead_man_timeout_secs;
    let _dms_handle = if dms_timeout > 0 {
        let handle = state.start_dead_man_switch(std::time::Duration::from_secs(dms_timeout));
        tracing::info!("dead man's switch active — timeout: {dms_timeout}s");
        Some(handle)
    } else {
        tracing::info!("dead man's switch disabled");
        None
    };

    let app = api::router(state);

    tracing::info!("picrypt server starting on {}", addr);
    tracing::info!("server is SEALED — POST /unseal to activate");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context(format!("failed to bind to {addr}"))?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    tracing::info!("picrypt server stopped");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => { tracing::info!("received SIGINT, shutting down"); }
            _ = sigterm.recv() => { tracing::info!("received SIGTERM, shutting down"); }
        }
    }
    #[cfg(not(unix))]
    {
        ctrl_c.await.expect("failed to listen for Ctrl+C");
        tracing::info!("received Ctrl+C, shutting down");
    }
}
