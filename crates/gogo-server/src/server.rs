//! Starting the server: state, libraries, listeners.

use crate::config::Config;
use crate::security::{guard, Scheme};
use crate::state::{AppState, Shared};
use crate::{api, tls, web};
use anyhow::{Context, Result};
use axum::extract::DefaultBodyLimit;
use axum::{middleware, Extension, Router};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Builds the application for one listener.
pub fn app(state: Shared, https: bool) -> Router {
    Router::new()
        .merge(api::router())
        .fallback(web::serve)
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .layer(Extension(Scheme { https }))
        .with_state(state)
}

/// Runs the server until `shutdown` completes.
pub async fn run<F>(cfg: Config, shutdown: F) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let _ = rustls::crypto::ring::default_provider().install_default();
    cfg.startup_checks()?;
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        mode = ?cfg.mode,
        data = %cfg.data_dir.display(),
        "starting Gogo Desktop"
    );
    let state = AppState::new(cfg.clone())?;
    state.register_config_libraries()?;
    state.start_libraries()?;

    // Daily audit-log retention.
    {
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                let days = st.cfg.audit_retention_days;
                let s2 = st.clone();
                let _ = tokio::task::spawn_blocking(move || s2.audit.apply_retention(days)).await;
                tokio::time::sleep(Duration::from_secs(86_400)).await;
            }
        });
    }

    #[cfg(windows)]
    if cfg.http_bind.map(|a| a.ip().is_loopback()).unwrap_or(false) {
        crate::winsignin::spawn_server(state.clone());
    }

    let handle = axum_server::Handle::new();
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let mut tasks = tokio::task::JoinSet::new();

    if let Some(addr) = cfg.http_bind {
        let listener = tokio::net::TcpListener::bind(addr).await.with_context(|| format!("can't listen on {addr}"))?;
        tracing::info!("web interface: http://{}", display_addr(addr));
        let app = app(state.clone(), false);
        let mut rx = stop_rx.clone();
        tasks.spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
                .with_graceful_shutdown(async move {
                    let _ = rx.wait_for(|v| *v).await;
                })
                .await
                .map_err(anyhow::Error::from)
        });
    }
    if let Some(addr) = cfg.https_bind {
        let mut names = cfg.allowed_hosts.clone();
        if let Ok(h) = std::env::var("HOSTNAME") {
            names.push(h);
        }
        let mat = tls::material(cfg.tls_cert.as_ref(), cfg.tls_key.as_ref(), &cfg.tls_dir(), &names)?;
        if mat.self_signed {
            tracing::warn!(
                "using a self-signed HTTPS certificate. Its SHA-256 fingerprint is {} - check it matches when your browser asks",
                mat.fingerprint
            );
        }
        let mut sc = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(mat.certs, mat.key)?;
        sc.alpn_protocols = vec![b"http/1.1".to_vec()];
        let rc = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(sc));
        tracing::info!("web interface: https://{}", display_addr(addr));
        let app = app(state.clone(), true);
        let h = handle.clone();
        tasks.spawn(async move {
            axum_server::bind_rustls(addr, rc)
                .handle(h)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .map_err(anyhow::Error::from)
        });
    }

    let h = handle.clone();
    tokio::spawn(async move {
        shutdown.await;
        tracing::info!("shutting down");
        let _ = stop_tx.send(true);
        h.graceful_shutdown(Some(Duration::from_secs(5)));
    });

    while let Some(res) = tasks.join_next().await {
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                handle.graceful_shutdown(Some(Duration::from_secs(2)));
                return Err(e);
            }
            Err(e) => return Err(anyhow::anyhow!(e)),
        }
    }
    Ok(())
}

fn display_addr(addr: SocketAddr) -> String {
    if addr.ip().is_unspecified() {
        format!("<this-machine>:{}", addr.port())
    } else {
        addr.to_string()
    }
}

/// Completes on Ctrl+C or SIGTERM (docker stop).
pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}
