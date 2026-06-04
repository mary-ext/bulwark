//! Bulwark server: runs the DNS engine and serves the web UI + REST API.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bulwark::app::{self, AppState, Paths};
use bulwark::{api, assets, auth, persist, store};
use bulwark_config::Config;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let data_dir = std::env::var("BULWARK_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("data"));
    let paths = Arc::new(Paths::new(data_dir));
    app::ensure_dirs(&paths)?;

    // Load (or create) config, applying any env overrides for binds.
    let mut config = Config::load_or_default(&paths.config).context("loading config")?;
    app::apply_env_overrides(&mut config);
    if !paths.config.exists() {
        config
            .save(&paths.config)
            .context("writing initial config")?;
    }

    tracing::info!(data_dir = %paths.data_dir.display(), "starting bulwark");

    // Build the engine.
    let engine = app::build_engine(&config, &paths).await?;

    // Restore persisted statistics.
    if config.stats.persist {
        persist::load_stats(&paths.stats, &engine);
    }

    // Warm the DNS cache from the last snapshot (after build_engine has applied
    // the cache's TTL/stale config, so expiry is judged correctly).
    persist::load_cache(&paths.cache_snapshot, &engine);

    // Open the disk-backed query-log store. When persistence is off we use an
    // in-memory database so the log still works for the lifetime of the process.
    let store_path = if config.query_log.persist {
        paths.querylog_db.to_string_lossy().into_owned()
    } else {
        ":memory:".to_string()
    };
    let store = Arc::new(
        store::QueryStore::open(&store_path)
            .await
            .context("opening query-log store")?,
    );
    // Wire the engine's hot-path sink to the background writer. Bounded so a slow
    // writer sheds load instead of growing memory without limit.
    let (tx, rx) = tokio::sync::mpsc::channel(persist::QUERYLOG_CHANNEL_CAP);
    engine.log().set_sink(tx);
    persist::spawn_querylog_writer(store.clone(), rx);

    let config = Arc::new(tokio::sync::RwLock::new(config));
    let state = AppState {
        engine: engine.clone(),
        config: config.clone(),
        paths: paths.clone(),
        sessions: Arc::new(auth::Sessions::new(Duration::from_secs(7 * 24 * 3600))),
        store: store.clone(),
    };

    // Background tasks.
    spawn_probe_loop(engine.clone(), config.clone());
    persist::spawn_stats_snapshotter(engine.clone(), paths.stats.clone(), config.clone());
    persist::spawn_cache_snapshotter(engine.clone(), paths.cache_snapshot.clone());
    persist::spawn_querylog_pruner(store.clone(), config.clone());

    // Start DNS listeners.
    let dns_binds = config.read().await.server.dns_bind.clone();
    match bulwark_engine::server::spawn(engine.clone(), &dns_binds).await {
        Ok(_handles) => {}
        Err(e) => {
            // Don't abort the whole server if e.g. :53 needs privileges — the
            // web UI should still come up so the user can reconfigure.
            tracing::error!(error = %e, "failed to bind DNS listeners (web UI still starts)");
        }
    }

    // Build the HTTP app.
    let http_bind = config.read().await.server.http_bind;
    let appy = api::router(state.clone())
        .merge(assets::router())
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(http_bind)
        .await
        .with_context(|| format!("binding HTTP {http_bind}"))?;
    tracing::info!(%http_bind, "web UI + API listening");

    // Serve with graceful shutdown.
    let shutdown_engine = engine.clone();
    let shutdown_paths = paths.clone();
    let shutdown_cfg = config.clone();
    axum::serve(listener, appy.into_make_service())
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            tracing::info!("shutting down; persisting stats + cache");
            if shutdown_cfg.read().await.stats.persist {
                persist::snapshot_stats_now(&shutdown_engine, &shutdown_paths.stats);
            }
            persist::snapshot_cache_now(&shutdown_engine, &shutdown_paths.cache_snapshot);
        })
        .await
        .context("http server error")?;

    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("BULWARK_LOG")
        .or_else(|_| EnvFilter::try_new("info,bulwark=info"))
        .unwrap();
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

/// Periodically run polite background latency probes against all upstreams.
fn spawn_probe_loop(engine: Arc<bulwark_engine::Engine>, config: Arc<tokio::sync::RwLock<Config>>) {
    tokio::spawn(async move {
        loop {
            let interval = config.read().await.upstreams.probe_interval_secs;
            if interval == 0 {
                tokio::time::sleep(Duration::from_secs(60)).await;
                continue;
            }
            tokio::time::sleep(Duration::from_secs(interval)).await;
            engine.pool().probe_all().await;
        }
    });
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
