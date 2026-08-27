//! Bulwark DNS and HTTP server.

// The query path is allocation-heavy and frees log entries across threads.
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bulwark::app::{self, AppState, Paths};
use bulwark::{api, assets, auth, persist, probe_store, store};
use bulwark_config::Config;
use bulwark_upstream::ProbeLog;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    enable_jemalloc_background_purge();

    let data_dir = std::env::var("BULWARK_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("data"));
    let paths = Arc::new(Paths::new(data_dir));
    app::ensure_dirs(&paths)?;

    let mut config = Config::load_or_default(&paths.config).context("loading config")?;
    app::apply_env_overrides(&mut config);
    // Persist the initial signing secret so sessions survive restarts.
    let mut needs_save = !paths.config.exists();
    if config.auth.session_secret.is_none() {
        config.auth.session_secret = Some(auth::generate_secret());
        needs_save = true;
    }
    if needs_save {
        config.save(&paths.config).context("writing config")?;
    }
    let sessions = Arc::new(auth::SessionSigner::new(
        config
            .auth
            .session_secret
            .as_deref()
            .expect("session secret set above"),
        Duration::from_secs(auth::SESSION_TTL_SECS),
    ));

    tracing::info!(data_dir = %paths.data_dir.display(), "starting bulwark");

    let probe_log = Arc::new(ProbeLog::new(config.upstream_log.enabled));

    let engine = app::build_engine(&config, &paths, probe_log.clone()).await?;

    if config.stats.persist {
        persist::load_stats(&paths.stats, &engine);
    }

    persist::load_cache(&paths.cache_snapshot, &engine);

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
    let (tx, rx) = tokio::sync::mpsc::channel(persist::QUERYLOG_CHANNEL_CAP);
    engine.log().set_sink(tx);
    persist::spawn_querylog_writer(store.clone(), rx);

    // The always-wired sink lets telemetry be enabled without restarting.
    let probe_store_path = if config.upstream_log.persist {
        paths.upstream_log_db.to_string_lossy().into_owned()
    } else {
        ":memory:".to_string()
    };
    let probe_store = Arc::new(
        probe_store::ProbeStore::open(&probe_store_path)
            .await
            .context("opening probe-log store")?,
    );
    let (ptx, prx) = tokio::sync::mpsc::channel(persist::PROBE_CHANNEL_CAP);
    probe_log.set_sink(ptx);
    persist::spawn_probe_writer(probe_store.clone(), prx);

    let config = Arc::new(tokio::sync::RwLock::new(config));
    let state = AppState {
        engine: engine.clone(),
        config: config.clone(),
        paths: paths.clone(),
        sessions,
        store: store.clone(),
        probe_log: probe_log.clone(),
        probe_store: probe_store.clone(),
        update_lock: Arc::new(tokio::sync::Mutex::new(())),
    };

    persist::spawn_stats_snapshotter(engine.clone(), paths.stats.clone(), config.clone());
    persist::spawn_cache_snapshotter(engine.clone(), paths.cache_snapshot.clone());
    persist::spawn_querylog_pruner(store.clone(), config.clone());
    persist::spawn_probe_pruner(probe_store.clone(), config.clone());

    let dns_binds = config.read().await.server.dns_bind.clone();
    match bulwark_engine::server::spawn(engine.clone(), &dns_binds).await {
        Ok(_handles) => {}
        Err(e) => {
            // Keep the web UI available when a DNS bind fails.
            tracing::error!(error = %e, "failed to bind DNS listeners (web UI still starts)");
        }
    }

    let http_bind = config.read().await.server.http_bind;
    let appy = api::router(state.clone())
        .merge(assets::router())
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(http_bind)
        .await
        .with_context(|| format!("binding HTTP {http_bind}"))?;
    tracing::info!(%http_bind, "web UI + API listening");

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

/// Enables jemalloc's background purge thread when supported.
fn enable_jemalloc_background_purge() {
    if let Err(e) = tikv_jemalloc_ctl::background_thread::write(true) {
        tracing::warn!(error = %e, "could not enable jemalloc background_thread");
    }
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
