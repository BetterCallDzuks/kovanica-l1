//! `kovanica-stratum` binary: Stratum V1 mining pool gateway.

use anyhow::{Context, Result};
use clap::Parser;
use kovanica_stratum::{StratumArgs, StratumConfig, StratumGateway};
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

#[tokio::main]
async fn main() -> Result<()> {
    let args = StratumArgs::parse();

    // Initialize logging based on config
    let log_format = args.log_format.clone();
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let fmt_layer = if log_format == "json" {
        tracing_subscriber::fmt::layer()
            .json()
            .with_current_span(true)
            .with_span_list(true)
            .boxed()
    } else {
        tracing_subscriber::fmt::layer().pretty().boxed()
    };

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .init();

    info!(
        listen = %args.listen,
        rpc_url = %args.rpc_url,
        difficulty = args.difficulty,
        chain_id = args.chain_id,
        tls = args.tls,
        metrics_addr = %args.metrics_addr,
        log_format = %log_format,
        "initializing Kovanica Stratum V1 gateway"
    );

    #[allow(unused_mut)]
    let mut config = StratumConfig::from(args);
    config.validate()?;

    // Generate self-signed cert if requested (requires "self-signed" feature)
    #[cfg(feature = "self-signed")]
    if config.tls && config.tls_self_signed {
        info!("generating self-signed TLS certificate for testing");
        let (cert, key) = StratumGateway::generate_self_signed_cert()?;
        let cert_path = config
            .tls_cert
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("tls_cert.pem"));
        let key_path = config
            .tls_key
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("tls_key.pem"));
        std::fs::write(&cert_path, &cert)?;
        std::fs::write(&key_path, &key)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        }
        config.tls_cert = Some(cert_path);
        config.tls_key = Some(key_path);
        info!("self-signed certificate written to tls_cert.pem and tls_key.pem (0600)");
    }

    let gateway = StratumGateway::new(config.clone())?;

    // Warn if observability server is bound to a non-loopback address
    if !config.metrics_addr.ip().is_loopback() {
        tracing::warn!(
            metrics_addr = %config.metrics_addr,
            "observability HTTP server (/metrics, /health) is bound to a non-loopback address; prefer 127.0.0.1 in production"
        );
    }

    // Bind and start metrics (/metrics) and health (/health) HTTP server
    let metrics_listener = TcpListener::bind(config.metrics_addr)
        .await
        .with_context(|| {
            format!(
                "failed to bind observability server on {}",
                config.metrics_addr
            )
        })?;
    let obs_gateway = gateway.clone();
    tokio::spawn(async move {
        if let Err(e) = obs_gateway.serve_observability(metrics_listener).await {
            error!(%e, "observability HTTP server terminated");
        }
    });

    // Spawn periodic uptime gauge updater & connection rate-limiter cleanup
    let uptime_gateway = gateway.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        loop {
            interval.tick().await;
            let uptime = uptime_gateway.start_time().elapsed().as_secs() as i64;
            uptime_gateway.metrics().uptime_seconds.set(uptime);
            uptime_gateway.cleanup_rate_limiter();
        }
    });

    // Spawn OS signal handler (SIGINT / SIGTERM) for graceful gateway shutdown
    let signal_gateway = gateway.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm =
                signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("received SIGINT (Ctrl-C), initiating graceful Stratum gateway shutdown");
                }
                _ = sigterm.recv() => {
                    info!("received SIGTERM, initiating graceful Stratum gateway shutdown");
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            info!("received SIGINT (Ctrl-C), initiating graceful Stratum gateway shutdown");
        }
        signal_gateway.shutdown();
    });

    gateway.run().await
}
