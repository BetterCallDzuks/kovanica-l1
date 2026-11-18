//! `kovanica-stratum` binary: Stratum V1 mining pool gateway.

use anyhow::Result;
use clap::Parser;
use kovanica_stratum::{StratumArgs, StratumConfig, StratumGateway};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = StratumArgs::parse();
    info!(
        listen = %args.listen,
        rpc_url = %args.rpc_url,
        difficulty = args.difficulty,
        chain_id = args.chain_id,
        "initializing Kovanica Stratum V1 gateway"
    );

    let config = StratumConfig::from(args);
    let gateway = StratumGateway::new(config);

    gateway.run().await
}
