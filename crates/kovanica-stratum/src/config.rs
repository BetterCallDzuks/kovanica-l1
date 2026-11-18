//! Configuration and CLI arguments for the Stratum V1 gateway.

use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;

/// Default Stratum V1 TCP listening port.
pub const DEFAULT_STRATUM_PORT: u16 = 3333;
/// Default upstream node JSON-RPC URL.
pub const DEFAULT_NODE_RPC_URL: &str = "http://127.0.0.1:8545";
/// Default initial share difficulty.
pub const DEFAULT_SHARE_DIFFICULTY: f64 = 1.0;
/// Default chain ID (2 = hybrid testnet).
pub const DEFAULT_CHAIN_ID: u64 = 2;
/// Default polling interval for new work templates from upstream node.
pub const DEFAULT_POLL_INTERVAL_MS: u64 = 500;

/// Command-line arguments for `kovanica-stratum`.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "kovanica-stratum",
    about = "Production-grade Stratum V1 mining pool gateway for Kovanica",
    version
)]
pub struct StratumArgs {
    /// TCP listen address for incoming Stratum miner connections.
    #[arg(long, default_value = "0.0.0.0:3333")]
    pub listen: SocketAddr,

    /// Upstream Kovanica node JSON-RPC endpoint.
    #[arg(long, default_value = DEFAULT_NODE_RPC_URL)]
    pub rpc_url: String,

    /// Initial share difficulty assigned to connected miners.
    #[arg(long, default_value_t = DEFAULT_SHARE_DIFFICULTY)]
    pub difficulty: f64,

    /// Target network chain ID (1 = Mainnet, 2 = Testnet).
    #[arg(long, default_value_t = DEFAULT_CHAIN_ID)]
    pub chain_id: u64,

    /// Fallback pool payout address (canonical PRO-21 base32 `kvnc...dag`) used when
    /// fetching upstream work before workers authorize.
    #[arg(long)]
    pub payout_address: Option<String>,

    /// Upstream template polling interval in milliseconds.
    #[arg(long, default_value_t = DEFAULT_POLL_INTERVAL_MS)]
    pub poll_interval_ms: u64,
}

/// Runtime configuration for `StratumGateway`.
#[derive(Debug, Clone)]
pub struct StratumConfig {
    /// TCP listen address.
    pub listen_addr: SocketAddr,
    /// Upstream node RPC URL.
    pub rpc_url: String,
    /// Initial share difficulty.
    pub difficulty: f64,
    /// Chain ID.
    pub chain_id: u64,
    /// Fallback pool payout address.
    pub payout_address: Option<String>,
    /// Upstream polling interval.
    pub poll_interval: Duration,
}

impl Default for StratumConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], DEFAULT_STRATUM_PORT)),
            rpc_url: DEFAULT_NODE_RPC_URL.to_string(),
            difficulty: DEFAULT_SHARE_DIFFICULTY,
            chain_id: DEFAULT_CHAIN_ID,
            payout_address: None,
            poll_interval: Duration::from_millis(DEFAULT_POLL_INTERVAL_MS),
        }
    }
}

impl From<StratumArgs> for StratumConfig {
    fn from(args: StratumArgs) -> Self {
        Self {
            listen_addr: args.listen,
            rpc_url: args.rpc_url,
            difficulty: args.difficulty,
            chain_id: args.chain_id,
            payout_address: args.payout_address,
            poll_interval: Duration::from_millis(args.poll_interval_ms),
        }
    }
}
