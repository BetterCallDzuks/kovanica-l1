//! Configuration and CLI arguments for the Stratum V1 gateway.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Result};
use clap::Parser;
use kovanica_types::Address;

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
/// Default maximum total concurrent connections.
pub const DEFAULT_MAX_CONNECTIONS: usize = 10_000;
/// Default maximum connections per IP address.
pub const DEFAULT_MAX_CONNECTIONS_PER_IP: usize = 100;
/// Default maximum new connections per second per IP.
pub const DEFAULT_MAX_CONNECTION_RATE_PER_IP: usize = 10;
/// Default maximum Stratum requests per second per connection.
pub const DEFAULT_MAX_REQUEST_RATE_PER_CONNECTION: usize = 50;
/// Default metrics/health HTTP server listen address.
pub const DEFAULT_METRICS_ADDR: &str = "127.0.0.1:9090";
/// Valid canonical PRO-21 burn address used when the operator does not supply a payout.
///
/// This replaces the previous invalid placeholder, which made `kovanica_getWork` fail on every
/// poll and left the gateway with no jobs to broadcast.
pub const DEFAULT_PAYOUT_ADDRESS: &str =
    "kvncqqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc07228f2dag";

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

    /// Enable TLS for Stratum connections.
    #[arg(long, default_value_t = false)]
    pub tls: bool,

    /// Path to TLS certificate file (PEM format).
    #[arg(long, requires = "tls")]
    pub tls_cert: Option<PathBuf>,

    /// Path to TLS private key file (PEM format).
    #[arg(long, requires = "tls")]
    pub tls_key: Option<PathBuf>,

    /// Generate self-signed TLS certificate for testing (if cert/key not provided).
    #[arg(long, requires = "tls")]
    pub tls_self_signed: bool,

    /// Maximum total concurrent connections.
    #[arg(long, default_value_t = DEFAULT_MAX_CONNECTIONS)]
    pub max_connections: usize,

    /// Maximum connections per IP address.
    #[arg(long, default_value_t = DEFAULT_MAX_CONNECTIONS_PER_IP)]
    pub max_connections_per_ip: usize,

    /// Maximum new connections per second per IP.
    #[arg(long, default_value_t = DEFAULT_MAX_CONNECTION_RATE_PER_IP)]
    pub max_connection_rate_per_ip: usize,

    /// Maximum Stratum requests per second per connection.
    #[arg(long, default_value_t = DEFAULT_MAX_REQUEST_RATE_PER_CONNECTION)]
    pub max_request_rate_per_connection: usize,

    /// HTTP listen address for metrics (/metrics) and health (/health) endpoints.
    #[arg(long, default_value = DEFAULT_METRICS_ADDR)]
    pub metrics_addr: std::net::SocketAddr,

    /// Log format: "json" for structured JSON logs, "pretty" for human-readable.
    #[arg(long, default_value = "json")]
    pub log_format: String,

    /// Optional bearer token for authenticated upstream node RPC write calls (`kovanica_submitWork`).
    /// Falls back to `KOVANICA_RPC_WRITE_TOKEN` or the first token in `KOVANICA_RPC_WRITE_TOKENS`.
    #[arg(long)]
    pub rpc_token: Option<String>,
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
    /// Enable TLS.
    pub tls: bool,
    /// TLS certificate path.
    pub tls_cert: Option<PathBuf>,
    /// TLS private key path.
    pub tls_key: Option<PathBuf>,
    /// Generate self-signed cert for testing.
    pub tls_self_signed: bool,
    /// Maximum total concurrent connections.
    pub max_connections: usize,
    /// Maximum connections per IP address.
    pub max_connections_per_ip: usize,
    /// Maximum new connections per second per IP.
    pub max_connection_rate_per_ip: usize,
    /// Maximum Stratum requests per second per connection.
    pub max_request_rate_per_connection: usize,
    /// HTTP listen address for metrics (/metrics) and health (/health) endpoints.
    pub metrics_addr: SocketAddr,
    /// Log format: "json" for structured JSON logs, "pretty" for human-readable.
    pub log_format: String,
    /// Optional bearer token for authenticated upstream node RPC write calls (`kovanica_submitWork`).
    pub rpc_token: Option<String>,
}

/// Resolve the bearer token for node write RPC calls from the environment.
pub fn resolve_rpc_token_from_env() -> Option<String> {
    let singular = std::env::var("KOVANICA_RPC_WRITE_TOKEN")
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());
    if singular.is_some() {
        return singular;
    }
    std::env::var("KOVANICA_RPC_WRITE_TOKENS")
        .ok()
        .and_then(|list| {
            list.split(',')
                .map(str::trim)
                .find(|t| !t.is_empty())
                .map(str::to_string)
        })
}

impl Default for StratumConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], DEFAULT_STRATUM_PORT)),
            rpc_url: DEFAULT_NODE_RPC_URL.to_string(),
            difficulty: DEFAULT_SHARE_DIFFICULTY,
            chain_id: DEFAULT_CHAIN_ID,
            payout_address: Some(DEFAULT_PAYOUT_ADDRESS.to_string()),
            poll_interval: Duration::from_millis(DEFAULT_POLL_INTERVAL_MS),
            tls: false,
            tls_cert: None,
            tls_key: None,
            tls_self_signed: false,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_connections_per_ip: DEFAULT_MAX_CONNECTIONS_PER_IP,
            max_connection_rate_per_ip: DEFAULT_MAX_CONNECTION_RATE_PER_IP,
            max_request_rate_per_connection: DEFAULT_MAX_REQUEST_RATE_PER_CONNECTION,
            metrics_addr: DEFAULT_METRICS_ADDR.parse().unwrap(),
            log_format: "json".to_string(),
            rpc_token: resolve_rpc_token_from_env(),
        }
    }
}

impl StratumConfig {
    /// Validate runtime configuration before starting the gateway.
    pub fn validate(&self) -> Result<()> {
        if let Some(addr) = &self.payout_address {
            if Address::decode(addr).is_err() {
                bail!("invalid payout address: {addr}");
            }
        }
        if self.difficulty < 0.0 {
            bail!("difficulty must be non-negative");
        }
        if self.max_connections == 0 {
            bail!("max_connections must be > 0");
        }
        if self.max_connections_per_ip == 0 {
            bail!("max_connections_per_ip must be > 0");
        }
        if self.max_connection_rate_per_ip == 0 {
            bail!("max_connection_rate_per_ip must be > 0");
        }
        if self.max_request_rate_per_connection == 0 {
            bail!("max_request_rate_per_connection must be > 0");
        }
        if self.log_format != "json" && self.log_format != "pretty" {
            bail!(
                "invalid log_format '{}': expected 'json' or 'pretty'",
                self.log_format
            );
        }
        if self.tls {
            if self.tls_self_signed {
                #[cfg(not(feature = "self-signed"))]
                bail!(
                    "--tls-self-signed requires building kovanica-stratum with --features self-signed"
                );
            } else if self.tls_cert.is_none() || self.tls_key.is_none() {
                bail!("TLS enabled but cert and/or key not provided (use --tls-self-signed for testing)");
            } else {
                // Check files exist
                if let Some(cert) = &self.tls_cert {
                    if !cert.exists() {
                        bail!("TLS certificate file not found: {}", cert.display());
                    }
                }
                if let Some(key) = &self.tls_key {
                    if !key.exists() {
                        bail!("TLS key file not found: {}", key.display());
                    }
                }
            }
        }
        Ok(())
    }
}

impl From<StratumArgs> for StratumConfig {
    fn from(args: StratumArgs) -> Self {
        Self {
            listen_addr: args.listen,
            rpc_url: args.rpc_url,
            difficulty: args.difficulty,
            chain_id: args.chain_id,
            payout_address: Some(
                args.payout_address
                    .unwrap_or_else(|| DEFAULT_PAYOUT_ADDRESS.to_string()),
            ),
            poll_interval: Duration::from_millis(args.poll_interval_ms),
            tls: args.tls,
            tls_cert: args.tls_cert,
            tls_key: args.tls_key,
            tls_self_signed: args.tls_self_signed,
            max_connections: args.max_connections,
            max_connections_per_ip: args.max_connections_per_ip,
            max_connection_rate_per_ip: args.max_connection_rate_per_ip,
            max_request_rate_per_connection: args.max_request_rate_per_connection,
            metrics_addr: args.metrics_addr,
            log_format: args.log_format,
            rpc_token: args
                .rpc_token
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .or_else(resolve_rpc_token_from_env),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_payout_address_is_canonical() {
        let addr = DEFAULT_PAYOUT_ADDRESS;
        assert_eq!(addr.len(), 64);
        assert!(Address::decode(addr).is_ok());
    }

    #[test]
    fn config_uses_valid_default_payout() {
        let config = StratumConfig::default();
        assert_eq!(
            config.payout_address.as_deref(),
            Some(DEFAULT_PAYOUT_ADDRESS)
        );
        config.validate().expect("default config must be valid");
    }

    #[test]
    fn invalid_payout_address_is_rejected() {
        let config = StratumConfig {
            payout_address: Some("kvnc1notvalid".to_string()),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn log_format_validation() {
        let json_cfg = StratumConfig {
            log_format: "json".to_string(),
            ..Default::default()
        };
        assert!(json_cfg.validate().is_ok());

        let pretty_cfg = StratumConfig {
            log_format: "pretty".to_string(),
            ..Default::default()
        };
        assert!(pretty_cfg.validate().is_ok());

        let invalid_cfg = StratumConfig {
            log_format: "xml".to_string(),
            ..Default::default()
        };
        assert!(invalid_cfg.validate().is_err());
    }

    #[test]
    fn tls_config_validation_requires_paired_existing_cert_and_key() {
        // TLS enabled without cert or key fails
        let missing_both = StratumConfig {
            tls: true,
            ..Default::default()
        };
        assert!(missing_both.validate().is_err());

        // TLS enabled with only cert fails
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, b"dummy cert").expect("write cert");
        std::fs::write(&key_path, b"dummy key").expect("write key");

        let only_cert = StratumConfig {
            tls: true,
            tls_cert: Some(cert_path.clone()),
            tls_key: None,
            ..Default::default()
        };
        assert!(only_cert.validate().is_err());

        let only_key = StratumConfig {
            tls: true,
            tls_cert: None,
            tls_key: Some(key_path.clone()),
            ..Default::default()
        };
        assert!(only_key.validate().is_err());

        // Non-existent files fail
        let nonexistent = StratumConfig {
            tls: true,
            tls_cert: Some(dir.path().join("missing_cert.pem")),
            tls_key: Some(key_path.clone()),
            ..Default::default()
        };
        assert!(nonexistent.validate().is_err());

        // Both existing files succeed
        let valid = StratumConfig {
            tls: true,
            tls_cert: Some(cert_path),
            tls_key: Some(key_path),
            ..Default::default()
        };
        assert!(valid.validate().is_ok());
    }

    #[test]
    fn stratum_args_tls_flags_require_tls() {
        assert!(StratumArgs::try_parse_from(["kovanica-stratum", "--tls-cert", "c.pem"]).is_err());
        assert!(StratumArgs::try_parse_from(["kovanica-stratum", "--tls-key", "k.pem"]).is_err());
        assert!(StratumArgs::try_parse_from(["kovanica-stratum", "--tls-self-signed"]).is_err());

        let parsed = StratumArgs::try_parse_from([
            "kovanica-stratum",
            "--tls",
            "--tls-cert",
            "c.pem",
            "--tls-key",
            "k.pem",
        ])
        .expect("valid TLS CLI args must parse");
        assert!(parsed.tls);
        assert_eq!(parsed.tls_cert, Some(PathBuf::from("c.pem")));
        assert_eq!(parsed.tls_key, Some(PathBuf::from("k.pem")));
    }
}
