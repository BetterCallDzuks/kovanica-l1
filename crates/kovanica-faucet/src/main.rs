//! Kovanica (KVNC) Faucet Service
//!
//! Rate-limited faucet that dispenses test KVNC to addresses.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use clap::Parser;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use zeroize::Zeroizing;

use ed25519_dalek::{Signer, SigningKey};
use kovanica_cli::wallet;
use kovanica_types::signing::chain_id;
use kovanica_types::{hash::Hash, Address, PublicKey, Signature, Transaction, TransactionKind};

mod cors;
mod proxy;

/// Faucet configuration
#[derive(Clone)]
struct FaucetConfig {
    /// Amount to dispense per request (in atoms)
    dispense_amount: u64,
    /// Rate limit window (seconds) for the per-client-IP limiter
    rate_limit_window: u64,
    /// Max requests per window per IP
    max_requests_per_window: usize,
    /// Rate limit window (seconds) for the per-destination-address limiter
    address_rate_limit_window: u64,
    /// Max requests per window per destination address
    address_max_requests: usize,
    /// RPC endpoint of the node
    rpc_url: String,
    /// Optional bearer token for authenticated write RPC methods
    /// (`KOVANICA_RPC_WRITE_TOKEN`, or the first entry of
    /// `KOVANICA_RPC_WRITE_TOKENS`). `None` means the node accepted auth is
    /// disabled, or writes will be rejected (fail-closed).
    rpc_token: Option<String>,
    /// Network signing context (signature format v1): every dispensed
    /// transaction commits to this `chain_id`.
    signing_ctx: kovanica_types::SigningContext,
    /// Reverse proxies whose `X-Forwarded-For` header may be trusted for
    /// rate-limit keying. Empty means every request keys on the socket peer.
    trusted_proxies: proxy::TrustedProxies,
    /// Refuse to dispense when the faucet's own balance (in atoms) is below
    /// this. `0` disables the check.
    min_balance_atoms: u64,
}

const DEFAULT_MAP_SIZE_CAP: usize = 100_000;

/// Keys visited on one at-cap admission. The request path never scans the
/// whole map; [`LimiterMap::maybe_sweep`] still walks every entry once per window.
const EXPIRED_SWEEP_BUDGET: usize = 32;

#[derive(Default)]
struct LimiterEntry {
    generation: u64,
    timestamps: Vec<std::time::Instant>,
}

#[derive(Default)]
struct LimiterMap {
    entries: std::collections::HashMap<String, LimiterEntry>,
    last_sweep: Option<std::time::Instant>,
    next_gen: u64,
    /// Insertion-order ring. At-cap admission walks a bounded prefix and
    /// rotates live keys to the back, lazily skipping dead/stale entries.
    sweep_order: std::collections::VecDeque<(String, u64)>,
}

impl LimiterMap {
    fn sweep_at(&mut self, window_secs: u64, now: std::time::Instant) {
        let window_start = now.checked_sub(Duration::from_secs(window_secs));
        self.entries.retain(|_, entry| {
            entry
                .timestamps
                .retain(|t| window_start.is_none_or(|start| *t > start));
            !entry.timestamps.is_empty()
        });
        self.sweep_order
            .retain(|(key, gen)| self.entries.get(key).is_some_and(|e| e.generation == *gen));
        self.last_sweep = Some(now);
    }

    /// Periodic full sweep: first use, then again after one window.
    /// A full map does not itself trigger this scan.
    fn maybe_sweep(&mut self, window_secs: u64, now: std::time::Instant) {
        let window_dur = Duration::from_secs(window_secs);
        let elapsed_enough = match self.last_sweep {
            Some(last) => now.saturating_duration_since(last) >= window_dur,
            None => true,
        };
        if elapsed_enough {
            self.sweep_at(window_secs, now);
        }
    }

    /// Drop expired timestamps from up to `budget` keys. Live keys stay and
    /// move to the back of the ring. Missing or stale generation entries are skipped.
    fn sweep_expired_budget(&mut self, window_secs: u64, now: std::time::Instant, budget: usize) {
        let window_start = now.checked_sub(Duration::from_secs(window_secs));
        for _ in 0..budget {
            let Some((key, gen)) = self.sweep_order.pop_front() else {
                break;
            };
            let expired = match self.entries.get_mut(&key) {
                Some(entry) if entry.generation == gen => {
                    entry
                        .timestamps
                        .retain(|t| window_start.is_none_or(|start| *t > start));
                    entry.timestamps.is_empty()
                }
                _ => continue,
            };
            if expired {
                self.entries.remove(&key);
            } else {
                self.sweep_order.push_back((key, gen));
            }
        }
    }

    /// Room for a key that is not in the map yet.
    ///
    /// At the cap, sweep a bounded number of expired entries. If the map is
    /// still full, refuse. Never deletes a live entry.
    fn try_admit_new_key(
        &mut self,
        window_secs: u64,
        size_cap: usize,
        now: std::time::Instant,
    ) -> bool {
        if self.entries.len() < size_cap {
            return true;
        }
        self.sweep_expired_budget(window_secs, now, EXPIRED_SWEEP_BUDGET);
        self.entries.len() < size_cap
    }

    fn forget_key(&mut self, key: &str) {
        self.entries.remove(key);
    }

    /// Shared admission path for the IP map and the address map.
    /// `Some(now)` means this attempt was recorded.
    fn record_at(
        &mut self,
        key: &str,
        window_secs: u64,
        max_requests: usize,
        size_cap: usize,
        now: std::time::Instant,
    ) -> Option<std::time::Instant> {
        self.maybe_sweep(window_secs, now);

        let window_start = now.checked_sub(Duration::from_secs(window_secs));

        if self.entries.contains_key(key) {
            let reject_empty = {
                let entry = self.entries.get_mut(key).expect("key just checked");
                entry
                    .timestamps
                    .retain(|t| window_start.is_none_or(|start| *t > start));
                if entry.timestamps.len() >= max_requests {
                    Some(entry.timestamps.is_empty())
                } else {
                    entry.timestamps.push(now);
                    None
                }
            };
            if let Some(drop_key) = reject_empty {
                if drop_key {
                    self.forget_key(key);
                }
                return None;
            }
            return Some(now);
        }

        if max_requests == 0 || !self.try_admit_new_key(window_secs, size_cap, now) {
            return None;
        }
        let gen = self.next_gen;
        self.next_gen = self.next_gen.wrapping_add(1);
        let owned = key.to_string();
        self.sweep_order.push_back((owned.clone(), gen));
        self.entries.insert(
            owned,
            LimiterEntry {
                generation: gen,
                timestamps: vec![now],
            },
        );
        Some(now)
    }

    fn rollback_at(&mut self, key: &str, timestamp: std::time::Instant) {
        let remove_key = if let Some(entry) = self.entries.get_mut(key) {
            if let Some(pos) = entry.timestamps.iter().position(|t| *t == timestamp) {
                entry.timestamps.remove(pos);
            }
            entry.timestamps.is_empty()
        } else {
            false
        };
        if remove_key {
            self.forget_key(key);
        }
    }
}

/// Rate limiter state supporting rate limiting by IP and by destination address
#[derive(Clone)]
struct RateLimiter {
    inner: Arc<RateLimiterInner>,
}

struct RateLimiterInner {
    requests: Mutex<LimiterMap>,
    address_requests: Mutex<LimiterMap>,
    size_cap: usize,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::with_capacity_limit(DEFAULT_MAP_SIZE_CAP)
    }
}

impl RateLimiter {
    fn with_capacity_limit(size_cap: usize) -> Self {
        Self {
            inner: Arc::new(RateLimiterInner {
                requests: Mutex::new(LimiterMap::default()),
                address_requests: Mutex::new(LimiterMap::default()),
                size_cap,
            }),
        }
    }

    fn check_and_record_ip(&self, ip: &str, window_secs: u64, max_requests: usize) -> bool {
        self.inner
            .requests
            .lock()
            .record_at(
                ip,
                window_secs,
                max_requests,
                self.inner.size_cap,
                std::time::Instant::now(),
            )
            .is_some()
    }

    fn reserve_address(
        &self,
        address: &str,
        window_secs: u64,
        max_requests: usize,
    ) -> Option<AddressReservation> {
        let now = std::time::Instant::now();
        let timestamp = self.inner.address_requests.lock().record_at(
            address,
            window_secs,
            max_requests,
            self.inner.size_cap,
            now,
        )?;
        Some(AddressReservation {
            limiter: self.clone(),
            address: address.to_string(),
            timestamp,
            committed: false,
        })
    }

    fn rollback_address_at(&self, address: &str, timestamp: std::time::Instant) {
        self.inner
            .address_requests
            .lock()
            .rollback_at(address, timestamp);
    }

    #[cfg(test)]
    fn ip_count(&self) -> usize {
        self.inner.requests.lock().entries.len()
    }

    #[cfg(test)]
    fn sweep_ip_at(&self, window_secs: u64, now: std::time::Instant) {
        self.inner.requests.lock().sweep_at(window_secs, now);
    }

    #[cfg(test)]
    fn record_ip_at(
        &self,
        ip: &str,
        window_secs: u64,
        max_requests: usize,
        now: std::time::Instant,
    ) -> bool {
        self.inner
            .requests
            .lock()
            .record_at(ip, window_secs, max_requests, self.inner.size_cap, now)
            .is_some()
    }

    #[cfg(test)]
    fn set_ip_last_sweep(&self, now: std::time::Instant) {
        self.inner.requests.lock().last_sweep = Some(now);
    }
}

/// RAII reservation guard for a destination-address rate-limit slot.
///
/// Rolled back on drop unless [`commit`](Self::commit) has run. Commit before
/// awaiting submit. [`rollback`](Self::rollback) undoes that commit when submit
/// returns `Err`. A drop after commit, with no rollback, keeps the slot.
struct AddressReservation {
    limiter: RateLimiter,
    address: String,
    timestamp: std::time::Instant,
    committed: bool,
}

impl AddressReservation {
    /// Keep the slot if this guard is dropped. The guard stays usable so
    /// [`rollback`](Self::rollback) can undo a failed submit.
    fn commit(&mut self) {
        self.committed = true;
    }

    /// Release the slot and make [`Drop`] a no-op.
    fn rollback(&mut self) {
        self.limiter
            .rollback_address_at(&self.address, self.timestamp);
        self.committed = true;
    }
}

impl Drop for AddressReservation {
    fn drop(&mut self) {
        if !self.committed {
            self.limiter
                .rollback_address_at(&self.address, self.timestamp);
        }
    }
}

/// Faucet state
struct FaucetState {
    config: FaucetConfig,
    signer: SigningKey,
    faucet_address: Address,
    rate_limiter: RateLimiter,
    client: reqwest::Client,
    pending_nonce: Mutex<Option<u64>>,
}

/// Request payload
#[derive(Deserialize)]
struct FaucetRequest {
    address: String,
}

/// Response payload
#[derive(Serialize)]
struct FaucetResponse {
    success: bool,
    message: String,
    tx_hash: Option<String>,
}

#[derive(Parser)]
#[command(name = "kovanica-faucet")]
#[command(about = "Kovanica (KVNC) Faucet Service")]
struct Cli {
    /// Faucet keystore path
    #[arg(long, default_value = "faucet.keystore")]
    keystore: String,
    /// File containing the keystore passphrase (unix: must be 0600 or 0400).
    /// Alternatives: env KOVANICA_FAUCET_PASSPHRASE, or an interactive prompt on a TTY.
    #[arg(long)]
    passphrase_file: Option<PathBuf>,
    /// Amount to dispense per request (in KVNC)
    #[arg(long, default_value = "10")]
    dispense_kovanica: u64,
    /// Rate limit window (seconds) applied per client IP
    #[arg(long, default_value = "3600")]
    rate_limit_window: u64,
    /// Max requests per window per client IP
    #[arg(long, default_value = "3")]
    max_requests: usize,
    /// Rate limit window (seconds) applied per destination address.
    ///
    /// Kept separate from the per-IP window so a shared address (a hot wallet,
    /// an exchange deposit address) cannot be drained by rotating IPs.
    /// Equivalent to `KOVANICA_FAUCET_ADDRESS_RATE_LIMIT_WINDOW`.
    #[arg(
        long,
        default_value = "86400",
        env = ADDRESS_RATE_LIMIT_WINDOW_ENV
    )]
    address_rate_limit_window: u64,
    /// Max requests per window per destination address.
    ///
    /// Defaults to a lifetime-style cap of one dispense per address per day.
    /// Equivalent to `KOVANICA_FAUCET_ADDRESS_MAX_REQUESTS`.
    #[arg(long, default_value = "1", env = ADDRESS_MAX_REQUESTS_ENV)]
    address_max_requests: usize,
    /// Network chain_id committed to by every transaction signature
    /// (1 mainnet, 2 testnet, 3 devnet, 1337 local). No default on purpose.
    #[arg(long)]
    chain_id: u64,
    /// Loud override required to run the faucet on MAINNET (chain_id 1).
    /// Default behaviour is to refuse mainnet outright.
    ///
    /// Equivalent to setting `KOVANICA_FAUCET_ALLOW_MAINNET=1`.
    #[arg(long)]
    allow_mainnet: bool,
    /// Comma-separated list of reverse-proxy IPs/CIDRs whose `X-Forwarded-For`
    /// header is trusted for rate-limit keying (e.g. `10.0.0.0/8,127.0.0.1`).
    ///
    /// When unset (or the socket peer is not in the list) the socket peer IP is
    /// used and `X-Forwarded-For` is ignored. Equivalent to
    /// `KOVANICA_FAUCET_TRUSTED_PROXIES`.
    #[arg(long)]
    trusted_proxies: Option<String>,
    /// Refuse requests when the faucet balance (in KVNC) is below this floor.
    /// `0` (default) disables the low-balance guard.
    #[arg(long, default_value = "0")]
    min_balance_ku: u64,
    /// Node RPC URL
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc_url: String,
    /// Listen address
    #[arg(long, default_value = "0.0.0.0:8080")]
    listen: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    // MAINNET GUARD: never dispense real KVNC by accident. Running on chain_id 1
    // requires an explicit, loudly-named override.
    let allow_mainnet = cli.allow_mainnet || env_truthy(ALLOW_MAINNET_ENV);
    ensure_chain_allowed(cli.chain_id, allow_mainnet)?;
    if cli.chain_id == chain_id::MAINNET {
        warn!(
            chain_id = cli.chain_id,
            "running the faucet on MAINNET with the explicit --allow-mainnet override: \
             it will dispense REAL KVNC"
        );
    }

    // Trusted reverse proxies for X-Forwarded-For handling. A malformed entry
    // fails startup rather than silently trusting (or not trusting) the wrong hosts.
    let trusted_proxies_raw = cli
        .trusted_proxies
        .clone()
        .or_else(|| std::env::var(TRUSTED_PROXIES_ENV).ok());
    let trusted_proxies = match trusted_proxies_raw.as_deref() {
        Some(list) => proxy::TrustedProxies::parse_list(list)
            .with_context(|| format!("parsing trusted proxies `{list}`"))?,
        None => proxy::TrustedProxies::default(),
    };
    if !trusted_proxies.is_empty() {
        info!("trusting X-Forwarded-For from configured reverse proxies");
    } else if listens_on_local_or_private(&cli.listen) {
        // Behind a local reverse proxy with no trusted-proxy list every caller
        // collapses onto the proxy's socket IP, so one caller can drain the
        // whole hourly budget. Say so once, loudly, at startup.
        warn!(
            listen = %cli.listen,
            "no trusted proxies configured while listening on a loopback/private \
             address: every caller shares one IP rate-limit bucket. Set \
             --trusted-proxies or {TRUSTED_PROXIES_ENV} to key on the real client IP."
        );
    }

    // Load faucet keystore
    let keystore = wallet::load(std::path::Path::new(&cli.keystore))
        .with_context(|| format!("loading faucet keystore {}", cli.keystore))?;
    // The passphrase is only needed to decrypt the seed; it is wiped right
    // after and never stored in config/state or logged.
    let cli_passphrase = if keystore.encrypted {
        Some(resolve_passphrase(cli.passphrase_file.as_deref())?)
    } else {
        None
    };
    let passphrase = cli_passphrase.as_ref().map(|p| p.as_str());
    let seed =
        wallet::secret_seed(&keystore, passphrase).with_context(|| "decrypting faucet keystore")?;
    let signer = SigningKey::from_bytes(&seed);
    drop(cli_passphrase);
    let faucet_address = Address::from_public_key(&PublicKey::from(signer.verifying_key()));

    info!(faucet_address = %faucet_address, "faucet identity loaded");

    let config = FaucetConfig {
        dispense_amount: cli.dispense_kovanica * 1_000_000_000, // KVNC to atoms
        rate_limit_window: cli.rate_limit_window,
        max_requests_per_window: cli.max_requests,
        address_rate_limit_window: cli.address_rate_limit_window,
        address_max_requests: cli.address_max_requests,
        rpc_url: normalize_rpc_url(&cli.rpc_url),
        rpc_token: resolve_rpc_token(),
        signing_ctx: kovanica_types::SigningContext::new(cli.chain_id),
        trusted_proxies,
        min_balance_atoms: cli.min_balance_ku * 1_000_000_000, // KVNC to atoms
    };
    if config.rpc_token.is_none() {
        warn!(
            "no {RPC_WRITE_TOKEN_ENV} / {RPC_WRITE_TOKENS_ENV} configured: \
             node write calls will be rejected when RPC auth is enabled"
        );
    }

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .context("building HTTP client with timeouts")?;

    let state = Arc::new(FaucetState {
        config,
        signer,
        faucet_address,
        rate_limiter: RateLimiter::default(),
        client,
        pending_nonce: Mutex::new(None),
    });

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/faucet", post(faucet_handler))
        .with_state(state)
        .layer(axum::middleware::from_fn(cors::faucet_cors));

    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;
    info!(addr = %cli.listen, "faucet server listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// Env override that permits running the faucet on mainnet.
const ALLOW_MAINNET_ENV: &str = "KOVANICA_FAUCET_ALLOW_MAINNET";

/// Env override with the comma-separated trusted-proxy IP/CIDR list.
const TRUSTED_PROXIES_ENV: &str = "KOVANICA_FAUCET_TRUSTED_PROXIES";

/// Env override for the per-destination-address rate-limit window (seconds).
const ADDRESS_RATE_LIMIT_WINDOW_ENV: &str = "KOVANICA_FAUCET_ADDRESS_RATE_LIMIT_WINDOW";

/// Env override for the per-destination-address request cap per window.
const ADDRESS_MAX_REQUESTS_ENV: &str = "KOVANICA_FAUCET_ADDRESS_MAX_REQUESTS";

/// Whether `listen` (`host:port`) binds a loopback, private or unspecified address.
///
/// Used only for the startup warning about a single shared IP bucket: when the
/// faucet listens locally it is almost certainly reached through a reverse proxy.
/// Hostnames are treated as local so the warning is never silently skipped.
fn listens_on_local_or_private(listen: &str) -> bool {
    let host = match listen.rsplit_once(':') {
        Some((host, _port)) => host,
        None => listen,
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => is_local_or_private(ip),
        Err(_) => true,
    }
}

/// Loopback, unspecified, or RFC 1918 / RFC 4193 / link-local address.
fn is_local_or_private(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_unspecified() || v4.is_private() || v4.is_link_local()
        }
        std::net::IpAddr::V6(v6) => {
            let first = v6.octets()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 unique-local
                || (first & 0xfe) == 0xfc
                // fe80::/10 link-local
                || (v6.octets()[0] == 0xfe && (v6.octets()[1] & 0xc0) == 0x80)
        }
    }
}

/// Whether an environment variable holds an affirmative boolean value
/// (`1`, `true`, `yes` or `on`, case-insensitive).
fn env_truthy(name: &str) -> bool {
    std::env::var(name)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Validate the configured `chain_id`.
///
/// * unregistered ids are always refused;
/// * `chain_id 1` (mainnet) is refused unless `allow_mainnet` was given
///   explicitly — the faucet would otherwise dispense real KVNC.
fn ensure_chain_allowed(chain_id: u64, allow_mainnet: bool) -> Result<()> {
    if !kovanica_types::signing::chain_id::is_registered(chain_id) {
        bail!(
            "unknown chain id {}: expected 1 (mainnet), 2 (testnet), 3 (devnet) or 1337 (local)",
            chain_id
        );
    }
    if chain_id == chain_id::MAINNET && !allow_mainnet {
        bail!(
            "refusing to run the faucet on MAINNET (chain_id 1): it would dispense REAL KVNC. \
             If this is intentional, pass --allow-mainnet or set {ALLOW_MAINNET_ENV}=1."
        );
    }
    Ok(())
}

/// Key client IP addresses for rate limiting:
/// - IPv4 stays per individual address.
/// - IPv4-mapped IPv6 is treated as IPv4.
/// - Native IPv6 clients are grouped by their /64 subnet prefix.
fn rate_limit_ip_key(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                v4.to_string()
            } else {
                let seg = v6.segments();
                let prefix = std::net::Ipv6Addr::new(seg[0], seg[1], seg[2], seg[3], 0, 0, 0, 0);
                format!("{prefix}/64")
            }
        }
    }
}

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

async fn faucet_handler(
    State(state): State<Arc<FaucetState>>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<FaucetRequest>,
) -> impl IntoResponse {
    // Resolve the client IP for rate limiting. `X-Forwarded-For` is only
    // honoured when the socket peer is a configured trusted proxy.
    let forwarded_for = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    let ip = proxy::client_ip(peer.ip(), forwarded_for, &state.config.trusted_proxies);
    let ip_str = rate_limit_ip_key(ip);

    // Check IP rate limit
    if !state.rate_limiter.check_and_record_ip(
        &ip_str,
        state.config.rate_limit_window,
        state.config.max_requests_per_window,
    ) {
        warn!(ip = %ip_str, "rate limit exceeded for IP");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(FaucetResponse {
                success: false,
                message: format!(
                    "Rate limit exceeded for IP. Max {} requests per {} seconds.",
                    state.config.max_requests_per_window, state.config.rate_limit_window
                ),
                tx_hash: None,
            }),
        )
            .into_response();
    }

    // Parse destination address
    let to_address = match parse_address(&req.address, state.config.signing_ctx.chain_id) {
        Ok(addr) => addr,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(FaucetResponse {
                    success: false,
                    message: format!("Invalid address: {}", e),
                    tx_hash: None,
                }),
            )
                .into_response();
        }
    };

    // Check PRO-21 destination address rate limit. This is deliberately keyed
    // on its own window and cap: an address must not become drainable just
    // because the caller rotates client IPs.
    let to_address_str = to_address.to_string();
    let mut reservation = match state.rate_limiter.reserve_address(
        &to_address_str,
        state.config.address_rate_limit_window,
        state.config.address_max_requests,
    ) {
        Some(res) => res,
        None => {
            warn!(
                address = %to_address_str,
                window = state.config.address_rate_limit_window,
                max = state.config.address_max_requests,
                "rate limit exceeded for address"
            );
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(FaucetResponse {
                    success: false,
                    message: format!(
                        "Rate limit exceeded for address. Max {} requests per {} seconds.",
                        state.config.address_max_requests, state.config.address_rate_limit_window
                    ),
                    tx_hash: None,
                }),
            )
                .into_response();
        }
    };

    // Prevent faucet from sending to itself
    if to_address == state.faucet_address {
        return (
            StatusCode::BAD_REQUEST,
            Json(FaucetResponse {
                success: false,
                message: "Faucet cannot send to itself".to_string(),
                tx_hash: None,
            }),
        )
            .into_response();
    }

    // Low-balance guard: refuse early when the faucet is running dry, so callers
    // get a clear error instead of a transaction that fails on-chain.
    if state.config.min_balance_atoms > 0 {
        match get_balance(
            &state.client,
            &state.config.rpc_url,
            state.config.rpc_token.as_deref(),
            &state.faucet_address,
        )
        .await
        {
            Ok(balance) if balance < state.config.min_balance_atoms => {
                warn!(
                    balance,
                    threshold = state.config.min_balance_atoms,
                    "faucet balance below minimum; refusing to dispense"
                );
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(FaucetResponse {
                        success: false,
                        message: "Faucet is low on funds; try again later.".to_string(),
                        tx_hash: None,
                    }),
                )
                    .into_response();
            }
            Ok(balance) => {
                tracing::debug!(balance, "faucet balance above minimum");
            }
            Err(e) => {
                // A transient balance-read error must not take the faucet down;
                // the nonce fetch below will surface a hard RPC outage anyway.
                warn!("Failed to read faucet balance: {}", e);
            }
        }
    }

    // Get faucet nonce from RPC
    let committed_nonce = match get_nonce(
        &state.client,
        &state.config.rpc_url,
        state.config.rpc_token.as_deref(),
        &state.faucet_address,
    )
    .await
    {
        Ok(n) => n,
        Err(e) => {
            warn!("Failed to get faucet nonce: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(FaucetResponse {
                    success: false,
                    message: "Failed to get faucet nonce".to_string(),
                    tx_hash: None,
                }),
            )
                .into_response();
        }
    };

    let mut nonce = {
        let mut guard = state.pending_nonce.lock();
        let next = match *guard {
            Some(last_sent) => std::cmp::max(committed_nonce, last_sent.saturating_add(1)),
            None => committed_nonce,
        };
        *guard = Some(next);
        next
    };

    let build_and_sign_tx = |n: u64| {
        let tx = Transaction {
            sender: state.faucet_address,
            nonce: n,
            fee: 1_000_000, // 0.001 KVNC fee
            kind: TransactionKind::Transfer {
                to: to_address,
                amount: state.config.dispense_amount,
            },
            signature: Signature([0; 64]),
            hash: Hash::zero(),
        };
        sign_transaction(tx, &state.signer, &state.config.signing_ctx)
    };

    let mut signed_tx = match build_and_sign_tx(nonce) {
        Ok(tx) => tx,
        Err(e) => {
            warn!("Failed to sign transaction: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(FaucetResponse {
                    success: false,
                    message: "Failed to sign transaction".to_string(),
                    tx_hash: None,
                }),
            )
                .into_response();
        }
    };

    // Commit before awaiting submit. A client disconnect drops this future
    // while the tx may already be in the node mempool; the slot must stay
    // consumed. `rollback` runs only when submit explicitly fails with 4xx / node rejection.
    // Pre-submit failures return above, while the guard is still uncommitted,
    // so `Drop` releases the slot.
    reservation.commit();

    let mut submit_outcome = submit_transaction(
        &state.client,
        &state.config.rpc_url,
        state.config.rpc_token.as_deref(),
        &signed_tx,
    )
    .await;

    // Nonce conflict retry: if rejected with "nonce too low / already proposed", resync from node and retry once
    if let SubmitOutcome::ExplicitRejection(ref err) = submit_outcome {
        if is_nonce_error(err) {
            warn!(
                nonce,
                error = %err,
                "nonce conflict detected; resyncing nonce from node and retrying once"
            );
            let fresh_committed = match get_nonce(
                &state.client,
                &state.config.rpc_url,
                state.config.rpc_token.as_deref(),
                &state.faucet_address,
            )
            .await
            {
                Ok(n) => n,
                Err(e) => {
                    warn!("Failed to resync faucet nonce: {}", e);
                    committed_nonce
                }
            };
            nonce = {
                let mut guard = state.pending_nonce.lock();
                let next = std::cmp::max(fresh_committed, nonce.saturating_add(1));
                *guard = Some(next);
                next
            };
            if let Ok(new_signed_tx) = build_and_sign_tx(nonce) {
                signed_tx = new_signed_tx;
                submit_outcome = submit_transaction(
                    &state.client,
                    &state.config.rpc_url,
                    state.config.rpc_token.as_deref(),
                    &signed_tx,
                )
                .await;
            }
        }
    }

    match submit_outcome {
        SubmitOutcome::Success(tx_hash) => {
            info!(
                to = %to_address,
                amount = state.config.dispense_amount,
                nonce,
                tx_hash = %tx_hash,
                "faucet dispensed"
            );
            (
                StatusCode::OK,
                Json(FaucetResponse {
                    success: true,
                    message: format!(
                        "Dispensed {} KVNC",
                        state.config.dispense_amount / 1_000_000_000
                    ),
                    tx_hash: Some(tx_hash),
                }),
            )
                .into_response()
        }
        SubmitOutcome::Unknown(e) => {
            // UNKNOWN outcome (transport error or timeout): keep address slot to prevent double payout.
            warn!(
                to = %to_address,
                error = %e,
                "faucet submit outcome unknown (transport/timeout); keeping address rate-limit slot to prevent double payout"
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(FaucetResponse {
                    success: false,
                    message: "Transaction submission status unknown, do not retry for 24h"
                        .to_string(),
                    tx_hash: None,
                }),
            )
                .into_response()
        }
        SubmitOutcome::ExplicitRejection(e) => {
            // Explicit rejection from node (e.g. invalid tx, balance insufficient): roll back address slot.
            reservation.rollback();
            warn!(
                to = %to_address,
                error = %e,
                "faucet submit explicitly rejected by node; rolling back address slot"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(FaucetResponse {
                    success: false,
                    message: format!("Failed to submit transaction: {e}"),
                    tx_hash: None,
                }),
            )
                .into_response()
        }
    }
}

/// Parse a dispense destination for the faucet's chain.
///
/// Canonical base32 is accepted on every chain. Legacy hex is accepted only
/// where [`kovanica_types::address::legacy_address_allowed`] is true, so
/// chain 1 refuses it.
fn parse_address(s: &str, chain_id: u64) -> Result<Address> {
    Address::parse_for_chain(s, chain_id).context("invalid address")
}

fn normalize_rpc_url(url: &str) -> String {
    let trimmed = url.trim_end_matches('/');
    if trimmed.ends_with("/rpc") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/rpc")
    }
}

/// Bearer token for node write RPC methods (singular, preferred).
const RPC_WRITE_TOKEN_ENV: &str = "KOVANICA_RPC_WRITE_TOKEN";

/// Comma-separated token list accepted by the node.
const RPC_WRITE_TOKENS_ENV: &str = "KOVANICA_RPC_WRITE_TOKENS";

/// Resolve the bearer token the faucet uses for node write calls.
///
/// Prefers `KOVANICA_RPC_WRITE_TOKEN`; otherwise the first non-empty entry of the
/// node's `KOVANICA_RPC_WRITE_TOKENS` list. `None` is valid: reads still work,
/// but write calls are rejected by a node running with auth enabled.
fn resolve_rpc_token() -> Option<String> {
    let singular = std::env::var(RPC_WRITE_TOKEN_ENV)
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());
    if singular.is_some() {
        return singular;
    }
    std::env::var(RPC_WRITE_TOKENS_ENV).ok().and_then(|list| {
        list.split(',')
            .map(str::trim)
            .find(|t| !t.is_empty())
            .map(str::to_string)
    })
}

/// Attach a bearer token when one is configured.
fn with_auth(req: reqwest::RequestBuilder, token: Option<&str>) -> reqwest::RequestBuilder {
    match token {
        Some(token) => req.bearer_auth(token),
        None => req,
    }
}

async fn get_nonce(
    client: &reqwest::Client,
    rpc_url: &str,
    token: Option<&str>,
    address: &Address,
) -> Result<u64> {
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "kovanica_getNonce",
        "params": [address.to_string()],
        "id": 1
    });
    let resp: serde_json::Value = with_auth(client.post(rpc_url).json(&req), token)
        .send()
        .await?
        .json()
        .await?;
    if let Some(err) = resp.get("error") {
        anyhow::bail!("rpc error: {err}");
    }
    let result = resp
        .get("result")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("invalid nonce response: {resp}"))?;
    let nonce = u64::from_str_radix(result.strip_prefix("0x").unwrap_or(result), 16)?;
    Ok(nonce)
}

async fn get_balance(
    client: &reqwest::Client,
    rpc_url: &str,
    token: Option<&str>,
    address: &Address,
) -> Result<u64> {
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "kovanica_getBalance",
        "params": [address.to_string()],
        "id": 1
    });
    let resp: serde_json::Value = with_auth(client.post(rpc_url).json(&req), token)
        .send()
        .await?
        .json()
        .await?;
    if let Some(err) = resp.get("error") {
        anyhow::bail!("rpc error: {err}");
    }
    let result = resp
        .get("result")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("invalid balance response: {resp}"))?;
    let balance = u64::from_str_radix(result.strip_prefix("0x").unwrap_or(result), 16)?;
    Ok(balance)
}

fn sign_transaction(
    mut tx: Transaction,
    signer: &SigningKey,
    ctx: &kovanica_types::SigningContext,
) -> Result<Transaction> {
    let msg = tx.signing_hash(ctx);
    let sig = signer.sign(&msg.0);
    tx.signature = Signature(sig.to_bytes());
    tx.hash = msg; // signing_hash(ctx) is the v1 domain- and chain-separated hash
    Ok(tx)
}

#[derive(Debug, PartialEq, Eq)]
enum SubmitOutcome {
    Success(String),
    ExplicitRejection(String),
    Unknown(String),
}

fn is_nonce_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("already in a proposed block")
        || lower.contains("already proposed")
        || lower.contains("invalid nonce")
        || lower.contains("nonce too low")
        || lower.contains("nonce in flight")
}

async fn submit_transaction(
    client: &reqwest::Client,
    rpc_url: &str,
    token: Option<&str>,
    tx: &Transaction,
) -> SubmitOutcome {
    let raw = match bincode::serialize(tx) {
        Ok(bytes) => bytes,
        Err(e) => return SubmitOutcome::ExplicitRejection(format!("tx serialization error: {e}")),
    };
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "kovanica_sendRawTransaction",
        "params": [hex::encode(raw)],
        "id": 1
    });
    let send_res = with_auth(client.post(rpc_url).json(&req), token)
        .send()
        .await;
    let resp = match send_res {
        Ok(r) => r,
        Err(e) => {
            return SubmitOutcome::Unknown(format!("transport/timeout error: {e}"));
        }
    };

    let status = resp.status();
    if status.is_client_error() {
        let err_text = resp.text().await.unwrap_or_default();
        return SubmitOutcome::ExplicitRejection(format!("HTTP {status}: {err_text}"));
    }
    if status.is_server_error() {
        let err_text = resp.text().await.unwrap_or_default();
        return SubmitOutcome::Unknown(format!("HTTP {status}: {err_text}"));
    }

    let json_val: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            return SubmitOutcome::Unknown(format!("error reading response body: {e}"));
        }
    };

    if let Some(err) = json_val.get("error") {
        let err_msg = if let Some(m) = err.get("message").and_then(|v| v.as_str()) {
            m.to_string()
        } else if let Some(s) = err.as_str() {
            s.to_string()
        } else {
            err.to_string()
        };
        return SubmitOutcome::ExplicitRejection(err_msg);
    }

    if let Some(result) = json_val.get("result").and_then(|v| v.as_str()) {
        SubmitOutcome::Success(result.to_string())
    } else {
        SubmitOutcome::ExplicitRejection(format!("invalid tx submit response: {json_val}"))
    }
}

/// Environment variable holding the faucet keystore passphrase.
const PASSPHRASE_ENV: &str = "KOVANICA_FAUCET_PASSPHRASE";

/// Resolve the keystore passphrase without ever taking it from argv.
///
/// Order: `--passphrase-file`, then `KOVANICA_FAUCET_PASSPHRASE`, then an
/// interactive no-echo prompt if stdin is a TTY. Errors if none is available.
fn resolve_passphrase(file: Option<&Path>) -> Result<Zeroizing<String>> {
    let env = std::env::var(PASSPHRASE_ENV).ok().map(Zeroizing::new);
    resolve_passphrase_from(file, env, || {
        if std::io::stdin().is_terminal() {
            let p = rpassword::prompt_password("Faucet keystore passphrase: ")
                .context("reading passphrase from TTY")?;
            Ok(Some(Zeroizing::new(p)))
        } else {
            Ok(None)
        }
    })
}

fn resolve_passphrase_from<F>(
    file: Option<&Path>,
    env: Option<Zeroizing<String>>,
    prompt: F,
) -> Result<Zeroizing<String>>
where
    F: FnOnce() -> Result<Option<Zeroizing<String>>>,
{
    if let Some(path) = file {
        return read_passphrase_file(path);
    }
    if let Some(p) = env {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    if let Some(p) = prompt()? {
        return Ok(p);
    }
    bail!(
        "keystore is encrypted but no passphrase source is available: \
         use --passphrase-file <path>, set {PASSPHRASE_ENV}, or run on a TTY"
    )
}

fn read_passphrase_file(path: &Path) -> Result<Zeroizing<String>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .with_context(|| format!("reading metadata of passphrase file {}", path.display()))?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "refusing passphrase file {}: permissions {:o} are too broad (use 0600 or 0400)",
                path.display(),
                mode
            );
        }
    }
    let mut raw = Zeroizing::new(
        std::fs::read_to_string(path)
            .with_context(|| format!("reading passphrase file {}", path.display()))?,
    );
    while raw.ends_with('\n') || raw.ends_with('\r') {
        raw.pop();
    }
    if raw.is_empty() {
        bail!("passphrase file {} is empty", path.display());
    }
    Ok(raw)
}

#[cfg(test)]
mod passphrase_tests {
    use super::*;
    use std::io::Write;

    fn write_file(contents: &str, mode: u32) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
        f
    }

    fn no_prompt() -> Result<Option<Zeroizing<String>>> {
        Ok(None)
    }

    #[test]
    fn file_trims_trailing_newline_and_wins_over_env() {
        let f = write_file("s3cret\r\n", 0o600);
        let env = Some(Zeroizing::new("from-env".to_string()));
        let p = resolve_passphrase_from(Some(f.path()), env, no_prompt).unwrap();
        assert_eq!(p.as_str(), "s3cret");
    }

    #[test]
    fn file_0400_is_accepted() {
        let f = write_file("pw\n", 0o400);
        assert_eq!(read_passphrase_file(f.path()).unwrap().as_str(), "pw");
    }

    #[cfg(unix)]
    #[test]
    fn file_with_broad_permissions_is_refused() {
        let f = write_file("pw\n", 0o644);
        let err = read_passphrase_file(f.path()).unwrap_err().to_string();
        assert!(err.contains("too broad"), "{err}");
        assert!(!err.contains("pw\n"));
    }

    #[test]
    fn env_used_when_no_file() {
        let env = Some(Zeroizing::new("from-env".to_string()));
        let p = resolve_passphrase_from(None, env, no_prompt).unwrap();
        assert_eq!(p.as_str(), "from-env");
    }

    #[test]
    fn prompt_used_as_last_resort() {
        let p =
            resolve_passphrase_from(None, None, || Ok(Some(Zeroizing::new("typed".to_string()))))
                .unwrap();
        assert_eq!(p.as_str(), "typed");
    }

    #[test]
    fn errors_clearly_when_no_source() {
        let err = resolve_passphrase_from(None, Some(Zeroizing::new(String::new())), no_prompt)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("--passphrase-file") && err.contains(PASSPHRASE_ENV),
            "{err}"
        );
    }
}

#[cfg(test)]
mod guard_tests {
    use super::*;

    #[test]
    fn unknown_chain_ids_are_always_refused() {
        for id in [0, 42, u64::MAX] {
            let err = ensure_chain_allowed(id, true).unwrap_err().to_string();
            assert!(err.contains("unknown chain id"), "{err}");
        }
    }

    #[test]
    fn mainnet_is_refused_without_the_explicit_override() {
        let err = ensure_chain_allowed(chain_id::MAINNET, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("MAINNET"), "{err}");
        assert!(err.contains("--allow-mainnet"), "{err}");
        assert!(err.contains(ALLOW_MAINNET_ENV), "{err}");
    }

    #[test]
    fn mainnet_is_allowed_with_the_explicit_override() {
        ensure_chain_allowed(chain_id::MAINNET, true).expect("explicit override permits mainnet");
    }

    #[test]
    fn non_mainnet_networks_do_not_need_the_override() {
        for id in [chain_id::TESTNET, chain_id::DEVNET, chain_id::LOCAL] {
            ensure_chain_allowed(id, false).expect("non-mainnet chain is allowed");
        }
    }

    #[test]
    fn env_truthy_accepts_common_affirmatives() {
        let name = "KOVANICA_FAUCET_TEST_TRUTHY_FLAG";
        for truthy in ["1", "true", "TRUE", " yes ", "on"] {
            std::env::set_var(name, truthy);
            assert!(env_truthy(name), "{truthy:?} should be truthy");
        }
        for falsy in ["0", "false", "off", "", "maybe"] {
            std::env::set_var(name, falsy);
            assert!(!env_truthy(name), "{falsy:?} should not be truthy");
        }
        std::env::remove_var(name);
        assert!(!env_truthy(name), "unset variable is falsy");
    }

    #[test]
    fn parse_address_accepts_canonical_kvnc_dag_format() {
        let pk_bytes = [1u8; 32];
        let address = Address(pk_bytes);
        let canonical = address.encode();
        let parsed = parse_address(&canonical, chain_id::MAINNET).expect("canonical format parses");
        assert_eq!(parsed.to_hex(), address.to_hex());
    }

    #[test]
    fn parse_address_rejects_invalid_canonical_checksum() {
        let pk_bytes = [2u8; 32];
        let address = Address(pk_bytes);
        let canonical = address.encode();
        let mut bad_canonical = canonical.clone();
        let checksum_start = bad_canonical.len() - "dag".len() - 8;
        bad_canonical.replace_range(checksum_start..checksum_start + 2, "ff");
        let err = parse_address(&bad_canonical, chain_id::MAINNET).unwrap_err();
        assert!(
            err.to_string().contains("invalid address"),
            "got error: {}",
            err
        );
    }

    /// Chain 1 refuses legacy hex. Devnet and local still accept it.
    #[test]
    fn parse_address_follows_the_chain_policy() {
        let pk_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let address = Address(hex::decode(pk_hex).unwrap().try_into().expect("32 bytes"));
        let forms = [
            pk_hex.to_string(),
            format!("0x{pk_hex}"),
            address.encode_legacy_hex(),
        ];
        for form in &forms {
            let err = parse_address(form, chain_id::MAINNET).unwrap_err();
            assert!(
                format!("{err:#}").contains("not accepted"),
                "{form} on chain 1: {err:#}"
            );
            for chain in [chain_id::DEVNET, chain_id::LOCAL] {
                let parsed = parse_address(form, chain)
                    .unwrap_or_else(|e| panic!("{form} on chain {chain}: {e:#}"));
                assert_eq!(parsed, address);
            }
        }
    }

    #[test]
    fn chain2_strictly_enforces_canonical_pro21_and_rejects_legacy() {
        let pk_hex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let address = Address(hex::decode(pk_hex).unwrap().try_into().unwrap());
        let canonical = address.encode();

        // Canonical PRO-21 format must succeed on Chain 2 (Testnet)
        let parsed = parse_address(&canonical, chain_id::TESTNET)
            .expect("canonical PRO-21 parses on chain 2");
        assert_eq!(parsed, address);

        // Legacy hex forms must be refused on Chain 2
        let legacy_forms = [
            pk_hex.to_string(),
            format!("0x{pk_hex}"),
            address.encode_legacy_hex(),
        ];
        for form in &legacy_forms {
            let err = parse_address(form, chain_id::TESTNET).unwrap_err();
            assert!(
                format!("{err:#}").contains("not accepted"),
                "expected legacy address {form} to be refused on Chain 2, got: {err:#}"
            );
        }
    }

    #[test]
    fn rate_limiter_dual_check_ip_and_pro21_address() {
        let limiter = RateLimiter::default();
        let ip1 = "192.0.2.1";
        let ip2 = "192.0.2.2";
        let addr1 = "kvnc000000000000000000000000000000000000000000000000000000000000dag";
        let addr2 = "kvnc111111111111111111111111111111111111111111111111111111111111dag";

        let window = 60;
        let max_req = 2;

        // IP rate limiting test
        assert!(limiter.check_and_record_ip(ip1, window, max_req));
        assert!(limiter.check_and_record_ip(ip1, window, max_req));
        // 3rd request from same IP is throttled
        assert!(!limiter.check_and_record_ip(ip1, window, max_req));

        // Different IP is allowed
        assert!(limiter.check_and_record_ip(ip2, window, max_req));

        // Address rate limiting goes through the reservation API. A committed
        // reservation keeps the slot; a refused one does not open a new slot.
        assert!(commit_address(&limiter, addr1, window, max_req));
        assert!(commit_address(&limiter, addr1, window, max_req));
        // 3rd request to same PRO-21 address is throttled
        assert!(!commit_address(&limiter, addr1, window, max_req));

        // Different address is allowed
        assert!(commit_address(&limiter, addr2, window, max_req));
    }

    fn commit_address(
        limiter: &RateLimiter,
        address: &str,
        window: u64,
        max_requests: usize,
    ) -> bool {
        match limiter.reserve_address(address, window, max_requests) {
            Some(mut reservation) => {
                reservation.commit();
                true
            }
            None => false,
        }
    }

    #[test]
    fn expired_keys_are_evicted_and_the_map_shrinks() {
        let limiter = RateLimiter::default();
        let now = std::time::Instant::now();
        let window = 60;

        assert!(limiter.record_ip_at("192.0.2.1", window, 1, now));
        assert!(limiter.record_ip_at("192.0.2.2", window, 1, now));
        assert_eq!(limiter.ip_count(), 2);

        // Sweep after window expires: both keys should be evicted and map shrinks
        let later = now + Duration::from_secs(window + 1);
        limiter.sweep_ip_at(window, later);
        assert_eq!(limiter.ip_count(), 0);
    }

    #[test]
    fn the_size_cap_holds() {
        let cap = 5;
        let limiter = RateLimiter::with_capacity_limit(cap);
        let now = std::time::Instant::now();
        let window = 3600;

        for i in 0..cap {
            let ip = format!("192.0.2.{i}");
            assert!(limiter.record_ip_at(&ip, window, 1, now), "{ip}");
        }
        assert_eq!(limiter.ip_count(), cap);
        for i in cap..15 {
            let ip = format!("192.0.2.{i}");
            assert!(
                !limiter.record_ip_at(&ip, window, 1, now),
                "new key {ip} must be refused at the cap"
            );
            assert_eq!(limiter.ip_count(), cap);
        }
        // The first key was not evicted to make room: its slot is still used.
        assert!(!limiter.record_ip_at("192.0.2.0", window, 1, now));
        assert_eq!(limiter.ip_count(), cap);
    }

    #[test]
    fn cap_refuses_a_new_ip_and_does_not_evict_a_live_victim() {
        let cap = 3;
        let limiter = RateLimiter::with_capacity_limit(cap);
        let now = std::time::Instant::now();
        let window = 3600;
        let victim = "192.0.2.1";

        assert!(limiter.record_ip_at(victim, window, 1, now));
        assert!(limiter.record_ip_at("192.0.2.2", window, 1, now));
        assert!(limiter.record_ip_at("192.0.2.3", window, 1, now));
        assert!(!limiter.record_ip_at("192.0.2.99", window, 1, now));
        assert_eq!(limiter.ip_count(), cap);
        assert!(
            !limiter.record_ip_at(victim, window, 1, now),
            "victim must keep its spent slot"
        );
        assert_eq!(limiter.ip_count(), cap);
    }

    #[test]
    fn address_cap_refuses_a_new_key_and_keeps_the_victim_limit() {
        let limiter = RateLimiter::with_capacity_limit(2);
        let window = 3600;
        let victim = "addr-victim";

        assert!(commit_address(&limiter, victim, window, 1));
        assert!(commit_address(&limiter, "addr-other", window, 1));
        assert!(!commit_address(&limiter, "addr-new", window, 1));
        assert!(
            !commit_address(&limiter, victim, window, 1),
            "victim must keep its spent slot"
        );
    }

    #[test]
    fn sweep_frees_capacity_after_expiry() {
        let cap = 2;
        let limiter = RateLimiter::with_capacity_limit(cap);
        let now = std::time::Instant::now();
        let window = 60;

        assert!(limiter.record_ip_at("192.0.2.1", window, 1, now));
        assert!(limiter.record_ip_at("192.0.2.2", window, 1, now));
        assert!(!limiter.record_ip_at("192.0.2.3", window, 1, now));

        let later = now + Duration::from_secs(window + 1);
        limiter.sweep_ip_at(window, later);
        assert_eq!(limiter.ip_count(), 0);
        assert!(limiter.record_ip_at("192.0.2.3", window, 1, later));
        assert_eq!(limiter.ip_count(), 1);
    }

    #[test]
    fn amortised_sweep_frees_expired_entries_when_periodic_sweep_is_not_due() {
        let cap = 2;
        let limiter = RateLimiter::with_capacity_limit(cap);
        let now = std::time::Instant::now();
        let window = 60;

        assert!(limiter.record_ip_at("192.0.2.1", window, 1, now));
        assert!(limiter.record_ip_at("192.0.2.2", window, 1, now));
        assert!(!limiter.record_ip_at("192.0.2.3", window, 1, now));

        // `probe` is past the rate-limit window, but last_sweep is only 1s
        // behind it, so the periodic full sweep does not run. Admission must
        // still drop the expired keys via the bounded sweep and then accept.
        let probe = now + Duration::from_secs(window + 1);
        limiter.set_ip_last_sweep(probe - Duration::from_secs(1));
        assert!(limiter.record_ip_at("192.0.2.3", window, 1, probe));
        assert_eq!(limiter.ip_count(), 1);

        assert!(limiter.record_ip_at("192.0.2.4", window, 1, probe));
        assert_eq!(limiter.ip_count(), cap);
        assert!(!limiter.record_ip_at("192.0.2.1", window, 1, probe));
        assert!(!limiter.record_ip_at("192.0.2.5", window, 1, probe));
        assert_eq!(limiter.ip_count(), cap);
    }

    #[test]
    fn two_ipv6_addresses_in_same_slash_64_share_bucket_different_do_not() {
        use std::net::IpAddr;
        let ip1: IpAddr = "2001:db8:1::1".parse().unwrap();
        let ip2: IpAddr = "2001:db8:1::2".parse().unwrap();
        let ip3: IpAddr = "2001:db8:2::1".parse().unwrap();

        let key1 = rate_limit_ip_key(ip1);
        let key2 = rate_limit_ip_key(ip2);
        let key3 = rate_limit_ip_key(ip3);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);

        let limiter = RateLimiter::default();
        let window = 60;
        let max_req = 1;

        assert!(limiter.check_and_record_ip(&key1, window, max_req));
        // Same /64 prefix is throttled
        assert!(!limiter.check_and_record_ip(&key2, window, max_req));
        // Different /64 prefix is admitted
        assert!(limiter.check_and_record_ip(&key3, window, max_req));
    }

    #[test]
    fn ipv4_mapped_ipv6_equals_ipv4() {
        use std::net::IpAddr;
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let v6_mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();

        let key_v4 = rate_limit_ip_key(v4);
        let key_v6 = rate_limit_ip_key(v6_mapped);

        assert_eq!(key_v4, "192.0.2.1");
        assert_eq!(key_v4, key_v6);

        let limiter = RateLimiter::default();
        let window = 60;
        let max_req = 1;

        assert!(limiter.check_and_record_ip(&key_v4, window, max_req));
        // IPv4-mapped equivalent is throttled
        assert!(!limiter.check_and_record_ip(&key_v6, window, max_req));
    }
}

/// End-to-end handler tests against a local stub node. No external network:
/// the stub answers `kovanica_getBalance`, `kovanica_getNonce` and
/// `kovanica_sendRawTransaction` in-process.
#[cfg(test)]
mod http_tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use serde_json::{json, Value};
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tower::ServiceExt;

    const DISPENSE_ATOMS: u64 = 10 * 1_000_000_000;

    #[derive(Clone)]
    struct StubState {
        balance_atoms: u64,
        dispensed: Arc<Mutex<Vec<u64>>>,
        dispensed_nonces: Arc<Mutex<Vec<u64>>>,
        fail_submit: Arc<Mutex<bool>>,
        submit_error: Arc<Mutex<Option<String>>>,
        /// When set, the next `sendRawTransaction` signals `submit_started`
        /// and then waits until the caller drops the request.
        hold_submit: Arc<AtomicBool>,
        submit_started: Arc<tokio::sync::Notify>,
        submit_delay_ms: Arc<Mutex<Option<u64>>>,
        fail_with_http_400: Arc<AtomicBool>,
    }

    async fn stub_rpc_handler(
        axum::extract::State(stub): axum::extract::State<StubState>,
        Json(req): Json<Value>,
    ) -> impl IntoResponse {
        let method = req
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if method == "kovanica_sendRawTransaction" && stub.fail_with_http_400.load(Ordering::SeqCst)
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid transaction" })),
            )
                .into_response();
        }
        let result = match method {
            "kovanica_getBalance" => json!(format!("0x{:x}", stub.balance_atoms)),
            "kovanica_getNonce" => json!("0x0"),
            "kovanica_sendRawTransaction" => {
                if let Some(delay) = *stub.submit_delay_ms.lock() {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                if let Some(err) = stub.submit_error.lock().take() {
                    return (
                        StatusCode::OK,
                        Json(json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "error": { "code": -32000, "message": err }
                        })),
                    )
                        .into_response();
                }
                if *stub.fail_submit.lock() {
                    return (
                        StatusCode::OK,
                        Json(json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "error": { "code": -32000, "message": "tx rejected" }
                        })),
                    )
                        .into_response();
                }
                let raw = req
                    .get("params")
                    .and_then(|p| p.get(0))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if let Ok(bytes) = hex::decode(raw) {
                    if let Ok(tx) = bincode::deserialize::<Transaction>(&bytes) {
                        stub.dispensed_nonces.lock().push(tx.nonce);
                        if let TransactionKind::Transfer { amount, .. } = tx.kind {
                            stub.dispensed.lock().push(amount);
                        }
                    }
                }
                if stub.hold_submit.swap(false, Ordering::SeqCst) {
                    stub.submit_started.notify_one();
                    std::future::pending::<()>().await;
                }
                json!("0xfeed")
            }
            _ => json!(null),
        };
        (
            StatusCode::OK,
            Json(json!({ "jsonrpc": "2.0", "id": 1, "result": result })),
        )
            .into_response()
    }

    /// Start an in-process JSON-RPC stub.
    ///
    /// Returns `(url, dispensed amounts, fail_submit flag, submit-started notify)`.
    /// `hold_submit` makes the first `sendRawTransaction` signal the notify and
    /// then wait until the faucet request is dropped.
    async fn spawn_stub(
        balance_atoms: u64,
        hold_submit: bool,
    ) -> (
        String,
        Arc<Mutex<Vec<u64>>>,
        Arc<Mutex<bool>>,
        Arc<tokio::sync::Notify>,
    ) {
        let (url, dispensed, fail_submit, notify, _, _, _, _) =
            spawn_stub_full(balance_atoms, hold_submit).await;
        (url, dispensed, fail_submit, notify)
    }

    #[allow(clippy::type_complexity)]
    async fn spawn_stub_full(
        balance_atoms: u64,
        hold_submit: bool,
    ) -> (
        String,
        Arc<Mutex<Vec<u64>>>,
        Arc<Mutex<bool>>,
        Arc<tokio::sync::Notify>,
        Arc<Mutex<Vec<u64>>>,
        Arc<Mutex<Option<String>>>,
        Arc<Mutex<Option<u64>>>,
        Arc<AtomicBool>,
    ) {
        let dispensed = Arc::new(Mutex::new(Vec::new()));
        let dispensed_nonces = Arc::new(Mutex::new(Vec::new()));
        let fail_submit = Arc::new(Mutex::new(false));
        let submit_error = Arc::new(Mutex::new(None));
        let submit_started = Arc::new(tokio::sync::Notify::new());
        let submit_delay_ms = Arc::new(Mutex::new(None));
        let fail_with_http_400 = Arc::new(AtomicBool::new(false));
        let stub = StubState {
            balance_atoms,
            dispensed: dispensed.clone(),
            dispensed_nonces: dispensed_nonces.clone(),
            fail_submit: fail_submit.clone(),
            submit_error: submit_error.clone(),
            hold_submit: Arc::new(AtomicBool::new(hold_submit)),
            submit_started: submit_started.clone(),
            submit_delay_ms: submit_delay_ms.clone(),
            fail_with_http_400: fail_with_http_400.clone(),
        };
        let app = Router::new()
            .route("/rpc", post(stub_rpc_handler))
            .with_state(stub);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (
            format!("http://{addr}/rpc"),
            dispensed,
            fail_submit,
            submit_started,
            dispensed_nonces,
            submit_error,
            submit_delay_ms,
            fail_with_http_400,
        )
    }

    /// Start an in-process JSON-RPC stub and return `(url, dispensed amounts, fail_submit flag)`.
    async fn stub_node_ext(balance_atoms: u64) -> (String, Arc<Mutex<Vec<u64>>>, Arc<Mutex<bool>>) {
        let (url, dispensed, fail_submit, _) = spawn_stub(balance_atoms, false).await;
        (url, dispensed, fail_submit)
    }

    /// Start an in-process JSON-RPC stub and return `(url, dispensed amounts)`.
    async fn stub_node(balance_atoms: u64) -> (String, Arc<Mutex<Vec<u64>>>) {
        let (url, dispensed, _) = stub_node_ext(balance_atoms).await;
        (url, dispensed)
    }

    fn faucet_state(
        rpc_url: &str,
        ip_window: u64,
        ip_max: usize,
        address_window: u64,
        address_max: usize,
        trusted: &str,
        min_balance_atoms: u64,
    ) -> Arc<FaucetState> {
        faucet_state_with(
            rpc_url,
            ip_window,
            ip_max,
            address_window,
            address_max,
            trusted,
            min_balance_atoms,
            RateLimiter::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn faucet_state_with(
        rpc_url: &str,
        ip_window: u64,
        ip_max: usize,
        address_window: u64,
        address_max: usize,
        trusted: &str,
        min_balance_atoms: u64,
        rate_limiter: RateLimiter,
    ) -> Arc<FaucetState> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        faucet_state_with_client(
            rpc_url,
            ip_window,
            ip_max,
            address_window,
            address_max,
            trusted,
            min_balance_atoms,
            rate_limiter,
            client,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn faucet_state_with_client(
        rpc_url: &str,
        ip_window: u64,
        ip_max: usize,
        address_window: u64,
        address_max: usize,
        trusted: &str,
        min_balance_atoms: u64,
        rate_limiter: RateLimiter,
        client: reqwest::Client,
    ) -> Arc<FaucetState> {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let faucet_address = Address::from_public_key(&PublicKey::from(signer.verifying_key()));
        Arc::new(FaucetState {
            config: FaucetConfig {
                dispense_amount: DISPENSE_ATOMS,
                rate_limit_window: ip_window,
                max_requests_per_window: ip_max,
                address_rate_limit_window: address_window,
                address_max_requests: address_max,
                rpc_url: rpc_url.to_string(),
                rpc_token: None,
                signing_ctx: kovanica_types::SigningContext::new(chain_id::TESTNET),
                trusted_proxies: proxy::TrustedProxies::parse_list(trusted).unwrap(),
                min_balance_atoms,
            },
            signer,
            faucet_address,
            rate_limiter,
            client,
            pending_nonce: Mutex::new(None),
        })
    }

    fn app(state: Arc<FaucetState>) -> Router {
        Router::new()
            .route("/health", get(health_check))
            .route("/faucet", post(faucet_handler))
            .with_state(state)
    }

    fn canonical(seed: u8) -> String {
        Address([seed; 32]).encode()
    }

    async fn post_faucet(
        app: &Router,
        peer: &str,
        forwarded_for: Option<&str>,
        body: Value,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/faucet")
            .header("content-type", "application/json");
        if let Some(xff) = forwarded_for {
            builder = builder.header("x-forwarded-for", xff);
        }
        let mut req = builder.body(Body::from(body.to_string())).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));

        let res = app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let payload = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, payload)
    }

    #[tokio::test]
    async fn address_limit_is_independent_of_the_ip_limit() {
        // Two different client IPs, one address: the second request must be
        // refused even though that IP has never asked before.
        let (rpc, _) = stub_node(1_000 * 1_000_000_000).await;
        let app = app(faucet_state(&rpc, 60, 100, 86_400, 1, "", 0));
        let address = canonical(1);

        let (first, _) = post_faucet(
            &app,
            "198.51.100.1:5000",
            None,
            json!({ "address": address }),
        )
        .await;
        assert_eq!(first, StatusCode::OK);

        let (second, body) = post_faucet(
            &app,
            "198.51.100.2:5000",
            None,
            json!({ "address": address }),
        )
        .await;
        assert_eq!(second, StatusCode::TOO_MANY_REQUESTS);
        assert!(
            body["message"]
                .as_str()
                .unwrap_or_default()
                .contains("address"),
            "expected the address limiter to reject, got {body}"
        );
    }

    #[tokio::test]
    async fn ip_limit_is_independent_of_the_address_limit() {
        // One IP, two addresses: the second request must be refused by the IP
        // limiter even though the address was never funded.
        let (rpc, _) = stub_node(1_000 * 1_000_000_000).await;
        let app = app(faucet_state(&rpc, 60, 1, 86_400, 100, "", 0));

        let (first, _) = post_faucet(
            &app,
            "198.51.100.1:5000",
            None,
            json!({ "address": canonical(2) }),
        )
        .await;
        assert_eq!(first, StatusCode::OK);

        let (second, body) = post_faucet(
            &app,
            "198.51.100.1:5000",
            None,
            json!({ "address": canonical(3) }),
        )
        .await;
        assert_eq!(second, StatusCode::TOO_MANY_REQUESTS);
        assert!(
            body["message"].as_str().unwrap_or_default().contains("IP"),
            "expected the IP limiter to reject, got {body}"
        );

        // A different IP with the same address is still within its own budget.
        let (third, _) = post_faucet(
            &app,
            "198.51.100.2:5000",
            None,
            json!({ "address": canonical(3) }),
        )
        .await;
        assert_eq!(third, StatusCode::OK);
    }

    #[tokio::test]
    async fn forwarded_for_is_honoured_only_from_a_trusted_peer() {
        let (rpc, _) = stub_node(1_000 * 1_000_000_000).await;
        // One request per IP bucket (limit 1), many per address.
        let app = app(faucet_state(&rpc, 60, 1, 86_400, 100, "10.0.0.0/8", 0));

        // Trusted peer: two different forwarded clients get their own buckets.
        let (a, _) = post_faucet(
            &app,
            "10.0.0.1:4000",
            Some("198.51.100.7"),
            json!({ "address": canonical(4) }),
        )
        .await;
        assert_eq!(a, StatusCode::OK);
        let (b, _) = post_faucet(
            &app,
            "10.0.0.1:4001",
            Some("198.51.100.8"),
            json!({ "address": canonical(5) }),
        )
        .await;
        assert_eq!(b, StatusCode::OK);

        // Untrusted peer: the header is ignored, the socket peer is the bucket.
        let (c, _) = post_faucet(
            &app,
            "203.0.113.9:4002",
            Some("198.51.100.7"),
            json!({ "address": canonical(6) }),
        )
        .await;
        assert_eq!(c, StatusCode::OK);
        let (d, body) = post_faucet(
            &app,
            "203.0.113.9:4003",
            Some("198.51.100.99"),
            json!({ "address": canonical(7) }),
        )
        .await;
        assert_eq!(d, StatusCode::TOO_MANY_REQUESTS);
        assert!(
            body["message"].as_str().unwrap_or_default().contains("IP"),
            "spoofed X-Forwarded-For must not create a new bucket, got {body}"
        );
    }

    #[tokio::test]
    async fn extra_amount_field_still_dispenses_the_fixed_amount() {
        let (rpc, dispensed) = stub_node(1_000 * 1_000_000_000).await;
        let app = app(faucet_state(&rpc, 60, 100, 86_400, 100, "", 0));

        let (status, body) = post_faucet(
            &app,
            "198.51.100.1:5000",
            None,
            json!({ "address": canonical(8), "amount": 999_000_000_000u64 }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["message"].as_str(), Some("Dispensed 10 KVNC"));
        assert_eq!(*dispensed.lock(), vec![DISPENSE_ATOMS]);
    }

    #[tokio::test]
    async fn low_balance_guard_returns_503() {
        let (rpc, dispensed) = stub_node(0).await;
        let app = app(faucet_state(
            &rpc,
            60,
            100,
            86_400,
            100,
            "",
            100 * 1_000_000_000,
        ));

        let (status, body) = post_faucet(
            &app,
            "198.51.100.1:5000",
            None,
            json!({ "address": canonical(9) }),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            body["message"]
                .as_str()
                .unwrap_or_default()
                .contains("low on funds"),
            "got {body}"
        );
        assert!(dispensed.lock().is_empty(), "nothing may be submitted");
    }

    #[test]
    fn address_limits_read_their_env_equivalents() {
        std::env::set_var(ADDRESS_RATE_LIMIT_WINDOW_ENV, "120");
        std::env::set_var(ADDRESS_MAX_REQUESTS_ENV, "2");
        let cli = Cli::try_parse_from(["kovanica-faucet", "--chain-id", "2"]).unwrap();
        std::env::remove_var(ADDRESS_RATE_LIMIT_WINDOW_ENV);
        std::env::remove_var(ADDRESS_MAX_REQUESTS_ENV);

        assert_eq!(cli.address_rate_limit_window, 120);
        assert_eq!(cli.address_max_requests, 2);
        // The IP limiter keeps its own defaults.
        assert_eq!(cli.rate_limit_window, 3600);
        assert_eq!(cli.max_requests, 3);
    }

    #[test]
    fn shared_bucket_warning_only_for_local_or_private_binds() {
        for listen in [
            "127.0.0.1:3000",
            "0.0.0.0:3000",
            "10.1.2.3:3000",
            "[::1]:3000",
        ] {
            assert!(listens_on_local_or_private(listen), "{listen}");
        }
        for listen in ["203.0.113.5:3000", "[2001:db8::1]:3000"] {
            assert!(!listens_on_local_or_private(listen), "{listen}");
        }
    }

    #[tokio::test]
    async fn failed_submit_does_not_consume_address_slot_and_successful_does() {
        let (rpc, _, fail_submit) = stub_node_ext(1_000 * 1_000_000_000).await;
        // Address limiter allows only 1 request per window; IP limiter allows 100
        let app = app(faucet_state(&rpc, 60, 100, 86_400, 1, "", 0));
        let address = canonical(15);

        // 1. When submit fails, the address slot must NOT be consumed
        *fail_submit.lock() = true;
        let (status1, _) = post_faucet(
            &app,
            "198.51.100.1:5000",
            None,
            json!({ "address": address }),
        )
        .await;
        assert_eq!(status1, StatusCode::INTERNAL_SERVER_ERROR);

        // 2. Second request for the same address from another IP: slot was rolled back, so it must be allowed
        *fail_submit.lock() = false;
        let (status2, body2) = post_faucet(
            &app,
            "198.51.100.2:5000",
            None,
            json!({ "address": address }),
        )
        .await;
        assert_eq!(
            status2,
            StatusCode::OK,
            "expected OK after rolled-back slot, got {body2}"
        );

        // 3. Now that submit succeeded, third request for the same address must be rate-limited
        let (status3, body3) = post_faucet(
            &app,
            "198.51.100.3:5000",
            None,
            json!({ "address": address }),
        )
        .await;
        assert_eq!(status3, StatusCode::TOO_MANY_REQUESTS);
        assert!(body3["message"]
            .as_str()
            .unwrap_or_default()
            .contains("address"));
    }

    #[tokio::test]
    async fn concurrent_double_request_for_one_address_lets_at_most_one_through() {
        let (rpc, _) = stub_node(1_000 * 1_000_000_000).await;
        // Address max: 1 request per day, IP limit generous (100)
        let app = app(faucet_state(&rpc, 60, 100, 86_400, 1, "", 0));
        let address = canonical(42);

        let app1 = app.clone();
        let app2 = app.clone();
        let addr1 = address.clone();
        let addr2 = address.clone();

        let req1 = tokio::spawn(async move {
            post_faucet(
                &app1,
                "198.51.100.10:5000",
                None,
                json!({ "address": addr1 }),
            )
            .await
        });
        let req2 = tokio::spawn(async move {
            post_faucet(
                &app2,
                "198.51.100.11:5000",
                None,
                json!({ "address": addr2 }),
            )
            .await
        });

        let (res1, res2) = tokio::join!(req1, req2);
        let (status1, _) = res1.unwrap();
        let (status2, _) = res2.unwrap();

        let ok_count = (status1 == StatusCode::OK) as usize + (status2 == StatusCode::OK) as usize;
        let rate_limited_count = (status1 == StatusCode::TOO_MANY_REQUESTS) as usize
            + (status2 == StatusCode::TOO_MANY_REQUESTS) as usize;

        assert_eq!(ok_count, 1, "exactly one request should succeed");
        assert_eq!(
            rate_limited_count, 1,
            "exactly one request should be rate limited"
        );
    }

    #[tokio::test]
    async fn cancelled_request_after_submit_started_keeps_address_slot() {
        let (rpc, dispensed, _, started) = spawn_stub(1_000 * 1_000_000_000, true).await;
        let app = app(faucet_state(&rpc, 60, 100, 86_400, 1, "", 0));
        let address = canonical(21);

        let mut req = Request::builder()
            .method("POST")
            .uri("/faucet")
            .header("content-type", "application/json")
            .body(Body::from(json!({ "address": address }).to_string()))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(
            "192.0.2.10:5000".parse::<SocketAddr>().unwrap(),
        ));

        // The block ends after the stub has the tx, which drops the handler
        // future. That is the client cancel. `pin!` keeps the future alive
        // until this scope ends; dropping the `Pin` alone would not.
        {
            let mut in_flight = std::pin::pin!(app.clone().oneshot(req));
            tokio::select! {
                finished = &mut in_flight => {
                    let status = finished.expect("handler response").status();
                    panic!("handler finished before the stub held submit: {status}");
                }
                _ = started.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                    panic!("timed out waiting for the stub to receive the transaction");
                }
            }
            assert_eq!(
                dispensed.lock().len(),
                1,
                "the stub must have received the transaction before cancel"
            );
        }

        let (status, body) =
            post_faucet(&app, "192.0.2.11:5000", None, json!({ "address": address })).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
        assert!(
            body["message"]
                .as_str()
                .unwrap_or_default()
                .contains("address"),
            "cancelled submit must keep the address slot, got {body}"
        );
    }

    #[tokio::test]
    async fn low_balance_refusal_does_not_consume_the_address_slot() {
        let (rpc, _) = stub_node(0).await;
        let app = app(faucet_state(
            &rpc,
            60,
            100,
            86_400,
            1,
            "",
            100 * 1_000_000_000,
        ));
        let address = canonical(33);

        let (first, _) =
            post_faucet(&app, "192.0.2.40:5000", None, json!({ "address": address })).await;
        assert_eq!(first, StatusCode::SERVICE_UNAVAILABLE);

        let (second, body) =
            post_faucet(&app, "192.0.2.41:5000", None, json!({ "address": address })).await;
        assert_eq!(
            second,
            StatusCode::SERVICE_UNAVAILABLE,
            "pre-submit failure must roll the slot back, got {body}"
        );
    }

    #[tokio::test]
    async fn cap_returns_429_and_keeps_a_live_victim() {
        let (rpc, _) = stub_node(1_000 * 1_000_000_000).await;
        let app = app(faucet_state_with(
            &rpc,
            60,
            10,
            86_400,
            10,
            "",
            0,
            RateLimiter::with_capacity_limit(1),
        ));
        let victim_ip = "192.0.2.20:5000";
        let addr_a = canonical(30);

        let (ok, _) = post_faucet(&app, victim_ip, None, json!({ "address": addr_a })).await;
        assert_eq!(ok, StatusCode::OK);

        let (blocked_ip, body_ip) = post_faucet(
            &app,
            "192.0.2.21:5000",
            None,
            json!({ "address": canonical(31) }),
        )
        .await;
        assert_eq!(blocked_ip, StatusCode::TOO_MANY_REQUESTS, "{body_ip}");
        assert!(
            body_ip["message"]
                .as_str()
                .unwrap_or_default()
                .contains("IP"),
            "a new IP at the cap must be limited, got {body_ip}"
        );

        let (blocked_addr, body_addr) =
            post_faucet(&app, victim_ip, None, json!({ "address": canonical(32) })).await;
        assert_eq!(blocked_addr, StatusCode::TOO_MANY_REQUESTS, "{body_addr}");
        assert!(
            body_addr["message"]
                .as_str()
                .unwrap_or_default()
                .contains("address"),
            "a new address at the cap must be limited, got {body_addr}"
        );

        let (again, again_body) =
            post_faucet(&app, victim_ip, None, json!({ "address": addr_a })).await;
        assert_eq!(
            again,
            StatusCode::OK,
            "live victim entries must stay usable, got {again_body}"
        );
    }

    #[tokio::test]
    async fn back_to_back_dispenses_get_consecutive_nonces() {
        let (rpc, _, _, _, nonces, _, _, _) = spawn_stub_full(1_000 * 1_000_000_000, false).await;
        let app = app(faucet_state(&rpc, 60, 100, 86_400, 100, "", 0));

        let (s1, b1) = post_faucet(
            &app,
            "192.0.2.1:5000",
            None,
            json!({ "address": canonical(1) }),
        )
        .await;
        assert_eq!(s1, StatusCode::OK, "{b1}");

        let (s2, b2) = post_faucet(
            &app,
            "192.0.2.2:5000",
            None,
            json!({ "address": canonical(2) }),
        )
        .await;
        assert_eq!(s2, StatusCode::OK, "{b2}");

        let (s3, b3) = post_faucet(
            &app,
            "192.0.2.3:5000",
            None,
            json!({ "address": canonical(3) }),
        )
        .await;
        assert_eq!(s3, StatusCode::OK, "{b3}");

        let recorded = nonces.lock().clone();
        assert_eq!(
            recorded,
            vec![0, 1, 2],
            "dispenses back-to-back must get consecutive nonces"
        );
    }

    #[tokio::test]
    async fn nonce_retry_on_proposed_block_conflict() {
        let (rpc, _, _, _, nonces, submit_error, _, _) =
            spawn_stub_full(1_000 * 1_000_000_000, false).await;
        // First submit fails with "Nonce 0 is already in a proposed block"
        *submit_error.lock() = Some("Nonce 0 is already in a proposed block".to_string());

        let app = app(faucet_state(&rpc, 60, 100, 86_400, 100, "", 0));
        let (status, body) = post_faucet(
            &app,
            "192.0.2.1:5000",
            None,
            json!({ "address": canonical(1) }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["success"], true);

        // First attempt sent nonce 0 (and was rejected), retry sent nonce 1 (and succeeded)
        let recorded = nonces.lock().clone();
        assert_eq!(
            recorded,
            vec![1],
            "retried transaction must be submitted with incremented nonce"
        );
    }

    #[tokio::test]
    async fn timeout_on_submit_preserves_address_slot_and_returns_bad_gateway() {
        let (rpc, _, _, _, _, _, submit_delay_ms, _) =
            spawn_stub_full(1_000 * 1_000_000_000, false).await;
        // Node delays sendRawTransaction by 200ms
        *submit_delay_ms.lock() = Some(200);

        // Faucet HTTP client with 40ms timeout
        let fast_timeout_client = reqwest::Client::builder()
            .timeout(Duration::from_millis(40))
            .build()
            .unwrap();

        let state = faucet_state_with_client(
            &rpc,
            60,
            100,
            86_400,
            1, // max 1 per address
            "",
            0,
            RateLimiter::default(),
            fast_timeout_client,
        );
        let app = app(state);
        let target_address = canonical(55);

        // First attempt times out -> UNKNOWN outcome -> HTTP 502 Bad Gateway
        let (status1, body1) = post_faucet(
            &app,
            "192.0.2.1:5000",
            None,
            json!({ "address": target_address }),
        )
        .await;
        assert_eq!(status1, StatusCode::BAD_GATEWAY, "{body1}");
        let msg = body1["message"].as_str().unwrap_or_default();
        assert!(
            msg.contains("status unknown, do not retry for 24h"),
            "expected unknown outcome message, got: {msg}"
        );

        // Reset submit delay on node so it would succeed
        *submit_delay_ms.lock() = None;

        // Second attempt to same address from a different IP: MUST be rejected with 429 because slot was kept
        let (status2, body2) = post_faucet(
            &app,
            "192.0.2.2:5000",
            None,
            json!({ "address": target_address }),
        )
        .await;
        assert_eq!(status2, StatusCode::TOO_MANY_REQUESTS, "{body2}");
        assert!(
            body2["message"]
                .as_str()
                .unwrap_or_default()
                .contains("address"),
            "address slot must be preserved on timeout, got: {body2}"
        );
    }

    #[tokio::test]
    async fn explicit_4xx_rejection_rolls_back_address_slot() {
        let (rpc, _, _, _, _, _, _, fail_with_http_400) =
            spawn_stub_full(1_000 * 1_000_000_000, false).await;
        fail_with_http_400.store(true, Ordering::SeqCst);

        let app = app(faucet_state(&rpc, 60, 100, 86_400, 1, "", 0));
        let target_address = canonical(66);

        // First attempt explicitly rejected with HTTP 400
        let (status1, body1) = post_faucet(
            &app,
            "192.0.2.1:5000",
            None,
            json!({ "address": target_address }),
        )
        .await;
        assert_eq!(status1, StatusCode::INTERNAL_SERVER_ERROR, "{body1}");

        // Now fix the node
        fail_with_http_400.store(false, Ordering::SeqCst);

        // Second attempt to same address from a different IP: slot was rolled back, so it must succeed
        let (status2, body2) = post_faucet(
            &app,
            "192.0.2.2:5000",
            None,
            json!({ "address": target_address }),
        )
        .await;
        assert_eq!(
            status2,
            StatusCode::OK,
            "slot must be rolled back on 4xx rejection, got: {body2}"
        );
        assert_eq!(body2["success"], true);
    }

    #[test]
    fn forget_key_bounded_time_with_100k_entries() {
        let mut map = LimiterMap::default();
        let now = std::time::Instant::now();
        for i in 0..100_000 {
            let key = format!("addr_{i}");
            map.record_at(&key, 3600, 10, 150_000, now);
        }
        assert_eq!(map.entries.len(), 100_000);

        let start = std::time::Instant::now();
        map.forget_key("addr_50000");
        let elapsed = start.elapsed();

        assert!(!map.entries.contains_key("addr_50000"));
        assert!(
            elapsed < Duration::from_millis(5),
            "forget_key with 100k entries must run in < 5 ms, took: {:?}",
            elapsed
        );
    }
}
