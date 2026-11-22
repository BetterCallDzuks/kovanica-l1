//! Stratum V1 TCP gateway listener, client connection handler, and upstream coordinator.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::Context as AnyhowContext;
use anyhow::Result;
use axum::{routing::get, Router};
use kovanica_crypto::KovanicaHasher;
use kovanica_types::Hash;
use parking_lot::RwLock;
use pem::parse_many;
use prometheus_client::encoding::text::encode;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::Registry;
use rustls::pki_types::CertificateDer;
use serde_json::{json, Value};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Notify, Semaphore};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, info_span, warn, Instrument};

/// Maximum length in bytes of a single inbound Stratum V1 line (4 KiB).
/// Prevents slowloris / unbounded `read_line` allocation OOM attacks.
pub const MAX_STRATUM_LINE_BYTES: usize = 4_096;

/// Idle read timeout per client connection (5 minutes).
pub const STRATUM_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// TLS handshake timeout (10 seconds).
pub const STRATUM_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Outbound channel capacity per connected miner (64 messages).
/// Bounds memory if a client stops reading its TCP socket.
pub const CLIENT_OUTBOUND_CHANNEL_CAP: usize = 64;

/// Maximum distinct IPs tracked in the connection rate limiter.
pub const MAX_RATE_LIMITER_IPS: usize = 100_000;

/// Maximum distinct labels tracked in Prometheus per-IP and per-worker gauge families
/// to prevent label cardinality explosion.
pub const MAX_PROMETHEUS_LABEL_CARDINALITY: usize = 1_024;

/// Maximum allowed forward drift (in seconds) of a submitted `ntime` relative to the job's
/// template timestamp when timestamps are expressed in Unix seconds.
pub const MAX_NTIME_DRIFT_SECS: u64 = 7_200;

/// Maximum allowed forward drift (in milliseconds) of a submitted `ntime` relative to the job's
/// template timestamp when timestamps are expressed in Unix milliseconds (Kovanica native).
pub const MAX_NTIME_DRIFT_MS: u64 = MAX_NTIME_DRIFT_SECS * 1_000;

/// Threshold separating Unix-second timestamps from Unix-millisecond timestamps.
const UNIX_MILLIS_THRESHOLD: u64 = 1_000_000_000_000;

/// Validate a submitted `extranonce2` hex string against the session's configured byte length.
///
/// Returns the normalized lowercase hex string on success, or a human-readable error message.
pub fn validate_extranonce2(
    extranonce2: &str,
    extranonce2_size: usize,
) -> std::result::Result<String, String> {
    if extranonce2_size == 0 {
        return Err("invalid session extranonce2_size".to_string());
    }
    let expected_hex_len = extranonce2_size * 2;
    if extranonce2.len() != expected_hex_len {
        return Err(format!(
            "invalid extranonce2 length: got {} hex chars, expected {} ({} bytes)",
            extranonce2.len(),
            expected_hex_len,
            extranonce2_size
        ));
    }
    if !extranonce2.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid extranonce2: must contain only hexadecimal characters".to_string());
    }
    Ok(extranonce2.to_ascii_lowercase())
}

/// Validate a submitted `ntime` hex string format and parse it as a `u64` timestamp.
fn parse_ntime_hex(ntime_str: &str) -> std::result::Result<u64, String> {
    if ntime_str.len() < 8 || ntime_str.len() > 16 {
        return Err(format!(
            "invalid ntime length: got {} hex chars, expected 8..=16",
            ntime_str.len()
        ));
    }
    if !ntime_str.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid ntime: must contain only hexadecimal characters".to_string());
    }
    u64::from_str_radix(ntime_str, 16)
        .map_err(|_| "invalid ntime: failed to parse hexadecimal timestamp".to_string())
}

/// Validate a submitted `ntime` hex string both for format and reasonable bounds relative to the
/// job's template timestamp (`job_timestamp`).
///
/// Accepts timestamps in `[job_timestamp, job_timestamp + max_drift]` where `max_drift` is
/// [`MAX_NTIME_DRIFT_MS`] for millisecond timestamps and [`MAX_NTIME_DRIFT_SECS`] for second
/// timestamps.
pub fn validate_ntime(ntime_str: &str, job_timestamp: u64) -> std::result::Result<u64, String> {
    let ntime = parse_ntime_hex(ntime_str)?;
    let max_drift = if job_timestamp >= UNIX_MILLIS_THRESHOLD {
        MAX_NTIME_DRIFT_MS
    } else {
        MAX_NTIME_DRIFT_SECS
    };
    if ntime < job_timestamp {
        return Err(format!(
            "invalid ntime: {ntime} precedes job timestamp {job_timestamp}"
        ));
    }
    let max_allowed = job_timestamp.saturating_add(max_drift);
    if ntime > max_allowed {
        return Err(format!(
            "invalid ntime: {ntime} exceeds maximum allowed drift from job timestamp {job_timestamp}"
        ));
    }
    Ok(ntime)
}

thread_local! {
    /// Thread-local reusable 2 MiB KovanicaHasher context to avoid per-share
    /// 2 MiB heap allocations in `mining.submit`.
    static THREAD_STRATUM_HASHER: RefCell<KovanicaHasher> = RefCell::new(KovanicaHasher::new());
}

fn compute_pow_hash_reusable(preimage: &[u8]) -> Hash {
    THREAD_STRATUM_HASHER.with(|h| h.borrow_mut().hash(preimage))
}

/// Rate limiter for connection attempts per IP.
struct ConnectionRateLimiter {
    /// Max new connections per second per IP.
    max_rate: usize,
    /// Tracks connection attempts per IP with timestamps.
    attempts: RwLock<HashMap<std::net::IpAddr, Vec<Instant>>>,
}

impl ConnectionRateLimiter {
    fn new(max_rate: usize) -> Self {
        Self {
            max_rate,
            attempts: RwLock::new(HashMap::new()),
        }
    }

    /// Check if a new connection from this IP is allowed.
    fn check(&self, ip: std::net::IpAddr) -> bool {
        let now = Instant::now();
        let window_start = now - Duration::from_secs(1);

        let mut attempts = self.attempts.write();
        if !attempts.contains_key(&ip) && attempts.len() >= MAX_RATE_LIMITER_IPS {
            // Sweep expired entries before rejecting at cap
            attempts.retain(|_, v| {
                v.retain(|&t| t > window_start);
                !v.is_empty()
            });
            if attempts.len() >= MAX_RATE_LIMITER_IPS {
                return false;
            }
        }
        let ip_attempts = attempts.entry(ip).or_default();

        // Remove old attempts outside the 1-second window
        ip_attempts.retain(|&t| t > window_start);

        // Check if we're at the limit
        if ip_attempts.len() >= self.max_rate {
            false
        } else {
            ip_attempts.push(now);
            true
        }
    }

    /// Clean up old entries periodically (call occasionally).
    pub(crate) fn cleanup(&self) {
        let now = Instant::now();
        let window_start = now - Duration::from_secs(2);
        let mut attempts = self.attempts.write();
        attempts.retain(|_, v| {
            v.retain(|&t| t > window_start);
            !v.is_empty()
        });
    }
}

/// Rate limiter for Stratum requests per connection.
struct RequestRateLimiter {
    max_rate: usize,
    count: AtomicU64,
    window_start: parking_lot::Mutex<Instant>,
}

impl RequestRateLimiter {
    fn new(max_rate: usize) -> Self {
        Self {
            max_rate,
            count: AtomicU64::new(0),
            window_start: parking_lot::Mutex::new(Instant::now()),
        }
    }

    /// Check if a new request is allowed.
    fn check(&self) -> bool {
        let now = Instant::now();
        let mut window_start = self.window_start.lock();

        if now.duration_since(*window_start) >= Duration::from_secs(1) {
            *window_start = now;
            self.count.store(0, Ordering::Relaxed);
        }

        let current = self.count.fetch_add(1, Ordering::Relaxed);
        current < self.max_rate as u64
    }
}

/// Wrapper for both TLS and non-TLS streams.
enum MaybeTlsStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl Unpin for MaybeTlsStream {}

use crate::config::{StratumConfig, VarDiffConfig, DEFAULT_PAYOUT_ADDRESS};
use crate::difficulty::{check_network_solution, check_share_hash_meets_difficulty};
use crate::job::{Job, JobManager};
use crate::protocol::{StratumNotification, StratumRequest, StratumResponse};
use crate::rpc::NodeRpcClient;
use crate::session::{parse_and_validate_username, SessionRegistry, WorkerSession};
use crate::{KOVANICA_STRATUM_ALGORITHM, KOVANICA_STRATUM_CAPABILITY};

/// Bounded channel message to send to a connected client TCP stream.
/// Capacity is CLIENT_OUTBOUND_CHANNEL_CAP (64) to bound memory if a client stops reading.
type ClientSender = mpsc::Sender<String>;

/// Read a single newline-terminated line with an explicit byte limit [`MAX_STRATUM_LINE_BYTES`]
/// and idle timeout [`STRATUM_IDLE_TIMEOUT`].
///
/// Returns `Ok(0)` on clean EOF, `Ok(n)` on a line read, or an error on timeout / oversized line.
async fn read_bounded_line<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    buf: &mut String,
) -> std::io::Result<usize> {
    buf.clear();
    let mut raw = Vec::new();
    let read_fut = async {
        let mut limited = reader.take(MAX_STRATUM_LINE_BYTES as u64 + 1);
        let n = limited.read_until(b'\n', &mut raw).await?;
        if n > MAX_STRATUM_LINE_BYTES || (n == MAX_STRATUM_LINE_BYTES && !raw.ends_with(b"\n")) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Stratum line exceeds {MAX_STRATUM_LINE_BYTES} byte limit"),
            ));
        }
        Ok(n)
    };

    let n = match tokio::time::timeout(STRATUM_IDLE_TIMEOUT, read_fut).await {
        Ok(res) => res?,
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Stratum connection idle read timeout",
            ));
        }
    };
    if n == 0 {
        return Ok(0);
    }
    let s = String::from_utf8(raw).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid UTF-8 in Stratum line: {e}"),
        )
    })?;
    *buf = s;
    Ok(n)
}

/// Label for per-IP connection metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct IpLabel {
    pub ip: String,
}

/// Label for share difficulty bucket metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct DifficultyBucketLabel {
    pub bucket: &'static str,
}

/// Label for per-worker hashrate metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct WorkerLabel {
    pub worker: String,
}

/// Reason a submitted share was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareRejectReason {
    InvalidParams,
    Duplicate,
    Stale,
    LowDifficulty,
    Unauthorized,
}

impl ShareRejectReason {
    /// Canonical Prometheus label value for this rejection reason.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidParams => "invalid_params",
            Self::Duplicate => "duplicate",
            Self::Stale => "stale",
            Self::LowDifficulty => "low_difficulty",
            Self::Unauthorized => "unauthorized",
        }
    }

    const ALL: [Self; 5] = [
        Self::InvalidParams,
        Self::Duplicate,
        Self::Stale,
        Self::LowDifficulty,
        Self::Unauthorized,
    ];
}

/// Label for per-reason share rejection metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ShareRejectReasonLabel {
    pub reason: &'static str,
}

/// Label for VarDiff retarget direction metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RetargetDirectionLabel {
    pub direction: &'static str,
}

/// Label for TLS handshake result metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct TlsHandshakeResultLabel {
    pub result: &'static str,
}

/// Map a share difficulty to a bounded Prometheus label bucket to avoid cardinality explosion.
fn difficulty_bucket_label(difficulty: f64) -> &'static str {
    if difficulty < 1.0 {
        "<1"
    } else if difficulty < 2.0 {
        "1"
    } else if difficulty < 4.0 {
        "2"
    } else if difficulty < 8.0 {
        "4"
    } else if difficulty < 16.0 {
        "8"
    } else if difficulty < 32.0 {
        "16"
    } else if difficulty < 64.0 {
        "32"
    } else if difficulty < 128.0 {
        "64"
    } else if difficulty < 256.0 {
        "128"
    } else if difficulty < 512.0 {
        "256"
    } else if difficulty < 1024.0 {
        "512"
    } else {
        "1024+"
    }
}

/// Metrics for the Stratum gateway.
#[derive(Clone)]
pub struct GatewayMetrics {
    // Connection metrics
    pub active_connections: Gauge,
    pub connections_per_ip: Family<IpLabel, Gauge>,
    pub connection_rate_limit_hits: Counter,
    pub connection_rejected_max: Counter,
    pub connection_rejected_per_ip: Counter,

    // Share metrics
    pub shares_submitted: Counter,
    pub shares_accepted: Counter,
    pub shares_rejected: Counter,
    pub shares_rejected_low_difficulty: Counter,
    pub shares_rejected_stale: Counter,
    pub shares_rejected_duplicate: Counter,
    pub shares_rejected_unauthorized: Counter,
    pub shares_rejected_invalid_params: Counter,
    pub shares_rejected_by_reason: Family<ShareRejectReasonLabel, Counter>,
    pub shares_by_difficulty_bucket: Family<DifficultyBucketLabel, Counter>,

    // VarDiff & active worker difficulty metrics
    pub vardiff_retargets: Counter,
    pub vardiff_retargets_by_direction: Family<RetargetDirectionLabel, Counter>,
    pub worker_difficulty_min: Gauge<f64, AtomicU64>,
    pub worker_difficulty_max: Gauge<f64, AtomicU64>,
    pub worker_difficulty_avg: Gauge<f64, AtomicU64>,

    // Hashrate metrics
    pub worker_hashrate: Family<WorkerLabel, Gauge>,

    // Request metrics
    pub request_rate_limit_hits: Counter,

    // RPC metrics
    pub rpc_getwork_latency: Histogram,
    pub rpc_submitwork_latency: Histogram,
    pub rpc_getwork_errors: Counter,
    pub rpc_submitwork_errors: Counter,

    // Job broadcast metrics
    pub job_broadcast_latency: Histogram,
    pub job_broadcast_errors: Counter,

    // TLS metrics
    pub tls_handshake_success: Counter,
    pub tls_handshake_failure: Counter,
    pub tls_handshakes: Family<TlsHandshakeResultLabel, Counter>,

    // Block metrics
    pub blocks_found: Counter,
    pub blocks_submitted: Counter,
    pub blocks_accepted: Counter,
    pub blocks_rejected: Counter,

    // Health metrics
    pub uptime_seconds: Gauge,

    // Bounded sets tracking registered labels to prevent Prometheus cardinality explosion
    tracked_ips: Arc<RwLock<HashSet<String>>>,
    tracked_workers: Arc<RwLock<HashSet<String>>>,
}

impl GatewayMetrics {
    pub fn new(registry: &mut Registry) -> Self {
        // Note: `prometheus_client` automatically appends `_total` to Counter names.

        // Connection metrics
        let active_connections = Gauge::default();
        registry.register(
            "stratum_active_connections",
            "Current active miner connections",
            active_connections.clone(),
        );

        let connections_per_ip = Family::<IpLabel, Gauge>::default();
        registry.register(
            "stratum_connections_per_ip",
            "Active connections per IP address",
            connections_per_ip.clone(),
        );

        let connection_rate_limit_hits = Counter::default();
        registry.register(
            "stratum_connection_rate_limit_hits",
            "Total connection rate limit hits",
            connection_rate_limit_hits.clone(),
        );

        let connection_rejected_max = Counter::default();
        registry.register(
            "stratum_connections_rejected_max",
            "Total connections rejected due to global limit",
            connection_rejected_max.clone(),
        );

        let connection_rejected_per_ip = Counter::default();
        registry.register(
            "stratum_connections_rejected_per_ip",
            "Total connections rejected due to per-IP limit",
            connection_rejected_per_ip.clone(),
        );

        // Share metrics
        let shares_submitted = Counter::default();
        registry.register(
            "stratum_shares_submitted",
            "Total shares submitted by miners",
            shares_submitted.clone(),
        );

        let shares_accepted = Counter::default();
        registry.register(
            "stratum_shares_accepted",
            "Total shares accepted",
            shares_accepted.clone(),
        );

        let shares_rejected = Counter::default();
        registry.register(
            "stratum_shares_rejected",
            "Total shares rejected",
            shares_rejected.clone(),
        );

        let shares_rejected_low_difficulty = Counter::default();
        registry.register(
            "stratum_shares_rejected_low_difficulty",
            "Total shares rejected due to low difficulty",
            shares_rejected_low_difficulty.clone(),
        );

        let shares_rejected_stale = Counter::default();
        registry.register(
            "stratum_shares_rejected_stale",
            "Total shares rejected due to stale job",
            shares_rejected_stale.clone(),
        );

        let shares_rejected_duplicate = Counter::default();
        registry.register(
            "stratum_shares_rejected_duplicate",
            "Total shares rejected as duplicates",
            shares_rejected_duplicate.clone(),
        );

        let shares_rejected_unauthorized = Counter::default();
        registry.register(
            "stratum_shares_rejected_unauthorized",
            "Total shares rejected due to unauthorized worker",
            shares_rejected_unauthorized.clone(),
        );

        let shares_rejected_invalid_params = Counter::default();
        registry.register(
            "stratum_shares_rejected_invalid_params",
            "Total shares rejected due to invalid parameters",
            shares_rejected_invalid_params.clone(),
        );

        let shares_rejected_by_reason = Family::<ShareRejectReasonLabel, Counter>::default();
        for reason in ShareRejectReason::ALL {
            let _ = shares_rejected_by_reason.get_or_create(&ShareRejectReasonLabel {
                reason: reason.as_str(),
            });
        }
        registry.register(
            "stratum_shares_rejected_by_reason",
            "Total shares rejected labeled by rejection reason",
            shares_rejected_by_reason.clone(),
        );

        let shares_by_difficulty_bucket = Family::<DifficultyBucketLabel, Counter>::default();
        registry.register(
            "stratum_shares_by_difficulty_bucket",
            "Shares submitted grouped by difficulty bucket",
            shares_by_difficulty_bucket.clone(),
        );

        // VarDiff & active worker difficulty metrics
        let vardiff_retargets = Counter::default();
        registry.register(
            "stratum_vardiff_retargets",
            "Total per-worker VarDiff difficulty retargets",
            vardiff_retargets.clone(),
        );

        let vardiff_retargets_by_direction = Family::<RetargetDirectionLabel, Counter>::default();
        for direction in ["up", "down"] {
            let _ =
                vardiff_retargets_by_direction.get_or_create(&RetargetDirectionLabel { direction });
        }
        registry.register(
            "stratum_vardiff_retargets_by_direction",
            "Total per-worker VarDiff retargets labeled by direction",
            vardiff_retargets_by_direction.clone(),
        );

        let worker_difficulty_min = Gauge::<f64, AtomicU64>::default();
        registry.register(
            "stratum_worker_difficulty_min",
            "Minimum share difficulty across currently connected workers",
            worker_difficulty_min.clone(),
        );

        let worker_difficulty_max = Gauge::<f64, AtomicU64>::default();
        registry.register(
            "stratum_worker_difficulty_max",
            "Maximum share difficulty across currently connected workers",
            worker_difficulty_max.clone(),
        );

        let worker_difficulty_avg = Gauge::<f64, AtomicU64>::default();
        registry.register(
            "stratum_worker_difficulty_avg",
            "Average share difficulty across currently connected workers",
            worker_difficulty_avg.clone(),
        );

        // Hashrate metrics
        let worker_hashrate = Family::<WorkerLabel, Gauge>::default();
        registry.register(
            "stratum_worker_hashrate",
            "Estimated hashrate per worker (H/s)",
            worker_hashrate.clone(),
        );

        // Request metrics
        let request_rate_limit_hits = Counter::default();
        registry.register(
            "stratum_request_rate_limit_hits",
            "Total request rate limit hits",
            request_rate_limit_hits.clone(),
        );

        // RPC metrics
        let rpc_getwork_latency =
            Histogram::new(exponential_buckets(0.001, 2.0, 20).collect::<Vec<f64>>());
        registry.register(
            "stratum_rpc_getwork_latency_seconds",
            "Upstream getWork RPC latency",
            rpc_getwork_latency.clone(),
        );

        let rpc_submitwork_latency =
            Histogram::new(exponential_buckets(0.001, 2.0, 20).collect::<Vec<f64>>());
        registry.register(
            "stratum_rpc_submitwork_latency_seconds",
            "Upstream submitWork RPC latency",
            rpc_submitwork_latency.clone(),
        );

        let rpc_getwork_errors = Counter::default();
        registry.register(
            "stratum_rpc_getwork_errors",
            "Total getWork RPC errors",
            rpc_getwork_errors.clone(),
        );

        let rpc_submitwork_errors = Counter::default();
        registry.register(
            "stratum_rpc_submitwork_errors",
            "Total submitWork RPC errors",
            rpc_submitwork_errors.clone(),
        );

        // Job broadcast metrics
        let job_broadcast_latency =
            Histogram::new(exponential_buckets(0.0001, 2.0, 20).collect::<Vec<f64>>());
        registry.register(
            "stratum_job_broadcast_latency_seconds",
            "Job broadcast latency to all miners",
            job_broadcast_latency.clone(),
        );

        let job_broadcast_errors = Counter::default();
        registry.register(
            "stratum_job_broadcast_errors",
            "Total job broadcast errors",
            job_broadcast_errors.clone(),
        );

        // TLS metrics
        let tls_handshake_success = Counter::default();
        registry.register(
            "stratum_tls_handshake_success",
            "Total successful TLS handshakes",
            tls_handshake_success.clone(),
        );

        let tls_handshake_failure = Counter::default();
        registry.register(
            "stratum_tls_handshake_failure",
            "Total failed TLS handshakes",
            tls_handshake_failure.clone(),
        );

        let tls_handshakes = Family::<TlsHandshakeResultLabel, Counter>::default();
        for result in ["success", "failure"] {
            let _ = tls_handshakes.get_or_create(&TlsHandshakeResultLabel { result });
        }
        registry.register(
            "stratum_tls_handshakes",
            "Total TLS handshakes labeled by result",
            tls_handshakes.clone(),
        );

        // Block metrics
        let blocks_found = Counter::default();
        registry.register(
            "stratum_blocks_found",
            "Total valid network blocks found by miners",
            blocks_found.clone(),
        );

        let blocks_submitted = Counter::default();
        registry.register(
            "stratum_blocks_submitted",
            "Total blocks submitted to upstream",
            blocks_submitted.clone(),
        );

        let blocks_accepted = Counter::default();
        registry.register(
            "stratum_blocks_accepted",
            "Total blocks accepted by upstream",
            blocks_accepted.clone(),
        );

        let blocks_rejected = Counter::default();
        registry.register(
            "stratum_blocks_rejected",
            "Total blocks rejected by upstream",
            blocks_rejected.clone(),
        );

        // Health metrics
        let uptime_seconds = Gauge::default();
        registry.register(
            "stratum_uptime_seconds",
            "Gateway uptime in seconds",
            uptime_seconds.clone(),
        );

        Self {
            active_connections,
            connections_per_ip,
            connection_rate_limit_hits,
            connection_rejected_max,
            connection_rejected_per_ip,
            shares_submitted,
            shares_accepted,
            shares_rejected,
            shares_rejected_low_difficulty,
            shares_rejected_stale,
            shares_rejected_duplicate,
            shares_rejected_unauthorized,
            shares_rejected_invalid_params,
            shares_rejected_by_reason,
            shares_by_difficulty_bucket,
            vardiff_retargets,
            vardiff_retargets_by_direction,
            worker_difficulty_min,
            worker_difficulty_max,
            worker_difficulty_avg,
            worker_hashrate,
            request_rate_limit_hits,
            rpc_getwork_latency,
            rpc_submitwork_latency,
            rpc_getwork_errors,
            rpc_submitwork_errors,
            job_broadcast_latency,
            job_broadcast_errors,
            tls_handshake_success,
            tls_handshake_failure,
            tls_handshakes,
            blocks_found,
            blocks_submitted,
            blocks_accepted,
            blocks_rejected,
            uptime_seconds,
            tracked_ips: Arc::new(RwLock::new(HashSet::new())),
            tracked_workers: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Update the `stratum_connections_per_ip` gauge only if within label cardinality cap.
    pub fn set_connections_for_ip(&self, ip_str: String, count: i64) {
        let allow = {
            let tracked = self.tracked_ips.read();
            tracked.contains(&ip_str) || tracked.len() < MAX_PROMETHEUS_LABEL_CARDINALITY
        };
        if allow {
            self.tracked_ips.write().insert(ip_str.clone());
            self.connections_per_ip
                .get_or_create(&IpLabel { ip: ip_str })
                .set(count);
        }
    }

    /// Update the `stratum_worker_hashrate` gauge only if within label cardinality cap.
    pub fn set_worker_hashrate(&self, worker: String, hashrate: i64) {
        let allow = {
            let tracked = self.tracked_workers.read();
            tracked.contains(&worker) || tracked.len() < MAX_PROMETHEUS_LABEL_CARDINALITY
        };
        if allow {
            self.tracked_workers.write().insert(worker.clone());
            self.worker_hashrate
                .get_or_create(&WorkerLabel { worker })
                .set(hashrate);
        }
    }

    /// Record a rejected share across the aggregate counter, legacy reason counter,
    /// and labeled `stratum_shares_rejected_by_reason_total{reason=...}` counter.
    pub fn record_share_rejected(&self, reason: ShareRejectReason) {
        self.shares_rejected.inc();
        match reason {
            ShareRejectReason::InvalidParams => self.shares_rejected_invalid_params.inc(),
            ShareRejectReason::Duplicate => self.shares_rejected_duplicate.inc(),
            ShareRejectReason::Stale => self.shares_rejected_stale.inc(),
            ShareRejectReason::LowDifficulty => self.shares_rejected_low_difficulty.inc(),
            ShareRejectReason::Unauthorized => self.shares_rejected_unauthorized.inc(),
        };
        self.shares_rejected_by_reason
            .get_or_create(&ShareRejectReasonLabel {
                reason: reason.as_str(),
            })
            .inc();
    }

    /// Record a VarDiff retarget event across aggregate and directional counters.
    pub fn record_vardiff_retarget(&self, old_diff: f64, new_diff: f64) {
        self.vardiff_retargets.inc();
        let direction = if new_diff >= old_diff { "up" } else { "down" };
        self.vardiff_retargets_by_direction
            .get_or_create(&RetargetDirectionLabel { direction })
            .inc();
    }

    /// Record a successful TLS handshake across legacy and labeled counters.
    pub fn record_tls_handshake_success(&self) {
        self.tls_handshake_success.inc();
        self.tls_handshakes
            .get_or_create(&TlsHandshakeResultLabel { result: "success" })
            .inc();
    }

    /// Record a failed TLS handshake across legacy and labeled counters.
    pub fn record_tls_handshake_failure(&self) {
        self.tls_handshake_failure.inc();
        self.tls_handshakes
            .get_or_create(&TlsHandshakeResultLabel { result: "failure" })
            .inc();
    }

    /// Update active worker difficulty summary gauges (min, max, avg).
    pub fn set_worker_difficulty_stats(&self, min: f64, max: f64, avg: f64) {
        self.worker_difficulty_min.set(min);
        self.worker_difficulty_max.set(max);
        self.worker_difficulty_avg.set(avg);
    }
}

/// Production Stratum V1 mining pool gateway.
#[derive(Clone)]
pub struct StratumGateway {
    config: StratumConfig,
    rpc_client: NodeRpcClient,
    job_manager: Arc<JobManager>,
    session_registry: Arc<SessionRegistry>,
    active_subscribers: Arc<RwLock<HashMap<String, ClientSender>>>,
    /// Active worker sessions keyed by `session_id` for difficulty telemetry aggregation.
    active_sessions: Arc<RwLock<HashMap<String, Arc<WorkerSession>>>>,
    shutdown: Arc<AtomicBool>,
    shutdown_notify: Arc<Notify>,
    tls_acceptor: Option<TlsAcceptor>,
    /// Semaphore for limiting total concurrent connections.
    connection_semaphore: Arc<Semaphore>,
    /// Rate limiter for connection attempts per IP.
    connection_rate_limiter: Arc<ConnectionRateLimiter>,
    /// Active connection count per IP.
    connections_per_ip: Arc<RwLock<HashMap<std::net::IpAddr, usize>>>,
    /// Monotonic counter for connection correlation IDs.
    next_conn_id: Arc<AtomicU64>,
    /// Metrics collector
    metrics: GatewayMetrics,
    /// Metrics registry for Prometheus exposition
    metrics_registry: Arc<Registry>,
    /// Gateway start time for uptime
    start_time: Instant,
}

impl StratumGateway {
    /// Create a new gateway from configuration.
    pub fn new(config: StratumConfig) -> Result<Self> {
        let max_connections = config.max_connections;
        let max_connection_rate_per_ip = config.max_connection_rate_per_ip;
        let rpc_client = NodeRpcClient::with_token(&config.rpc_url, config.rpc_token.clone());

        // Build TLS acceptor if TLS is enabled
        let tls_acceptor = if config.tls {
            Some(Self::build_tls_acceptor(&config)?)
        } else {
            None
        };

        // Initialize metrics registry and metrics
        let mut metrics_registry = Registry::default();
        let metrics = GatewayMetrics::new(&mut metrics_registry);
        let metrics_registry = Arc::new(metrics_registry);

        Ok(Self {
            config,
            rpc_client,
            job_manager: Arc::new(JobManager::new()),
            session_registry: Arc::new(SessionRegistry::new()),
            active_subscribers: Arc::new(RwLock::new(HashMap::new())),
            active_sessions: Arc::new(RwLock::new(HashMap::new())),
            shutdown: Arc::new(AtomicBool::new(false)),
            shutdown_notify: Arc::new(Notify::new()),
            tls_acceptor,
            connection_semaphore: Arc::new(Semaphore::new(max_connections)),
            connection_rate_limiter: Arc::new(ConnectionRateLimiter::new(
                max_connection_rate_per_ip,
            )),
            connections_per_ip: Arc::new(RwLock::new(HashMap::new())),
            next_conn_id: Arc::new(AtomicU64::new(1)),
            metrics,
            metrics_registry,
            start_time: Instant::now(),
        })
    }

    /// Access the underlying configuration.
    pub fn config(&self) -> &StratumConfig {
        &self.config
    }

    /// Access the job manager.
    pub fn job_manager(&self) -> &Arc<JobManager> {
        &self.job_manager
    }

    /// Access the session registry.
    pub fn session_registry(&self) -> &Arc<SessionRegistry> {
        &self.session_registry
    }

    /// Access the metrics collector.
    pub fn metrics(&self) -> &GatewayMetrics {
        &self.metrics
    }

    /// Access the metrics registry for Prometheus exposition.
    pub fn metrics_registry(&self) -> &Arc<Registry> {
        &self.metrics_registry
    }

    /// Gateway start instant for uptime calculations.
    pub fn start_time(&self) -> Instant {
        self.start_time
    }

    /// Build the Axum HTTP router exposing `/metrics` (Prometheus) and `/health` (JSON).
    pub fn observability_router(&self) -> Router {
        let gateway_for_metrics = self.clone();
        let gateway_for_health = self.clone();
        let obs_semaphore = Arc::new(Semaphore::new(16));
        let metrics_sem = Arc::clone(&obs_semaphore);
        let health_sem = Arc::clone(&obs_semaphore);

        Router::new()
            .route(
                "/metrics",
                get(move || {
                    let gw = gateway_for_metrics.clone();
                    let sem = Arc::clone(&metrics_sem);
                    async move {
                        let Ok(_permit) = sem.try_acquire() else {
                            return axum::response::Response::builder()
                                .status(503)
                                .body("too many concurrent observability requests".to_string())
                                .unwrap_or_default();
                        };
                        gw.metrics
                            .uptime_seconds
                            .set(gw.start_time.elapsed().as_secs() as i64);
                        gw.refresh_difficulty_metrics();
                        let mut buffer = String::new();
                        if let Err(e) = encode(&mut buffer, &gw.metrics_registry) {
                            error!(%e, "failed to encode Prometheus metrics");
                            return axum::response::Response::builder()
                                .status(500)
                                .body(format!("metrics encoding error: {e}"))
                                .unwrap_or_default();
                        }
                        axum::response::Response::builder()
                            .header(
                                "Content-Type",
                                "application/openmetrics-text; version=1.0.0; charset=utf-8",
                            )
                            .body(buffer)
                            .unwrap_or_default()
                    }
                }),
            )
            .route(
                "/health",
                get(move || {
                    let gw = gateway_for_health.clone();
                    let sem = Arc::clone(&health_sem);
                    async move {
                        let Ok(_permit) = sem.try_acquire() else {
                            return axum::response::Response::builder()
                                .status(503)
                                .body("too many concurrent observability requests".to_string())
                                .unwrap_or_default();
                        };
                        let uptime = gw.start_time.elapsed().as_secs();
                        let active_connections = gw.metrics.active_connections.get();
                        let current_job_id =
                            gw.job_manager.get_current_job().map(|j| j.job_id.clone());
                        let health = json!({
                            "status": "healthy",
                            "uptime_seconds": uptime,
                            "active_connections": active_connections,
                            "current_job_id": current_job_id,
                            "tls_enabled": gw.config.tls,
                            "timestamp": chrono::Utc::now().to_rfc3339()
                        });
                        axum::response::Response::builder()
                            .header("Content-Type", "application/json")
                            .body(health.to_string())
                            .unwrap_or_default()
                    }
                }),
            )
    }

    /// Serve `/metrics` and `/health` on the given bound TCP listener.
    pub async fn serve_observability(&self, listener: TcpListener) -> Result<()> {
        let local_addr = listener.local_addr().unwrap_or(self.config.metrics_addr);
        info!(%local_addr, "Stratum observability HTTP server (/metrics, /health) started");
        axum::serve(listener, self.observability_router())
            .await
            .context("observability HTTP server exited with error")
    }

    /// Signal shutdown.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.shutdown_notify.notify_waiters();
    }

    /// Sweep expired per-IP connection rate-limiter entries.
    pub fn cleanup_rate_limiter(&self) {
        self.connection_rate_limiter.cleanup();
    }

    /// Recompute active worker difficulty min/max/avg gauges from connected sessions.
    pub fn refresh_difficulty_metrics(&self) {
        Self::refresh_difficulty_metrics_from(&self.active_sessions, &self.metrics);
    }

    fn refresh_difficulty_metrics_from(
        active_sessions: &RwLock<HashMap<String, Arc<WorkerSession>>>,
        metrics: &GatewayMetrics,
    ) {
        let sessions = active_sessions.read();
        if sessions.is_empty() {
            metrics.set_worker_difficulty_stats(0.0, 0.0, 0.0);
            return;
        }
        let mut min_d = f64::INFINITY;
        let mut max_d = f64::NEG_INFINITY;
        let mut sum = 0.0;
        let mut count = 0usize;
        for sess in sessions.values() {
            let d = sess.get_difficulty();
            if d.is_finite() {
                if d < min_d {
                    min_d = d;
                }
                if d > max_d {
                    max_d = d;
                }
                sum += d;
                count += 1;
            }
        }
        if count == 0 {
            metrics.set_worker_difficulty_stats(0.0, 0.0, 0.0);
        } else {
            metrics.set_worker_difficulty_stats(min_d, max_d, sum / count as f64);
        }
    }

    /// Broadcast a new job notification to all active subscribed miners.
    pub fn broadcast_notify(&self, job: &Job) {
        let notif = StratumNotification::notify(
            &job.job_id,
            &job.prevhash,
            &job.coinb1_hex,
            "",
            &[],
            &format!("{:08x}", job.round),
            &format!("{:08x}", job.target_bits),
            &format!("{:08x}", job.header.timestamp),
            true,
        );
        let wire_msg = notif.to_wire_line();

        let broadcast_start = Instant::now();
        let mut subscribers = self.active_subscribers.write();
        let mut dead_sessions = Vec::new();

        for (session_id, tx) in subscribers.iter() {
            if let Err(e) = tx.try_send(wire_msg.clone()) {
                self.metrics.job_broadcast_errors.inc();
                debug!(%session_id, %e, "miner channel full or closed, dropping subscriber");
                dead_sessions.push(session_id.clone());
            }
        }

        for dead in dead_sessions {
            subscribers.remove(&dead);
        }
        self.metrics
            .job_broadcast_latency
            .observe(broadcast_start.elapsed().as_secs_f64());
    }

    /// Start the Stratum TCP listener and upstream background polling loop.
    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.config.listen_addr)
            .await
            .context(format!(
                "failed to bind TCP listener on {}",
                self.config.listen_addr
            ))?;

        self.run_with_listener(listener).await
    }

    /// Run the Stratum TCP listener and upstream polling loop on an existing listener.
    pub async fn run_with_listener(&self, listener: TcpListener) -> Result<()> {
        let local_addr = listener.local_addr().unwrap_or(self.config.listen_addr);

        info!(
            listen_addr = %local_addr,
            rpc_url = %self.config.rpc_url,
            chain_id = self.config.chain_id,
            difficulty = self.config.difficulty,
            "Stratum V1 pool gateway started"
        );

        // Spawn upstream template poller
        let poller_shutdown = Arc::clone(&self.shutdown);
        let poller_shutdown_notify = Arc::clone(&self.shutdown_notify);
        let poller_rpc = self.rpc_client.clone();
        let poller_jobs = Arc::clone(&self.job_manager);
        let poller_subscribers = Arc::clone(&self.active_subscribers);
        let poller_payout = self.config.payout_address.clone();
        let poll_interval = self.config.poll_interval;
        let poller_metrics = self.metrics.clone();

        tokio::spawn(async move {
            let mut last_round = 0u64;
            let mut last_target_bits = 0u32;
            let fallback_payout =
                poller_payout.unwrap_or_else(|| DEFAULT_PAYOUT_ADDRESS.to_string());

            while !poller_shutdown.load(Ordering::Relaxed) {
                let rpc_start = Instant::now();
                match poller_rpc.get_work(&fallback_payout).await {
                    Ok(template) => {
                        poller_metrics
                            .rpc_getwork_latency
                            .observe(rpc_start.elapsed().as_secs_f64());
                        let target_bits = template.parse_target_bits().unwrap_or(0);
                        if template.round != last_round || target_bits != last_target_bits {
                            match template.to_candidate_header() {
                                Ok(header) => {
                                    last_round = template.round;
                                    last_target_bits = target_bits;

                                    let job = poller_jobs.add_template(header);
                                    info!(
                                        job_id = %job.job_id,
                                        round = job.round,
                                        target_bits = format!("0x{:08x}", job.target_bits),
                                        "new work template received from node; broadcasting to workers"
                                    );

                                    // Broadcast to active miners
                                    let notif = StratumNotification::notify(
                                        &job.job_id,
                                        &job.prevhash,
                                        &job.coinb1_hex,
                                        "",
                                        &[],
                                        &format!("{:08x}", job.round),
                                        &format!("{:08x}", job.target_bits),
                                        &format!("{:08x}", job.header.timestamp),
                                        true,
                                    );
                                    let wire_msg = notif.to_wire_line();

                                    let broadcast_start = Instant::now();
                                    let mut subscribers = poller_subscribers.write();
                                    let mut dead = Vec::new();
                                    for (sess_id, tx) in subscribers.iter() {
                                        if tx.try_send(wire_msg.clone()).is_err() {
                                            poller_metrics.job_broadcast_errors.inc();
                                            dead.push(sess_id.clone());
                                        }
                                    }
                                    for d in dead {
                                        subscribers.remove(&d);
                                    }
                                    poller_metrics
                                        .job_broadcast_latency
                                        .observe(broadcast_start.elapsed().as_secs_f64());
                                }
                                Err(e) => {
                                    warn!(%e, "failed to convert work template to candidate header");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        poller_metrics
                            .rpc_getwork_latency
                            .observe(rpc_start.elapsed().as_secs_f64());
                        poller_metrics.rpc_getwork_errors.inc();
                        debug!(%e, "upstream kovanica_getWork polling failed");
                    }
                }

                tokio::select! {
                    _ = poller_shutdown_notify.notified() => break,
                    _ = tokio::time::sleep(poll_interval) => {}
                }
            }
        });

        // Spawn periodic connection rate-limiter cleanup task
        let cleanup_shutdown = Arc::clone(&self.shutdown);
        let cleanup_shutdown_notify = Arc::clone(&self.shutdown_notify);
        let cleanup_limiter = Arc::clone(&self.connection_rate_limiter);
        tokio::spawn(async move {
            while !cleanup_shutdown.load(Ordering::Relaxed) {
                tokio::select! {
                    _ = cleanup_shutdown_notify.notified() => break,
                    _ = tokio::time::sleep(Duration::from_secs(10)) => {
                        cleanup_limiter.cleanup();
                    }
                }
            }
        });

        // Accept loop
        while !self.shutdown.load(Ordering::Relaxed) {
            let accept_res = tokio::select! {
                _ = self.shutdown_notify.notified() => {
                    info!("Stratum gateway shutdown signal received, exiting accept loop");
                    break;
                }
                res = listener.accept() => res,
            };
            match accept_res {
                Ok((socket, remote_addr)) => {
                    let client_ip = remote_addr.ip();
                    let conn_seq = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
                    let correlation_id = format!("conn-{conn_seq:08x}");

                    // Check global connection limit and acquire permit up front
                    let connection_permit =
                        match self.connection_semaphore.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                self.metrics.connection_rejected_max.inc();
                                warn!(
                                    event = "stratum_access_denied",
                                    reason = "max_connections",
                                    %correlation_id,
                                    %remote_addr,
                                    max_connections = self.config.max_connections,
                                    "connection rejected: max connections reached"
                                );
                                continue;
                            }
                        };

                    // Check per-IP connection limit
                    {
                        let per_ip = self.connections_per_ip.read();
                        let current = per_ip.get(&client_ip).copied().unwrap_or(0);
                        if current >= self.config.max_connections_per_ip {
                            self.metrics.connection_rejected_per_ip.inc();
                            warn!(
                                event = "stratum_access_denied",
                                reason = "max_connections_per_ip",
                                %correlation_id,
                                %remote_addr,
                                max_connections_per_ip = self.config.max_connections_per_ip,
                                "connection rejected: per-IP limit reached"
                            );
                            drop(connection_permit);
                            continue;
                        }
                    }

                    info!(
                        event = "stratum_accept_debug",
                        %correlation_id,
                        %remote_addr,
                        "accepted connection, checking limits"
                    );
                    // Check connection rate limit per IP
                    if !self.connection_rate_limiter.check(client_ip) {
                        self.metrics.connection_rate_limit_hits.inc();
                        warn!(
                            event = "stratum_access_denied",
                            reason = "connection_rate_limit",
                            %correlation_id,
                            %remote_addr,
                            max_rate = self.config.max_connection_rate_per_ip,
                            "connection rejected: rate limit exceeded"
                        );
                        drop(connection_permit);
                        continue;
                    }

                    // Increment per-IP connection count
                    let per_ip_count = {
                        let mut per_ip = self.connections_per_ip.write();
                        let entry = per_ip.entry(client_ip).or_insert(0);
                        *entry += 1;
                        *entry
                    };

                    // Update active connections and per-IP gauges (bounded cardinality)
                    let active_count =
                        self.config.max_connections - self.connection_semaphore.available_permits();
                    self.metrics.active_connections.set(active_count as i64);
                    self.metrics
                        .set_connections_for_ip(client_ip.to_string(), per_ip_count as i64);

                    info!(
                        event = "stratum_access_connect",
                        %correlation_id,
                        %remote_addr,
                        tls = self.tls_acceptor.is_some(),
                        active_connections = active_count,
                        "accepted new Stratum TCP client connection"
                    );

                    let tls_acceptor = self.tls_acceptor.clone();
                    let session = self.session_registry.create_session(self.config.difficulty);
                    {
                        self.active_sessions
                            .write()
                            .insert(session.session_id.clone(), Arc::clone(&session));
                    }
                    self.refresh_difficulty_metrics();
                    let vardiff_config = self.config.vardiff_config();
                    let gateway_jobs = Arc::clone(&self.job_manager);
                    let gateway_subscribers = Arc::clone(&self.active_subscribers);
                    let gateway_active_sessions = Arc::clone(&self.active_sessions);
                    let gateway_rpc = self.rpc_client.clone();
                    let gateway_self = Arc::new(self.clone());
                    let request_rate_limiter = Arc::new(RequestRateLimiter::new(
                        self.config.max_request_rate_per_connection,
                    ));
                    let connected_at = Instant::now();
                    let conn_span = info_span!(
                        "stratum_connection",
                        correlation_id = %correlation_id,
                        session_id = %session.session_id,
                        remote_addr = %remote_addr
                    );

                    info!(
                        event = "stratum_spawn_connection_handler",
                        %correlation_id,
                        %remote_addr,
                        "spawning connection handler task"
                    );
                    tokio::spawn(
                        async move {
                            // Perform TLS handshake inside the spawned task with a strict timeout
                            // so a stalling client never blocks the main accept loop (P0-B).
                            let upgraded_socket = if let Some(tls_acceptor) = tls_acceptor {
                                match tokio::time::timeout(
                                    STRATUM_TLS_HANDSHAKE_TIMEOUT,
                                    tls_acceptor.accept(socket),
                                )
                                .await
                                {
                                    Ok(Ok(tls_stream)) => {
                                        gateway_self.metrics.record_tls_handshake_success();
                                        debug!(%correlation_id, %remote_addr, "TLS handshake successful");
                                        Some(MaybeTlsStream::Tls(Box::new(tls_stream)))
                                    }
                                    Ok(Err(e)) => {
                                        gateway_self.metrics.record_tls_handshake_failure();
                                        warn!(
                                            event = "stratum_access_tls_error",
                                            %correlation_id,
                                            %remote_addr,
                                            %e,
                                            "TLS handshake failed"
                                        );
                                        None
                                    }
                                    Err(_) => {
                                        gateway_self.metrics.record_tls_handshake_failure();
                                        warn!(
                                            event = "stratum_access_tls_timeout",
                                            %correlation_id,
                                            %remote_addr,
                                            timeout_secs = STRATUM_TLS_HANDSHAKE_TIMEOUT.as_secs(),
                                            "TLS handshake timed out"
                                        );
                                        None
                                    }
                                }
                            } else {
                                Some(MaybeTlsStream::Plain(socket))
                            };

                            let session_for_log = Arc::clone(&session);
                            let result = if let Some(upgraded_socket) = upgraded_socket {
                                Self::handle_connection(
                                    upgraded_socket,
                                    remote_addr,
                                    session,
                                    gateway_jobs,
                                    gateway_subscribers,
                                    gateway_active_sessions,
                                    gateway_rpc,
                                    request_rate_limiter,
                                    gateway_self.metrics.clone(),
                                    vardiff_config,
                                    correlation_id.clone(),
                                )
                                .await
                            } else {
                                Ok(())
                            };

                            // Remove session from active difficulty tracking
                            {
                                gateway_self
                                    .active_sessions
                                    .write()
                                    .remove(&session_for_log.session_id);
                            }
                            gateway_self.refresh_difficulty_metrics();

                            // Decrement per-IP count on disconnect
                            let new_per_ip = {
                                let mut per_ip = gateway_self.connections_per_ip.write();
                                let remaining = if let Some(count) = per_ip.get_mut(&client_ip) {
                                    *count = count.saturating_sub(1);
                                    *count
                                } else {
                                    0
                                };
                                if remaining == 0 {
                                    per_ip.remove(&client_ip);
                                }
                                remaining
                            };
                            gateway_self
                                .metrics
                                .set_connections_for_ip(client_ip.to_string(), new_per_ip as i64);

                            // Release global semaphore permit and update active gauge
                            drop(connection_permit);
                            let new_active = gateway_self.config.max_connections
                                - gateway_self.connection_semaphore.available_permits();
                            gateway_self
                                .metrics
                                .active_connections
                                .set(new_active as i64);

                            let worker_name = session_for_log
                                .authorized_worker
                                .read()
                                .as_ref()
                                .map(|w| w.worker_name.clone())
                                .unwrap_or_else(|| "unauthorized".to_string());
                            info!(
                                event = "stratum_access_disconnect",
                                %correlation_id,
                                %remote_addr,
                                session_id = %session_for_log.session_id,
                                worker = %worker_name,
                                duration_ms = connected_at.elapsed().as_millis() as u64,
                                accepted_shares = session_for_log.accepted_shares.load(Ordering::Relaxed),
                                rejected_shares = session_for_log.rejected_shares.load(Ordering::Relaxed),
                                blocks_found = session_for_log.blocks_found.load(Ordering::Relaxed),
                                "Stratum client disconnected"
                            );

                            if let Err(e) = result {
                                debug!(%correlation_id, %remote_addr, %e, "Stratum client connection terminated with error");
                            }
                        }
                        .instrument(conn_span),
                    );
                }
                Err(e) => {
                    if self.shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    warn!(%e, "error accepting TCP connection");
                }
            }
        }

        Ok(())
    }

    /// Process a single miner's TCP session.
    #[allow(clippy::too_many_arguments)]
    async fn handle_connection(
        socket: MaybeTlsStream,
        remote_addr: SocketAddr,
        session: Arc<WorkerSession>,
        job_manager: Arc<JobManager>,
        active_subscribers: Arc<RwLock<HashMap<String, ClientSender>>>,
        active_sessions: Arc<RwLock<HashMap<String, Arc<WorkerSession>>>>,
        rpc_client: NodeRpcClient,
        request_rate_limiter: Arc<RequestRateLimiter>,
        metrics: GatewayMetrics,
        vardiff_config: VarDiffConfig,
        correlation_id: String,
    ) -> Result<()> {
        info!(
            event = "stratum_handle_connection_start",
            %correlation_id,
            %remote_addr,
            "handle_connection started"
        );
        let (reader, mut writer) = tokio::io::split(socket);
        let mut buf_reader = BufReader::new(reader);

        let (outbound_tx, mut outbound_rx) = mpsc::channel::<String>(CLIENT_OUTBOUND_CHANNEL_CAP);

        // Writer task
        let writer_handle = tokio::spawn(async move {
            while let Some(msg) = outbound_rx.recv().await {
                if let Err(e) = writer.write_all(msg.as_bytes()).await {
                    debug!(%e, "failed to write to miner socket");
                    break;
                }
                let _ = writer.flush().await;
            }
        });

        let mut line = String::new();
        let mut req_seq: u64 = 0;
        while read_bounded_line(&mut buf_reader, &mut line).await? > 0 {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                line.clear();
                continue;
            }

            req_seq += 1;
            let request_correlation_id = format!("{correlation_id}:{req_seq}");

            debug!(
                %request_correlation_id,
                %remote_addr,
                request = %trimmed,
                "inbound Stratum line"
            );
            let req = match StratumRequest::parse_line(trimmed) {
                Ok(r) => r,
                Err(e) => {
                    warn!(%remote_addr, %e, "malformed JSON-RPC request");
                    let resp =
                        StratumResponse::invalid_params(Value::Null, "Malformed JSON-RPC request");
                    let _ = outbound_tx.send(resp.to_wire_line()).await;
                    line.clear();
                    continue;
                }
            };

            let req_id = req.id.clone();

            // Check request rate limit
            if !request_rate_limiter.check() {
                metrics.request_rate_limit_hits.inc();
                warn!(%remote_addr, "request rate limit exceeded, closing connection");
                let resp = StratumResponse::error(req_id, 25, "Request rate limit exceeded");
                let _ = outbound_tx.send(resp.to_wire_line()).await;
                break;
            }
            match req.method.as_str() {
                // -------------------------------------------------------------
                // mining.subscribe
                // -------------------------------------------------------------
                "mining.subscribe" => {
                    // Register as active subscriber for broadcasts
                    {
                        let mut subs = active_subscribers.write();
                        subs.insert(session.session_id.clone(), outbound_tx.clone());
                    }

                    let sub_response = StratumResponse::ok(
                        req_id,
                        json!([
                            [
                                ["mining.set_difficulty", session.session_id.clone()],
                                ["mining.notify", session.session_id.clone()]
                            ],
                            session.extranonce1.clone(),
                            session.extranonce2_size,
                            {
                                "algorithm": KOVANICA_STRATUM_ALGORITHM,
                                "profile": KOVANICA_STRATUM_CAPABILITY,
                                "version": 1
                            }
                        ]),
                    );
                    let _ = outbound_tx.send(sub_response.to_wire_line()).await;
                }

                // -------------------------------------------------------------
                // mining.authorize
                // -------------------------------------------------------------
                "mining.authorize" => {
                    let params = req.params.as_array();
                    let username = params
                        .and_then(|arr| arr.first())
                        .and_then(Value::as_str)
                        .unwrap_or_default();

                    match parse_and_validate_username(username) {
                        Ok(authorized) => {
                            info!(
                                %remote_addr,
                                session_id = %session.session_id,
                                worker = %authorized.worker_name,
                                payout = %authorized.payout_address,
                                "worker authorized"
                            );
                            session.authorize(authorized);

                            // 1. Authorize response
                            let auth_resp = StratumResponse::ok(req_id, Value::Bool(true));
                            let _ = outbound_tx.send(auth_resp.to_wire_line()).await;

                            // 2. Set difficulty notification
                            let diff = session.get_difficulty();
                            let diff_notif = StratumNotification::set_difficulty(diff);
                            let _ = outbound_tx.send(diff_notif.to_wire_line()).await;

                            // 3. Immediately send active job notification if available
                            if let Some(job) = job_manager.get_current_job() {
                                let job_notif = StratumNotification::notify(
                                    &job.job_id,
                                    &job.prevhash,
                                    &job.coinb1_hex,
                                    "",
                                    &[],
                                    &format!("{:08x}", job.round),
                                    &format!("{:08x}", job.target_bits),
                                    &format!("{:08x}", job.header.timestamp),
                                    true,
                                );
                                let _ = outbound_tx.send(job_notif.to_wire_line()).await;
                            }
                        }
                        Err(err_msg) => {
                            warn!(%remote_addr, username, %err_msg, "worker authorization failed");
                            let auth_err = StratumResponse::unauthorized(req_id, &err_msg);
                            let _ = outbound_tx.send(auth_err.to_wire_line()).await;
                        }
                    }
                }

                // -------------------------------------------------------------
                // mining.submit
                // -------------------------------------------------------------
                "mining.submit" => {
                    // Track submitted shares
                    metrics.shares_submitted.inc();

                    // Track difficulty bucket
                    let diff_label = DifficultyBucketLabel {
                        bucket: difficulty_bucket_label(session.get_difficulty()),
                    };
                    metrics
                        .shares_by_difficulty_bucket
                        .get_or_create(&diff_label)
                        .inc();

                    if !session.is_authorized() {
                        metrics.record_share_rejected(ShareRejectReason::Unauthorized);
                        let err_resp = StratumResponse::unauthorized(
                            req_id,
                            "Unauthorized: please call mining.authorize first",
                        );
                        let _ = outbound_tx.send(err_resp.to_wire_line()).await;
                        line.clear();
                        continue;
                    }

                    let params = req.params.as_array().cloned().unwrap_or_default();
                    if params.len() < 4 {
                        metrics.record_share_rejected(ShareRejectReason::InvalidParams);
                        let err_resp = StratumResponse::invalid_params(
                            req_id,
                            "mining.submit requires at least [worker, job_id, extranonce2, nonce]",
                        );
                        let _ = outbound_tx.send(err_resp.to_wire_line()).await;
                        line.clear();
                        continue;
                    }

                    let Some(_worker_name) = params[0].as_str() else {
                        session.record_rejected_share();
                        metrics.record_share_rejected(ShareRejectReason::InvalidParams);
                        let _ = outbound_tx
                            .send(
                                StratumResponse::invalid_params(
                                    req_id,
                                    "worker name must be a string",
                                )
                                .to_wire_line(),
                            )
                            .await;
                        line.clear();
                        continue;
                    };
                    let Some(job_id) = params[1].as_str() else {
                        session.record_rejected_share();
                        metrics.record_share_rejected(ShareRejectReason::InvalidParams);
                        let _ = outbound_tx
                            .send(
                                StratumResponse::invalid_params(req_id, "job_id must be a string")
                                    .to_wire_line(),
                            )
                            .await;
                        line.clear();
                        continue;
                    };
                    let Some(extranonce2_raw) = params[2].as_str() else {
                        session.record_rejected_share();
                        metrics.record_share_rejected(ShareRejectReason::InvalidParams);
                        let _ = outbound_tx
                            .send(
                                StratumResponse::invalid_params(
                                    req_id,
                                    "extranonce2 must be a string",
                                )
                                .to_wire_line(),
                            )
                            .await;
                        line.clear();
                        continue;
                    };

                    // Validate extranonce2 format and length against session.extranonce2_size
                    let extranonce2 =
                        match validate_extranonce2(extranonce2_raw, session.extranonce2_size) {
                            Ok(normalized) => normalized,
                            Err(msg) => {
                                session.record_rejected_share();
                                metrics.record_share_rejected(ShareRejectReason::InvalidParams);
                                let _ = outbound_tx
                                    .send(
                                        StratumResponse::invalid_params(req_id, &msg)
                                            .to_wire_line(),
                                    )
                                    .await;
                                line.clear();
                                continue;
                            }
                        };

                    // Param layout can be 4 or 5 args:
                    // 4 args: [worker, job_id, extranonce2, nonce]
                    // 5 args: [worker, job_id, extranonce2, ntime, nonce]
                    let (ntime_opt, nonce_str) = if params.len() >= 5 {
                        let Some(ntime_raw) = params[3].as_str() else {
                            session.record_rejected_share();
                            metrics.record_share_rejected(ShareRejectReason::InvalidParams);
                            let _ = outbound_tx
                                .send(
                                    StratumResponse::invalid_params(
                                        req_id,
                                        "ntime must be a string",
                                    )
                                    .to_wire_line(),
                                )
                                .await;
                            line.clear();
                            continue;
                        };
                        if let Err(msg) = parse_ntime_hex(ntime_raw) {
                            session.record_rejected_share();
                            metrics.record_share_rejected(ShareRejectReason::InvalidParams);
                            let _ = outbound_tx
                                .send(StratumResponse::invalid_params(req_id, &msg).to_wire_line())
                                .await;
                            line.clear();
                            continue;
                        }
                        let Some(nonce_raw) = params[4].as_str() else {
                            session.record_rejected_share();
                            metrics.record_share_rejected(ShareRejectReason::InvalidParams);
                            let _ = outbound_tx
                                .send(
                                    StratumResponse::invalid_params(
                                        req_id,
                                        "nonce must be a string",
                                    )
                                    .to_wire_line(),
                                )
                                .await;
                            line.clear();
                            continue;
                        };
                        (Some(ntime_raw), nonce_raw)
                    } else {
                        let Some(nonce_raw) = params[3].as_str() else {
                            session.record_rejected_share();
                            metrics.record_share_rejected(ShareRejectReason::InvalidParams);
                            let _ = outbound_tx
                                .send(
                                    StratumResponse::invalid_params(
                                        req_id,
                                        "nonce must be a string",
                                    )
                                    .to_wire_line(),
                                )
                                .await;
                            line.clear();
                            continue;
                        };
                        (None, nonce_raw)
                    };

                    let job = match job_manager.get_job(job_id) {
                        Some(j) => j,
                        None => {
                            session.record_rejected_share();
                            metrics.record_share_rejected(ShareRejectReason::Stale);
                            let _ = outbound_tx
                                .send(StratumResponse::job_not_found(req_id).to_wire_line())
                                .await;
                            line.clear();
                            continue;
                        }
                    };

                    // Validate ntime bounds relative to the job's template timestamp
                    if let Some(ntime_raw) = ntime_opt {
                        if let Err(msg) = validate_ntime(ntime_raw, job.header.timestamp) {
                            session.record_rejected_share();
                            metrics.record_share_rejected(ShareRejectReason::InvalidParams);
                            let _ = outbound_tx
                                .send(StratumResponse::invalid_params(req_id, &msg).to_wire_line())
                                .await;
                            line.clear();
                            continue;
                        }
                    }

                    // Parse nonce
                    let nonce = if nonce_str.len() <= 8 {
                        let nonce_u32 =
                            match u32::from_str_radix(nonce_str.trim_start_matches("0x"), 16) {
                                Ok(n) => n,
                                Err(_) => {
                                    session.record_rejected_share();
                                    metrics.record_share_rejected(ShareRejectReason::InvalidParams);
                                    let _ = outbound_tx
                                        .send(
                                            StratumResponse::invalid_params(
                                                req_id,
                                                "invalid hex nonce",
                                            )
                                            .to_wire_line(),
                                        )
                                        .await;
                                    line.clear();
                                    continue;
                                }
                            };
                        let en2_u32 = u32::from_str_radix(&extranonce2, 16).unwrap_or(0);
                        ((en2_u32 as u64) << 32) | (nonce_u32 as u64)
                    } else {
                        match u64::from_str_radix(nonce_str.trim_start_matches("0x"), 16) {
                            Ok(n) => n,
                            Err(_) => {
                                session.record_rejected_share();
                                metrics.record_share_rejected(ShareRejectReason::InvalidParams);
                                let _ = outbound_tx
                                    .send(
                                        StratumResponse::invalid_params(
                                            req_id,
                                            "invalid hex nonce",
                                        )
                                        .to_wire_line(),
                                    )
                                    .await;
                                line.clear();
                                continue;
                            }
                        }
                    };

                    // Check duplicate share
                    if session.check_and_record_share(job_id, &extranonce2, nonce) {
                        session.record_rejected_share();
                        metrics.record_share_rejected(ShareRejectReason::Duplicate);
                        let _ = outbound_tx
                            .send(StratumResponse::duplicate_share(req_id).to_wire_line())
                            .await;
                        line.clear();
                        continue;
                    }

                    // Reconstruct header with session payout
                    let payout = session.payout_address();
                    let mut candidate_header = job.reconstruct_header(nonce, payout);
                    let preimage = candidate_header.preimage();
                    let pow_hash =
                        tokio::task::spawn_blocking(move || compute_pow_hash_reusable(&preimage))
                            .await
                            .unwrap_or_else(|_| candidate_header.compute_pow_hash());

                    // Check share difficulty target
                    let current_diff = session.get_difficulty();
                    let meets_share = check_share_hash_meets_difficulty(&pow_hash, current_diff);

                    if !meets_share {
                        session.record_rejected_share();
                        metrics.record_share_rejected(ShareRejectReason::LowDifficulty);
                        debug!(
                            %remote_addr,
                            job_id,
                            nonce,
                            pow_hash = %pow_hash,
                            difficulty = current_diff,
                            "low difficulty share rejected"
                        );
                        let _ = outbound_tx
                            .send(StratumResponse::low_difficulty_share(req_id).to_wire_line())
                            .await;
                        line.clear();
                        continue;
                    }

                    // Valid share!
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    session.record_share_timestamp_with_window(
                        now,
                        vardiff_config.retarget_interval_secs,
                    );
                    session.record_accepted_share();
                    metrics.shares_accepted.inc();
                    let _ = outbound_tx
                        .send(StratumResponse::ok(req_id, Value::Bool(true)).to_wire_line())
                        .await;

                    // Update worker hashrate metric
                    let hashrate = session.estimated_hashrate();
                    if let Some(worker) = session.authorized_worker.read().as_ref() {
                        metrics.set_worker_hashrate(worker.worker_name.clone(), hashrate as i64);
                    }

                    // Check for bounded per-worker VarDiff retarget
                    if vardiff_config.enabled {
                        if let Some(new_diff) =
                            session.maybe_retarget_difficulty_with_config(&vardiff_config, now)
                        {
                            info!(
                                %remote_addr,
                                session_id = %session.session_id,
                                old_diff = current_diff,
                                new_diff = new_diff,
                                "retargeting share difficulty via VarDiff"
                            );
                            metrics.record_vardiff_retarget(current_diff, new_diff);
                            Self::refresh_difficulty_metrics_from(&active_sessions, &metrics);
                            let diff_notif = StratumNotification::set_difficulty(new_diff);
                            let _ = outbound_tx.send(diff_notif.to_wire_line()).await;
                        }
                    }

                    // Check if solution also meets full network target
                    if check_network_solution(&pow_hash, candidate_header.target_bits) {
                        session.record_block_found();
                        metrics.blocks_found.inc();
                        candidate_header.pow_hash = Some(pow_hash);

                        info!(
                            %remote_addr,
                            round = candidate_header.round,
                            nonce = candidate_header.nonce,
                            pow_hash = %pow_hash,
                            target_bits = format!("0x{:08x}", candidate_header.target_bits),
                            "VALID NETWORK BLOCK FOUND! Submitting upstream to kovanica_submitWork"
                        );

                        metrics.blocks_submitted.inc();
                        let upstream_rpc = rpc_client.clone();
                        let metrics_clone = metrics.clone();
                        let block_corr_id = request_correlation_id.clone();
                        tokio::spawn(async move {
                            let submit_start = Instant::now();
                            match upstream_rpc.submit_work(&candidate_header).await {
                                Ok(true) => {
                                    metrics_clone
                                        .rpc_submitwork_latency
                                        .observe(submit_start.elapsed().as_secs_f64());
                                    metrics_clone.blocks_accepted.inc();
                                    info!(
                                        correlation_id = %block_corr_id,
                                        round = candidate_header.round,
                                        "block ACCEPTED by upstream node!"
                                    );
                                }
                                Ok(false) => {
                                    metrics_clone
                                        .rpc_submitwork_latency
                                        .observe(submit_start.elapsed().as_secs_f64());
                                    metrics_clone.blocks_rejected.inc();
                                    warn!(
                                        correlation_id = %block_corr_id,
                                        round = candidate_header.round,
                                        "block REJECTED by upstream node"
                                    );
                                }
                                Err(e) => {
                                    metrics_clone
                                        .rpc_submitwork_latency
                                        .observe(submit_start.elapsed().as_secs_f64());
                                    metrics_clone.blocks_rejected.inc();
                                    metrics_clone.rpc_submitwork_errors.inc();
                                    error!(
                                        correlation_id = %block_corr_id,
                                        round = candidate_header.round,
                                        %e,
                                        "upstream kovanica_submitWork RPC failed"
                                    );
                                }
                            }
                        });
                    }
                }

                // -------------------------------------------------------------
                // mining.extranonce.subscribe
                // -------------------------------------------------------------
                "mining.extranonce.subscribe" => {
                    let _ = outbound_tx
                        .send(StratumResponse::ok(req_id, Value::Bool(true)).to_wire_line())
                        .await;
                }

                // -------------------------------------------------------------
                // mining.suggest_difficulty / mining.suggest_target
                // -------------------------------------------------------------
                "mining.suggest_difficulty" => {
                    if let Some(diff) = req
                        .params
                        .as_array()
                        .and_then(|a| a.first())
                        .and_then(Value::as_f64)
                    {
                        if diff.is_finite() && diff > 0.0 {
                            let applied = if vardiff_config.enabled {
                                session.set_difficulty_bounded(
                                    diff,
                                    vardiff_config.min_difficulty,
                                    vardiff_config.max_difficulty,
                                )
                            } else {
                                session.set_difficulty(diff);
                                Some(session.get_difficulty())
                            };
                            if let Some(applied_diff) = applied {
                                Self::refresh_difficulty_metrics_from(&active_sessions, &metrics);
                                let notif = StratumNotification::set_difficulty(applied_diff);
                                let _ = outbound_tx.send(notif.to_wire_line()).await;
                            }
                        }
                    }
                    let _ = outbound_tx
                        .send(StratumResponse::ok(req_id, Value::Bool(true)).to_wire_line())
                        .await;
                }

                // -------------------------------------------------------------
                // mining.ping
                // -------------------------------------------------------------
                "mining.ping" => {
                    let _ = outbound_tx
                        .send(StratumResponse::ok(req_id, json!("pong")).to_wire_line())
                        .await;
                }

                other => {
                    debug!(method = other, "unrecognized Stratum method");
                    let _ = outbound_tx
                        .send(
                            StratumResponse::error(
                                req_id,
                                20,
                                &format!("Method '{other}' not supported"),
                            )
                            .to_wire_line(),
                        )
                        .await;
                }
            }

            line.clear();
        }

        // Clean up subscriber on disconnect
        {
            let mut subs = active_subscribers.write();
            subs.remove(&session.session_id);
        }
        writer_handle.abort();

        Ok(())
    }

    /// Build TLS acceptor from configuration.
    fn build_tls_acceptor(config: &StratumConfig) -> Result<TlsAcceptor> {
        let cert_path = config
            .tls_cert
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("TLS cert path required"))?;
        let key_path = config
            .tls_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("TLS key path required"))?;

        let cert_data = std::fs::read(cert_path)
            .context(format!("failed to read TLS cert: {}", cert_path.display()))?;
        let key_data = std::fs::read(key_path)
            .context(format!("failed to read TLS key: {}", key_path.display()))?;

        let certs = parse_many(&cert_data)?
            .into_iter()
            .filter_map(|p| {
                if p.tag() == "CERTIFICATE" {
                    Some(CertificateDer::from(p.contents().to_vec()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let keys = parse_many(&key_data)?
            .into_iter()
            .filter_map(|p| {
                if p.tag() == "PRIVATE KEY"
                    || p.tag() == "RSA PRIVATE KEY"
                    || p.tag() == "EC PRIVATE KEY"
                {
                    // Try to parse as PKCS#8 first
                    use rustls::pki_types::PrivateKeyDer;
                    PrivateKeyDer::try_from(p.contents().to_vec()).ok()
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if certs.is_empty() {
            anyhow::bail!("no valid certificates found in {}", cert_path.display());
        }
        if keys.is_empty() {
            anyhow::bail!("no valid private keys found in {}", key_path.display());
        }

        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, keys.into_iter().next().unwrap())
            .map_err(|e| anyhow::anyhow!("failed to build TLS config: {}", e))?;

        config.alpn_protocols = vec![b"stratum".to_vec()];

        Ok(TlsAcceptor::from(Arc::new(config)))
    }

    /// Generate a self-signed TLS certificate for testing (requires "self-signed" feature).
    #[cfg(feature = "self-signed")]
    pub fn generate_self_signed_cert() -> Result<(Vec<u8>, Vec<u8>)> {
        use rcgen::{generate_simple_self_signed, CertifiedKey};

        let CertifiedKey { cert, key_pair } = generate_simple_self_signed(vec![
            "localhost".to_string(),
            "kovanica-stratum".to_string(),
        ])?;

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        Ok((cert_pem.into_bytes(), key_pem.into_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_difficulty_bucket_label_bounds() {
        assert_eq!(difficulty_bucket_label(0.0), "<1");
        assert_eq!(difficulty_bucket_label(0.5), "<1");
        assert_eq!(difficulty_bucket_label(1.0), "1");
        assert_eq!(difficulty_bucket_label(1.9), "1");
        assert_eq!(difficulty_bucket_label(2.0), "2");
        assert_eq!(difficulty_bucket_label(15.9), "8");
        assert_eq!(difficulty_bucket_label(1024.0), "1024+");
        assert_eq!(difficulty_bucket_label(1_000_000.0), "1024+");
    }

    #[test]
    fn test_prometheus_metrics_exposition_names() {
        let mut registry = Registry::default();
        let metrics = GatewayMetrics::new(&mut registry);

        metrics.active_connections.set(3);
        metrics
            .connections_per_ip
            .get_or_create(&IpLabel {
                ip: "127.0.0.1".to_string(),
            })
            .set(2);
        metrics.shares_submitted.inc();
        metrics.shares_accepted.inc();
        metrics.record_share_rejected(ShareRejectReason::Stale);
        metrics.record_share_rejected(ShareRejectReason::Duplicate);
        metrics.record_vardiff_retarget(1.0, 2.0);
        metrics.record_vardiff_retarget(2.0, 1.0);
        metrics.set_worker_difficulty_stats(0.5, 4.0, 2.25);
        metrics.record_tls_handshake_success();
        metrics.record_tls_handshake_failure();
        metrics
            .shares_by_difficulty_bucket
            .get_or_create(&DifficultyBucketLabel { bucket: "1" })
            .inc();
        metrics
            .worker_hashrate
            .get_or_create(&WorkerLabel {
                worker: "rig1".to_string(),
            })
            .set(4200);
        metrics.rpc_getwork_latency.observe(0.012);
        metrics.rpc_submitwork_latency.observe(0.025);
        metrics.job_broadcast_latency.observe(0.0005);

        let mut encoded = String::new();
        encode(&mut encoded, &registry).expect("metrics encoding must succeed");

        assert!(encoded.contains("stratum_active_connections 3"));
        assert!(encoded.contains("stratum_connections_per_ip{ip=\"127.0.0.1\"} 2"));
        assert!(encoded.contains("stratum_shares_submitted_total 1"));
        assert!(encoded.contains("stratum_shares_accepted_total 1"));
        assert!(encoded.contains("stratum_shares_rejected_total 2"));
        assert!(encoded.contains("stratum_shares_rejected_by_reason_total{reason=\"stale\"} 1"));
        assert!(encoded.contains("stratum_shares_rejected_by_reason_total{reason=\"duplicate\"} 1"));
        assert!(encoded
            .contains("stratum_shares_rejected_by_reason_total{reason=\"invalid_params\"} 0"));
        assert!(encoded
            .contains("stratum_shares_rejected_by_reason_total{reason=\"low_difficulty\"} 0"));
        assert!(
            encoded.contains("stratum_shares_rejected_by_reason_total{reason=\"unauthorized\"} 0")
        );
        assert!(encoded.contains("stratum_vardiff_retargets_total 2"));
        assert!(
            encoded.contains("stratum_vardiff_retargets_by_direction_total{direction=\"up\"} 1")
        );
        assert!(
            encoded.contains("stratum_vardiff_retargets_by_direction_total{direction=\"down\"} 1")
        );
        assert!(encoded.contains("stratum_worker_difficulty_min 0.5"));
        assert!(encoded.contains("stratum_worker_difficulty_max 4.0"));
        assert!(encoded.contains("stratum_worker_difficulty_avg 2.25"));
        assert!(encoded.contains("stratum_tls_handshakes_total{result=\"success\"} 1"));
        assert!(encoded.contains("stratum_tls_handshakes_total{result=\"failure\"} 1"));
        assert!(encoded.contains("stratum_shares_by_difficulty_bucket_total{bucket=\"1\"} 1"));
        assert!(encoded.contains("stratum_worker_hashrate{worker=\"rig1\"} 4200"));
        assert!(encoded.contains("stratum_rpc_getwork_latency_seconds_count 1"));
        assert!(encoded.contains("stratum_rpc_submitwork_latency_seconds_count 1"));
        assert!(encoded.contains("stratum_job_broadcast_latency_seconds_count 1"));
        assert!(
            !encoded.contains("_total_total"),
            "counter names must not have duplicated _total suffix"
        );
    }

    #[test]
    fn test_validate_extranonce2_valid_cases() {
        assert_eq!(validate_extranonce2("00000001", 4).unwrap(), "00000001");
        assert_eq!(validate_extranonce2("DEADBEEF", 4).unwrap(), "deadbeef");
        assert_eq!(validate_extranonce2("a1b2", 2).unwrap(), "a1b2");
        assert_eq!(
            validate_extranonce2("0123456789abcdef", 8).unwrap(),
            "0123456789abcdef"
        );
    }

    #[test]
    fn test_validate_extranonce2_invalid_cases() {
        // Empty / wrong length / oversized
        assert!(validate_extranonce2("", 4).is_err());
        assert!(validate_extranonce2("000001", 4).is_err());
        assert!(validate_extranonce2("0000000001", 4).is_err());
        assert!(validate_extranonce2(&"a".repeat(256), 4).is_err());
        // Non-hex / prefixed
        assert!(validate_extranonce2("0000000g", 4).is_err());
        assert!(validate_extranonce2("0x000001", 4).is_err());
        assert!(validate_extranonce2("0000 001", 4).is_err());
        // Zero configured size
        assert!(validate_extranonce2("", 0).is_err());
    }

    #[test]
    fn test_validate_ntime_valid_cases_millis_and_secs() {
        // Millisecond timestamp (Kovanica native)
        let job_ts_ms: u64 = 1_731_800_000_000;
        assert_eq!(
            validate_ntime(&format!("{job_ts_ms:08x}"), job_ts_ms).unwrap(),
            job_ts_ms
        );
        // Uppercase hex accepted
        assert_eq!(
            validate_ntime(&format!("{job_ts_ms:08X}"), job_ts_ms).unwrap(),
            job_ts_ms
        );
        // Forward drift within bound
        let rolled_ms = job_ts_ms + 60_000;
        assert_eq!(
            validate_ntime(&format!("{rolled_ms:08x}"), job_ts_ms).unwrap(),
            rolled_ms
        );
        // Exact upper bound
        let max_ms = job_ts_ms + MAX_NTIME_DRIFT_MS;
        assert_eq!(
            validate_ntime(&format!("{max_ms:08x}"), job_ts_ms).unwrap(),
            max_ms
        );

        // Second timestamp (standard Stratum V1)
        let job_ts_s: u64 = 1_731_800_000;
        assert_eq!(
            validate_ntime(&format!("{job_ts_s:08x}"), job_ts_s).unwrap(),
            job_ts_s
        );
        let max_s = job_ts_s + MAX_NTIME_DRIFT_SECS;
        assert_eq!(
            validate_ntime(&format!("{max_s:08x}"), job_ts_s).unwrap(),
            max_s
        );
    }

    #[test]
    fn test_validate_ntime_invalid_cases() {
        let job_ts_ms: u64 = 1_731_800_000_000;
        // Malformed / wrong length / non-hex / 0x prefix
        assert!(validate_ntime("", job_ts_ms).is_err());
        assert!(validate_ntime("1234", job_ts_ms).is_err());
        assert!(validate_ntime("00000000000000001", job_ts_ms).is_err());
        assert!(validate_ntime("zzzzzzzz", job_ts_ms).is_err());
        assert!(validate_ntime("0x673a5f20", job_ts_ms).is_err());
        // Zero / before job timestamp
        assert!(validate_ntime("00000000", job_ts_ms).is_err());
        assert!(validate_ntime(&format!("{:08x}", job_ts_ms - 1), job_ts_ms).is_err());
        // Beyond max forward drift
        assert!(validate_ntime(
            &format!("{:08x}", job_ts_ms + MAX_NTIME_DRIFT_MS + 1),
            job_ts_ms
        )
        .is_err());

        // Seconds timestamp bounds
        let job_ts_s: u64 = 1_731_800_000;
        assert!(validate_ntime(&format!("{:08x}", job_ts_s - 1), job_ts_s).is_err());
        assert!(validate_ntime(
            &format!("{:08x}", job_ts_s + MAX_NTIME_DRIFT_SECS + 1),
            job_ts_s
        )
        .is_err());
    }
}
