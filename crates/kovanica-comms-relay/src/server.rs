//! Relay HTTP API v1. Spec moved to KovanicaDAG/kovanica-apps (Comms); removed from kovanica-l1 in #247 (former M1 §4).
//!
//! axum 0.7 server exposing exactly:
//!
//! | Method | Path | Success | Errors |
//! |---|---|---|---|
//! | POST | `/v1/envelope` | `201 {"ok":true,"id":"<hex>"}` | `400`,`413`,`429` |
//! | GET  | `/v1/inbox/{comms_id}` | `200 {"envelopes":[…]}` | `400` |
//! | POST | `/v1/ack` | `200 {"ok":true,"deleted":<n>}` | `400`,`401` |
//! | GET  | `/v1/health` | `200 {"ok":true,"version":…,"envelopes":<n>}` | — |
//! | GET  | `/metrics` | `200` OpenMetrics 1.0 text exposition | — |
//!
//! Errors are `{"error":{"code":"<slug>","message":"…"}}` with slugs
//! `bad_request`, `unauthorized`, `too_large`, `not_found`, `rate_limited`, `internal`.
//! **GET never deletes** — deletion is only via `/v1/ack`.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ed25519_dalek::{Signature, VerifyingKey};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::envelope::{Envelope, MAX_CT, MAX_ENVELOPE_JSON};
use crate::store::{Store, StoreError, StoreStats, DEFAULT_INBOX_LIMIT, MAX_INBOX_LIMIT};
use crate::{
    ack_signing_bytes, comms_id_bytes, comms_id_from_hex, now_ms, pow_verify, SubmissionWrapper,
};

/// OpenMetrics 1.0 `Content-Type` header value returned by `GET /metrics`.
pub const OPENMETRICS_CONTENT_TYPE: &str =
    "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// How often the background task sweeps expired envelopes.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Error slugs (`error.code`) used by §4.
pub mod slug {
    pub const BAD_REQUEST: &str = "bad_request";
    pub const UNAUTHORIZED: &str = "unauthorized";
    pub const TOO_LARGE: &str = "too_large";
    pub const NOT_FOUND: &str = "not_found";
    pub const RATE_LIMITED: &str = "rate_limited";
    pub const INTERNAL: &str = "internal";
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
}

#[derive(Debug, Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

fn error_response(status: StatusCode, code: &'static str, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorEnvelope {
            error: ErrorBody {
                code,
                message: message.into(),
            },
        }),
    )
        .into_response()
}

fn bad_request(message: impl Into<String>) -> Response {
    error_response(StatusCode::BAD_REQUEST, slug::BAD_REQUEST, message)
}

fn unauthorized(message: impl Into<String>) -> Response {
    error_response(StatusCode::UNAUTHORIZED, slug::UNAUTHORIZED, message)
}

fn too_large(message: impl Into<String>) -> Response {
    error_response(StatusCode::PAYLOAD_TOO_LARGE, slug::TOO_LARGE, message)
}

fn rate_limited() -> Response {
    error_response(
        StatusCode::TOO_MANY_REQUESTS,
        slug::RATE_LIMITED,
        "recipient quota exceeded",
    )
}

#[derive(Debug, Serialize)]
struct PostEnvelopeResponse {
    ok: bool,
    id: String,
}

/// LRU entry for PoW replay (id, nonce)
#[derive(Clone, Debug)]
struct PowSeen {
    id: String,
    nonce: String,
    expires_at: u64,
}

#[derive(Debug, Default)]
struct RelayMetrics {
    /// Envelope submissions rejected with 400/413 before reaching the store.
    envelopes_rejected_total: AtomicU64,
    /// Envelope submissions rejected with 429 at the HTTP layer (unpaid or PoW replay).
    /// Store-level quota rejections are tracked in `StoreStats::envelopes_quota_rejected_total`.
    http_rate_limited_total: AtomicU64,
    /// Valid `GET /v1/inbox/{comms_id}` requests served.
    inbox_requests_total: AtomicU64,
    /// `POST /v1/ack` requests rejected with 400 or 401.
    ack_rejected_total: AtomicU64,
}

impl RelayMetrics {
    fn inc_rejected(&self) {
        self.envelopes_rejected_total
            .fetch_add(1, Ordering::Relaxed);
    }

    fn inc_http_rate_limited(&self) {
        self.http_rate_limited_total.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_inbox_requests(&self) {
        self.inbox_requests_total.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_ack_rejected(&self) {
        self.ack_rejected_total.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Debug)]
struct AppState {
    store: Arc<Store>,
    pow_seen: Arc<Mutex<VecDeque<PowSeen>>>,
    metrics: Arc<RelayMetrics>,
    started_at: Instant,
}

fn pow_ttl_ms() -> u64 {
    std::env::var("KOVANICA_RELAY_POW_TTL_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(600_000)
}

fn pow_bits_required() -> u8 {
    std::env::var("KOVANICA_RELAY_POW_BITS")
        .ok()
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(20)
}

fn allow_unpaid() -> bool {
    std::env::var("KOVANICA_RELAY_ALLOW_UNPAID")
        .ok()
        .and_then(|v| {
            let s = v.trim().to_ascii_lowercase();
            match s.as_str() {
                "true" | "1" | "yes" | "y" => Some(true),
                "false" | "0" | "no" | "n" => Some(false),
                _ => None,
            }
        })
        .unwrap_or(false)
}

fn now_ms_u64() -> u64 {
    now_ms()
}

/// `POST /v1/envelope` — validate and store an opaque envelope.
async fn post_envelope(State(state): State<AppState>, body: Bytes) -> Response {
    if body.len() > MAX_ENVELOPE_JSON {
        state.metrics.inc_rejected();
        return too_large(format!("envelope json exceeds {MAX_ENVELOPE_JSON} bytes"));
    }

    // Try to deserialize wrapper first, else bare envelope
    let (envelope, pow_opt, payment_opt) = match serde_json::from_slice::<SubmissionWrapper>(&body)
    {
        Ok(w) => (w.envelope, w.pow, w.payment),
        Err(_) => match Envelope::from_json(&body) {
            Ok(envelope) => (envelope, None, None),
            Err(e) => {
                state.metrics.inc_rejected();
                return bad_request(format!("malformed envelope: {e}"));
            }
        },
    };

    if let Err(e) = envelope.validate_shape() {
        state.metrics.inc_rejected();
        return bad_request(format!("invalid envelope: {e}"));
    }
    if envelope.ct.len() > MAX_CT {
        state.metrics.inc_rejected();
        return too_large(format!("ct exceeds {MAX_CT} bytes"));
    }
    let env_id = match envelope.compute_id() {
        Ok(id) => id,
        Err(e) => {
            state.metrics.inc_rejected();
            return bad_request(format!("invalid envelope: {e}"));
        }
    };
    if env_id != envelope.id {
        state.metrics.inc_rejected();
        return bad_request("envelope id does not match its contents");
    }

    let now = now_ms_u64();
    let mut admitted = false;

    // PoW handling
    let pow_ttl = pow_ttl_ms();
    let req_bits = pow_bits_required();
    if let Some(ref p) = pow_opt {
        if p.bits < req_bits {
            state.metrics.inc_rejected();
            return bad_request(format!(
                "insufficient pow bits: required {req_bits}, got {}",
                p.bits
            ));
        }
        {
            let mut seen = state.pow_seen.lock();
            seen.retain(|s| s.expires_at > now);
            // check replay
            let mut replay = false;
            for s in seen.iter() {
                if s.id == env_id && s.nonce == p.nonce {
                    replay = true;
                    break;
                }
            }
            if replay {
                state.metrics.inc_http_rate_limited();
                return rate_limited();
            }
            if pow_verify(&env_id, &p.nonce, p.bits) {
                seen.push_back(PowSeen {
                    id: env_id.clone(),
                    nonce: p.nonce.clone(),
                    expires_at: now + pow_ttl,
                });
                if seen.len() > 10000 {
                    seen.pop_front();
                }
                admitted = true;
            } else {
                state.metrics.inc_rejected();
                return bad_request("invalid pow");
            }
        }
    }

    // Payment handling — unverified off-chain HTLC credit minting is disabled
    // until on-chain RPC verification is enabled.
    if payment_opt.is_some() {
        state.metrics.inc_rejected();
        return bad_request(
            "unverified off-chain HTLC payment disabled until on-chain RPC verification is enabled",
        );
    }

    // If no PoW provided, check allow_unpaid (defaults to false).
    if !admitted && !allow_unpaid() {
        state.metrics.inc_http_rate_limited();
        return rate_limited();
    }

    let id_res = envelope.id.clone();
    match state.store.insert(envelope, now) {
        Ok(_outcome) => (
            StatusCode::CREATED,
            Json(PostEnvelopeResponse {
                ok: true,
                id: id_res,
            }),
        )
            .into_response(),
        Err(StoreError::RateLimited) => rate_limited(),
    }
}

#[derive(Debug, Deserialize)]
struct InboxQuery {
    limit: Option<usize>,
    since: Option<u64>,
}

#[derive(Debug, Serialize)]
struct InboxResponse {
    envelopes: Vec<Envelope>,
}

/// `GET /v1/inbox/{comms_id}` — undelivered envelopes, oldest first. Never deletes.
async fn get_inbox(
    State(state): State<AppState>,
    Path(comms_id): Path<String>,
    Query(query): Query<InboxQuery>,
) -> Response {
    if comms_id_from_hex(&comms_id).is_err() {
        return bad_request("invalid comms id");
    }
    let limit = query
        .limit
        .unwrap_or(DEFAULT_INBOX_LIMIT)
        .min(MAX_INBOX_LIMIT);
    let envelopes = state.store.inbox(&comms_id, limit, query.since, now_ms());
    state.metrics.inc_inbox_requests();
    (StatusCode::OK, Json(InboxResponse { envelopes })).into_response()
}

#[derive(Debug, Deserialize)]
struct AckRequest {
    to: String,
    ids: Vec<String>,
    #[serde(default)]
    pubkey: Option<String>,
    #[serde(default)]
    signature: Option<String>,
}

#[derive(Debug, Serialize)]
struct AckResponse {
    ok: bool,
    deleted: usize,
}

/// `POST /v1/ack` — the only delete path. Requires a valid Ed25519 recipient
/// signature over `ack_signing_bytes(to, ids)` from the public key matching `to`.
async fn post_ack(State(state): State<AppState>, Json(req): Json<AckRequest>) -> Response {
    let to_bytes = match comms_id_from_hex(&req.to) {
        Ok(b) => b,
        Err(_) => {
            state.metrics.inc_ack_rejected();
            return bad_request("invalid comms id");
        }
    };
    for id in &req.ids {
        if !is_lower_hex64(id) {
            state.metrics.inc_ack_rejected();
            return bad_request("invalid envelope id");
        }
    }

    let (Some(pubkey_hex), Some(sig_hex)) = (&req.pubkey, &req.signature) else {
        state.metrics.inc_ack_rejected();
        return unauthorized("missing ack pubkey or signature");
    };
    let pubkey_bytes: [u8; 32] = match hex::decode(pubkey_hex).ok().and_then(|v| v.try_into().ok())
    {
        Some(b) => b,
        None => {
            state.metrics.inc_ack_rejected();
            return unauthorized("invalid ack pubkey");
        }
    };
    if comms_id_bytes(&pubkey_bytes) != to_bytes {
        state.metrics.inc_ack_rejected();
        return unauthorized("ack pubkey does not match recipient comms id");
    }
    let sig_bytes: [u8; 64] = match hex::decode(sig_hex).ok().and_then(|v| v.try_into().ok()) {
        Some(b) => b,
        None => {
            state.metrics.inc_ack_rejected();
            return unauthorized("invalid ack signature");
        }
    };
    let verifying_key = match VerifyingKey::from_bytes(&pubkey_bytes) {
        Ok(k) => k,
        Err(_) => {
            state.metrics.inc_ack_rejected();
            return unauthorized("invalid ack pubkey");
        }
    };
    let signature = Signature::from_bytes(&sig_bytes);
    let msg = ack_signing_bytes(&req.to, &req.ids);
    if verifying_key.verify_strict(&msg, &signature).is_err() {
        state.metrics.inc_ack_rejected();
        return unauthorized("invalid ack signature");
    }

    let deleted = state.store.ack(&req.to, &req.ids);
    (StatusCode::OK, Json(AckResponse { ok: true, deleted })).into_response()
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    ok: bool,
    version: &'static str,
    envelopes: usize,
}

/// `GET /v1/health`.
async fn get_health(State(state): State<AppState>) -> Response {
    (
        StatusCode::OK,
        Json(HealthResponse {
            ok: true,
            version: env!("CARGO_PKG_VERSION"),
            envelopes: state.store.len(),
        }),
    )
        .into_response()
}

/// Render relay telemetry in OpenMetrics 1.0 text exposition format.
///
/// Only aggregate counts and queue depth gauges are ever emitted; envelope
/// payloads, recipient comms IDs, envelope IDs, and credentials are never
/// included.
fn render_openmetrics(store: &StoreStats, http: &RelayMetrics, uptime_seconds: u64) -> String {
    let rate_limited_total = http
        .http_rate_limited_total
        .load(Ordering::Relaxed)
        .saturating_add(store.envelopes_quota_rejected_total);
    let rejected_total = http.envelopes_rejected_total.load(Ordering::Relaxed);
    let inbox_requests_total = http.inbox_requests_total.load(Ordering::Relaxed);
    let ack_rejected_total = http.ack_rejected_total.load(Ordering::Relaxed);

    let mut out = String::with_capacity(2048);
    let _ = writeln!(
        out,
        "# HELP kovanica_comms_relay_envelopes_queued Current number of queued undelivered envelopes across all mailboxes.\n\
         # TYPE kovanica_comms_relay_envelopes_queued gauge\n\
         kovanica_comms_relay_envelopes_queued {}\n\
         # HELP kovanica_comms_relay_active_mailboxes Current number of mailboxes holding at least one queued envelope.\n\
         # TYPE kovanica_comms_relay_active_mailboxes gauge\n\
         kovanica_comms_relay_active_mailboxes {}\n\
         # HELP kovanica_comms_relay_max_mailbox_depth Current maximum queued envelope depth of any single mailbox.\n\
         # TYPE kovanica_comms_relay_max_mailbox_depth gauge\n\
         kovanica_comms_relay_max_mailbox_depth {}\n\
         # HELP kovanica_comms_relay_uptime_seconds Seconds elapsed since the relay HTTP router started.\n\
         # TYPE kovanica_comms_relay_uptime_seconds gauge\n\
         kovanica_comms_relay_uptime_seconds {}\n\
         # HELP kovanica_comms_relay_envelopes_accepted Total unique envelopes accepted into the relay store.\n\
         # TYPE kovanica_comms_relay_envelopes_accepted counter\n\
         kovanica_comms_relay_envelopes_accepted_total {}\n\
         # HELP kovanica_comms_relay_envelopes_duplicate Total duplicate envelope submissions deduplicated by id.\n\
         # TYPE kovanica_comms_relay_envelopes_duplicate counter\n\
         kovanica_comms_relay_envelopes_duplicate_total {}\n\
         # HELP kovanica_comms_relay_envelopes_delivered Total envelopes acknowledged and removed from mailboxes.\n\
         # TYPE kovanica_comms_relay_envelopes_delivered counter\n\
         kovanica_comms_relay_envelopes_delivered_total {}\n\
         # HELP kovanica_comms_relay_envelopes_expired Total envelopes dropped due to TTL expiration during sweeps.\n\
         # TYPE kovanica_comms_relay_envelopes_expired counter\n\
         kovanica_comms_relay_envelopes_expired_total {}\n\
         # HELP kovanica_comms_relay_envelopes_rejected Total envelope submissions rejected as invalid, malformed, or oversized.\n\
         # TYPE kovanica_comms_relay_envelopes_rejected counter\n\
         kovanica_comms_relay_envelopes_rejected_total {}\n\
         # HELP kovanica_comms_relay_envelopes_rate_limited Total envelope submissions rejected due to rate limiting, quota, or missing/replayed PoW.\n\
         # TYPE kovanica_comms_relay_envelopes_rate_limited counter\n\
         kovanica_comms_relay_envelopes_rate_limited_total {}\n\
         # HELP kovanica_comms_relay_inbox_requests Total valid inbox read requests served.\n\
         # TYPE kovanica_comms_relay_inbox_requests counter\n\
         kovanica_comms_relay_inbox_requests_total {}\n\
         # HELP kovanica_comms_relay_ack_rejected Total ack requests rejected as invalid or unauthorized.\n\
         # TYPE kovanica_comms_relay_ack_rejected counter\n\
         kovanica_comms_relay_ack_rejected_total {}\n\
         # EOF",
        store.queued_envelopes,
        store.active_mailboxes,
        store.max_mailbox_depth,
        uptime_seconds,
        store.envelopes_accepted_total,
        store.envelopes_duplicate_total,
        store.envelopes_delivered_total,
        store.envelopes_expired_total,
        rejected_total,
        rate_limited_total,
        inbox_requests_total,
        ack_rejected_total,
    );
    out
}

/// `GET /metrics` — OpenMetrics 1.0 telemetry endpoint.
async fn get_metrics(State(state): State<AppState>) -> Response {
    let store_stats = state.store.stats();
    let uptime_seconds = state.started_at.elapsed().as_secs();
    let body = render_openmetrics(&store_stats, &state.metrics, uptime_seconds);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, OPENMETRICS_CONTENT_TYPE)],
        body,
    )
        .into_response()
}

fn is_lower_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Build the §4 router around a shared [`Store`].
pub fn router(store: Arc<Store>) -> Router {
    let state = AppState {
        store,
        pow_seen: Arc::new(Mutex::new(VecDeque::new())),
        metrics: Arc::new(RelayMetrics::default()),
        started_at: Instant::now(),
    };
    Router::new()
        .route("/v1/envelope", post(post_envelope))
        .route("/v1/inbox/:comms_id", get(get_inbox))
        .route("/v1/ack", post(post_ack))
        .route("/v1/health", get(get_health))
        .route("/metrics", get(get_metrics))
        .with_state(state)
}

/// The relay HTTP server. Mirrors the `kovanica-rpc` [`RpcServer`] shape
/// (`router()` / `start()`).
///
/// [`RpcServer`]: https://docs.rs/kovanica-rpc
#[derive(Clone)]
pub struct RelayServer {
    addr: SocketAddr,
    store: Arc<Store>,
}

impl RelayServer {
    /// Create a server with a fresh, empty store.
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            store: Arc::new(Store::new()),
        }
    }

    /// Create a server sharing an existing store (tests, embedding).
    pub fn with_store(addr: SocketAddr, store: Arc<Store>) -> Self {
        Self { addr, store }
    }

    /// The shared store backing this server.
    pub fn store(&self) -> Arc<Store> {
        self.store.clone()
    }

    /// The configured bind address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Build the §4 router (exposed for tests and embedded use).
    pub fn router(&self) -> Router {
        router(self.store.clone())
    }

    /// Bind, serve, and return the background task handle.
    ///
    /// Shuts down gracefully on `SIGINT`/`SIGTERM`. Also spawns the periodic
    /// expiry sweep for the lifetime of the store.
    pub async fn start(self) -> Result<JoinHandle<()>, std::io::Error> {
        let app = self.router();
        let listener = TcpListener::bind(self.addr).await?;
        let actual_addr = listener.local_addr()?;
        info!("kovanica-comms-relay listening on http://{}", actual_addr);

        spawn_sweeper(self.store.clone());

        let handle = tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await
            {
                error!(error = %e, "relay server stopped with an error");
            }
        });

        Ok(handle)
    }
}

/// Spawn the background expiry sweep (drops envelopes past `expiresAt`).
///
/// Returns the task handle; the task runs until the process exits.
pub fn spawn_sweeper(store: Arc<Store>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let dropped = store.sweep(now_ms());
            if dropped > 0 {
                info!(dropped, "relay sweep dropped expired envelopes");
            }
        }
    })
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    warn!("relay shutdown signal received");
}
