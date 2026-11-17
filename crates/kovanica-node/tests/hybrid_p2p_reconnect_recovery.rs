//! Hybrid PoW + GHOSTDAG P2P reconnect & catch-up integration test (Chain 2).
//!
//! Verifies that when a peer goes offline, misses blocks while another peer
//! advances, and reconnects with its existing data directory, it:
//! 1. Re-establishes P2P peering (`peer_count >= 1`).
//! 2. Catches up missed blocks via P2P sync and commits them via GHOSTDAG
//!    (with local mining disabled on restart, proving progress comes from P2P).
//! 3. Recovers `/health` cleanly (HTTP 200, `"healthy": true`, `"status": "ok"`,
//!    running consensus & execution states).

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use kovanica_crypto::generate_keypair;
use kovanica_types::{signing::chain_id, Address, PublicKey};
use reqwest::Client;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::time::sleep;
use tracing::info;

const NODES: usize = 2;
const CHAIN_ID: u64 = chain_id::HYBRID_TESTNET;
const RPC_READY_TIMEOUT_SECS: u64 = 60;
const PEER_TIMEOUT_SECS: u64 = 90;
const MINING_TIMEOUT_SECS: u64 = 300;
const CATCHUP_TIMEOUT_SECS: u64 = 180;
const POLL_INTERVAL_MS: u64 = 500;
const PORT_ATTEMPTS: usize = 32;
const MISSED_BLOCKS_TARGET: u64 = 5;

struct ManagedNode {
    index: usize,
    child: Option<Child>,
    data_dir: TempDir,
    temp_log_path: PathBuf,
    log_path: PathBuf,
    rpc_port: u16,
    p2p_port: u16,
    bootnodes: Vec<String>,
    signing_key: SigningKey,
    binary: PathBuf,
}

impl ManagedNode {
    #[allow(clippy::too_many_arguments)]
    fn spawn_new(
        index: usize,
        rpc_port: u16,
        p2p_port: u16,
        bootnodes: Vec<String>,
        signing_key: SigningKey,
        binary: PathBuf,
        genesis_toml: &str,
        log_dir: &Path,
        mining_enabled: bool,
    ) -> Result<Self> {
        let data_dir = TempDir::new().with_context(|| format!("node {index}: temp dir"))?;
        std::fs::write(
            data_dir.path().join("genesis_validators.toml"),
            genesis_toml,
        )
        .with_context(|| format!("node {index}: write genesis"))?;

        let key_path = data_dir.path().join("validator.key");
        write_private(&key_path, hex::encode(signing_key.to_bytes()))
            .with_context(|| format!("node {index}: write validator key"))?;

        let temp_log_path = data_dir.path().join(format!("node{index}.log"));
        let log_path = log_dir.join(format!("node{index}.log"));

        let mut node = Self {
            index,
            child: None,
            data_dir,
            temp_log_path,
            log_path,
            rpc_port,
            p2p_port,
            bootnodes,
            signing_key,
            binary,
        };
        node.start(mining_enabled)?;
        Ok(node)
    }

    fn start(&mut self, mining_enabled: bool) -> Result<()> {
        if self.child.is_some() {
            bail!("node {} already running", self.index);
        }
        let key_path = self.data_dir.path().join("validator.key");
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.temp_log_path)
            .with_context(|| format!("node {}: open log", self.index))?;
        let log_err = log.try_clone()?;

        let mut cmd = Command::new(&self.binary);
        cmd.current_dir(self.data_dir.path())
            .env("KOVANICA_DATA_DIR", self.data_dir.path())
            .env("KOVANICA_RPC_ADDR", "127.0.0.1")
            .env("KOVANICA_RPC_PORT", self.rpc_port.to_string())
            .env(
                "KOVANICA_LISTEN_ADDR",
                format!("127.0.0.1:{}", self.p2p_port),
            )
            .env("KOVANICA_MAX_PEERS", "8")
            .env("KOVANICA_RUN_VALIDATOR", "true")
            .env("KOVANICA_CHAIN_ID", CHAIN_ID.to_string())
            .env(
                "KOVANICA_MINING_ENABLED",
                if mining_enabled { "true" } else { "false" },
            )
            .env("KOVANICA_MINING_THREADS", "1")
            .env("KOVANICA_MINING_AUTHOR", self.index.to_string())
            .env("KOVANICA_RPC_AUTH", "disable")
            .env("KOVANICA_RPC_RATE_LIMIT_PER_MIN", "0")
            .env("KOVANICA_VALIDATOR_KEY", key_path.as_os_str())
            .env("RUST_LOG", "info");

        if !self.bootnodes.is_empty() {
            cmd.env("KOVANICA_BOOTNODES", self.bootnodes.join(","));
        }

        let child = cmd
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .spawn()
            .with_context(|| format!("node {}: spawn {}", self.index, self.binary.display()))?;

        self.child = Some(child);
        info!(
            node = self.index,
            rpc = self.rpc_port,
            p2p = self.p2p_port,
            mining_enabled,
            "started node"
        );
        Ok(())
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for ManagedNode {
    fn drop(&mut self) {
        self.stop();
        if let Some(parent) = self.log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::copy(&self.temp_log_path, &self.log_path);
        // Keep signing_key referenced so compiler doesn't warn if unused after spawn.
        let _ = &self.signing_key;
    }
}

fn build_genesis_toml(validators: &[(SigningKey, PublicKey, Address)]) -> String {
    let mut out = String::from("# generated by hybrid_p2p_reconnect_recovery\n");
    out.push_str(&format!("chain_id = {CHAIN_ID}\n"));
    out.push_str("emission_policy = \"no-stake-82m\"\n\n");
    for (_, pk, addr) in validators {
        out.push_str("[[validator]]\n");
        out.push_str(&format!("address = \"{}\"\n", addr.encode()));
        out.push_str(&format!("public_key = \"{}\"\n\n", hex::encode(pk.0)));
    }
    out
}

fn node_binary_path() -> PathBuf {
    std::env::var("KOVANICA_NODE_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_BIN_EXE_kovanica-node")))
}

fn stable_log_dir(label: &str) -> PathBuf {
    if let Ok(dir) = std::env::var("KOVANICA_TEST_LOG_DIR") {
        return PathBuf::from(dir).join(label);
    }
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .map(|p| p.join("../.."))
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("target/hybrid-reconnect-logs")
        .join(format!("reconnect-{ts}"))
        .join(label)
}

fn port_is_available(port: u16) -> bool {
    if std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(5),
    )
    .is_ok()
    {
        return false;
    }
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

fn pick_free_ports(start: u16, end: u16) -> Result<(u16, u16)> {
    let span = (2 * NODES) as u64;
    let blocks = (end - start) as u64 / span;
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        ^ ((std::process::id() as u64) << 32);
    for _ in 0..PORT_ATTEMPTS {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let base = start + ((seed % blocks) * span) as u16;
        if (0..span as u16).all(|offset| port_is_available(base + offset)) {
            std::thread::sleep(Duration::from_millis(150));
            return Ok((base, base + NODES as u16));
        }
    }
    bail!("no free block of {span} ports in {start}..{end}")
}

fn write_private(path: &Path, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

async fn rpc_call(client: &Client, port: u16, method: &str, params: Value) -> Result<Value> {
    let resp = client
        .post(format!("http://127.0.0.1:{port}/rpc"))
        .json(&json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        }))
        .send()
        .await
        .with_context(|| format!("RPC {method} on {port}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .with_context(|| format!("RPC body {method} on {port}"))?;
    if !status.is_success() {
        bail!("RPC {method} on {port}: HTTP {status} body {body}");
    }
    let value: Value = serde_json::from_str(&body)
        .with_context(|| format!("RPC {method} on {port}: invalid JSON {body}"))?;
    if let Some(err) = value.get("error") {
        bail!("RPC {method} on {port}: {err}");
    }
    Ok(value)
}

async fn get_health_with_status(client: &Client, port: u16) -> Result<(u16, Value)> {
    let resp = client
        .get(format!("http://127.0.0.1:{port}/health"))
        .send()
        .await
        .with_context(|| format!("health on {port}"))?;
    let status = resp.status().as_u16();
    let body = resp
        .json::<Value>()
        .await
        .with_context(|| format!("health JSON on {port}"))?;
    Ok((status, body))
}

async fn get_height(client: &Client, port: u16) -> Result<u64> {
    let v = rpc_call(client, port, "kovanica_blockNumber", json!([])).await?;
    let raw = v
        .get("result")
        .and_then(Value::as_str)
        .with_context(|| format!("missing hex height in {v}"))?;
    let raw = raw.strip_prefix("0x").unwrap_or(raw);
    u64::from_str_radix(raw, 16).with_context(|| format!("invalid hex height {raw}"))
}

async fn wait_ready(client: &Client, port: u16, label: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(RPC_READY_TIMEOUT_SECS);
    loop {
        if get_health_with_status(client, port).await.is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("{label} RPC on 127.0.0.1:{port} not ready within {RPC_READY_TIMEOUT_SECS}s");
        }
        sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    }
}

async fn wait_for_peer(client: &Client, port: u16, label: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(PEER_TIMEOUT_SECS);
    loop {
        if let Ok((_, health)) = get_health_with_status(client, port).await {
            if health
                .get("peer_count")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                >= 1
            {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            bail!("{label} on 127.0.0.1:{port} did not peer within {PEER_TIMEOUT_SECS}s");
        }
        sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    }
}

async fn wait_for_height_at_least(
    client: &Client,
    port: u16,
    target: u64,
    timeout_secs: u64,
    label: &str,
) -> Result<u64> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if let Ok(h) = get_height(client, port).await {
            if h >= target {
                return Ok(h);
            }
        }
        if Instant::now() >= deadline {
            let last_h = get_height(client, port).await.unwrap_or(0);
            bail!("{label} did not reach height >= {target} within {timeout_secs}s (at {last_h})");
        }
        sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    }
}

#[tokio::test]
async fn hybrid_peer_offline_catchup_and_health_recovery() -> Result<()> {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let binary = node_binary_path();
    if !binary.exists() {
        bail!("node binary {} not found", binary.display());
    }
    let log_dir = stable_log_dir("p2p-reconnect");
    std::fs::create_dir_all(&log_dir)?;

    let mut validators = Vec::with_capacity(NODES);
    for _ in 0..NODES {
        let (sk, pk) = generate_keypair();
        let addr = Address::from_public_key(&pk);
        validators.push((sk, pk, addr));
    }
    let genesis = build_genesis_toml(&validators);
    let (rpc_base, p2p_base) = pick_free_ports(30_000, 34_000)?;

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("reqwest client")?;

    let mut node0 = ManagedNode::spawn_new(
        0,
        rpc_base,
        p2p_base,
        vec![],
        validators[0].0.clone(),
        binary.clone(),
        &genesis,
        &log_dir,
        true,
    )?;

    sleep(Duration::from_millis(500)).await;

    let mut node1 = ManagedNode::spawn_new(
        1,
        rpc_base + 1,
        p2p_base + 1,
        vec![format!("127.0.0.1:{p2p_base}")],
        validators[1].0.clone(),
        binary,
        &genesis,
        &log_dir,
        true,
    )?;

    // 1. Both nodes come up, peer, and commit initial blocks.
    wait_ready(&client, node0.rpc_port, "node0").await?;
    wait_ready(&client, node1.rpc_port, "node1").await?;
    wait_for_peer(&client, node0.rpc_port, "node0").await?;
    wait_for_peer(&client, node1.rpc_port, "node1").await?;

    let h1_initial = wait_for_height_at_least(
        &client,
        node1.rpc_port,
        2,
        MINING_TIMEOUT_SECS,
        "node1-init",
    )
    .await?;
    info!(h1_initial, "node1 reached initial committed height");

    // 2. Take node1 offline while node0 continues mining.
    node1.stop();
    let target_ahead = h1_initial + MISSED_BLOCKS_TARGET;
    let h0_ahead = wait_for_height_at_least(
        &client,
        node0.rpc_port,
        target_ahead,
        MINING_TIMEOUT_SECS,
        "node0-ahead",
    )
    .await?;
    info!(
        h0_ahead,
        target_ahead, "node0 advanced while node1 was offline"
    );

    // 3. Restart node1 with mining disabled so it can only advance via P2P catch-up + GHOSTDAG commit.
    node1.start(false)?;
    wait_ready(&client, node1.rpc_port, "node1-restart").await?;
    wait_for_peer(&client, node1.rpc_port, "node1-restart").await?;

    let h1_caught_up = wait_for_height_at_least(
        &client,
        node1.rpc_port,
        h0_ahead,
        CATCHUP_TIMEOUT_SECS,
        "node1-catchup",
    )
    .await?;
    info!(h1_caught_up, "node1 caught up via P2P + GHOSTDAG commit");

    // 4. Verify syncStatus settles to catchingUp == false and /health recovers cleanly on node1.
    let settle_deadline = Instant::now() + Duration::from_secs(CATCHUP_TIMEOUT_SECS);
    let sync_res = loop {
        let sync = rpc_call(&client, node1.rpc_port, "kovanica_syncStatus", json!([])).await?;
        let res = sync
            .get("result")
            .cloned()
            .context("missing syncStatus result")?;
        let catching_up = res
            .get("catchingUp")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let committed_height = res
            .get("committedHeight")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if !catching_up && committed_height >= h0_ahead {
            break res;
        }
        if Instant::now() >= settle_deadline {
            bail!("node1 syncStatus did not settle within {CATCHUP_TIMEOUT_SECS}s: {res}");
        }
        sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    };
    let committed_height = sync_res
        .get("committedHeight")
        .and_then(Value::as_u64)
        .context("missing committedHeight")?;
    assert!(
        committed_height >= h0_ahead,
        "node1 committedHeight {committed_height} < expected {h0_ahead}"
    );

    let (http_status, health) = get_health_with_status(&client, node1.rpc_port).await?;
    assert_eq!(http_status, 200, "/health must return 200: {health}");
    assert_eq!(health.get("healthy").and_then(Value::as_bool), Some(true));
    assert_eq!(health.get("status").and_then(Value::as_str), Some("ok"));
    assert!(
        health
            .get("peer_count")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 1,
        "peer_count must be >= 1: {health}"
    );
    assert_eq!(
        health
            .get("consensus")
            .and_then(|c| c.get("state"))
            .and_then(Value::as_str),
        Some("running"),
        "consensus state must be running: {health}"
    );
    assert_eq!(
        health
            .get("execution")
            .and_then(|e| e.get("state"))
            .and_then(Value::as_str),
        Some("running"),
        "execution state must be running: {health}"
    );
    assert!(
        health
            .get("consensus")
            .and_then(|c| c.get("last_committed_round"))
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 1,
        "health last_committed_round must advance: {health}"
    );
    assert!(
        health
            .get("consensus")
            .and_then(|c| c.get("committed_leaders"))
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= MISSED_BLOCKS_TARGET,
        "health committed_leaders must reflect post-restart commits: {health}"
    );
    assert!(
        health
            .get("execution")
            .and_then(|e| e.get("last_executed_round"))
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 1,
        "health last_executed_round must advance: {health}"
    );

    node1.stop();
    node0.stop();
    Ok(())
}
