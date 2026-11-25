# Kovanica Mainnet Launch Runbook

> **Network:** kovanica-mainnet (chain ID `1`)
> **Ticker:** KVNC (9 decimals; `1 KVNC = 10^9` atoms)
> **Consensus:** Hybrid PoW + GHOSTDAG. Stake is not used for consensus.
> **Status:** Operational runbook. Frozen parameters, ceremony addresses (`1-f35df34c92001436`), grey-cloud bootnode DNS (`mainnet.kovanica.online:8000`), public RPC hostname (`rpc.kovanica.online`), and treasury custody (single founder) are locked. Launch time is **2027-01-01 12:00 UTC**.
> **Consensus impact:** None. This runbook tells operators how to start clients. It does not change consensus bytes, genesis files, or a live deploy.

Read [`AGENT-RULES.md`](AGENT-RULES.md) before acting on this document. Key generation and the genesis file set are in [`KEY-CEREMONY.md`](KEY-CEREMONY.md) and [`GENESIS-CEREMONY.md`](GENESIS-CEREMONY.md). Mining mechanics are in [`MINING.md`](MINING.md).

---

## 1. Launch shape

Three kinds of process participate. None of them is a voting validator.

| Process | Job | Consensus role |
|---|---|---|
| Bootstrap seed | Holds the genesis files, listens on TCP `8000`, publishes the bootnode name | Relay and initial discovery |
| Miner | Searches KovanicaHash and publishes blocks | Produces blocks. Payout is the block author reward |
| RPC / full node | Serves `127.0.0.1:8545` (or an operator bind) and syncs the DAG | Follows GHOSTDAG order |

`GHOSTDAG_K = 5` orders blocks. `TARGET_BLOCK_MS = 4000` is the difficulty target. A committee quorum, a VRF leader, and a stake threshold are not part of liveness. Legacy constants (`WAVE_LENGTH`, `EPOCH_ROUNDS`, `MIN_VALIDATOR_STAKE`, `JAIL_ROUNDS`, and the rest) stay in the tree and stay off the consensus path.

Resource budget for a seed, miner, or RPC node: 2–4 GB RAM, 2 vCPU, about 50 GB SSD. The systemd unit caps the node at `MemoryMax=3G` ([`ops/systemd/kovanica-node.service`](../ops/systemd/kovanica-node.service)).

---

## 2. Frozen parameters to verify before start

Confirm the binary matches this table. Operators do not override these in config.

| Parameter | Mainnet value |
|---|---|
| Chain ID | `1` |
| Total supply | 90 200 000 KVNC |
| Decimals | 9 (`ONE_KVNC = 10^9`) |
| Founder premine | 200 000 KVNC |
| Treasury | 8 000 000 KVNC, linear, 1 000 000 KVNC/year × 8, `vested = 0` at genesis |
| Seed allocation | 0 KVNC |
| Mining budget | 82 000 000 KVNC |
| Initial block reward | 2.5 KVNC to the committed block author |
| Subsidy era | 8 200 000 rewarded blocks, then × 3/4 |
| Fee split | 3/4 burned, 1/4 miner |
| Target block time | 4000 ms |
| GHOSTDAG k | 5 |
| PoW | KovanicaHash |
| Easiest target / `MAX_TARGET_BITS` | `0x1f00ffff` |
| Hardest target / `MIN_TARGET_BITS` | `0x01010000` |
| Genesis time | `0` |
| Bootnode | `mainnet.kovanica.online:8000` |
| BIP44 coin type | `3007` (`m/44'/3007'/<account>'/<change>'/<index>'`) |
| Public launch | 1.1.2027 |
| Address | PRO-21: `kvnc` + 57 bech32 chars + `dag` |

The DAA aims at 4 seconds and clamps to those two bit values. Operators do not write a target into the config. The testnet tag `2-24cdb5fadd98b207` and the testnet bounds `0x1f7fffff` / `0x1e00ffff` are chain ID 2. A mainnet node that prints that tag is on the wrong genesis.

---

## 3. Launch ceremony & operational parameters

The offline mainnet genesis ceremony (`#290`) was executed on `2026-11-17` with public artifacts committed under `mainnet/` (`SHA256SUMS`, `genesis.json`, `genesis_validators.toml`, `founder_premine.hex`, `bootnodes.toml`). Remaining launch decisions were locked on `2026-11-25`:

| Item | State |
|---|---|
| Founder PRO-21 address | `kvnc2yuzlhwfvp7v44yje2cgtfy540q8vv6c780ug3xfel36kswhpwnfthzxvdag` (locked in `mainnet/genesis.json`) |
| Treasury PRO-21 address | `kvncd2xkjdt78kyqc4ekret0wr3dnnrr3wyxdwmykkwujrpp3l3l6p80mk2dgdag` (locked in `mainnet/genesis.json`) |
| Bootstrap seeds (address + 32-byte public key, count 1..=20, recommend 3–5) | **5 bootstrap seeds locked** in `mainnet/genesis_validators.toml` (`stake = 0`) |
| Mainnet network tag `1-<16 hex chars>` | **`1-f35df34c92001436`** (ceremony executed 2026-11-17; bundle `/tmp/kovanica-mainnet-genesis.tar.gz` sha256 `d0ac07ba0bbe7fff87f3a7713a19239ceebb201944b4984d579a1f5f60edd7bf`) |
| DNS A/AAAA for `mainnet.kovanica.online` | **Verified grey-cloud + TCP `8000` OPEN** (2026-11-25 live DNS/TCP probe) |
| Extra seed DNS names | **None** (single primary bootnode `mainnet.kovanica.online:8000`; confirmed Toni 2026-11-25) |
| Public RPC hostname | **`rpc.kovanica.online`** (confirmed Toni 2026-11-25) |
| Exact UTC start on 1.1.2027 | **`12:00 UTC`** (confirmed Toni 2026-11-25) |
| Treasury custodians | **Single founder** (offline cold key; confirmed Toni 2026-11-25) |

`OPEN` is a marker in this document. Do not put the word `OPEN` into a config or a genesis file.

---

## 4. Config that must be true on every mainnet node

`funded_accounts.toml` must be absent from the data directory. Chain ID 1 aborts at startup when that file is present. Every KVNC on mainnet comes from the premine, the treasury vest, or the mining subsidy.

Pre-flight, with the ceremony files already in the data directory and `treasury_address` set to the ceremony treasury:

```bash
kovanica-node --check-config --config /etc/kovanica/config.toml
kovanica-node network-tag --config /etc/kovanica/config.toml
```

`--check-config` prints `config OK` and the chain id. On chain ID 1 it also checks that a present ceremony file declares between 1 and 20 seeds. `network-tag` prints `1-` plus 16 hex characters. Every node prints the same tag. A mismatch means the genesis files or `KOVANICA_TREASURY_ADDRESS` differ, and the libp2p handshake will reject the peer.

Example config keys (values that are still **OPEN** stay as words here, not in the real file):

```toml
# /etc/kovanica/config.toml
chain_id = 1
data_dir = "/var/lib/kovanica"
listen_addr = "0.0.0.0:8000"
rpc_addr = "127.0.0.1"
rpc_port = 8545
bootnodes = ["mainnet.kovanica.online:8000"]
treasury_address = "<OPEN: treasury PRO-21 address>"
round_duration_ms = 4000
max_peers = 50

# Legacy Mysticeti signing path. Hybrid blocks come from [mining].
run_validator = false

[mining]
enabled = false
```

`run_validator = true` is the code default and then the node requires `validator_key`. Mainnet seeds, miners, and RPC nodes set `run_validator = false` (or `KOVANICA_RUN_VALIDATOR=false`). Leave `KOVANICA_VRF_LEADER` unset.

`KOVANICA_MINE`, `KOVANICA_FAUCET`, `KOVANICA_OPERATOR`, and `KOVANICA_ALLOW_RESET` are not read by `kovanica-node`. Mining is `KOVANICA_MINING_ENABLED` / `[mining]`. The faucet is a separate binary and refuses chain ID 1 unless `--allow-mainnet` or `KOVANICA_FAUCET_ALLOW_MAINNET=1` is set. Do not set that override. Mainnet has no public faucet.

RPC writes require bearer auth. Do not publish a config that turns `KOVANICA_RPC_AUTH` off. Read methods used below (`kovanica_blockNumber`, `kovanica_syncStatus`, `GET /health`, `GET /metrics`) stay available for local checks.

Bind RPC to loopback unless the host is the public RPC and the auth and the rate limit are in place. JSON-RPC is `POST /rpc`. WebSocket is `GET /ws`. Health is `GET /health`. Prometheus text is `GET /metrics`. All four share the RPC port (default `8545`). There is no separate metrics port in the node.

P2P is TCP `8000` with libp2p Noise and Yamux. The frozen bootnode string is the DNS name and the port:

```text
mainnet.kovanica.online:8000
```

The DNS record for that name is grey-cloud (DNS only). An HTTP proxy in front of port `8000` breaks the handshake. The ceremony writes this name into `bootnodes.toml` and does not write an IP. Peer ids are created on the seed when `p2p_node.key` appears in the data directory. That key stays on the seed. It is not a ceremony input and it is not committed.

---

## 5. Genesis files on the node

Copy only the public ceremony output into the data directory:

- `genesis_validators.toml`
- `founder_premine.hex`
- `bootnodes.toml` (or set the same bootnode in config)

Set `treasury_address` in config, or `KOVANICA_TREASURY_ADDRESS`, to the same treasury string recorded in `genesis_validators.toml`. The digest binds that string. A node with a different treasury builds a different tag and cannot join.

`genesis.json` may sit beside those files for human review. The node derives genesis state from the toml, the founder file, and the configured treasury address.

`genesis_validators.toml` (legacy file name; entries are bootstrap seed identities, not validators; on non-mainnet chains `funded_accounts.toml` is likewise a legacy name for mining-reward/faucet recipients) on chain ID 1 looks like this once the OPEN markers are replaced:

```toml
chain_id = 1
emission_policy = "no-stake-82m"
treasury_address = "<OPEN: treasury PRO-21 address>"

[[validator]]
address = "<OPEN: seed PRO-21 address>"
public_key = "<OPEN: 64 hex chars>"
```

No `stake` key. `emission_policy` must be `no-stake-82m`.

---

## 6. Process layout

### 6.1 Seed

`[mining].enabled = false`. `run_validator = false`. Listen on `0.0.0.0:8000`. Use the genesis files from section 5. The first seed is the host that `mainnet.kovanica.online` will resolve to. Further seeds, if Toni names them, use the same genesis bytes and the same treasury, and they add each other as bootnodes. Their DNS names are **OPEN**.

Start:

```bash
systemctl start kovanica-node
journalctl -u kovanica-node -f
```

Confirm the log shows chain ID 1 and a network tag that starts with `1-`.

### 6.2 Miner

A miner is any node with a PRO-21 payout address. It does not appear in `validators.json`.

```bash
# environment, or the matching [mining] keys
KOVANICA_MINING_ENABLED=true
KOVANICA_MINING_ADDRESS=<PRO-21 payout address>
KOVANICA_MINING_THREADS=2
KOVANICA_RUN_VALIDATOR=false
```

`KOVANICA_MINING_ADDRESS` is the reward address. `KOVANICA_MINING_AUTHOR` is an optional bootstrap-seed index and is unnecessary when the address is set. The payout address can be a BIP44 account at coin type 3007; the node only sees the PRO-21 string.

KovanicaHash uses a 2 MiB mix per hash. Size the thread count so the process stays inside the 2–4 GB budget together with the node.

### 6.3 RPC node

Same genesis and the same tag as the seeds. `run_validator = false`. Mining stays off unless this host is also a miner. Keep the RPC bind on localhost until a reviewed reverse proxy and bearer auth are in front of it.

---

## 7. Launch window

Public launch is **2027-01-01 at 12:00 UTC** (confirmed Toni 2026-11-25). Then:

1. At least 15 minutes before that minute, start seeds with empty data directories that contain only the ceremony files and a fresh `p2p_node.key` created by the process. Do not copy a chain ID 2 data directory.
2. At the agreed minute, start miners and RPC nodes.
3. Watch height. With a miner running, committed height should advance on a 4 second target. The first blocks can be slower while the DAG has few parents. A multi-minute stall with miners connected is an incident (section 9), not a reason to edit difficulty.

Do not reset a data directory to “line everyone up” after the first block exists. GHOSTDAG commits a total order once blocks have propagated.

---

## 8. Health checks

CLI (`kovanica`, from `kovanica-cli`):

```bash
kovanica node sync --rpc-url http://127.0.0.1:8545
kovanica node peers --rpc-url http://127.0.0.1:8545
```

`sync` rows are `RPC`, `Signing chain id`, `Height`, `Round`, `Epoch`, `Sync`, `Peers`, and `Committee size (legacy)`. Expect:

- Signing chain id `1 (matches the node)`.
- `Sync` of `in sync` once the node has the peer tip.
- `Height` increasing.
- `Peers` greater than 0 after the mesh exists.
- `Committee size (legacy)` is a leftover counter. It is not a quorum and it does not gate commits.

Direct HTTP on the node:

```bash
curl -fsS http://127.0.0.1:8545/health

curl -fsS -X POST http://127.0.0.1:8545/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"kovanica_blockNumber","params":[],"id":1}'

curl -fsS -X POST http://127.0.0.1:8545/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"kovanica_syncStatus","params":[],"id":1}'
```

`kovanica_syncStatus` includes `networkTag`. It must equal the `network-tag` line from section 4.

There is no required peer count for consensus. The alert rules in [`ops/prometheus/alerts.yml`](../ops/prometheus/alerts.yml) still fire when `peer_count < 3` for 2 minutes and when `peer_count == 0` for 1 minute. On the first hour, with fewer than three peers, `KovanicaPeerCountDrop` will page. Treat it as “the mesh is smaller than the alert expects”, then compare with the number of seeds Toni actually started. A later quiet hour with `peer_count == 0` on a public seed is a real partition.

`ops/monitoring/check-cluster.sh` is the chain ID 2 monitor (it queries `seed1` and `seed3`). It is not the mainnet check. Use the commands in this section against mainnet binds.

### 8.1 Operator CLI pre-flight & recovery reference

Use `kovanica` (`kovanica-cli`) for pre-flight verification, incident triage, and offline recovery checks. Canonical network tags are `1-f35df34c92001436` (Chain 1 mainnet) and `2-24cdb5fadd98b207` (Chain 2 testnet).

| Command | Purpose |
|---|---|
| `kovanica node doctor` | Runs consolidated node diagnostics: RPC reachability, chain ID, canonical network tag verification, sync progress, and peer health. |
| `kovanica rpc probe <url> [--expected-chain-id <id>] [--json]` | Probes a JSON-RPC endpoint for JSON-RPC 2.0 batch support, `X-Kovanica-Network-Tag` and `X-Kovanica-Rpc-Version` identity headers, canonical tag match, and latency. |
| `kovanica snapshot verify <path> [--expected-chain-id <id>] [--json]` | Verifies a state/chain snapshot archive offline (integrity, checksums, and expected chain ID) before restoring a node. |
| `kovanica address inspect <addr> [--expected-chain-id <id>] [--json]` | Validates and inspects a PRO-21 (`kvnc...dag` / `tknc...dag`) or 32-byte hex address offline, checking checksum and chain compatibility. |
| `kovanica tx decode <hex> [--json]` | Decodes a raw signed/unsigned transaction hex payload offline for operator inspection prior to broadcast or incident analysis. |
| `kovanica tx envelope encode\|decode` | Encodes or decodes compact air-gapped transaction envelopes (`kvnc-tx:v1:<base64url>`) with BLAKE3 integrity verification and canonical network-tag pinning (`1-f35df34c92001436` / `2-24cdb5fadd98b207`). |

### 8.2 Cluster monitor & Prometheus alert rules

- **Python cluster monitor ([`ops/monitoring/check-cluster.py`](../ops/monitoring/check-cluster.py)):** Checks Chain 2 seed `/health`, JSON-RPC 2.0 batch responses, and RPC identity headers (`X-Kovanica-Network-Tag`, `X-Kovanica-Rpc-Version`). Optional sidecar checks can be enabled with:
  - `--stratum-health-url <url>`: alerts on `"draining"` status or share rejection ratio > 10%, and warns when `active_workers == 0`.
  - `--indexer-health-url <url>`: checks `sync_state` (`synced` / `lagging` / `stalled`) and `lag_blocks` (> 10 warning, > 50 alert).
  - `--faucet-health-url <url>`: verifies faucet `/health`, `X-Kovanica-Chain-Id`, canonical Chain 2 tag `2-24cdb5fadd98b207`, and balance floor.
- **Prometheus alert rule files:**
  - [`ops/monitoring/kovanica-rpc-alerts.yml`](../ops/monitoring/kovanica-rpc-alerts.yml) — RPC availability, p95 latency, slow requests, batch rejections, WebSocket connection caps, and subscriber lag.
  - [`ops/monitoring/kovanica-stratum-alerts.yml`](../ops/monitoring/kovanica-stratum-alerts.yml) — Stratum gateway availability, share rejection ratio, zero workers, stuck graceful drain, VarDiff churn, TLS failures, stale templates, IP ban storms, and idle evictions.
  - [`ops/monitoring/kovanica-faucet-indexer-alerts.yml`](../ops/monitoring/kovanica-faucet-indexer-alerts.yml) — Faucet low balance, rejection rate, and rate-limit spikes; Indexer lagging, stalled, and zero-progress alerts.

### 8.3 Lightnode verification & sync states

`kovanica-lightnode` verifies committed-leader headers and enforces fail-closed canonical network tag checks before accepting headers:

- **Canonical network tag verification:** On Chain 1 (`1-f35df34c92001436`) and Chain 2 (`2-24cdb5fadd98b207`), any mismatched or empty tag is rejected. Custom devnets require a non-empty network tag.
- **Sync states (`LightnodeSyncState`):**
  - `Synced`: within 2 headers of the network head (`lag_headers <= 2`) with at least one verified peer.
  - `CatchingUp`: between 3 and 50 headers behind the network head (`3 <= lag_headers <= 50`) with at least one verified peer.
  - `Stalled`: more than 50 headers behind the network head (`lag_headers > 50`) or zero verified peers.

---

## 9. Alerts

Scrape `GET /metrics` on the RPC port. Rule names below are the ones in `ops/prometheus/alerts.yml`. The annotation text on `KovanicaPeerCountDrop` still says “4-node quorum”. Read the condition (`peer_count < 3`). Consensus does not have that quorum.

| Alert | Condition | What to do |
|---|---|---|
| `KovanicaPeerCountCritical` | `peer_count == 0` for 1 minute | Check `ss -tulpn` for port `8000`, the grey-cloud DNS record, and `bootnodes`. Read the log for handshake errors and a wrong network tag. |
| `KovanicaPeerCountDrop` | `peer_count < 3` for 2 minutes | Compare with the planned seed count. If the count is below the plan, fix reachability on port `8000`. |
| `KovanicaBlockHeightStalled` | no `block_height` increase for 5 minutes | See section 9.1. |
| `KovanicaBlockHeightDrift` | max height − min height > 10 for 2 minutes | The lagging node is syncing or its disk is saturated (`iostat -xz 1`). Give it peers. Do not delete its store because it is behind. |
| `KovanicaCommitLatencyHigh` | `commit_latency > 5000` ms for 3 minutes | Target is 4000 ms. Check CPU (the 2 MiB hash mix), disk, and RTT between miners and seeds. |
| `KovanicaMempoolBacklog` | `mempool_size > 1000` for 5 minutes | Block production is slower than transaction intake. Check that a miner is actually hashing. Fees still follow the 3/4 burn, 1/4 miner split. |
| `KovanicaMemoryHigh` / `KovanicaMemoryCritical` | `rss_proxy` above 3000 MB / 3500 MB | Stay inside the 2–4 GB budget. A graceful restart releases RSS. Raise `MemoryMax` only with an explicit capacity decision. |
| `KVCNNodeDown` | Prometheus `up{job="kovanica"} == 0` for 1 minute | `systemctl status kovanica-node`, then disk space on `/var/lib/kovanica`. The alert name is `KVCN`, which is the string in the rules file. |
| `KovanicaMysticGhostMergesetLarge` / `KovanicaMysticGhostColouringFallback` | mergeset or colouring fallback | The node is slow to colour the DAG. Check CPU and disk. Leave `GHOSTDAG_K` at 5. |

### 9.1 Height stalled

1. Query `kovanica_blockNumber` on each seed. If one node is quiet and the others advance, the quiet node has a local fault (process down, disk, or no peers). Restart that process. Keep its `consensus.redb` and `state.redb`.
2. If every node is quiet, check that at least one miner has `KOVANICA_MINING_ENABLED=true`, a valid PRO-21 `KOVANICA_MINING_ADDRESS`, and peers on port `8000`.
3. Confirm every node still prints the same `1-…` tag. A tag split means the genesis bytes or the treasury address diverged. Stop the divergent node and restore the ceremony files. Do not edit bits, `k`, or the reward to force a block.
4. Do not wipe data directories as the first response. A wipe after height > 0 forks that operator off the chain they already accepted.

### 9.2 Two blocks from one miner

GHOSTDAG orders competing blocks into blue and red. There is no equivocation slash and no jail. Leave both blocks in the DAG. The committed order is the one every node with the same history will compute. Restarting a miner is appropriate when it is crashing. Deleting peer stores is not.

### 9.3 Partition

Restore the path on TCP `8000`. Nodes that kept their stores will exchange the blocks they missed and commit one order. Do not reset one side to genesis. Do not copy `consensus.redb` or `state.redb` from one operator to another.

### 9.4 Corrupt local store

When a single node’s store is unreadable and the rest of the mesh is healthy:

```bash
systemctl stop kovanica-node
rm -f /var/lib/kovanica/consensus.redb /var/lib/kovanica/state.redb
```

Leave `genesis_validators.toml`, `founder_premine.hex`, `bootnodes.toml`, the config, and `p2p_node.key` in place. Start the node. It catches up through `/kovanica/<tag>/block-sync/1.1.0`. If the tag in the log differs from the mesh, stop and fix the treasury or the genesis files before deleting anything else.

---

## 10. Launch checklist

- [x] Ceremony sign-off in [`KEY-CEREMONY.md`](KEY-CEREMONY.md) is complete (`1-f35df34c92001436`, no remaining **OPEN** address).
- [ ] `sha256sum -c SHA256SUMS` matches on every operator’s copy.
- [ ] `network-tag` is the same `1-` value on every node.
- [x] `mainnet.kovanica.online` resolves grey-cloud and accepts TCP `8000` (verified 2026-11-25).
- [ ] `funded_accounts.toml` is absent. Faucet override is unset.
- [ ] `run_validator = false` on seeds, miners, and RPC nodes.
- [ ] At least one miner has a PRO-21 payout address and `KOVANICA_MINING_ENABLED=true`.
- [ ] `kovanica node sync` shows height advancing and `Sync` = `in sync`.
- [ ] `ops/prometheus/alerts.yml` is loaded, and `KVCNNodeDown` is clear.
- [ ] RPC write methods require the bearer token.
- [x] Launch calendar day is 2027-01-01, and the UTC start time is locked at **12:00 UTC**.

This runbook does not authorize a deploy, a tag move, or a genesis commit. Those stay with Toni.
