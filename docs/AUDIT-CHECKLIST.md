# External Audit / Seed / DNS — Checklist

Updated 2026-11-27 to reflect merged `BetterCallDzuks/kovanica-l1` `main` (`80eec39`) — canonical Hybrid PoW + GHOSTDAG consensus, KovanicaHash, Wasmi execution + CPI (depth 4, reentrancy guard), 47 contract entry points (adding KVP-106 `kovanica-rwa`, `kovanica-scheduler`, and multi-chain `kovanica-bridge` for Bitcoin/Solana/all-EVM), Balanced Fixed Fees (75% burn / 25% miner), Wave A (`Batch`, `Sponsored`), Wave B (EIP-1559 dynamic base fee, refundable `STORAGE_DEPOSITS`), Wave C (`SESSION_KEYS` + `RegisterSessionKey`/`RevokeSessionKey` txs, real `p256` 0.14 ECDSA WebAuthn), Wave D (real `fips204` NIST ML-DSA-65 hybrid PQ), 3-node Mainnet $T_0$ dress rehearsal (`scripts/dress-rehearsal-3node.sh`), and 189-metric / 33-panel / 19-alert monitoring validation. Ecosystem `protect-main-pr-only` rulesets and `.github/workflows/pr-policy.yml` are active across all 5 `BetterCallDzuks/*` repos (`kovanica-l1` `80eec39`, `kovanica-sdk` `837b1d9` `v0.10.0`, `kovanica-web` `d1064af`, `kovanica-apps` `412def9`, `kovanica-playground` `a6cf792`).

## 1. Seed / DNS audit (gating before public launch)
- [x] Automated DNS probe script (`scripts/check-dns-seeds.sh`) implemented and verified
- [x] Verify **kovanica-native** grey-cloud DNS seeds (`testnet.kovanica.online`, `seed1.kovanica.online`, `mainnet.kovanica.online`; `seed2`/`seed3` retired)
- [x] Verify grey-cloud origin IP resolution (no Cloudflare HTTP proxying / CDN) across all active P2P seeds (`testnet.kovanica.online`, `seed1.kovanica.online`, `mainnet.kovanica.online`; `seed2`/`seed3` retired 2026-11-25)
- [x] Ensure TCP port 8000 reachability across all active deployed VPS seeds (`testnet.kovanica.online`, `seed1.kovanica.online`, `mainnet.kovanica.online` — all 3/3 verified TCP `8000` OPEN on 2026-11-25)
- [x] Publish active seed libp2p PeerId and confirm `/p2p/` in the multiaddr matches — *2026-11-25 verified on `seed1.kovanica.online` / `testnet.kovanica.online`: `/dns4/seed1.kovanica.online/tcp/8000/p2p/12D3KooWN1dCoKYtbKhd9sgVPy4rF34BDzq8vfs5a5VmjLoRbcv2` (`/health` ok, `peer_count: 3`, `node1` RSS `222 MiB`); `seed2`/`seed3` retired*
- [x] Confirm `KOVANICA_BOOTNODES` defaults stay empty in code; seeds configured via env/TOML

## 2. External audit scope (mandatory before mainnet $T_0$; internal code verification synced to `BetterCallDzuks/kovanica-l1` `main` `80eec39`)
- [ ] **Consensus (Hybrid PoW + GHOSTDAG, K=5, target 4s):**
  - [ ] Verify KovanicaHash PoW algorithm (BLAKE3 + 2 MiB memory mix scratchpad, `KOVANICA_HASH_MIX_ROUNDS = 1024`) determinism and memory-hardness (`crates/kovanica-types/src/pow.rs:59-175`)
  - [ ] Verify Difficulty Adjustment Algorithm (LWMA DAA, `TARGET_BLOCK_MS = 4000`) stability, time warp resistance, and target clamping (`crates/kovanica-consensus/src/daa.rs:204-518`, `crates/kovanica-params/src/lib.rs:37`)
  - [ ] Verify GHOSTDAG K=5 (`GHOSTDAG_K = 5`) coloring, blue set selection, and topological DAG linear order (`crates/kovanica-params/src/lib.rs:39`, `crates/kovanica-consensus/src/ghostdag_scoped.rs:40`)
  - [ ] Verify edge anti-DoS ingress: PoW target & `GHOSTDAG_K` parent bound verification before gossip relay (`validate_pow_target`, `crates/kovanica-network/src/validation.rs:268`)
  - [ ] Verify automated fuzz smoke test suite & runner across block, tx, vote, and consensus boundaries (`fuzz/tests/smoke_tests.rs`, `scripts/run-fuzz-smoke.sh`, `#309`/`#310`)
  - [ ] Verify that consensus is strictly leaderless PoW + GHOSTDAG (NO stake in consensus path; legacy Mysticeti gated on `!is_hybrid` in `crates/kovanica-node/src/main.rs`)
- [ ] **Execution & Hardening Gates (Wasmi deterministic WASM engine):**
  - [ ] Verify deterministic fuel metering per instruction and host call (`crates/kovanica-runtime/src/lib.rs`, `crates/kovanica-execution/src/lib.rs:912`)
  - [ ] Verify memory bounding (256 pages = 16 MiB limit, `DEFAULT_CONTRACT_MEMORY_PAGES = 256` in `crates/kovanica-params/src/lib.rs:127`, `crates/kovanica-execution/src/lib.rs:1430`) and trap cleanup on out-of-gas / stack exhaustion
  - [ ] Verify hardening gates active from round 0 (`GAS/CONTRACT/SLASHING/SIZE_LIMITS_ACTIVE_FROM_ROUND = GENESIS_ROUND = 0` in `crates/kovanica-params/src/lib.rs:148-152`, `crates/kovanica-dag/src/block_manager.rs:233`, `#288`), Mainnet round-0 full-state commitment (`state_commitment_active_from_round_for_chain(1) == 0`, Testnet `500_000`), pre-read host gas charging (`crates/kovanica-runtime/src/lib.rs:700-745`), and bounded WASM module cache (`MAX_CACHED_MODULES = 128` in `crates/kovanica-execution/src/contracts.rs`, `6d07b55`)
  - [ ] Verify native & WASM contract host dispatch (HTLC, Vault, Multisig, Token in `crates/kovanica-execution/src/contracts.rs`)
- [ ] **Tokenomics & Emissions:**
  - [ ] Verify hard cap: 90 200 000 KVNC total supply (`crates/kovanica-params/src/lib.rs`)
  - [ ] Verify block reward: 2.5 KVNC minted to committed block author (`block_reward(height)`) and PRO-53 fee split (3/4 burned, 1/4 miner on chains 1 & 2; 100% burned on chain 3 in `crates/kovanica-execution/src/lib.rs:478-551`)
  - [ ] Verify subsidy decay curve: ×3/4 every 8 200 000 rewarded blocks; total subsidy budget 82 000 000 KVNC (`NoStake82M` in `crates/kovanica-types/src/emission.rs:18-56`)
  - [ ] Verify treasury vesting: 8 000 000 KVNC over 8 years (1M/year linear)
  - [ ] Verify genesis validator allocation is 0 KVNC on chains 1 and 2 (`NoStake82M`, enforced by `ensure_emission_policy_matches_chain` in `crates/kovanica-node/src/main.rs:6003`); genesis bootstrap seeds 1..=20 hold no stake
- [ ] **Cryptography & Address Format:**
  - [ ] Verify Ed25519 signatures (strict dalek v2.1 `verify_strict`: canonical S check, small-order rejection in `crates/kovanica-types/src/crypto.rs:171-181`)
  - [ ] Verify PRO-21 addresses: `kvnc` + 57 base32 chars + `dag` (64 chars; 32B Ed25519 ‖ 29-bit BLAKE3 checksum in `crates/kovanica-types/src/address.rs`)
  - [ ] Confirm legacy hex format is strictly rejected on kovanica-mainnet (chain ID 1) and kovanica-testnet (chain ID 2), and retired chain ID `1337` (`local`) is rejected across all paths (`chain_id::is_registered` in `crates/kovanica-types/src/signing.rs:37-142`, `#284`)
  - [ ] Verify canonical testnet genesis bundle `kovanica-testnet-genesis.tar.gz` (`#283`/`#287`/`#308`, `sha256: a2c5ed9213a25cd3ed2ca99a1db80dc8d9403856d27e0f84916d3e253ddaebee` / refreshed release bundle `sha256: 5857c83e1eb911bf30f890079e18370c5dc74986580303795fd2d173c2296377`, network tag `2-24cdb5fadd98b207`)
  - [ ] Verify keystore v2: Argon2id (64 MiB, 3 iter, 4 parallelism) + XChaCha20-Poly1305 (`crates/kovanica-keystore/src/lib.rs:29-35,112`)
- [ ] **P2P Networking, Mining Gateway & Node Security:**
  - [ ] Verify eclipse / Sybil resistance, peer discovery, gossip limits (port 8000 default), per-IP/IPv6 `/64` eclipse cap (`MAX_PEERS_PER_IP = 3` in `crates/kovanica-network/src/service.rs`), and bounded bincode deserialization (`6d07b55`)
  - [ ] Verify in-memory peer reputation & IP ban scoring subsystem (`crates/kovanica-network/src/peer_scorer.rs`), penalty matrix (+50 malformed, +100 invalid block/PoW instant ban, +25 bad sig, +20 flood spam), socket gating (`InboundGate`), 15-minute ban enforcement (`#312`), and 1-hour idle record eviction (`6d07b55`)
  - [ ] Verify RPC middleware (`TrustedProxies` fail-closed `X-Forwarded-For`, IPv6 `/64` rate-limit bucketing, constant-time Bearer write auth), JSON-RPC 2.0 batch support (`MAX_JSONRPC_BATCH_SIZE = 32` in `crates/kovanica-rpc/src/lib.rs`) with per-item rate-limit accounting, and `kovanica-comms-relay` signed inbox ACK verification (`KVNC-RELAY-ACK-v1`, `6d07b55`, `ee908ca`)
  - [ ] Verify SIM-1 multi-threaded transaction spam and mempool soak simulation (`crates/kovanica-node/tests/sim1_soak_simulation.rs`, `ops/soak/run-sim1-soak.sh`, `#316`: 8,522.29 TPS, 13.14 MiB peak RSS vs 2,048 MiB budget, 0 panics, deterministic OOG rollback)
  - [ ] Verify Stratum V1 mining pool gateway (`crates/kovanica-stratum/`, `#319`–`#322`, `ee908ca`) and CLI (`crates/kovanica-cli/src/stratum_client.rs`, `crates/kovanica-cli/src/contracts.rs`): PRO-21 64-char `kvnc...dag` payout validation, `kovanicahash-v1` capability profile, canonical header preimage hashing, 4 KiB line bound, per-worker `VarDiff`, TLS + E2E test, per-IP misbehavior rate-limit & temporary ban (`IpBanScorer`), sanitized `GET /workers`, `mining.extranonce.subscribe` / `mining.set_extranonce`, `mining.ping` & idle session eviction sweep, Prometheus alerts (`ops/monitoring/kovanica-stratum-alerts.yml`) + 17-panel Grafana dashboard (`ops/monitoring/kovanica-stratum-dashboard.json`) + `ops/monitoring/validate-monitoring.py`, and CLI `contract call` / `contract storage`
  - [ ] Confirm no keys or seed material passed to or stored by the node daemon
  - [ ] Verify systemd sandboxing (`MemoryMax=3G`, `ProtectSystem=strict`, syscall filters, plus `ops/systemd/kovanica-faucet.service` & `ops/systemd/kovanica-stratum.service` in `6d07b55`; audited 5/5 in [`docs/PRE_AUDIT_REPRODUCTION_2026_11.md`](PRE_AUDIT_REPRODUCTION_2026_11.md))
- [ ] **Licensing & Copyleft:**
  - [ ] Verify GPL-3.0-or-later project relicensing (PRO-36 Option 2, written owner decision Toni 2026-11-03)
  - [ ] Verify cargo-deny CI enforcement for advisories, bans, licenses, and sources

## 3. Live node verification (repeat before release)
- [ ] Run `curl -s http://<kovanica-node>:8545` and check mining/sync status
- [ ] Confirm node memory usage stabilizes within the 2–4 GB VPS budget under soak
- [ ] Confirm `ALLOW_RESET=0`, `MINE=0` (on non-mining nodes), and `OPERATOR=0` on participant nodes
- [ ] Verify persistence across node daemon restarts without state corruption

Status: Scoping complete (`docs/AUDIT-SCOPE.md`); ready for external auditor engagement (see [`docs/INTERNAL_PRE_AUDIT_2026_11.md`](INTERNAL_PRE_AUDIT_2026_11.md) & [`docs/PRE_AUDIT_REPRODUCTION_2026_11.md`](PRE_AUDIT_REPRODUCTION_2026_11.md)).  
Latest verification sweep (2026-11-25, `9391ae8`): `cargo fmt --all -- --check` + `cargo clippy --workspace --all-targets -- -D warnings` (0 warnings), `cargo test --workspace` (PASS), `cargo audit` + `cargo deny check` (PASS, `p256` 0.14 + `fips204` 0.4), `gitleaks` (PASS), `python3 scripts/lint_docs.py` (OK), `python3 ops/monitoring/validate-monitoring.py` (PASS: 189 exported metrics, 54 `stratum_*` metrics, 33 Grafana panels, 19 alert rules), `bash scripts/dress-rehearsal-3node.sh` (5/5 PASS), and audit dossier packaged via `scripts/package-audit-dossier.sh`.
