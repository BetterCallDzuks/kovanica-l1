# External Audit / Seed / DNS — Checklist

Updated 2026-11-17 to reflect canonical Hybrid PoW + GHOSTDAG consensus, KovanicaHash, Wasmi execution, KVNC tokenomics, PRO-21 address requirements, 3-chain registry (`1` mainnet, `2` testnet, `3` devnet; `1337` retired in `#284`), canonical testnet genesis bundle `kovanica-testnet-genesis.tar.gz` (`#283`/`#287`), genesis-active hardening gates (`#288`), and pinned `main` commit `6bcca8630f97d7c9e599fe51b70c4d29a2766d8b`.

## 1. Seed / DNS audit (gating before public launch)
- [x] Automated DNS probe script (`scripts/check-dns-seeds.sh`) implemented and verified
- [x] Verify 3+ **kovanica-native** DNS seeds (`testnet.kovanica.online`, `seed1/2/3.kovanica.online`)
- [x] Verify grey-cloud origin IP resolution (no Cloudflare HTTP proxying / CDN)
- [ ] Ensure TCP port 8000 reachability across all deployed VPS seeds (via `scripts/cutover-vps-systemd.sh`)
- [ ] Publish each seed's libp2p PeerId and confirm `/p2p/` in the multiaddr matches
- [x] Confirm `KOVANICA_BOOTNODES` defaults stay empty in code; seeds configured via env/TOML

## 2. External audit scope (mandatory before mainnet $T_0$; internal code verification locked at `6bcca86`)
- [ ] **Consensus (Hybrid PoW + GHOSTDAG, K=5, target 4s):**
  - [ ] Verify KovanicaHash PoW algorithm (BLAKE3 + 2 MiB memory mix scratchpad, `KOVANICA_HASH_MIX_ROUNDS = 1024`) determinism and memory-hardness (`crates/kovanica-types/src/pow.rs:59-175`)
  - [ ] Verify Difficulty Adjustment Algorithm (LWMA DAA, `TARGET_BLOCK_MS = 4000`) stability, time warp resistance, and target clamping (`crates/kovanica-consensus/src/daa.rs:204-518`, `crates/kovanica-params/src/lib.rs:37`)
  - [ ] Verify GHOSTDAG K=5 (`GHOSTDAG_K = 5`) coloring, blue set selection, and topological DAG linear order (`crates/kovanica-params/src/lib.rs:39`, `crates/kovanica-consensus/src/ghostdag_scoped.rs:40`)
  - [ ] Verify edge anti-DoS ingress: PoW target & `GHOSTDAG_K` parent bound verification before gossip relay (`validate_pow_target`, `crates/kovanica-network/src/validation.rs:268`)
  - [ ] Verify that consensus is strictly leaderless PoW + GHOSTDAG (NO stake in consensus path; legacy Mysticeti gated on `!is_hybrid` in `crates/kovanica-node/src/main.rs`)
- [ ] **Execution & Hardening Gates (Wasmi deterministic WASM engine):**
  - [ ] Verify deterministic fuel metering per instruction and host call (`crates/kovanica-runtime/src/lib.rs`, `crates/kovanica-execution/src/lib.rs:912`)
  - [ ] Verify memory bounding (256 pages = 16 MiB limit, `DEFAULT_CONTRACT_MEMORY_PAGES = 256` in `crates/kovanica-params/src/lib.rs:127`, `crates/kovanica-execution/src/lib.rs:1430`) and trap cleanup on out-of-gas / stack exhaustion
  - [ ] Verify hardening gates active from round 0 (`GAS/CONTRACT/SLASHING/SIZE_LIMITS_ACTIVE_FROM_ROUND = GENESIS_ROUND = 0` in `crates/kovanica-params/src/lib.rs:148-152`, `crates/kovanica-dag/src/block_manager.rs:233`, `#288`)
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
  - [ ] Verify canonical testnet genesis bundle `kovanica-testnet-genesis.tar.gz` (`#283`/`#287`, `sha256: a2c5ed9213a25cd3ed2ca99a1db80dc8d9403856d27e0f84916d3e253ddaebee`, network tag `2-24cdb5fadd98b207`)
  - [ ] Verify keystore v2: Argon2id (64 MiB, 3 iter, 4 parallelism) + XChaCha20-Poly1305 (`crates/kovanica-keystore/src/lib.rs:29-35,112`)
- [ ] **P2P Networking & Node Security:**
  - [ ] Verify eclipse / Sybil resistance, peer discovery, gossip limits (port 8000 default)
  - [ ] Confirm no keys or seed material passed to or stored by the node daemon
  - [ ] Verify systemd sandboxing (`MemoryMax=3G`, `ProtectSystem=strict`, syscall filters)
- [ ] **Licensing & Copyleft:**
  - [ ] Verify GPL-3.0-or-later project relicensing (PRO-36 Option 2, written owner decision Toni 2026-11-03)
  - [ ] Verify cargo-deny CI enforcement for advisories, bans, licenses, and sources

## 3. Live node verification (repeat before release)
- [ ] Run `curl -s http://<kovanica-node>:8545` and check mining/sync status
- [ ] Confirm node memory usage stabilizes within the 2–4 GB VPS budget under soak
- [ ] Confirm `ALLOW_RESET=0`, `MINE=0` (on non-mining nodes), and `OPERATOR=0` on participant nodes
- [ ] Verify persistence across node daemon restarts without state corruption

Status: Scoping complete (`docs/AUDIT-SCOPE.md`); ready for external auditor engagement.
