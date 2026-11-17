# Kovanica Internal Pre-Audit Security Assessment Report (P4-4)

**Audit Team:** Kovanica Core Security & Protocol Engineering (Internal Pre-Audit Handoff)  
**Audit Period:** 2026-11-05 – 2026-11-17  
**Report Date:** 2026-11-17  
**Codebase Commit (`origin/main`):** `e15b20a1dbdc97fc7ebecb78a9c2ce0320490eb7` (code tip post-`#308`–`#312`)  
**Scope Document:** [`docs/AUDIT-SCOPE.md`](AUDIT-SCOPE.md) v2.0  
**Checklist Document:** [`docs/AUDIT-CHECKLIST.md`](AUDIT-CHECKLIST.md)  
**Testnet Genesis Bundle:** `kovanica-testnet-genesis.tar.gz` (`#283`/`#287`, `sha256: a2c5ed9213a25cd3ed2ca99a1db80dc8d9403856d27e0f84916d3e253ddaebee`, network tag `2-24cdb5fadd98b207`)  
**Chain Registry:** `1` (`kovanica-mainnet`), `2` (`kovanica-testnet`), `3` (`kovanica-devnet`; `1337` retired in `#284`)  
**Hardening Gates (`P4-6` `#288`):** `GAS/CONTRACT/SIZE_LIMITS/SLASHING_ACTIVE_FROM_ROUND = 0` (`GENESIS_ROUND`)  
**Classification:** PUBLIC (External Auditor Handoff Package)

---

## Executive Summary

| Metric | Value |
|--------|-------|
| **Overall Pre-Audit Risk Posture** | **Low** (All Critical/High internal findings remediated and verified in CI) |
| **Critical Findings (Open / Fixed)** | **0 Open** / 2 Fixed (`#259` LWMA DAA, `#288` Genesis Hardening Gates) |
| **High Findings (Open / Fixed)** | **0 Open** / 3 Fixed (`#233`/`#272` Hybrid Stake Refusal, `#284` Chain `1337` Retirement, `#285` Secret Untracking) |
| **Medium Findings (Open / Fixed)** | **0 Open** / 2 Fixed (`#279` Faucet Nonce/Rate-Limit Serialization, `#283` Canonical Genesis Bundle) |
| **Low / Informational** | **0 Open** / 2 Informational notes documented for external auditor |
| **Crates in Scope** | 27 workspace crates |

**One-sentence summary:** Static and test-backed verification across all 7 [`docs/AUDIT-SCOPE.md`](AUDIT-SCOPE.md) areas confirms that Hybrid PoW (`KovanicaHash` 2 MiB mix) + GHOSTDAG (`K=5`), `Wasmi` sandbox execution, `NoStake82M` tokenomics, PRO-21 addresses, and round-0 hardening gates (`#288`) uphold all protocol invariants with zero open Critical/High issues.

**Recommendation:** **READY FOR EXTERNAL AUDITOR DISPATCH & SIGN-OFF** (Mainnet $T_0$ remains gated on independent third-party audit sign-off per [`docs/AUDITOR-INVITATION.md`](AUDITOR-INVITATION.md)).

---

## Methodology

- **Approach:** Line-by-line static code review of all consensus, execution, cryptography, tokenomics, mempool, P2P, and RPC crates against [`docs/AUDIT-SCOPE.md`](AUDIT-SCOPE.md) v2.0 and [`docs/AUDIT-CHECKLIST.md`](AUDIT-CHECKLIST.md), paired with deterministic unit, property, adversarial fork, and multi-node simulation test suites.
- **Verification Gates:** GitHub Actions CI (`cargo fmt`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace`, `cargo-deny`, `gitleaks` v8.24.3, `python3 scripts/lint_docs.py`).
- **Standards Referenced:** ADR 0003 (Hybrid PoW + GHOSTDAG, No Stake), PRO-21 (Canonical 64-char `kvnc...dag` Address), PRO-53 (Fee Split & Burn), RFC 9106 (Argon2id Keystore v2).

---

## Detailed Verification Across the 7 `AUDIT-SCOPE.md` Areas

### Area 1: `KovanicaHash` 2 MiB Mix & PoW Header Verification (`kovanica-types`, `kovanica-network`)

| Invariant / Check | Code Reference | Verification Details & Backing Tests | Status |
|---|---|---|---|
| **Constant 2 MiB scratchpad & chunk bounds** | `crates/kovanica-types/src/pow.rs:50-59`, `86-90` | `KOVANICA_HASH_MEMORY_SIZE = 2 * 1024 * 1024` (2,097,152 B), `KOVANICA_HASH_CHUNK_SIZE = 32`, `KOVANICA_HASH_NUM_CHUNKS = 65_536` ($2^{16}$), `KOVANICA_HASH_MIX_ROUNDS = 1_024`. Heap-allocated via `vec![0u8; KOVANICA_HASH_MEMORY_SIZE].into_boxed_slice()` to prevent thread stack overflow. | **VERIFIED** |
| **Unbiased, panic-free scratchpad indexing** | `crates/kovanica-types/src/pow.rs:111-151` | `chunk_idx = u16::from_le_bytes([state[0], state[1]]) as usize` maps onto $0..65535$; `offset = chunk_idx * 32` is strictly $\le 2,097,120$, so `self.memory[offset..offset + 32]` can never panic or go out of bounds for any header preimage or nonce. All arithmetic uses explicit `.wrapping_add()` and `.rotate_left()` on little-endian `u64` words (`pow.rs:120-141`). | **VERIFIED** |
| **Domain-separated BLAKE3 seed & finalize phases** | `crates/kovanica-types/src/pow.rs:62-65`, `98-107`, `153-167` | Seed phase uses `blake3::keyed_hash` with `KVNC-POW-SEED-v1` (`pow.rs:62,101`), expands buffer via `blake3::Hasher::new_keyed(&seed_bytes).finalize_xof()` (`pow.rs:105-106`), and finalizes under `KVNC-POW-FINL-v1` over `seed_bytes`, `state`, and boundary chunks `[0..32]` and `[2097120..2097152]` (`pow.rs:157-166`). | **VERIFIED** |
| **Cheap structural & clock checks BEFORE 2 MiB PoW hash** | `crates/kovanica-network/src/validation.rs:250-300`, `crates/kovanica-types/src/block.rs:590-645` | Gossip edge verifies `block.digest`, `merkle_root`, PoW header extraction, `header.parents.len() <= GHOSTDAG_K` (`5`), duplicate parent rejection, self-parent rejection, parent round ordering (`p.round < block.round`), and `block.round - p.round <= MAX_PARENT_ROUND_GAP` (`validation.rs:268-295`) *before* invoking `header.verify_pow_with_clock(now_ms)` (`validation.rs:297-299`). Inside `verify_pow_with_clock`, timestamp drift and compact target validity are checked before `kovanica_hash` is evaluated (`crates/kovanica-crypto/tests/audit_31_hot_path.rs`). | **VERIFIED** |

- **Key Tests:** `kovanica_hash_buffer_size_invariants`, `kovanica_hash_deterministic_and_reproducible`, `kovanica_hash_golden_vectors` (`crates/kovanica-types/src/pow.rs:185-238`); `crates/kovanica-crypto/tests/audit_31_hot_path.rs`; `crates/kovanica-network/src/validation.rs:1050-1120`; automated fuzz smoke parser/boundary suite (`fuzz/tests/smoke_tests.rs`, `scripts/run-fuzz-smoke.sh`, PR `#309`/`#310`).

---

### Area 2: `GHOSTDAG K=5` Committer & Non-Compounding LWMA DAA (`kovanica-consensus`, `kovanica-dag`, `kovanica-types`)

| Invariant / Check | Code Reference | Verification Details & Backing Tests | Status |
|---|---|---|---|
| **GHOSTDAG `K=5` deterministic colouring & tie-breaking** | `crates/kovanica-params/src/lib.rs:39`, `crates/kovanica-types/src/colouring.rs:44-87`, `130-225`, `crates/kovanica-consensus/src/ghostdag_scoped.rs:46-66` | `GHOSTDAG_K = 5`. `colour_mergeset` sorts blocks deterministically by `(b.round, b.digest.0)` (`colouring.rs:156`), selects `selected_parent` by highest `blue_score` with deterministic digest tie-breaking, and orders blue blocks via `blue_ordered()` where roots and child lists are sorted by `h.0` (`colouring.rs:67-70`), eliminating `HashMap` iteration non-determinism. | **VERIFIED** |
| **1/W non-compounding damping & LWMA difficulty controller (`#259`)** | `crates/kovanica-consensus/src/daa.rs:204-268`, `272-390` | `calculate_next_target_bits` applies $1/W$ sliding-window damping (`damped_num = (W - 1) * target_duration_ms + clamped_actual`, `damped_den = W * target_duration_ms`, `daa.rs:248-253`). `calculate_next_target_bits_lwma` (`daa.rs:322-390`) computes the 320-bit overflow-free arithmetic mean of window targets (`average_u256_targets`, `daa.rs:272-311`) and scales by linearly weighted solve times (`weight = i`), preventing exponential per-block compounding across the sliding window. | **VERIFIED** |
| **Per-interval timestamp clamping & min/max target bounds** | `crates/kovanica-consensus/src/daa.rs:341-388`, `crates/kovanica-params/src/lib.rs:37` | `TARGET_BLOCK_MS = 4_000`. Each interval solve time is clamped to `1..=target_block_time_ms * max_adjustment_factor` via `saturating_sub` (`daa.rs:351-354`), neutralizing backward timestamps (time-warp) and single-gap spikes. Final target is clamped between `min_target_bits` (`0x1e00_ffff` on testnet/devnet) and `max_target_bits` (`0x1f00_ffff` mainnet, `0x1f7f_ffff` testnet/devnet) (`daa.rs:379-388`). | **VERIFIED** |
| **Strictly NO stake or VRF leader election on hybrid chains** | `crates/kovanica-node/src/main.rs:6003-6019`, `crates/kovanica-consensus/src/engine.rs` | `use_vrf_leader`, validator-mempool wiring, and `TimeoutGossip` are gated on `!is_hybrid(chain_id)`; legacy Mysticeti constants in `kovanica-params` are marked `NON-CONSENSUS`. | **VERIFIED** |

- **Key Tests:** `crates/kovanica-consensus/src/daa.rs:530-699` (LWMA stability, gap recovery, clamping); `crates/kovanica-consensus/tests/hybrid_pow_simulation.rs`; `crates/kovanica-consensus/tests/adversarial_fork_tests.rs`.

---

### Area 3: `Wasmi` WASM Sandbox & Round-0 Active Hardening Gates (`kovanica-runtime`, `kovanica-execution`, `kovanica-dag`, `kovanica-params`)

| Invariant / Check | Code Reference | Verification Details & Backing Tests | Status |
|---|---|---|---|
| **Deterministic fuel metering & OOG full-limit burn** | `crates/kovanica-runtime/src/lib.rs:134-141`, `255-270` | `wasmi::Config::consume_fuel(true)` is enabled unconditionally (`lib.rs:138`). `store.set_fuel(config.gas_limit)` bounds execution (`lib.rs:256`). On `RuntimeError::OutOfGas`, `*gas_used = config.gas_limit` burns the entire allotment deterministically (`lib.rs:263-270`) while rolling back state changes (`crates/kovanica-execution/src/lib.rs:4323-4336`). | **VERIFIED** |
| **256-page (16 MiB) linear memory ceiling & trap-on-grow** | `crates/kovanica-params/src/lib.rs:127`, `crates/kovanica-runtime/src/lib.rs:240-254` | `DEFAULT_CONTRACT_MEMORY_PAGES = 256` (256 × 64 KiB = 16 MiB). `StoreLimitsBuilder::new().memory_size(256 * 65536).trap_on_grow_failure(true)` is attached via `store.limiter(...)` (`lib.rs:240-254`), preventing unbounded guest memory growth. | **VERIFIED** |
| **Host ABI boundary & packed return bounds check** | `crates/kovanica-runtime/src/lib.rs:45`, `234-238`, `326-354` | Argument copy is capped at `MAX_BUFFER_BYTES` (`lib.rs:234`). Packed `i64` return `(out_ptr, out_len)` validates `out_len <= MAX_BUFFER_BYTES` and `out_ptr.saturating_add(out_len) <= memory.data_size(&mut *store)` before `memory.read` (`lib.rs:339-350`), preventing integer-overflow or out-of-bounds host reads. Crate enforces `#![deny(unsafe_code)]` (`lib.rs:24`). | **VERIFIED** |
| **Round-0 activation of `P4-6` hardening gates (`#288`)** | `crates/kovanica-params/src/lib.rs:148-152`, `crates/kovanica-dag/src/block_manager.rs:36-37`, `233-248`, `crates/kovanica-execution/src/lib.rs:429-441` | `GAS_HARDENING_ACTIVE_FROM_ROUND = 0`, `CONTRACT_HARDENING_ACTIVE_FROM_ROUND = 0`, `SLASHING_ACTIVE_FROM_ROUND = 0`, `SIZE_LIMITS_ACTIVE_FROM_ROUND = 0` (`GENESIS_ROUND`). Enforces per-block `BLOCK_GAS_BUDGET = 80_000_000` (`MAX_TX_GAS_LIMIT * 8`), per-byte module compilation gas floor (`min_gas_for_module`), deploy bytecode & entry-point validation, and `MAX_TX_BYTES = 512 KiB` / `MAX_BLOCK_BYTES = 960 KiB` from round 0. (`STATE_COMMITMENT_ACTIVE_FROM_ROUND` remains `500_000`). | **VERIFIED** |

- **Key Tests:** `big_bytecode_tiny_gas_calls_are_rejected_from_genesis` (`crates/kovanica-execution/src/lib.rs:4343`); `size_limits_gate_is_enforced_from_genesis`, `size_limits_reject_a_block_over_the_block_cap_when_active` (`crates/kovanica-dag/src/block_manager.rs:1767-1822`); `crates/kovanica-params/src/lib.rs:200-212`.

---

### Area 4: Tokenomics, `NoStake82M` Supply Cap & PRO-53 Fee Split (`kovanica-params`, `kovanica-staking`, `kovanica-execution`, `kovanica-node`)

| Invariant / Check | Code Reference | Verification Details & Backing Tests | Status |
|---|---|---|---|
| **90,200,000 KVNC hard cap & `NoStake82M` budget** | `crates/kovanica-params/src/lib.rs:45-95`, `crates/kovanica-types/src/emission.rs:18-56` | `ONE_KVNC = 1_000_000_000` (9 decimals). Premine `200_000 KVNC` + Treasury `8_000_000 KVNC` (1M/yr × 8 linear vesting) + Genesis Validator Allocation `0 KVNC` + Mining Subsidy Budget `82_000_000 KVNC` (`NoStake82M`) = **90,200,000 KVNC**. Initial block reward `2.5 KVNC`, decaying by $\times 3/4$ every `8_200_000` rewarded blocks. | **VERIFIED** |
| **PRO-53 fee split (3/4 burn, 1/4 miner on chains 1 & 2; 100% burn on chain 3)** | `crates/kovanica-execution/src/lib.rs:478-555` | Under `NoStake82M` (chains 1 & 2), `miner_fee_share = fee_total / 4` is credited to the block author and `burn_fee_share = fee_total.saturating_sub(miner_fee_share)` (the remaining 3/4, including rounding remainder) is permanently burned and added to `fee_state.cumulative_fees_burned` (`lib.rs:539-551`). On devnet (chain 3), 100% of debited fees are burned (`lib.rs:514-518`). | **VERIFIED** |
| **Hybrid chain `NoStake82M` enforcement & Mainnet `funded_accounts.toml` refusal** | `crates/kovanica-node/src/main.rs:6003-6053`, `crates/kovanica-node/src/genesis_bundle.rs` | `ensure_emission_policy_matches_chain` refuses to boot chain 1 or 2 unless `emission_policy == NoStake82M`. Mainnet (`chain_id = 1`) refuses `funded_accounts.toml` at node startup, in `genesis-bundle`, and in `install.sh`. | **VERIFIED** |
| **Fail-closed staking refusal on hybrid chains (`#233`, `#272`)** | `crates/kovanica-execution/src/lib.rs`, `crates/kovanica-rpc/src/chain_methods.rs` | `Stake`, `Unstake`, `Delegate`, `ClaimRewards`, and `SetCommission` transactions are rejected in execution on chains 1 & 2, and legacy staking RPCs (`kovanica_getValidators`, `kovanica_getStake`, `kovanica_getLeaderSchedule`) return `RpcError::InvalidRequest` (`-32600`). | **VERIFIED** |

---

### Area 5: Cryptography, PRO-21 Address Checksum, 3-Chain Registry & Keystore v2 (`kovanica-crypto`, `kovanica-types`, `kovanica-keystore`)

| Invariant / Check | Code Reference | Verification Details & Backing Tests | Status |
|---|---|---|---|
| **Ed25519 strict verification (`verify_strict`)** | `crates/kovanica-types/src/crypto.rs:167-183` | Uses `ed25519_dalek::VerifyingKey::verify_strict`, rejecting non-canonical scalar $S$ values and small-order/weak public keys across all transaction and block signature checks (`crates/kovanica-crypto/tests/strict_vectors.rs`). | **VERIFIED** |
| **PRO-21 64-char base32 address & 29-bit BLAKE3 checksum** | `crates/kovanica-types/src/address.rs:8-37`, `85-165` | `kvnc` (4) + 57 lowercase bech32 chars (256-bit pubkey ‖ top 29 bits of `blake3(pubkey)`) + `dag` (3) = 64 chars. `legacy_address_allowed(chain_id)` (`address.rs:35-37`) permits legacy hex *only* on `chain_id::DEVNET` (`3`) and rejects it on Mainnet (`1`), Testnet (`2`), retired `1337`, and all other IDs. | **VERIFIED** |
| **3-chain registry (`1/2/3`) & fail-closed `1337` retirement (`#284`)** | `crates/kovanica-types/src/signing.rs:15-55`, `135-145` | `chain_id::is_registered(id)` accepts only `1` (`MAINNET`), `2` (`TESTNET`), and `3` (`DEVNET`). Chain ID `1337` (`LOCAL`) is removed and fails closed across node config validation, CLI signing, RPC, faucet, light-ffi, SDK (`kovanica-sdk#11`), Playground (`#12`/`#13`), Web (`#17`), and Apps (`#26`). | **VERIFIED** |
| **Keystore v2 (Argon2id + XChaCha20-Poly1305 + `0600` perms + `Zeroizing`)** | `crates/kovanica-keystore/src/lib.rs:29-36`, `111-215`, `crates/kovanica-keystore/src/perms.rs` | `KEYSTORE_VERSION = 2`, Argon2id (`64 MiB` KiB, `3` iterations, `4` lanes), random 16B salt + 24B XNonce, XChaCha20-Poly1305 AEAD binding `address`, `public_key`, `salt`, and `nonce` as AAD. Private seeds wrapped in `Zeroizing` and files written atomically with `0600` owner-only permissions. | **VERIFIED** |

---

### Area 6: Mempool Admission, RBF & Nonce Accounting (`kovanica-mempool`)

| Invariant / Check | Code Reference | Verification Details & Backing Tests | Status |
|---|---|---|---|
| **Admission size, signature, hash-binding & fee floors** | `crates/kovanica-mempool/src/lib.rs:380-520` | Enforces `MAX_TX_BYTES = 512 KiB`, `MAX_TX_GAS_LIMIT = 10_000_000`, `tx.hash == tx.signing_hash(chain_id)`, strict Ed25519 signature verification, and `fee_rate >= min_fee_rate` (`lib.rs:437-442`). | **VERIFIED** |
| **Replace-By-Fee (RBF) 10% minimum bump & cumulative balance check** | `crates/kovanica-mempool/src/lib.rs:490-515` | Replacing an existing same-sender, same-nonce transaction requires at least a 10% fee bump (`bump.max(1)`, `lib.rs:493-498`), and cumulative pending spend (`amount + fee`) across all queued nonces for a sender cannot exceed committed account balance. | **VERIFIED** |

- **Key Tests:** `mempool_rbf_and_eviction_tests` (`crates/kovanica-mempool/tests/`); `fuzz/tests/smoke_tests.rs` (transaction deserialization and malformed signature bounds).

---

### Area 7: P2P Network Anti-DoS & RPC Security Middleware (`kovanica-network`, `kovanica-rpc`)

| Invariant / Check | Code Reference | Verification Details & Backing Tests | Status |
|---|---|---|---|
| **P2P Gossipsub frame cap & network-tag isolation** | `crates/kovanica-network/src/lib.rs`, `crates/kovanica-network/src/network_id.rs` | Transport uses TCP port `8000` + Noise + Yamux; protocol and gossip topics bind `/kovanica/<network-tag>/1.0.0` (`2-24cdb5fadd98b207` on testnet). `MAX_TRANSMIT_SIZE = 1 MiB` bounds gossip frames above `MAX_BLOCK_BYTES = 960 KiB`. | **VERIFIED** |
| **Peer reputation tracker & Inbound socket IP ban gate (`#312`)** | `crates/kovanica-network/src/peer_scorer.rs`, `crates/kovanica-network/src/behaviour.rs:50-135` | Thread-safe `PeerScorer` assigns deterministic penalties: malformed frame (+50), invalid block/PoW (+100 instant ban), invalid tx signature (+25), rate limit flood (+20). Reaching `BAN_SCORE_THRESHOLD = 100` bans the IP for 15 minutes (`DEFAULT_BAN_DURATION`). `InboundGate` intercepts pending connections in libp2p and drops banned IPs immediately before allocating frame buffers, handshake cryptography, or protocol state. Automatic ban expiration and thread-safe ban maintenance. | **VERIFIED** |
| **RPC Bearer token write auth (constant-time, no loopback bypass)** | `crates/kovanica-rpc/src/rpc_middleware.rs:250-276` | `AuthConfig::authorize` requires `Authorization: Bearer <token>` on all `WRITE_METHODS` (`kovanica_sendRawTransaction`, `kovanica_submitWork`, etc.) when `require_auth_for_writes` is enabled, comparing every configured token via `constant_time_eq` without early exit (`rpc_middleware.rs:266-270`) and with no loopback bypass. | **VERIFIED** |
| **Per-IP token-bucket rate limiter & strict CORS allowlist** | `crates/kovanica-rpc/src/rpc_middleware.rs:124-145`, `288-360` | Per-IP `TokenBucket` with `MAX_TRACKED_CLIENTS = 100_000` and idle eviction (`rpc_middleware.rs:124-128`). Browser CORS is restricted to `CONSOLE_ALLOWED_ORIGINS` on `/rpc`, `/ws`, and `/health` (`rpc_middleware.rs:313-327`), leaving `/metrics` unexposed to cross-origin browsers. | **VERIFIED** |

- **Key Tests:** `crates/kovanica-network/tests/peer_reputation_scoring.rs` (reputation accumulation, ban threshold, socket gating, expiration); `crates/kovanica-rpc/tests/middleware_tests.rs`.

---

## Component Coverage Matrix

| Component | Key Files Reviewed | Open Findings | Verification Status |
|-----------|--------------------|---------------|---------------------|
| `kovanica-consensus` | `daa.rs`, `ghostdag_scoped.rs`, `engine.rs`, `committer.rs` | C:0 H:0 M:0 L:0 | **100% (Verified)** |
| `kovanica-types` & `kovanica-crypto` | `pow.rs`, `address.rs`, `signing.rs`, `crypto.rs`, `colouring.rs`, `block.rs` | C:0 H:0 M:0 L:0 | **100% (Verified)** |
| `kovanica-dag` | `block_manager.rs`, `ghostdag.rs` | C:0 H:0 M:0 L:0 | **100% (Verified)** |
| `kovanica-execution` & `kovanica-runtime` | `kovanica-runtime/src/lib.rs`, `kovanica-execution/src/lib.rs`, `contracts.rs` | C:0 H:0 M:0 L:0 | **100% (Verified)** |
| `kovanica-staking` & `kovanica-params` | `kovanica-params/src/lib.rs`, `kovanica-staking/src/lib.rs`, `emission.rs` | C:0 H:0 M:0 L:0 | **100% (Verified)** |
| `kovanica-mempool` | `kovanica-mempool/src/lib.rs` | C:0 H:0 M:0 L:0 | **100% (Verified)** |
| `kovanica-network` | `validation.rs`, `network_id.rs`, `lib.rs` | C:0 H:0 M:0 L:0 | **100% (Verified)** |
| `kovanica-keystore` | `kovanica-keystore/src/lib.rs`, `perms.rs` | C:0 H:0 M:0 L:0 | **100% (Verified)** |
| `kovanica-rpc` & `kovanica-faucet` | `rpc_middleware.rs`, `chain_methods.rs`, `kovanica-faucet/src/main.rs` | C:0 H:0 M:0 L:0 | **100% (Verified)** |
| `kovanica-node` | `main.rs`, `config.rs`, `genesis_bundle.rs`, `miner.rs` | C:0 H:0 M:0 L:0 | **100% (Verified)** |

---

## Informational Notes for External Auditor Handoff

1. **`KOVANICA-I-001` — `STATE_COMMITMENT_ACTIVE_FROM_ROUND` remains at `500_000` (`crates/kovanica-params/src/lib.rs:151`):**
   - While `GAS`, `CONTRACT`, `SLASHING`, and `SIZE_LIMITS` hardening gates were flipped to `GENESIS_ROUND` (`0`) in `#288` (`P4-6`), `STATE_COMMITMENT_ACTIVE_FROM_ROUND` intentionally remains at `500_000` so live `seed1` (`kovanica-testnet`, chain ID 2) headers below round `500_000` remain compatible without forcing an unscheduled testnet re-genesis. External auditors should confirm whether `STATE_COMMITMENT_ACTIVE_FROM_ROUND` should also be set to `0` prior to the Mainnet (`chain_id = 1`) genesis ceremony.
2. **`KOVANICA-I-002` — Legacy Mysticeti constants retained as `NON-CONSENSUS` (`crates/kovanica-params/src/lib.rs`):**
   - Legacy constants (`WAVE_LENGTH`, `EPOCH_ROUNDS`, `MIN_VALIDATOR_STAKE`, `JAIL_ROUNDS`) remain compiled in the workspace for devnet/test compatibility but are strictly gated off on hybrid chains (`chain_id::is_hybrid(1 | 2)`).

---

## Unsafe Code Inventory

| Crate | Location | Purpose | Reviewed |
|-------|----------|---------|----------|
| `kovanica-multisig` | `args_slice` (WASM guest) | Guest FFI pointer slice | [x] |
| `kovanica-token` | `args_slice` (WASM guest) | Guest FFI pointer slice | [x] |
| `kovanica-vault` | `args_slice` (WASM guest) | Guest FFI pointer slice | [x] |
| `kovanica-htlc` | `args_slice` (WASM guest) | Guest FFI pointer slice | [x] |
| `crates/kovanica-common/src/wasm.rs` | Guest ABI helpers | WASM guest FFI | [x] |
| `kovanica-light-ffi` | `uniffi` scaffolding | Mobile/desktop FFI bindings | [x] |

*All host runtime and consensus crates (`kovanica-runtime`, `kovanica-keystore`, etc.) enforce `#![deny(unsafe_code)]`.*

---

*Prepared for external auditor dispatch per [`docs/AUDITOR-INVITATION.md`](AUDITOR-INVITATION.md) and [`docs/AUDIT-SCOPE.md`](AUDIT-SCOPE.md).*
