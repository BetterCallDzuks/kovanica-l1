# STATE — living source of truth

**Tip:** `833e7e9caa46d696402968567a67bfc95e2ac260` (2026-11-17, current `main` post-`#283`–`#289`, code tip `6bcca8630f97d7c9e599fe51b70c4d29a2766d8b`; cross-repo `main` tips: `kovanica-sdk#11` `b534224`, `kovanica-playground#12` `e620025` & `#13` `0dd469d`, `kovanica-web#17` `b2fe0be`, `kovanica-apps#24` `67dc47f`, `#25` `305df94` & `#26` `be4baae`. Live `seed1` `kovanica-testnet` (chain ID 2) remains on `9758ffe0d0129dd58851d916d183753618fd71de` as an empty-volume re-genesis that **activates the non-compounding DAA (#259)** — network tag `2-24cdb5fadd98b207` (live re-genesis 2026-11-17), and live faucet `kvnc8a4atp0g5tngcua9h90anhel7233alyd5y88h0yc592cv8adu5uyz46d3dag` is funded via live mining payout (`P3-5` Done). Tag `v0.3.0-node` stays on `e3fce499afe6637b2a594b60306aef6312ef4bbf` with `kovanica-testnet-genesis.tar.gz` attached (`#283`/`#287`); agent SoT docs remain `docs/AGENT-RULES.md`, `docs/PLAN-2026-11.md`, and `docs/PLAN-FULL-SCOPE.md`; prior living tips `6bcca86`, `9758ffe0`, `e3fce499`, `9029514b448fd825cd9f19f6d72885974bc3340a`, `7b5b5a7`, `d0b129639150e114d88d6d97336cb82546ae4f76`, `89394a2da7d9fb119072aacd1ff7997f0e3225c4`, `559cc2014592e1c621da2df78d9671e7476972d1`).
Update this file when frozen params or open product gaps change. Point-in-time dumps live under `docs/archive/`; they are not SoT.

## Active Priority: Hybrid PoW + GHOSTDAG (P0–P8)

- **Consensus Direction (Toni 2026-11-05):** Hybrid PoW + GHOSTDAG. **NO stake for consensus**.
- **Priority Rank:** Hybrid PoW + GHOSTDAG phases P0–P8 rank strictly above PRO-6, PRO-14, and Gate leftover 20/36/7.
- **PRO-7:** **FROZEN** for hybrid (Mysticeti VRF leader path dead under hybrid PoW + GHOSTDAG).
- **Public Launch:** Public launch planned for 1.1.2027.
- **PoW Hash:** Planned PoW hash name is **KovanicaHash** (strictly NOT KunaHash; blake3 + 2 MiB memory mix; audit required before mainnet).
- **Consensus Defaults:** `TARGET_BLOCK_MS = 4000`, `GHOSTDAG_K = 5`.
- **Product Ticker:** **KVNC** (renamed back from KUNA per Toni 2026-11-05).
- **DAA (#259, non-compounding LWMA):** **LIVE on `seed1` `kovanica-testnet` (chain ID 2) since `9758ffe0`** (2026-11-16 empty-volume re-genesis, Toni-approved activation). Network tag unchanged; no height gate was needed.
- **Re-genesis 2026-11-17 (empty-volume):** Seed1 `kovanica-testnet` (chain ID 2) re-genesis on L1 `fecc84c` (KVNC/* domain tags active). Live network tag `2-24cdb5fadd98b207`. Cluster: node1/node2/node3 + observer + faucet + prometheus + grafana; `/health` 200 OK, `peer_count=3`, faucet active on port 3000. Previous frozen tag `2-24cdb5fadd98b207` is retired. Genesis files byte-identical to prior tree; new tag reflects the new genesis block. The 20-minute post-activation sample committed 226 leaders at 5.42 s mean interval with no stall >60 s (pre-activation the chain sat on ~55 s PoW waits and `/health` 503). Follow-up P3-1 read-only sample (2026-11-17T02:07Z): heights `6652..7552` (901 blocks over 5197.5 s = 1.44 h) — median 4.42 s, mean 5.78 s, max 42.86 s, 0 stalls >60 s (6 gaps >30 s), `/health` 200 (`peer_count=3`, `committed_leaders=7502`, `last_committed_round=6213`). Not yet live on any other chain.

## Canonical chains (Hybrid PoW + GHOSTDAG)

- kovanica-mainnet (chain ID 1) and kovanica-testnet (chain ID 2) are both Hybrid PoW + GHOSTDAG (`NoStake82M`). kovanica-devnet (chain ID 3) is the single dev/local chain (`1337` `local` was retired and merged into devnet `3` in `#284`, and former chain ID `4` Testnet v2 was removed).
- kovanica-testnet (chain ID 2). Canonical Hybrid PoW + GHOSTDAG public testnet (`NETWORK_TAG_TESTNET = NETWORK_TAG_HYBRID_TESTNET = "kovanica-testnet"` in `kovanica-params`; P2P/RPC wire `networkTag` is `<chain_id>-<16 hex genesis digest>`). Canonical PRO-21 base32 addresses only; legacy hex rejected.
- Network tag form (wire / RPC `kovanica_syncStatus.networkTag`): `<chain_id>-<16 hex genesis digest>` (see `docs/TESTNET-SEED-NODES.md` for topology).
- Launch gating: public launch planned for 1.1.2027.
- Genesis bootstrap seeds: **1..=20** on kovanica-mainnet (chain ID 1) and kovanica-testnet (chain ID 2); they hold no stake (`NoStake82M`).
- Ordering default: GHOSTDAG (lifted k=3 hard-lock in P0 to allow `GHOSTDAG_K = 5`).
- Topology, seeds, and ops runbooks: `docs/TESTNET-SEED-NODES.md`, `docs/TESTNET-RESET.md`, `docs/MINING.md`. Do not treat archived `sync-*.md` tables as live inventory.

## Frozen protocol params (code-true decisions)

| Topic | Value |
| --- | --- |
| Coin | KVNC, **9** decimals (`ONE_KVNC = 10^9`) |
| Consensus | Hybrid PoW + GHOSTDAG (NO stake in consensus path; `TARGET_BLOCK_MS = 4000`, `GHOSTDAG_K = 5`; PoW: KovanicaHash) |
| Cap / subsidy sketch | 90.2M total; mining budget 82M; treasury 8M; genesis bootstrap-seed allocation 0 (1M folded into mining); founder premine 200k |
| Fee split | 3/4 burned, 1/4 miner on kovanica-mainnet (chain ID 1) and kovanica-testnet (chain ID 2); 100% burned on kovanica-devnet (chain ID 3) |
| DAA targets | kovanica-mainnet (chain ID 1) easiest `0x1f00_ffff`; kovanica-testnet (chain ID 2) and kovanica-devnet (chain ID 3) easiest `0x1f7f_ffff`, hardest `0x1e00_ffff` |
| Address | `kvnc` + 57 bech32-alphabet base32 + `dag` (**64** chars); 32 B Ed25519 ‖ 29-bit blake3 checksum. Legacy hex only on kovanica-devnet (chain ID 3) (`1337` retired in `#284`) |
| Epoch (legacy) | **7200** DAG rounds ≈ 8 h ≈ **2400** leader heights (legacy Mysticeti constant still in tree until hybrid flag) |
| Jail (legacy) | `JAIL_ROUNDS = 7200` committed leaders (legacy / non-consensus under hybrid) |
| Min validator stake (legacy) | `50_000` KVNC (`MIN_VALIDATOR_STAKE = 50_000 * ONE_KVNC`; legacy / non-consensus) |
| Min delegation (legacy) | `50_000` KVNC (`MIN_DELEGATION = 50_000 * ONE_KVNC`; legacy / non-consensus) |
| `funded_accounts.toml` / `genesis_validators.toml` | Legacy file names (accounts are mining-reward / faucet / bootstrap-seed entries, not validators). `funded_accounts.toml` allowed on every chain **except** kovanica-mainnet (chain ID 1) |
| Hash / sig domains | `KVNC-*` / `KVNC/*` crypto context tags (KUNA-* retired) |

Hardening gates (`*_ACTIVE_FROM_ROUND`: gas, contract, size limits, slashing) are `0` (`GENESIS_ROUND`) in tree since `P4-6` (`#288`, 2026-11-17), so fresh genesis / empty-volume re-genesis chains enforce them from round 0 (`STATE_COMMITMENT_ACTIVE_FROM_ROUND` stays `500_000`). Live seed1 (chain ID 2, deploy SHA `9758ffe0`) still runs the pre-flip build, so they remain inert there until an empty-volume re-genesis; seed1 is **not** re-deployed unless Toni orders it.

- **Mainnet (chain ID 1) genesis ceremony (P4-3) executed 2026-11-17.** Network tag `1-f35df34c92001436`. Bundle `/tmp/kovanica-mainnet-genesis.tar.gz` sha256 `d0ac07ba0bbe7fff87f3a7713a19239ceebb201944b4984d579a1f5f60edd7bf` (files: `genesis_validators.toml`, `founder_premine.hex`). Public genesis files committed under `mainnet/` (5 seeds, founder `kvnc2yuz...`, treasury `kvncd2xk...`). `funded_accounts.toml` absent (forbidden on chain 1). Keystores/passphrases remain in `/tmp/mainnet-ceremony-private` (never committed).

## Open product gaps (not archived noise)

1. Ops drift (live fleet cutover): VPS systemd units & migration script prepared in `ops/systemd/` and `scripts/cutover-vps-systemd.sh` (live cutover execution pending VPS Seed Ops deploy); DNS seed audit probe automated in `scripts/check-dns-seeds.sh` (`docs/SEED-DNS-AUDIT.md`).
2. External security review (formal external audit sign-off of `v1.0.0-mainnet` covering KovanicaHash and Wasmi sandbox; comprehensive internal pre-audit report completed in `docs/INTERNAL_PRE_AUDIT_2026_11.md` alongside `docs/AUDIT-CHECKLIST.md`, `docs/AUDIT-SCOPE.md`, `docs/AUDITOR-INVITATION.md`, and `docs/AUDIT_REPORT.template.md` — `#278`, `#286`, `#289`; ready for external auditor sign-off).
3. Production Key Ceremony & Launch ($T_0 - 48\text{h}$): Live key collection and final distribution for 15–20 mainnet bootstrap operators via `ops/genesis/ceremony.sh` per `docs/KEY-CEREMONY.md` and `docs/MAINNET-RUNBOOK.md`.
4. kovanica-testnet (chain ID 2) genesis bundle publication (`P3-2` / `P4-5`) — **DONE (`#283`, `#287`)**: `kovanica-testnet-genesis.tar.gz` (`747` bytes, `sha256: a2c5ed9213a25cd3ed2ca99a1db80dc8d9403856d27e0f84916d3e253ddaebee`, `expected-tag: 2-24cdb5fadd98b207`) cut from `testnet/chain2/` with canonical naming (`#283`) and uploaded to release `v0.3.0-node` (`#287`), enabling `node/scripts/install.sh` for chain 2 (`node/README.md`).
5. kovanica-testnet (chain ID 2) faucet funding after re-genesis (`P3-5`, ops) — **DONE (resolved on `seed1` via live mining payout to `kvnc8a4atp0g5tngcua9h90anhel7233alyd5y88h0yc592cv8adu5uyz46d3dag`)**:
   - Live faucet `kvnc8a4atp0g5tngcua9h90anhel7233alyd5y88h0yc592cv8adu5uyz46d3dag` has been funded above its `--min-balance-ku 100` floor on `seed1` via live mining payout (Path C1 in `docs/FAUCET-FUNDING.md` `#287`), without touching `testnet/chain2/funded_accounts.toml` or the frozen network tag `2-24cdb5fadd98b207` (retired by re-genesis `2-24cdb5fadd98b207`).
   - Secret hygiene (`P3-6` **Done in `#285`**): `ops/docker/chain2/faucet.keystore`, `faucet_passphrase`, and `node1_p2p.key` have been untracked from git, added to `.gitignore`, and their misleading `.gitleaks.toml` "test fixture" allowlist entries removed (see `ops/docker/chain2/README.md` and `docs/FAUCET-FUNDING.md`).

**Done / frozen, do not re-open as missing:**
- Mainnet Freeze & Gate Sign-Off (Phases C1–C3): Audit scoping updated (`docs/AUDIT-SCOPE.md`), genesis key ceremony streamlined (`ops/genesis/ceremony.sh`), bootstrap seed bounds relaxed to `1..=20`, byte-for-byte deterministic genesis validated (`2f46c80940dc5226f8f25aad6eff428c3cd58c7fb505cf9861ad63db4cdbabc9`), soak pre-flight verification passed (monotonic height growth, 0 OOM kills under 2 GB limit), Gates 1–6 signed off in `docs/MAINNET-FREEZE-CHECKLIST.md`, and release tag `v1.0.0-mainnet` tagged on `main`.
- Automated CI pipeline: fmt, clippy, doc lint, workspace tests, cargo-deny (licenses/advisories/bans/sources), gitleaks 8.24.3 (`.github/workflows/ci.yml`, `scripts/ci-local.sh`).
- BIP32 HD derivation (`kovanica-wallet-core`), soak harness (`ops/soak/`), DNS audit probe (`scripts/check-dns-seeds.sh`), and mainnet runbook (`docs/MAINNET-RUNBOOK.md`). Note: legacy stake-weighted governance (`propose`/`vote`) was removed under no-stake Hybrid PoW + GHOSTDAG (`TASKLIST.md:33`).
- PRO-7 (Mysticeti VRF leader set + pin): **FROZEN** for hybrid.
- Hybrid PoW + GHOSTDAG P1–P8 & Milestone M8 (PoW header primitives, preimages, target conversion, kovanica-testnet (chain ID 2) wiring, KovanicaHash BLAKE3+2MiB algorithm, header verification, CPU mining worker, DAA, P2P network anti-DoS ingress, GHOSTDAG k=5 committer, 2.5 KVNC reward minting, node miner loop, JSON-RPC getWork/submitWork/miningInfo/dagTips, CLI mining/dag commands, Prometheus metrics, live 3-node cluster integration test suite, faucet alignment, ops templates). Milestone M8 PASSED.
- Contract SDK (`crates/kovanica-contract-sdk`) and Indexer (`crates/kovanica-indexer`).
- Staking transaction refusal on hybrid chains: `Stake`, `Unstake`, `Delegate`, `ClaimRewards`, and `SetCommission` transactions are explicitly refused on hybrid chains kovanica-mainnet (chain ID 1) and kovanica-testnet (chain ID 2) (`HYBRID_STAKE_REFUSAL` in `kovanica-execution`).
- Node installer (`node/scripts/install.sh`) is chain-agnostic (#225): `--chain-id` (default 2), bundle asset derived from the chain id, expected tag from `--expected-tag`/`KOVANICA_EXPECTED_TAG` or an `expected-tag` file inside the checksum-verified bundle, fail-closed when unpinned, `--skip-tag-check` as the explicit opt-out, kovanica-mainnet (chain ID 1) `funded_accounts.toml` refusal, and no legacy Mysticeti knobs in the generated config.
- Genesis bundle writer (`kovanica-node genesis-bundle`, #226): deterministic hand-written ustar tar + stored-deflate gzip (no compression dependency), allowlist of genesis files, `SHA256SUMS` and `expected-tag` inside the archive, refusals for unregistered chains, non-genesis files, a `chain_id` mismatch and mainnet `funded_accounts.toml`; tag computed from the files plus `--chain-id` only (no `KOVANICA_*` overrides).
