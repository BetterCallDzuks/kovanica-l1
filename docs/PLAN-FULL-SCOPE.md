# PLAN-FULL-SCOPE — Kovanica ecosystem work plan

**Companion to `docs/AGENT-RULES.md` and `docs/PLAN-2026-11.md`.**
This is the full-scope plan across all public product repos. Frozen values stay frozen. Consensus changes need an activation plan and Toni’s OK before deploy.

Snapshot: 2026-11-21 (L1 `main` at `e72d8e1`, post-#308–#322; cross-repo `main` tips: `kovanica-sdk#17` `83a6495` (v0.3.0), `kovanica-playground#22` `391dd88`, `kovanica-web#24` `772ccbb`, `kovanica-apps#36` `633f130`).
Live L1: `seed1` (`kovanica-testnet`, chain ID 2, tag `2-24cdb5fadd98b207`) live at `9758ffe0` with `#259` non-compounding LWMA DAA active; release tag `v0.3.0-node` stays on `e3fce499` with `kovanica-testnet-genesis.tar.gz` attached (`#283`/`#287`). Mainnet (`kovanica-mainnet`, chain ID 1) genesis ceremony executed in `#290` with frozen network tag `1-f35df34c92001436` and bundle `kovanica-mainnet-genesis.tar.gz` (`sha256: 75403dff7380c3066b479b80c8b7ae37b7df165fa2283a5cbf6fa4e2be554c2e`).

## Repos in scope

| Repo | Role | Default branch | Notes |
|------|------|----------------|-------|
| `kovanica-l1` | Rust L1 (consensus, node, faucet, Wasmi, light-ffi) | main | Source of truth for protocol |
| `kovanica-web` | Public site kovanica.online (TanStack Start) | main | Private repo; no secrets in commits |
| `kovanica-sdk` | TypeScript client & HD wallet toolkit | main | v0.3.0 release; SLIP-0010, contract builders & tx signing |
| `kovanica-apps` | Android / iOS / desktop / wallet-web clients | main | FFI stays in L1 |
| `kovanica-playground` | Developer console / RPC explorer | main | Pins a specific SDK SHA |

Out of this plan: `kovanica-vault` (separate private tool).

## Cross-repo rules

- L1 owns consensus, genesis, tokenomics, light-ffi, node binary.
- Apps and web never reintroduce light-ffi or consensus code.
- SDK implements canonical Wasmi smart contract call builders, SLIP-0010 key derivation, and RFC 8032 Ed25519 signing under `KVNC/tx/v1` (post-v0.3.0).
- Playground and web consume SDK; they do not talk to seed1 docker directly.
- No force-push, no self-merge, no secrets, no seed1 volume changes unless the prompt is an explicit ops task.
- DAA #259 is merged but **not activated**. Do not deploy it until Toni chooses empty-volume re-genesis or a height gate.

## P0 — Live L1 (do not break seed1)

| ID | Item | Repo | Status |
|----|------|------|--------|
| P0-1 | Keep seed1 on `e3fce499` until DAA activation | l1 / ops | Live |
| P0-2 | Tag `v0.3.0-node` on that SHA | l1 | Done |
| P0-3 | Document DAA oscillation | l1 | Done (#259 investigation) |

## P1 — DAA activation (consensus, Toni decides)

| ID | Item | Repo | Status |
|----|------|------|--------|
| P1-1 | Non-compounding DAA on main | l1 | Merged #259 |
| P1-2 | Choose activation: empty-volume re-genesis **or** height gate | l1 / Toni | Open |
| P1-3 | Deploy only after OK | ops | Blocked |

## P2 — L1 docs and tip hygiene

| ID | Item | Repo | Status |
|----|------|------|--------|
| P2-1 | AGENT-RULES + PLAN-2026-11 | l1 | Merged #260 |
| P2-2 | KEY-CEREMONY + MAINNET-RUNBOOK rewrite | l1 | PR #261 |
| P2-3 | STATE tip = tag applied + agent docs | l1 | PR #262 |
| P2-4 | This full-scope plan | l1 | This PR |

## P3 — L1 ops / faucet / install polish

| ID | Item | Repo | Notes |
|----|------|------|-------|
| P3-1 | Multi-hour height watch & multi-node soak test | ops | **Done (#277, soak verified)** — 10m multi-node cluster soak (`ops/soak/run-soak.sh --duration 10m`) passed: heights advancing in lockstep across 3 peered nodes (3 -> 138, 3 -> 140, 3 -> 141; +138 blocks), 0 container OOM kills (`oom_killed == false`), peak RSS 22.67 MiB per node (budget 2048 MiB), avg tx latency 1.37 ms (p95 2.37 ms, p99 5.33 ms); 2026-11-17 sample `6652..7552` (901 blocks / 1.44 h), 0 gaps >60 s |
| P3-2 | Genesis bundle (`kovanica-testnet-genesis.tar.gz`) on a node release for `install.sh` | l1 | **Done (#283, #287, Toni OK)** — `/tmp/kovanica-testnet-genesis.tar.gz` (`sha256: a2c5ed9213a25cd3ed2ca99a1db80dc8d9403856d27e0f84916d3e253ddaebee`, `expected-tag: 2-24cdb5fadd98b207`) attached to release `v0.3.0-node` |
| P3-3 | Faucet stays sequential under load | l1 | **Done (#279)** — concurrent nonce serialization & fail-closed IP/address limit tests |
| P3-4 | Safe nginx Authorization check (from #257) | ops | Docs already merged |
| P3-5 | Fund the rotated chain-2 faucet after re-genesis | l1/ops | **Done on `seed1` (#287, #291)**: live faucet `kvnc8a4atp0g5tngcua9h90anhel7233alyd5y88h0yc592cv8adu5uyz46d3dag` funded above the 100 KVNC floor via live mining payout on `seed1` (`docs/FAUCET-FUNDING.md`) |
| P3-6 | Untrack `ops/docker/chain2/{faucet.keystore,faucet_passphrase,node1_p2p.key}` and fix the `.gitleaks.toml` "test fixture" allowlist | l1 | **Done (#285, Toni OK)** — untracked in git, gitignored, and misleading allowlist entries removed |

## P4 — Mainnet preparation (frozen params unchanged)

| ID | Item | Repo | Status |
|----|------|------|--------|
| P4-1 | Ceremony docs for PoW + no-stake | l1 | **Done (#261)** |
| P4-2 | Mainnet runbook for PoW + no-stake | l1 | **Done (#261)** |
| P4-3 | Offline genesis ceremony (addresses OPEN) | Toni | **Done (#290, Toni OK)** — executed 2026-11-17: frozen network tag `1-f35df34c92001436`; bundle `/tmp/kovanica-mainnet-genesis.tar.gz` (`sha256: 75403dff7380c3066b479b80c8b7ae37b7df165fa2283a5cbf6fa4e2be554c2e`); public genesis files under `mainnet/` (5 seeds); keystores in `/tmp/mainnet-ceremony-private` (never committed) |
| P4-4 | External audit of KovanicaHash + Wasmi | l1 | **IN PROGRESS** — syncing `docs/INTERNAL_PRE_AUDIT_2026_11.md` and companion audit dossier docs to latest `main` (`e72d8e1`, post-#308–#322); internal pre-audit complete (#291, #313, #315), ready for external auditor sign-off |
| P4-5 | Attach chain-2 genesis bundle (`kovanica-testnet-genesis.tar.gz`) to a node release | l1 | **Done (#287, Toni OK)** — `kovanica-testnet-genesis.tar.gz` (`sha256: a2c5ed9213a25cd3ed2ca99a1db80dc8d9403856d27e0f84916d3e253ddaebee`) uploaded to `v0.3.0-node` |
| P4-6 | Height-gated hardening (`*_ACTIVE_FROM_ROUND`) | l1 | **Done (#288, Toni OK)** — gas, contract, size-limit, and slashing gates set to `0` (`GENESIS_ROUND`) |

## P5 — L1 codebase polish (non-consensus)

| ID | Item | Notes |
|----|------|-------|
| P5-1 | Stubs (codec, consensus-sim, governance, hw-signer, oracle, sync) | Leave unless assigned |
| P5-2 | Legacy Mysticeti constants | Keep; do not re-activate |
| P5-3 | `ONE_KUNA` alias removed (renamed to `ONE_KVNC`) | **Done** | All uses in `crates/` renamed; alias removed from `kovanica-params` and `kovanica-staking` |
| P5-4 | Contract crates polish | No tokenomics changes |
| P5-5 | Wasmi fuel / memory | Do not raise without Toni (2–4 GB target) |

## P6 — SDK (kovanica-sdk)

Current state: TypeScript SDK client (`main` at `83a6495`, post-#17, v0.3.0 release). Enforces canonical 3-chain registry (`1` mainnet, `2` testnet, `3` devnet; `1337` retired in `#11`), documents `-32600` (`InvalidRequest`) rejection of legacy staking RPCs, and provides full `KovanicaWallet` SLIP-0010 HD key derivation (`m/44'/3007'/0'/0/0`), RFC 8032 Ed25519 signing under `KVNC/tx/v1`, canonical Wasmi contract call builders (Name Registry, HTLC, NFT, Escrow, Token, Vault), and `sendRawTransaction` broadcasting (#16, #17).

| ID | Item | Status / Notes |
|----|------|----------------|
| P6-1 | Re-verify RPC methods against current L1 main | Done (`#8` `039d0e8`, `#9` `5aa4f34`, `#10` `9a8a2045` citing L1 `de641f6`) |
| P6-2 | Confirm hybrid methods (`getMiningInfo`, `getDagTips`) match live chain 2 | Done (`#10` `9a8a2045` + deterministic transport tests) |
| P6-3 | Canonical contract builders & signing support | Done (`#16` `76cbd85`, `#17` `83a6495`, v0.3.0 release) |
| P6-4 | Chain registry stays 1/2/3 (`1337` retired) with frozen address rules | Done (`#11` `b534224`) |
| P6-5 | Publish or document how web/playground should pin a SHA | Done (`#10` / playground `#10`, `#13` `0dd469d`, `#17` `83a6495`) |

## P7 — Playground (kovanica-playground)

Current state: `main` at `a8909db` (PR `#21` merged, expands Wasmi contract builders and interactive console for Name Registry, HTLC, NFT, and Escrow; pins `kovanica-sdk` `76cbd85`). Read-only, no keys, no faucet, no mining submit.

| ID | Item | Status / Notes |
|----|------|----------------|
| P7-1 | After SDK update, bump the pinned SHA and re-run CI | Done (`#9`, `#10` `f7b2892`, `#11` `9aabda4`, `#12` `e620025`, `#13` `0dd469d`, `#21` `a8909db`) |
| P7-2 | Point default testnet endpoint at public testnet only if CORS and auth are confirmed | Open (no seed1 docker changes) |
| P7-3 | Keep zero-key boundary | Active boundary |

## P8 — Web (kovanica-web)

Current state: TanStack Start site for kovanica.online (`main` at `057e4eb`, PR `#23` merged). Features Explorer Smart Contract Call Decoding with `BincodeReader` and `ExplorerTxCard` for canonical entry points, vendored `@kovanica/sdk-wasm`, env-driven config, and no secrets in repo.

| ID | Item | Status / Notes |
|----|------|----------------|
| P8-1 | Align public copy with live testnet (chain 2, tag, no stake, 3-chain registry 1/2/3) | Done (`#14` `1366018`, `#15` `b5ddb18`, `#17` `b2fe0be`) |
| P8-2 | Confirm explorer / health links match deployed endpoints | Done (`#14` / `#15` `b5ddb18`, no nginx edits; `#16` `66d2c0a` fixes stale-build test harness) |
| P8-3 | Explorer Smart Contract Call Decoding | Done (`#23` `057e4eb`) |
| P8-4 | Brand assets stay consistent with L1 palette (ink / copper / paper) | Done (`#14` `1366018`) |

## P9 — Apps (kovanica-apps)

Current state: Android (wallet, comms, chain, node), iOS light client, desktop / console-desktop / node-desktop (Tauri), wallet-web (`main` at `633f130`, PR `#36` merged). Wallet-web supports canonical contract call dispatch for Name Registry, NFT Minting, and Escrow using `kovanica-sdk` v0.3.0. FFI stays in L1.

| ID | Item | Status / Notes |
|----|------|----------------|
| P9-1 | Fix sibling paths to `KovanicaDAG/kovanica-l1` & align with L1 `main` | Done (`#22` `92f2d904`, `#23` `86ad7d89`, `#24` `67dc47f`, `#25` `305df94`, `#26` `be4baae`) |
| P9-2 | Android-node: confirm testnet chain 2 + network tag | Done (`#21` `6ba74fb1`, `#24` `67dc47f`, `#26` `be4baae`) |
| P9-3 | Wallet-web: consume current SDK contract builders | Done (`#36` `633f130`) |
| P9-4 | node-desktop: document pointing at a self-built `kovanica-node` | Done (`#19`, `#20` `37ec0290`, `#26` `be4baae`) |
| P9-5 | Do not move light-ffi into this repo | Active boundary |

## Explicit non-goals

- Changing total supply, premine, treasury, reward, era, decay, block time, GHOSTDAG k, or network tag
- Re-introducing stake into consensus
- Deploying #259 without an activation decision
- Adding signing or key handling to SDK or playground without a design
- Moving light-ffi out of L1
- Force-push, self-merge, or seed1 volume changes without an explicit ops prompt

## How agents use this plan

1. Read `docs/AGENT-RULES.md` first.
2. Pick one open item that matches your role and does not collide with another agent’s current PR.
3. Consensus or deploy work stops at a plan until Toni says activate.
4. After merge, update this file or STATE in a follow-up docs PR.
