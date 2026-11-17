# PLAN-FULL-SCOPE — Kovanica ecosystem work plan

**Companion to `docs/AGENT-RULES.md` and `docs/PLAN-2026-11.md`.**
This is the full-scope plan across all public product repos. Frozen values stay frozen. Consensus changes need an activation plan and Toni’s OK before deploy.

Snapshot: 2026-11-17 (L1 `main` at `6bcca86` / `6bcca8630f97d7c9e599fe51b70c4d29a2766d8b`, post-#272–#288; cross-repo `main` tips: `kovanica-sdk#11` `b534224`, `kovanica-playground#12` `e620025` & `#13` `0dd469d`, `kovanica-web#17` `b2fe0be`, `kovanica-apps#24` `67dc47f`, `#25` `305df94` & `#26` `be4baae`).
Live L1: `seed1` (`kovanica-testnet`, chain ID 2, tag `2-acfdf6a6c80fd28a`) live at `9758ffe0` with `#259` non-compounding LWMA DAA active; release tag `v0.3.0-node` stays on `e3fce499` with `kovanica-testnet-genesis.tar.gz` attached (`#283`/`#287`).

## Repos in scope

| Repo | Role | Default branch | Notes |
|------|------|----------------|-------|
| `kovanica-l1` | Rust L1 (consensus, node, faucet, Wasmi, light-ffi) | main | Source of truth for protocol |
| `kovanica-web` | Public site kovanica.online (TanStack Start) | main | Private repo; no secrets in commits |
| `kovanica-sdk` | TypeScript read-only client | main | Preview only; no signing yet |
| `kovanica-apps` | Android / iOS / desktop / wallet-web clients | main | FFI stays in L1 |
| `kovanica-playground` | Developer console / RPC explorer | main | Pins a specific SDK SHA |

Out of this plan: `kovanica-vault` (separate private tool).

## Cross-repo rules

- L1 owns consensus, genesis, tokenomics, light-ffi, node binary.
- Apps and web never reintroduce light-ffi or consensus code.
- SDK stays read-only until a dedicated signing design is approved.
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
| P3-1 | Multi-hour height watch after any future deploy | ops | **Done (#277)** — 2026-11-17 sample `6652..7552` (901 blocks / 1.44 h), median 4.42 s, mean 5.78 s, max 42.86 s, 0 gaps >60 s |
| P3-2 | Genesis bundle (`kovanica-testnet-genesis.tar.gz`) on a node release for `install.sh` | l1 | **Done (#283, #287, Toni OK)** — `/tmp/kovanica-testnet-genesis.tar.gz` (`sha256: 0892ff8056b1a4d999141752d258750b02be7e141ae0e742b1721b3d2bcfd38a`, `expected-tag: 2-acfdf6a6c80fd28a`) attached to release `v0.3.0-node` |
| P3-3 | Faucet stays sequential under load | l1 | **Done (#279)** — concurrent nonce serialization & fail-closed IP/address limit tests |
| P3-4 | Safe nginx Authorization check (from #257) | ops | Docs already merged |
| P3-5 | Fund the rotated chain-2 faucet after re-genesis | l1/ops | **Path C runbook ready (#287, approved by Toni)**: exact operator steps to generate gitignored `ops/docker/chain2/faucet.keystore` + `faucet_passphrase` and fund from a miner payout address on `seed1` in `docs/FAUCET-FUNDING.md` |
| P3-6 | Untrack `ops/docker/chain2/{faucet.keystore,faucet_passphrase,node1_p2p.key}` and fix the `.gitleaks.toml` "test fixture" allowlist | l1 | **Done (#285, Toni OK)** — untracked in git, gitignored, and misleading allowlist entries removed |

## P4 — Mainnet preparation (frozen params unchanged)

| ID | Item | Repo | Status |
|----|------|------|--------|
| P4-1 | Ceremony docs for PoW + no-stake | l1 | **Done (#261)** |
| P4-2 | Mainnet runbook for PoW + no-stake | l1 | **Done (#261)** |
| P4-3 | Offline genesis ceremony (addresses OPEN) | Toni | Open (tooling dry-run verified #278) |
| P4-4 | External audit of KovanicaHash + Wasmi | l1 | Open (internal code-against-checklist verification & scope locked at `6bcca86`, #278/#286; awaiting auditor dispatch) |
| P4-5 | Attach chain-2 genesis bundle (`kovanica-testnet-genesis.tar.gz`) to a node release | l1 | **Done (#287, Toni OK)** — `kovanica-testnet-genesis.tar.gz` (`sha256: 0892ff8056b1a4d999141752d258750b02be7e141ae0e742b1721b3d2bcfd38a`) uploaded to `v0.3.0-node` |
| P4-6 | Height-gated hardening (`*_ACTIVE_FROM_ROUND`) | l1 | **Done (#288, Toni OK)** — gas, contract, size-limit, and slashing gates set to `0` (`GENESIS_ROUND`) |

## P5 — L1 codebase polish (non-consensus)

| ID | Item | Notes |
|----|------|-------|
| P5-1 | Stubs (codec, consensus-sim, governance, hw-signer, oracle, sync) | Leave unless assigned |
| P5-2 | Legacy Mysticeti constants | Keep; do not re-activate |
| P5-3 | `ONE_KUNA` alias | Keep until a rename PR |
| P5-4 | Contract crates polish | No tokenomics changes |
| P5-5 | Wasmi fuel / memory | Do not raise without Toni (2–4 GB target) |

## P6 — SDK (kovanica-sdk)

Current state: read-only preview (`main` at `b534224`, PR `#11` merged after `#10` `9a8a2045`). Verified against L1 `de641f6`/`496f874`; enforces canonical 3-chain registry (`1` mainnet, `2` testnet, `3` devnet; `1337` retired in `#11`) and documents `-32600` (`InvalidRequest`) rejection of legacy staking RPCs (`kovanica_getValidators`, `kovanica_getStake`, `kovanica_getLeaderSchedule`) on hybrid chains 1 and 2. No key derivation, no signing, no mining submit.

| ID | Item | Status / Notes |
|----|------|----------------|
| P6-1 | Re-verify RPC methods against current L1 main | Done (`#8` `039d0e8`, `#9` `5aa4f34`, `#10` `9a8a2045` citing L1 `de641f6`) |
| P6-2 | Confirm hybrid methods (`getMiningInfo`, `getDagTips`) match live chain 2 | Done (`#10` `9a8a2045` + deterministic transport tests) |
| P6-3 | Keep read-only | Active boundary — no signing until a design PR is approved |
| P6-4 | Chain registry stays 1/2/3 (`1337` retired) with frozen address rules | Done (`#11` `b534224`) |
| P6-5 | Publish or document how web/playground should pin a SHA | Done (`#10` / playground `#10`, `#13` `0dd469d`) |

## P7 — Playground (kovanica-playground)

Current state: `main` at `0dd469d` (PR `#13` merged, pins `kovanica-sdk` `b534224a` and asserts `1337` rejection; PR `#12` `e620025` retired chain `1337`; PR `#11` `9aabda4` & `#10` `f7b2892`). Read-only, no keys, no faucet, no mining submit.

| ID | Item | Status / Notes |
|----|------|----------------|
| P7-1 | After SDK update, bump the pinned SHA and re-run CI | Done (`#9`, `#10` `f7b2892`, `#11` `9aabda4`, `#12` `e620025`, `#13` `0dd469d` pinning `b534224a`) |
| P7-2 | Point default testnet endpoint at public testnet only if CORS and auth are confirmed | Open (no seed1 docker changes) |
| P7-3 | Keep zero-key boundary | Active boundary |

## P8 — Web (kovanica-web)

Current state: TanStack Start site for kovanica.online (`main` at `b2fe0be`; PR `#17` `b2fe0be` retired chain `1337` and consolidated on devnet `3`; PR `#16` `66d2c0a` and PR `#15` `b5ddb18` merged). Vendored `@kovanica/sdk-wasm`. Env-driven config; no secrets in repo.

| ID | Item | Status / Notes |
|----|------|----------------|
| P8-1 | Align public copy with live testnet (chain 2, tag, no stake, 3-chain registry 1/2/3) | Done (`#14` `1366018`, `#15` `b5ddb18`, `#17` `b2fe0be`) |
| P8-2 | Confirm explorer / health links match deployed endpoints | Done (`#14` / `#15` `b5ddb18`, no nginx edits; `#16` `66d2c0a` fixes stale-build test harness) |
| P8-3 | Refresh vendored wasm only from a tagged SDK build | Open (awaiting tagged SDK build) |
| P8-4 | Brand assets stay consistent with L1 palette (ink / copper / paper) | Done (`#14` `1366018`) |

## P9 — Apps (kovanica-apps)

Current state: Android (wallet, comms, chain, node), iOS light client, desktop / console-desktop / node-desktop (Tauri), wallet-web (`main` at `be4baae`; PR `#24` `67dc47f` aligned apps with L1 `main`, PR `#25` `305df94` added ESLint 9 flat config, and PR `#26` `be4baae` retired chain `1337` and consolidated on devnet `3`). FFI stays in L1.

| ID | Item | Status / Notes |
|----|------|----------------|
| P9-1 | Fix sibling paths to `KovanicaDAG/kovanica-l1` & align with L1 `main` | Done (`#22` `92f2d904`, `#23` `86ad7d89`, `#24` `67dc47f`, `#25` `305df94`, `#26` `be4baae`) |
| P9-2 | Android-node: confirm testnet chain 2 + network tag | Done (`#21` `6ba74fb1`, `#24` `67dc47f`, `#26` `be4baae`) |
| P9-3 | Wallet-web: consume current SDK (read-only first) | Open |
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
