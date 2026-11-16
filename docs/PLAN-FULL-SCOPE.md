# PLAN-FULL-SCOPE — Kovanica ecosystem work plan

**Companion to `docs/AGENT-RULES.md` and `docs/PLAN-2026-11.md`.**
This is the full-scope plan across all public product repos. Frozen values stay frozen. Consensus changes need an activation plan and Toni’s OK before deploy.

Snapshot: 2026-11-16.
Live L1: seed1 on `e3fce499` / tag `v0.3.0-node`. #259 merged, not activated.

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
| P3-1 | Multi-hour height watch after any future deploy | ops | Read-only |
| P3-2 | Genesis bundle on a node release for `install.sh` | l1 | After ceremony addresses exist |
| P3-3 | Faucet stays sequential under load | l1 | Already passed basic checks |
| P3-4 | Safe nginx Authorization check (from #257) | ops | Docs already merged |
| P3-5 | Fund the rotated chain-2 faucet after re-genesis | l1/ops | **Blocked**: faucet is `0x0`, below the 100 KVNC floor; no signable funded key on the host. Procedure and unblock options: `docs/FAUCET-FUNDING.md` |
| P3-6 | Untrack `ops/docker/chain2/{faucet.keystore,faucet_passphrase,node1_p2p.key}` and fix the `.gitleaks.toml` "test fixture" allowlist | l1 | Committed live-key material; needs Toni OK (CI gate + ops state) |

## P4 — Mainnet preparation (frozen params unchanged)

| ID | Item | Repo | Status |
|----|------|------|--------|
| P4-1 | Ceremony docs for PoW + no-stake | l1 | PR #261 |
| P4-2 | Mainnet runbook for PoW + no-stake | l1 | PR #261 |
| P4-3 | Offline genesis ceremony (addresses OPEN) | Toni | Open |
| P4-4 | External audit of KovanicaHash + Wasmi | l1 | Scope docs exist |
| P4-5 | Height-gated hardening still inert | l1 | Do not flip `*_ACTIVE_FROM_ROUND` without Toni |

## P5 — L1 codebase polish (non-consensus)

| ID | Item | Notes |
|----|------|-------|
| P5-1 | Stubs (codec, consensus-sim, governance, hw-signer, oracle, sync) | Leave unless assigned |
| P5-2 | Legacy Mysticeti constants | Keep; do not re-activate |
| P5-3 | `ONE_KUNA` alias | Keep until a rename PR |
| P5-4 | Contract crates polish | No tokenomics changes |
| P5-5 | Wasmi fuel / memory | Do not raise without Toni (2–4 GB target) |

## P6 — SDK (kovanica-sdk)

Current state: read-only preview. README still cites an old L1 commit (`feab9050`). No key derivation, no signing, no mining submit.

| ID | Item | Notes |
|----|------|-------|
| P6-1 | Re-verify RPC methods against current L1 main | Update the cited SHA |
| P6-2 | Confirm hybrid methods (`getMiningInfo`, `getDagTips`) match live chain 2 | |
| P6-3 | Keep read-only | No signing until a design PR is approved |
| P6-4 | Chain registry stays 1/2/3/1337 with frozen address rules | |
| P6-5 | Publish or document how web/playground should pin a SHA | |

## P7 — Playground (kovanica-playground)

Current state: pins SDK at `7b790bee`. Read-only, no keys, no faucet, no mining submit.

| ID | Item | Notes |
|----|------|-------|
| P7-1 | After SDK update, bump the pinned SHA and re-run CI | Do not float on moving main |
| P7-2 | Point default testnet endpoint at public testnet only if CORS and auth are confirmed | No seed1 docker changes |
| P7-3 | Keep zero-key boundary | |

## P8 — Web (kovanica-web)

Current state: TanStack Start site for kovanica.online. Vendored `@kovanica/sdk-wasm`. Env-driven config; no secrets in repo.

| ID | Item | Notes |
|----|------|-------|
| P8-1 | Align public copy with live testnet (chain 2, tag, no stake) | Docs/copy only |
| P8-2 | Confirm explorer / health links match deployed endpoints | No nginx edits unless ops prompt |
| P8-3 | Refresh vendored wasm only from a tagged SDK build | |
| P8-4 | Brand assets stay consistent with L1 palette (ink / copper / paper) | |

## P9 — Apps (kovanica-apps)

Current state: Android (wallet, comms, chain, node), iOS light client, desktop / console-desktop / node-desktop (Tauri), wallet-web. FFI stays in L1. Some relative paths still say `kovanica` instead of `kovanica-l1`.

| ID | Item | Notes |
|----|------|-------|
| P9-1 | Fix sibling paths to `KovanicaDAG/kovanica-l1` | Docs or build config only |
| P9-2 | Android-node: confirm testnet chain 2 + network tag | No consensus code |
| P9-3 | Wallet-web: consume current SDK (read-only first) | |
| P9-4 | node-desktop: document pointing at a self-built `kovanica-node` | Already partially done |
| P9-5 | Do not move light-ffi into this repo | |

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
