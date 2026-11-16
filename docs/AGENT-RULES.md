# AGENT-RULES — Kovanica L1 project manager rules

**Replaces Gazda for day-to-day agent work.**
Read this before any change. If a rule here conflicts with a prompt, stop and ask Toni.

Last updated: 2026-11-16 (after seed1 deploy of `e3fce499`, tag `v0.3.0-node`, docs #257/#258 merged, DAA #259 open).

## 1. Frozen values — do not change, do not remove

These are locked. Any PR that alters them without an explicit Toni decision is rejected.

| Item | Value | Where |
|------|-------|-------|
| Ticker | KVNC | `kovanica-params::TICKER` |
| Decimals | 9 (`ONE_KVNC = 10^9`) | params |
| Consensus | Hybrid PoW + GHOSTDAG, **NO stake** | ADR / AGENTS.md |
| Target block time | 4000 ms | `TARGET_BLOCK_MS` |
| GHOSTDAG k | 5 | `GHOSTDAG_K` |
| PoW hash | KovanicaHash (BLAKE3 + 2 MiB mix) | crypto |
| Total supply | 90 200 000 KVNC | params |
| Founder premine | 200 000 KVNC | params |
| Treasury | 8 000 000 KVNC (1 M/yr × 8) | params |
| Mining budget (NoStake82M) | 82 000 000 KVNC | params |
| Initial block reward | 2.5 KVNC | params |
| Subsidy era (NoStake82M) | 8 200 000 rewarded blocks | params |
| Decay | × 3/4 per era | params |
| Fee split (mainnet + testnet) | 3/4 burn, 1/4 miner | execution |
| Fee split (devnet + local) | 100% burn | execution |
| Address format | `kvnc` + 57 base32 + `dag` (64 chars) | types |
| Chain IDs | 1 mainnet, 2 testnet, 3 devnet, 1337 local | params |
| Network tag (testnet) | `2-acfdf6a6c80fd28a` | genesis |
| DAA easiest (testnet/devnet) | `0x1f7f_ffff` | params |
| DAA hardest (testnet/devnet) | `0x1e00_ffff` | params |
| DAA easiest (mainnet) | `0x1f00_ffff` | params |
| Public launch | 1.1.2027 | AGENTS / STATE |
| BIP44 coin type | 3007 | wallet-core |
| Genesis time (mainnet) | 0 | Toni decision |
| Bootnode (mainnet) | `mainnet.kovanica.online:8000` | Toni decision |
| MAX_TARGET_BITS (mainnet) | `0x1f00ffff` | Toni decision |

Legacy Mysticeti constants (`WAVE_LENGTH`, `EPOCH_ROUNDS`, `MIN_VALIDATOR_STAKE`, `JAIL_ROUNDS`, etc.) stay in the tree but are **non-consensus** under hybrid. Do not re-activate them. Do not delete them without a dedicated cleanup PR that Toni approved.

## 2. What agents may touch

| Area | Allowed | Notes |
|------|---------|-------|
| Docs (`*.md`, comments) | Yes | Prefer docs-only PRs |
| Bug fixes that do not change consensus bytes | Yes | Cite the bug, add a test |
| Tests, simulation, CI | Yes | Must stay green |
| Faucet rate-limit / nonce logic | Yes | Do not weaken security |
| Observability, metrics, logging | Yes | No secrets in logs |
| Web / apps (separate repos) | Yes, in their own repos | Never mix into L1 |

## 3. What agents must NOT touch without explicit Toni OK

- Genesis files (`testnet/chain2/*`, `mainnet/genesis.json`, tags)
- Network tag `2-acfdf6a6c80fd28a`
- Any frozen value in section 1
- `Cargo.toml` workspace version or dependency pins that affect consensus determinism
- CI workflows that gate merges
- LICENSE
- Keystores, `.env`, passphrases, RPC write tokens
- seed1 / seed2 / seed3 docker, volumes, nginx (unless the prompt is an explicit ops task)
- Force-push, self-merge, tag creation (except the one tag Toni named)
- Consensus rule changes (DAA formula, GHOSTDAG k, block time, reward schedule) without a height-gated activation plan or empty-volume re-genesis plan written in the PR

## 4. Consensus changes (special rule)

A change to `calculate_next_target_bits`, reward math, header format, or commit rules is a **consensus change**.

- Open the PR.
- Write the activation plan in the PR body (height gate **or** empty-volume re-genesis).
- Do **not** deploy to seed1 until Toni says so.
- Current example: #259 (non-compounding DAA) is open and must stay undeployed until activation is decided.

## 5. Live seed1 state (do not break)

- Deployed SHA: `e3fce499afe6637b2a594b60306aef6312ef4bbf`
- Path: `/opt/kovanica-testnet-e3fce499`
- Compose project: `kovanica-chain2-official`
- Tag: `v0.3.0-node` points at the same SHA
- Faucet rotated: new address `kvnc8a4atp0g5tngcua9h90anhel7233alyd5y88h0yc592cv8adu5uyz46d3dag`
- Backup: `/root/kovanica-backup/20261116-pre-e3fce499/`
- DAA still oscillates (known). Do not “fix” it by restarting or changing volumes.

## 6. Agent roles (short)

| Agent | May | Must not |
|-------|-----|----------|
| OpenCode | Implement assigned prompts, open PRs | Force-push, self-merge, touch seed1 without explicit ops prompt |
| Antigravity / AGY | Code + docs PRs from a brief | Deploy, tag, merge |
| Gate | DA / NE on PR head | Implement, merge (unless Toni says merge) |
| Forge | Implement assigned L1 code | Review as Gate, merge |
| Web | kovanica-web only | L1 consensus, seed1 docker |
| Sekretar | Linear / Notion | Code, merges |
| Any agent | Read AGENT-RULES + STATE + this plan | Invent new tokenomics or consensus params |

## 7. PR discipline

- One PR = one intent.
- Branch from current main (or the SHA Toni names).
- No force-push.
- No self-merge.
- Cite the SHA you based on.
- For consensus changes, state the activation plan.
- Never print secrets, IPs, keystores, or env contents.

## 8. When in doubt

Stop. Ask Toni. Do not guess a frozen value. Do not “clean up” legacy constants that are still referenced.
