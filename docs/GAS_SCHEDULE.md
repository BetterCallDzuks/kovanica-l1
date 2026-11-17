# KVNC Gas Cost Schedule

> Deterministic WASM metering via wasmi fuel (`1 fuel = 1 gas unit`).
> This document is reconciled against the current code. Anything that is not
> yet implemented is marked **PLANNED** — do **not** treat those numbers as
> live consensus rules.

## 0. Status legend

| Marker | Meaning |
|--------|---------|
| **Implemented** | In the code on `main` today, and enforced where it says it is. |
| **Gated** | Implemented but behind a round gate. Since P4-6 (2026-11-17) the gas, contract, size-limit and slashing gates are `0` (active from genesis); `STATE_COMMITMENT_ACTIVE_FROM_ROUND = 500_000` is the one remaining gated rule. |
| **PLANNED** | Target design only. Not implemented anywhere in the repo. |

The host-call and base-cost tables below are **active from genesis**:
`GAS_HARDENING_ACTIVE_FROM_ROUND = 0` since P4-6 (2026-11-17), so on a fresh
chain contracts pay wasmi instruction fuel **plus** the charges below on every
call. A live chain that has not been re-genesised keeps running its existing
build.

## 1. Canonical constants

Canonical source: `crates/kovanica-params` (re-exported by `kovanica-types`).

| Constant | Value | Where | Status |
|----------|-------|-------|--------|
| `kovanica_types::MAX_TX_GAS_LIMIT` | `10_000_000` | `crates/kovanica-types/src/lib.rs` | Implemented |
| `kovanica_runtime::GAS_PER_MODULE_BYTE` | `8` | `crates/kovanica-runtime/src/lib.rs` | Implemented |
| `kovanica_runtime::min_gas_for_module(byte_len)` | `byte_len * GAS_PER_MODULE_BYTE` (saturating) | `crates/kovanica-runtime/src/lib.rs` | Implemented |
| Per-block gas budget (`BLOCK_GAS_BUDGET`) | `MAX_TX_GAS_LIMIT * 8` = `80_000_000` | `crates/kovanica-dag/src/block_manager.rs` (private const) | Implemented (from genesis) |
| `ExecutionConfig::default().gas_limit` | `MAX_TX_GAS_LIMIT` (`10_000_000`) | `crates/kovanica-runtime/src/lib.rs` | Implemented |
| `ExecutionConfig::default().memory_limit_pages` | `256` (64 KiB pages = 16 MiB, `DEFAULT_CONTRACT_MEMORY_PAGES = 256`) | `crates/kovanica-runtime/src/lib.rs` | Implemented |
| `MempoolConfig::max_gas_limit` | `MAX_TX_GAS_LIMIT` (`10_000_000`) | `crates/kovanica-mempool/src/lib.rs` | Implemented |
| `MempoolConfig::min_fee_rate` | `0` (operator policy) | `crates/kovanica-mempool/src/lib.rs` | Implemented |
| `kovanica_types::GAS_HARDENING_ACTIVE_FROM_ROUND` | `0` (active from genesis) | `crates/kovanica-types/src/lib.rs` | Implemented |
| `kovanica_types::CONTRACT_HARDENING_ACTIVE_FROM_ROUND` | `0` (active from genesis) | `crates/kovanica-types/src/lib.rs` | Implemented |
| `kovanica_types::SLASHING_ACTIVE_FROM_ROUND` | `0` (active from genesis) | `crates/kovanica-types/src/lib.rs` | Implemented |
| `kovanica_types::SIZE_LIMITS_ACTIVE_FROM_ROUND` | `0` (active from genesis) | `crates/kovanica-types/src/lib.rs` | Implemented |
| `kovanica_types::STATE_COMMITMENT_ACTIVE_FROM_ROUND` | `500_000` | `crates/kovanica-types/src/lib.rs` | Gated |

`MAX_TX_GAS_LIMIT` is the **single source of truth** for the per-transaction
cap: `kovanica-runtime` re-exports it, the mempool derives `max_gas_limit`
from it, and `kovanica-dag`'s block manager enforces it on the consensus path.
Change it in `kovanica-types` only.

> The earlier `max_gas_limit = 50_000_000` figure that used to appear here was
> stale; the real cap is `10_000_000`.

## 2. Gas units

- `Call.gas_limit` is charged directly into wasmi's `Store::set_fuel`, so
  `1 fuel == 1 gas unit`.
- `gas_used` in `TransactionReceipt` is the fuel actually consumed
  (`gas_limit - remaining_fuel`); on an out-of-gas trap the whole allotment is
  reported as consumed.
- Contracts that exceed their fuel budget trap with `RuntimeError::OutOfGas`.

## 3. Implemented: wasmi instruction fuel

**Implemented.** wasmi is built with `config.consume_fuel(true)`, and the store
is fuelled from `ExecutionConfig::gas_limit`. The interpreter then charges fuel
per executed WebAssembly instruction; the exact per-instruction schedule is
defined by the pinned wasmi version, not by this repo, and is therefore not
enumerated here. The budget is the total fuel a call may burn.

**Active from genesis — module-size floor.** Compiling a wasm module is
host-side work that wasmi fuel does not pay for, so a `Call` must carry at
least `min_gas_for_module(bytecode_len)` = `bytecode_len * GAS_PER_MODULE_BYTE`
so the requested gas is proportional to the compile work it forces every
validator to do.

**Active from genesis — per-transaction cap and per-block budget.**

- `kovanica-dag`'s `validate_transaction` rejects a `Call` with
  `gas_limit > MAX_TX_GAS_LIMIT`;
- `validate_block_content` rejects a block whose summed `Call` gas limits
  exceed `BLOCK_GAS_BUDGET` (`MAX_TX_GAS_LIMIT * 8`).

There is no pre-activation window on a fresh chain: all three rules apply to
every block. A chain that has not been re-genesised keeps running its existing
build, which carries the old inert value, so no live node forks on upgrade.

**Active from genesis — contract hardening (deploy / entry points).**
`CONTRACT_HARDENING_ACTIVE_FROM_ROUND = 0` since P4-6 (separate gate):

- a `Deploy` is rejected unless its bytecode compiles as a valid wasm module
  (the same wasmi engine the interpreter uses) **and** the derived contract
  address holds no code; both checks run before any storage write;
- a `Call` whose `method` is not one of the 19 `ENTRY_POINTS` is rejected
  **before** the interpreter runs (so it charges no fuel and writes nothing).

All checks are deterministic. A rejected deploy/call still charges fee and
nonce, matching every other body failure.

## 4. Implemented: memory limits

- `memory_limit_pages` is enforced through `StoreLimitsBuilder::memory_size()`,
  which applies on both memory creation and `memory.grow`.
- Default is 256 pages of 64 KiB = **16 MiB** (`DEFAULT_CONTRACT_MEMORY_PAGES = 256`).
- Guest argument/result buffers are additionally bounded by
  `MAX_BUFFER_BYTES` (64 MiB) in `kovanica-runtime`.

## 5. Implemented: unused gas

- **No refunds**: unused gas is not returned to the caller.
- The receipt's `gas_used` reports fuel actually consumed.

## 6. Active from genesis: base / intrinsic costs

> **Active from genesis.** Host-call charges are applied by `kovanica-runtime`
> on every call because `GAS_HARDENING_ACTIVE_FROM_ROUND = 0` since P4-6. The
> "target" column is the `kovanica-fee` schedule; a live chain that has not
> been re-genesised keeps the legacy no-charge behavior.

| Operation | Target gas cost | Notes |
|-----------|-----------------|-------|
| Call base fee | 2,100 | host setup, argument copy |
| Memory page | 3,000 | per additional 64 KiB page (PLANNED; memory is currently capped, not charged) |
| Storage read (`kovanica_storage_get`) | 200 | per call |
| Storage write (`kovanica_storage_set`) | 5,000 | per call |
| Balance read (`kovanica_balance_of`) | 100 | per call |
| Native transfer (`kovanica_transfer`) | 1,500 | per call |
| Event emit (`kovanica_emit_event`) | 500 | per call |
| Contract creation (`Deploy`) | 32,000 | code hash, account init |

## 7. Active from genesis: host-function per-call costs

> **Active from genesis.** The `env` host functions in `kovanica-runtime` debit
> fuel per `kovanica-fee` on every call since `GAS_HARDENING_ACTIVE_FROM_ROUND =
> 0` (P4-6).

| Host function | Target base gas | Target per-call cost |
|---------------|-----------------|----------------------|
| `kovanica_caller` | 0 | 50 |
| `kovanica_contract_address` | 0 | 50 |
| `kovanica_block_height` | 0 | 10 |
| `kovanica_timestamp` | 0 | 10 |
| Signed value (`kovanica_call_value`) | 50 | per call |
| `kovanica_balance_of` | 100 | 50 |
| `kovanica_transfer` | 1,500 | 200 |
| `kovanica_storage_get` | 200 | 50 (+ 2 per 32 bytes copied) |
| `kovanica_storage_set` | 5,000 | 100 (+ 2 per 32 bytes written) |
| `kovanica_emit_event` | 500 | 20 (+ 1 per byte of topic+data) |

## 8. PLANNED: fee model

> **PLANNED — not implemented.** There is no `gas_price` / `gas_used`-derived
> fee and no dynamic fee floor in the codebase today. Transaction `fee` is a
> fixed atom amount set by the sender; the mempool enforces an
> operator-configured `min_fee_rate` (default `0`, i.e. no floor) plus a
> replacement bump.

Target design (not live):

```
fee = gas_price * gas_used
```

with a minimum fee floor derived from the block subsidy. Neither term is
implemented; `gas_used` is recorded in the receipt but is not yet priced.

## 9. Configuration

`config.example.toml` documents the execution limits in a **commented-out**
`[execution]` block; the node does not yet parse an `[execution]` table and
uses the `ExecutionConfig` defaults above. The commented values are:

```toml
# [execution]
# default_gas_limit = 10000000          # per-call fuel cap (kovanica_types::MAX_TX_GAS_LIMIT)
# default_memory_limit_pages = 256      # 16 MiB linear-memory cap (ExecutionConfig::default)
# max_gas_limit = 10000000              # mempool admission cap (MempoolConfig::max_gas_limit)
```

## 10. Testing

Unit tests in `kovanica-runtime`:

- `low_gas_rejects_an_infinite_guest_loop` — fuel exhaustion traps
- `execute_with_gas_reports_consumed_fuel_on_success_and_out_of_gas` — real
  fuel accounting on both outcomes
- `memory_grow_is_limited_by_configured_page_cap` — memory cap enforced
- `packed_contract_error_codes_are_decoded` — error packing deterministic

`kovanica-dag` (`block_manager`) has gas-hardening tests covering the
per-transaction cap, the per-block budget and proposer truncation, all
enforced from the genesis round.

E2E test in `kovanica-execution` (`wasmi_e2e_kovanica_token_wasm`):

- native and wasm paths produce identical state transitions.

## 11. Governance

Once the PLANNED costs become **Implemented**, they are consensus-critical:
every validator must compute the same fee/gas outcome from the same
transaction. Any change then requires:

1. an RFC proposing the change;
2. an activation plan: fresh genesis / empty-volume re-genesis (the gates are
   `0` since P4-6), or a round gate if a future change must not apply to an
   existing chain;
3. migration tooling if existing contracts are affected.

## Appendix: fuel-to-gas conversion

In the current implementation `1 wasmi fuel unit = 1 gas unit`:
`ExecutionConfig.gas_limit` is passed straight to `Store::set_fuel()`.
Adjusting this ratio would be a hard fork.
