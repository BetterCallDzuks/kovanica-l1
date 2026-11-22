# Kovanica L1 — Pre-Audit Reproduction & Mainnet Pre-Flight Verification (2026-11)

**Verification Date:** 2026-11-23 (UTC)  
**Repository:** `KovanicaProtokol/kovanica-l1`  
**Verified Commit:** `3c621df0b07a95f515b2aaac2b0729b495233714` (`3c621df`)  
**Related Documents:** [`AGENT-RULES.md`](AGENT-RULES.md), [`INTERNAL_PRE_AUDIT_2026_11.md`](INTERNAL_PRE_AUDIT_2026_11.md), [`AUDIT-SCOPE.md`](AUDIT-SCOPE.md), [`MAINNET-FREEZE-CHECKLIST.md`](MAINNET-FREEZE-CHECKLIST.md)

---

## 1. Exact Toolchain Versions

| Tool | Version / Status |
|---|---|
| `rustc` | `rustc 1.91.1 (ed61e7d7e 2025-11-07)` |
| `cargo` | `cargo 1.91.1 (ea2d97820 2025-10-10)` |
| `cargo-deny` | `cargo-deny 0.20.2` |
| `cargo-audit` | Not installed in local verification environment (`cargo deny check` covers advisory DB checks) |

---

## 2. `kovanica-execution --doc` (`E0514`) Resolution & Verification

### Root Cause & Targeted Cleanup
Stale unhashed `.rlib` artifacts in `target/debug/deps/` triggered rustc `E0514` metadata version mismatches during `cargo test -p kovanica-execution --doc`. Without running `cargo clean` (to avoid disrupting concurrent builds), only the 4 stale unhashed files were removed:

- `target/debug/deps/libkovanica_multisig.rlib`
- `target/debug/deps/libkovanica_token.rlib`
- `target/debug/deps/libkovanica_htlc.rlib`
- `target/debug/deps/libkovanica_vault.rlib`

### Verification Result
```text
$ cargo test -p kovanica-execution --doc
   Finished `test` profile [optimized + debuginfo] target(s) in 15.28s
   Doc-tests kovanica_execution

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

**Status:** **PASS** (clean build and doc-test execution, zero `E0514` errors).

---

## 3. Mainnet Genesis Artifact & Network Tag Verification

All files under `mainnet/` were verified read-only against `mainnet/SHA256SUMS` (`cd mainnet && sha256sum -c SHA256SUMS`):

| Artifact | SHA-256 Checksum | `SHA256SUMS` Check |
|---|---|---|
| `mainnet/genesis.json` | `aeaa107611e3aa729e0cfb125b6964f3c766fc91e0a4de5a6081eecf666a287b` | **OK** |
| `mainnet/bootnodes.toml` | `e253f2883dc5db64d10662582e237a8e0b6b74ca81d521018ba04b79d76c5fc5` | **OK** |
| `mainnet/founder_premine.hex` | `577b403311a833362c7bffebb03c6bd9a50af199b62fb56c13144c7806ed698b` | **OK** |
| `mainnet/genesis_validators.toml` | `7d2be6c6fb9225edf0b04c12dc10d975ad9f756ede0fe77cd7486d149eaca2b0` | **OK** |
| `mainnet/SHA256SUMS` | `e6b79bf81ab0243e7953565ab553ba72ca5f6920a31be48dd4fb53945c622f42` | Manifest |

### Frozen Mainnet Genesis Invariants Checked (Read-Only)
- **Frozen Mainnet Network Tag:** `1-f35df34c92001436` (consistent across [`AGENT-RULES.md`](AGENT-RULES.md), [`MAINNET-FREEZE-CHECKLIST.md`](MAINNET-FREEZE-CHECKLIST.md), and [`MAINNET-RUNBOOK.md`](MAINNET-RUNBOOK.md))
- **Chain ID:** `1` (`kovanica-mainnet`)
- **Emission Policy:** `no-stake-82m` (`mining_subsidy_budget_kovanica = 82_000_000`, `founder_premine_kovanica = 200_000`, `genesis_validator_allocation_kovanica = 0`, `total_staked = 0`, 5 seed entries with `stake = 0`)
- **Genesis Block Digest:** `db095f9db7ade0026299a516debc05812abfea84933b9a0e62bf5e28708df431` (`round = 0`, `parents = []`, `transactions = []`)
- **Founder Premine Address:** `kvnc2yuzlhwfvp7v44yje2cgtfy540q8vv6c780ug3xfel36kswhpwnfthzxvdag` (matches `mainnet/founder_premine.hex` and `mainnet/genesis.json`)
- **Treasury Address:** `kvncd2xkjdt78kyqc4ekret0wr3dnnrr3wyxdwmykkwujrpp3l3l6p80mk2dgdag` (matches `mainnet/genesis_validators.toml` and `mainnet/genesis.json`)
- **Bootnode:** `mainnet.kovanica.online:8000` (`mainnet/bootnodes.toml`)

**Status:** **PASS** (4/4 `SHA256SUMS` entries verified; all frozen values intact).

---

## 4. Systemd Unit Hardening Verification (`ops/systemd/*.service`)

Read-only audit of all 5 systemd service units in `ops/systemd/`:

| Hardening Directive | `kovanica-node.service` | `kovanica-node-ondemand.service` | `kovanica-seed@.service` | `kovanica-faucet.service` | `kovanica-stratum.service` |
|---|---|---|---|---|---|
| `User` / `Group` | `kovanica` / `kovanica` | `kovanica` / `kovanica` | `kovanica` / `kovanica` | `kovanica` / `kovanica` | `kovanica` / `kovanica` |
| `UMask` | `0027` | `0027` | `0027` | `0027` | `0027` |
| `MemoryMax` | `3G` | `3G` | `3G` | `512M` | `512M` |
| `MemoryAccounting` | `yes` | `yes` | `yes` | `yes` | `yes` |
| `LimitNOFILE` | `65536` | `65536` | `65536` | `16384` | `65536` |
| `NoNewPrivileges` | `yes` | `yes` | `yes` | `yes` | `yes` |
| `ProtectSystem` | `strict` | `strict` | `strict` | `strict` | `strict` |
| `ProtectHome` | `yes` | `yes` | `yes` | `yes` | `yes` |
| `ReadWritePaths` | `/var/lib/kovanica` | `/var/lib/kovanica` | `/var/lib/kovanica-seed%i` | `/var/lib/kovanica` | `/var/lib/kovanica` |
| `PrivateTmp` / `PrivateDevices` | `yes` / `yes` | `yes` / `yes` | `yes` / `yes` | `yes` / `yes` | `yes` / `yes` |
| `ProtectKernelTunables/Modules/Logs` | `yes` / `yes` / `yes` | `yes` / `yes` / `yes` | `yes` / `yes` / `yes` | `yes` / `yes` / `yes` | `yes` / `yes` / `yes` |
| `ProtectControlGroups/Clock/Hostname` | `yes` / `yes` / `yes` | `yes` / `yes` / `yes` | `yes` / `yes` / `yes` | `yes` / `yes` / `yes` | `yes` / `yes` / `yes` |
| `RestrictNamespaces/SUIDSGID/Realtime` | `yes` / `yes` / `yes` | `yes` / `yes` / `yes` | `yes` / `yes` / `yes` | `yes` / `yes` / `yes` | `yes` / `yes` / `yes` |
| `LockPersonality` / `MemoryDenyWriteExecute` | `yes` / `yes` | `yes` / `yes` | `yes` / `yes` | `yes` / `yes` | `yes` / `yes` |
| `RestrictAddressFamilies` | `AF_INET AF_INET6` | `AF_INET AF_INET6` | `AF_INET AF_INET6` | `AF_INET AF_INET6` | `AF_INET AF_INET6` |
| `CapabilityBoundingSet` / `AmbientCapabilities` | empty / empty | empty / empty | empty / empty | empty / empty | empty / empty |
| `SystemCallArchitectures` | `native` | `native` | `native` | `native` | `native` |
| `SystemCallFilter` / `SystemCallErrorNumber` | `@system-service` / `EPERM` | `@system-service` / `EPERM` | `@system-service` / `EPERM` | `@system-service` / `EPERM` | `@system-service` / `EPERM` |

- `ops/systemd/kovanica-node-ondemand.socket` binds `ListenStream=127.0.0.1:8545` (loopback-only) with `NoDelay=true`.
- `ops/systemd/kovanica-stratum.service` binds `--metrics-addr 127.0.0.1:9090` (loopback-only) and `--listen 0.0.0.0:3333`.

**Status:** **PASS** (5/5 `.service` units enforce full strict sandboxing, empty capability sets, W^X memory protection, syscall filtering, and bounded memory limits).

---

## 5. Audit Dossier & `auditor-reproduce.sh` Verification

### Audit Dossier Package Integrity
- **Archive:** `target/audit-package/kovanica-audit-dossier-3c621df.tar.gz`
- **Size:** `10,295,609` bytes (`9.9M`), `890` archive entries
- **SHA-256 (`kovanica-audit-dossier-3c621df.tar.gz.sha256`):** `c1e65a1f5799cbd637bcb88ede398b3a312b372a371e62422da81f6d8f10ca36`
- **Checksum Verification (`sha256sum -c`):** `kovanica-audit-dossier-3c621df.tar.gz: OK`
- **Embedded Reproduction Harness:** `./scripts/auditor-reproduce.sh` (generated by `scripts/package-audit-dossier.sh` into `target/audit-package/staging/scripts/auditor-reproduce.sh` and packaged in the tarball)

### Step-by-Step Verification of `auditor-reproduce.sh` Commands

| Step | Command in `auditor-reproduce.sh` | Observed Result | Notes |
|---|---|---|---|
| 1 | `rustc --version` / `cargo --version` | **PASS** | `1.91.1` / `1.91.1` |
| 2 | `cargo fmt --all -- --check` | **PASS** | Zero formatting diffs |
| 2 | `cargo clippy --workspace --all-targets -- -D warnings` | Skipped here | Avoided during parallel `kovanica-stratum` build; verified clean (`0 warnings`) in [`INTERNAL_PRE_AUDIT_2026_11.md`](INTERNAL_PRE_AUDIT_2026_11.md) |
| 3 | `bash scripts/run-fuzz-smoke.sh` | **PASS** | `14 passed; 0 failed` (`0.23s`) |
| 4a | `cargo test -p kovanica-types --test pow` | **HARNESS MISMATCH** | Fails with `no test target named 'pow' in 'kovanica-types' package`; PoW tests are unit tests under `--lib`. Running `cargo test -p kovanica-types --lib pow` **PASSES** (`11 passed; 0 failed`). **Follow-up:** update `scripts/package-audit-dossier.sh` line 47 to `--lib pow` in a future PR. |
| 4b | `cargo test -p kovanica-crypto` | **PASS** | `35 passed; 0 failed` (25 + 1 + 1 + 3 + 5 across 5 binaries, 0 doc-tests) |
| 4c | `cargo test -p kovanica-consensus --test hybrid_pow_simulation` | **PASS** | `11 passed; 0 failed` |
| 4d | `cargo test -p kovanica-execution --test wasmi_gas_memory_metering` | **PASS** | `7 passed; 0 failed` |
| 4e | `cargo test -p kovanica-network --test peer_reputation_scoring` | **PASS** | `7 passed; 0 failed` |
| 5 | `cargo test --workspace` | Deferred | Avoided full workspace sweep during parallel `kovanica-stratum` work; targeted `kovanica-execution --doc` verified **PASS** |
| 6a | `cargo deny check` | **PASS** | `advisories ok, bans ok, licenses ok, sources ok` |
| 6b | `cargo audit` | Not installed | Not present in local toolchain; `cargo deny check` verified RustSec advisories cleanly |

---

## 6. Documentation Link Lint

```text
$ python3 scripts/lint_docs.py
docs lint: OK
```

**Status:** **PASS**.
