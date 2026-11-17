# Fuzzing

## Automated Smoke Runner (Deterministic)

Run the fast, deterministic fuzz smoke test suite across all parser boundaries (no nightly or libfuzzer binaries required):

```bash
bash scripts/run-fuzz-smoke.sh
```

Or run via cargo directly:

```bash
cargo test --manifest-path fuzz/Cargo.toml
```

## Continuous Fuzzing with cargo-fuzz (nightly)

Run with cargo-fuzz (nightly):

```
cargo fuzz run fuzz_block
cargo fuzz run fuzz_tx
cargo fuzz run fuzz_vote
cargo fuzz run fuzz_consensus
```

Targets (four existing harnesses):

- `fuzz_block` — block deserialization / validation
- `fuzz_tx` — transaction parsing and signature checks
- `fuzz_vote` — vote message handling
- `fuzz_consensus` — consensus state transitions

Targets are optional and not part of default build.
