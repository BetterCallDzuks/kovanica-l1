# Fuzzing

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
