# Archived Legacy Mainnet Files (legacy-81m)

These files (`validators/`, `run-seed1.sh`, `run-seed3.sh`) are legacy artifacts from the deprecated `legacy-81m` emission policy and early configuration.

## Retirement Notice
- **Consensus & Emission Policy:** kovanica-mainnet (chain ID 1) runs hybrid PoW + GHOSTDAG with the `no-stake-82m` emission policy. Staking validator sets and the `legacy-81m` emission policy are retired and rejected fail-closed by the node.
- **Infrastructure:** `seed3` has been retired as a host; `seed1` is the sole host for seed node operations.
- **Replacements:** Tooling for kovanica-mainnet (chain ID 1) is generated via `ops/genesis/ceremony.sh` using the `no-stake-82m` template (`mainnet/genesis.json`).
