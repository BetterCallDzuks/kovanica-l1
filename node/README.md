# Running a Kovanica node

Prebuilt `kovanica-node` binaries for Linux (x86_64, aarch64) and a genesis
bundle per network are published as GitHub releases by
`.github/workflows/release-node.yml`. Tag naming: `v<version>-node`.

One binary serves every network; a network is chosen by its `chain_id` and its
genesis bundle, not by a separate build.

| `--chain-id` | Network                     | Registry name       |
|--------------|-----------------------------|---------------------|
| `1`          | kovanica-mainnet (chain ID 1) | `MAINNET`         |
| `2`          | kovanica-testnet (chain ID 2) (default) | `TESTNET` |
| `3`          | kovanica-devnet (chain ID 3)  | `DEVNET`          |
| `1337`       | local (chain ID 1337)       | `LOCAL`             |

Chain 4 (`TESTNET_V2`) is **retired** and no longer registered: a binary built
from current `main` refuses to start on it. See
`docs/dev/CANONICAL-TESTNET-2.md`.

## Install (kovanica-testnet, release `v0.3.0-node`)

The default installer downloads `v0.3.0-node`, writes a bootnode of
`seed1.kovanica.online:8000` (DNS name only), and refuses to finish unless
`kovanica-node network-tag` prints `2-acfdf6a6c80fd28a`.

```sh
curl -fsSL https://kovanica.online/download/install.sh | sh
```

The installer:

1. detects the architecture and downloads
   `kovanica-node-<arch>-linux.tar.gz` plus the network's genesis bundle
   (`kovanica-chain<chain-id>-genesis.tar.gz` by default), verifying both
   against the published `SHA256SUMS`;
2. installs the binary (default `/usr/local/bin/kovanica-node`);
3. copies the genesis bundle into the data directory (default
   `/var/lib/kovanica`), refusing a data directory that already holds chain
   data;
4. writes a non-validating config (`/etc/kovanica/kovanica.toml`) with
   `seed1.kovanica.online:8000` as the bootnode (DNS name only) and RPC bound
   to loopback;
5. runs `kovanica-node --check-config` and `kovanica-node network-tag` against
   that candidate config and **refuses to continue** on a mismatch, before the
   config is moved into place;
6. on systemd hosts, installs and starts `kovanica-node.service` as the
   `kovanica` system user.

Useful options: `--chain-id <id>`, `--bundle-asset <name>`,
`--expected-tag <tag>`, `--no-service`, `--data-dir <dir>`, `--prefix <dir>`,
`--version <v>`, `--skip-tag-check`, `--uninstall`, `--help`.
Without root it installs under `$HOME/.local` and `$HOME/.kovanica` and does
not touch systemd.

## Why the tag check matters

Every node on a network must share the same chain id and genesis file set; the
network tag (`<chain_id>-<16 hex of the genesis config digest>`) is mixed into
all libp2p protocol ids and gossip topics. A node with a different tag silently
has no peers. See `docs/TESTNET-RESET.md`.

The installer takes the expected tag from, in order:

1. `--expected-tag` (or `KOVANICA_EXPECTED_TAG`);
2. on kovanica-testnet, the built-in pin `2-acfdf6a6c80fd28a`;
3. an `expected-tag` file inside the checksum-verified bundle.

A bundle `expected-tag` that disagrees with the pin is refused. If none of
the three exists it **fails closed**. `--skip-tag-check` is the explicit
opt-out; the node still prints its tag. `--version` and
`KOVANICA_RELEASE_BASE` still override the download.

## Cutting a genesis bundle

Do not build the bundle by hand. The node binary writes the archive, the
checksums and the expected tag in one step:

```sh
kovanica-node genesis-bundle --chain-id 2 --source <genesis-dir>
```

`--source` may only contain genesis files (`genesis_validators.toml`,
`founder_premine.hex`, `funded_accounts.toml`, `validators.json`); anything
else — a signing key, a keystore, a config — is refused, so it cannot be
published by accident. The output
`kovanica-chain<chain-id>-genesis.tar.gz` (`--out` to change it) carries a
`SHA256SUMS` over the genesis files and an `expected-tag`, and is
byte-identical across rebuilds. Attach it to the `v<version>-node` release
next to the binaries. Details and the refusal rules: `docs/TESTNET-RESET.md`.

### BLOCKED: do not cut the chain-2 bundle yet

**Status: not run.** `node/scripts/install.sh` cannot complete an install for
kovanica-testnet (chain ID 2) until this bundle is attached to a
`v<version>-node` release, but the bundle must not be cut until the final
production key ceremony addresses exist.

- **What is still missing:** the final mainnet/testnet addresses produced by the
  production key ceremony (`ops/genesis/ceremony.sh`, see `docs/KEY-CEREMONY.md`
  and `docs/MAINNET-RUNBOOK.md`). Until Toni supplies them, `testnet/chain2/`
  carries placeholder/pre-ceremony content and any bundle cut from it would
  publish the wrong genesis and the wrong network tag.
- **Exact command to run later** (from the repo root, on the commit whose tree
  contains the final `testnet/chain2/` file set):

  ```sh
  kovanica-node genesis-bundle --chain-id 2 --source testnet/chain2
  ```

  Then attach `kovanica-chain2-genesis.tar.gz` to the `v<version>-node`
  release and confirm the embedded `expected-tag` is `2-acfdf6a6c80fd28a`.
- **Gate:** do **not** run the command, generate a bundle, or attach one to a
  release until **Toni supplies the ceremony addresses** and the genesis file
  set is final. Generating one now is out of scope for every agent; changing
  `testnet/chain2/*` genesis files or the network tag is forbidden without an
  explicit Toni decision.

## State sync: full-state commitment is activated at round 500 000

A node installed by this script starts at height 0 with the network's genesis
file set and bootstraps from the chunked state snapshot served by its peers.
Sealed headers produced **below** `STATE_COMMITMENT_ACTIVE_FROM_ROUND` are
account-only, because the constant was `u64::MAX` when those blocks were
produced, while `snapshot_committed_root()` always recomputes the full-state
root that includes the reserved `AUX_STATE_LEAF_ADDRESS` leaf. The two can
never be equal, so `import_verified_snapshot()` fails closed with:

```
rejected state snapshot ... sealed header state_root ... != full-state
commitment ... recomputed from the snapshot accounts, contracts and staking
```

That check must not be weakened: without it a peer could forge staking and
contract rows while every signature still verifies. Instead it is replaced by
an explicit activation and a clear refusal reason:

- `STATE_COMMITMENT_ACTIVE_FROM_ROUND` is **500 000** (about five days of
  committed leaders at 12 s each). Every sealed header produced at or above
  that leader round commits to the full state, so snapshots from those heights
  import normally.
- Below it, the importer refuses the snapshot up front with
  `... predates the full-state commitment (active from round 500000, chain <id>)`
  instead of a root mismatch. Nothing is applied.

**Before round 500 000 every block-authoring node must run a build that
contains the activation constant** (v0.2.0-node or later). A node that signs a
header at or above the activation round with an older build would seal an
account-only root that newer nodes reject; a mixed fleet would therefore stall
state sync again. Roll the binary out with the usual canary-first procedure;
each node logs the activation round at startup
(`state_commitment_active_from_round=...`), so check that line on every node
before the round arrives.

Snapshots taken below the activation round remain valid for peers that already
hold the state: the refusal only affects *imports*, so a node that was running
before the activation keeps producing blocks. A brand-new node can join once a
sealed header at or above the activation round exists (and the serving peer's
snapshot is at least that new).

## Block-author identities & mining

kovanica-mainnet (chain ID 1) and kovanica-testnet (chain ID 2) have no validator committee and no stake in consensus: blocks come from Hybrid PoW + GHOSTDAG mining. The installer never generates or handles validator keys — it produces a read-only full node. Mining setup is documented in [`docs/MINING.md`](../docs/MINING.md); staking operations are refused fail-closed on hybrid networks (#233).

## Faucet (chain 2)

The faucet is a separate process (`kovanica-faucet`, shipped in the same image) that signs
transfers from its own keystore. After a re-genesis it can be healthy and still unable to
dispense: `funded_accounts.toml` is a genesis input, so a top-up is an ordinary transfer from
an already-funded account, not a genesis edit. Procedure, preconditions and the current
blocked status: [`docs/FAUCET-FUNDING.md`](../docs/FAUCET-FUNDING.md).

## Cutting a release

```sh
git tag -a v0.3.0-node <merge SHA> -m "kovanica-node 0.3.0 (kovanica-testnet)"
git push origin v0.3.0-node
```

The workflow builds both architectures, fails unless `network-tag` prints
`2-acfdf6a6c80fd28a`, and on a tag publishes the tarballs, the
kovanica-testnet genesis bundle and `SHA256SUMS`. `workflow_dispatch` builds
the same artifacts and does not publish. The installer defaults to
`VERSION=0.3.0` and pins that network tag. Earlier tags `v0.1.0-node` and
`v0.2.0-node` stay where they are.

> The release workflow cuts the kovanica-testnet bundle from `testnet/chain2/`
> with `kovanica-node genesis-bundle --chain-id 2` and requires the computed
> network tag to be `2-acfdf6a6c80fd28a`.
