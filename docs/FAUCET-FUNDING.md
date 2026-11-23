# Faucet funding (chain 2, post-genesis top-up)

The chain-2 genesis is frozen. `testnet/chain2/funded_accounts.toml` is a genesis
input: its balances are baked into the genesis digest, and the digest is what
produces the network tag `2-24cdb5fadd98b207`. Adding the current faucet address
to that file would change the tag, so it is **not** a usable top-up path on a
live chain. Top-ups are ordinary on-chain transfers from an already-funded
account.

This document is the supported post-genesis funding path, plus the exact state
that blocked it on 2026-11-16.

## Live state (2026-11-16, seed1, chain 2)

| Account | Address | Balance | Note |
|---|---|---|---|
| Pre-rotation faucet (genesis-funded) | `kvnck2559l6vnpcchmtkuf2eslmdtxc6wtfm9nf9zqqructs4336nla58y78mdag` | 100 000 KVNC, nonce 0 | only genesis-funded account; the sender for a top-up |
| Live faucet (rotated) | `kvnc8a4atp0g5tngcua9h90anhel7233alyd5y88h0yc592cv8adu5uyz46d3dag` | `0x0` | process healthy (`/health` 200) but cannot dispense |
| Genesis bootstrap identities (`testnet/chain2/genesis_validators.toml`) | `kvncda8z9…`, `kvnc8kscelhl…`, `kvnc30f77rhd…` | 630 / 735 / 772.5 KVNC | no genesis allocation (the `[[validator]]` table is a legacy-named bootstrap record: no stake, no balance); balances are block rewards earned as block authors, and no host key derives to them |
| Treasury | `kvncqctcedn…` | `0x0` | treasury funds are emitted on the vesting schedule, not minted at genesis |

The compose faucet also runs with `--min-balance-ku 100`
(`ops/docker/docker-compose.chain2.yml`), so it refuses to dispense at all while
its balance is under 100 KVNC — a small top-up would leave it looking healthy and
still serving nothing. Any top-up must land well above that floor.

## Why not `kovanica transfer`

`kovanica transfer` cannot submit on a node with write auth enabled (the testnet
default):

- `RpcClient::new` in `kovanica-sdk` never attaches an `Authorization` header.
- `kovanica_sendRawTransaction` is listed in `WRITE_METHODS`
  (`crates/kovanica-rpc/src/rpc_middleware.rs`).
- `AuthConfig::authorize` has **no loopback bypass** — a request from
  `127.0.0.1` without a matching `Bearer` token is rejected.

`kovanica-faucet` already resolves RPC write auth (`KOVANICA_RPC_WRITE_TOKEN`, or
the first entry of `KOVANICA_RPC_WRITE_TOKENS`), signs from a keystore, and can
read its passphrase from a file instead of a TTY. Running it once as a *sender*
is therefore the repo's own funding path.

## Procedure

Preconditions:

1. Node RPC reachable at `http://127.0.0.1:8545/rpc` (not `/`).
2. A funded keystore for the sender, plus its passphrase in a file with mode
   `0600` or `0400` (`--passphrase-file` refuses anything broader).
3. The node's write token available as an env file — never paste it on a command
   line.
4. Nothing is published on a host port: the funder shares the node's network
   namespace and listens on loopback only.

Run on seed1. `<retired-keystore>` is
`faucet.keystore.retired-20261116` on the deploy host; the passphrase file is the
operator-supplied `0600` file:

```sh
docker run --rm --name kovanica-faucet-topup \
  --user 0:0 \
  --network container:kovanica-chain2-node1 \
  --env-file /root/kovanica-chain2-rpc.env \
  -v <retired-keystore>:/keystore:ro \
  -v /root/faucet-topup/old.pass:/pass:ro \
  --entrypoint kovanica-faucet kovanica-node:local \
  --chain-id 2 \
  --keystore /keystore \
  --passphrase-file /pass \
  --rpc-url http://127.0.0.1:8545/rpc \
  --listen 127.0.0.1:18500 \
  --dispense-kovanica 99999
```

- There is no separate `kovanica-faucet` image: the repo builds one image
  (`kovanica-node:local`) that ships both binaries, hence
  `--entrypoint kovanica-faucet`.
- `--chain-id 2` is mandatory — the binary has no default on purpose and refuses
  to start without it.
- `--dispense-kovanica 99999` must exceed the live faucet's 100 KVNC floor or the
  top-up arrives and the faucet still refuses to dispense. 99 999 KVNC leaves
  about 0.999 KVNC in the sender (fee 0.001 KVNC). Any amount
  ≤ `balance − 0.001` works.
- `--user 0:0` is needed because the bind-mounted keystore/passphrase are
  root-owned `0600`: the container user must be able to read them, and
  `read_passphrase_file` separately rejects any file that is group- or
  world-readable. (The long-running compose faucet runs as uid 10001 and
  therefore takes its passphrase from the env instead.)
- `--rm` is fine because the `tx_hash` comes back in the HTTP response, not from
  the container log. If the `POST` fails, rerun without `--rm` to read why.

Then request the single dispense from inside the node's namespace (the funder is
not reachable from the host):

```sh
docker exec kovanica-chain2-node1 curl -s \
  -X POST -H 'content-type: application/json' \
  -d '{"address":"kvnc8a4atp0g5tngcua9h90anhel7233alyd5y88h0yc592cv8adu5uyz46d3dag"}' \
  http://127.0.0.1:18500/faucet
```

The response carries `tx_hash`. The body has no per-request cap and its `amount`
field is ignored: the dispense size is fixed by `--dispense-kovanica`.

Verify the faucet, not the funder:

```sh
docker exec kovanica-chain2-faucet sh -lc \
  'curl -s -o /dev/null -w "health=%{http_code}\n" http://127.0.0.1:3000/health'
docker exec kovanica-chain2-node1 curl -s -X POST \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"kovanica_getBalance","params":["kvnc8a4atp0g5tngcua9h90anhel7233alyd5y88h0yc592cv8adu5uyz46d3dag"]}' \
  http://127.0.0.1:8545/rpc
```

Report the `tx_hash` and the new balance only. Then shred the passphrase file
(`shred -u /root/faucet-topup/old.pass`) and delete any keystore copy:
`docker rm -f kovanica-faucet-topup` if it is still around.

## Guardrails

- **Never** run the signing step under a pty wrapper (`script`, `expect`,
  `docker run -i`). The interactive prompt can echo the passphrase to the
  terminal and into any log that captures it. `--passphrase-file` exists so no
  TTY is involved.
- Do not edit genesis files, `funded_accounts.toml`, or the network tag to fund
  the faucet.
- Do not print the passphrase, the keystore contents, or the RPC write token.
  An `--env-file` reference keeps the token out of the process list.
- Set `--address-max-requests` to `1` for the top-up. A funded faucet with a
  high per-address cap is a drain target.
- A prior `docker run -i` attempt **echoed a passphrase to the terminal**. Treat
  that passphrase as exposed and rotate the live faucet passphrase once funding
  works — the new value goes in the host env file only, never in git.
- Do not add new secrets to the repo; the tracked ones stay where they are until
  a separate, explicitly approved cleanup lands.

## Status on 2026-11-16: BLOCKED

The transfer could not be signed. The pre-rotation account is funded and its
keystore is intact, but **the passphrase for that keystore is not stored on the
host or in git history**, so nothing can sign from it. Concretely:

- The live (rotated) faucet keystore and the retired keystore are different
  keys; the rotated passphrase does not decrypt the retired one.
- The keystore tracked in git (`ops/docker/chain2/faucet.keystore`) *is* the
  retired keystore, but neither passphrase blob tracked in its history decrypts
  it. The pre-rotation live faucet never used the mounted
  `ops/docker/chain2/faucet_passphrase`: the compose service passes
  `KOVANICA_FAUCET_PASSPHRASE` from the host environment and no
  `--passphrase-file`, so the on-disk passphrase was dead config.
- The real passphrase was supplied out-of-band and is not recoverable from the
  repo, the vault, shell history, or any backup on the host.

Nothing else on the host can sign: the founder/operator wallet seeds, the
node-volume signing keys (`validator.key`, legacy file name) and the
`etc-kovanica` key files all derive to accounts with `0x0`, and
`founder_premine.hex` is a placeholder, not a seed. The three genesis bootstrap
identities hold 2 137.5 KVNC of earned block rewards between them, but no host
key derives to those addresses either.

### Paths

- **Path A (the only one that recovers the funds):** the operator supplies the
  pre-rotation passphrase in a `0600` file on seed1, then runs the one-shot
  funder above and reports the `tx_hash` plus the new balance.
- **Path B (not available):** fund from a genesis bootstrap identity. No host key
  derives to those addresses, and they hold only earned block rewards.
- **Path C (approved by Toni — rotate to a new faucet keystore & fund from a miner payout address on `seed1`):**
  Since `ops/docker/chain2/faucet.keystore` and `ops/docker/chain2/faucet_passphrase` are now untracked and gitignored (`#285`), the operator can rotate to a fresh faucet keystore on `seed1` and fund it above the 100 KVNC floor (`--min-balance-ku 100`) from a miner payout address without touching genesis files or the network tag:

  1. **Generate a fresh passphrase and encrypted v2 faucet keystore on `seed1` (never committed to git):**
     ```sh
     umask 077
     openssl rand -base64 32 > ops/docker/chain2/faucet_passphrase
     chmod 0600 ops/docker/chain2/faucet_passphrase

     docker run --rm -it \
       --user "$(id -u):$(id -g)" \
       -v "$PWD/ops/docker/chain2:/out" \
       --entrypoint kovanica kovanica-node:local \
       keygen --out /out/faucet.keystore
     chmod 0600 ops/docker/chain2/faucet.keystore
     NEW_FAUCET_ADDR="$(jq -r .address ops/docker/chain2/faucet.keystore)"
     echo "New faucet address: $NEW_FAUCET_ADDR"
     ```
     Enter the passphrase from `ops/docker/chain2/faucet_passphrase` at the `kovanica keygen` prompt, set `KOVANICA_FAUCET_PASSPHRASE` in the host compose environment file to that exact value, and recreate the faucet container:
     ```sh
     docker compose -f ops/docker/docker-compose.chain2.yml up -d faucet
     ```

  2. **Fund `$NEW_FAUCET_ADDR` above the 100 KVNC floor from a miner payout address on `seed1`:**
     - **Option C1 (Direct mining payout to `$NEW_FAUCET_ADDR`):** Mine block rewards (`2.5 KVNC` per committed block) directly to `$NEW_FAUCET_ADDR` until `kovanica_getBalance` exceeds `100 KVNC` (≥ 41 committed blocks = `102.5 KVNC`):
       ```sh
       KOVANICA_MINER_ADDRESS="$NEW_FAUCET_ADDR" \
         docker compose -f ops/docker/docker-compose.chain2.yml --profile miner up -d miner
       ```
     - **Option C2 (One-shot transfer from a funded miner payout keystore):** If block rewards were accumulated in a separate miner keystore (`/root/faucet-topup/miner.keystore` with `0600` passphrase file `/root/faucet-topup/miner.pass` and balance > 100 KVNC), run the one-shot `kovanica-faucet` sender with `--address-max-requests 1`:
       ```sh
       docker run --rm --name kovanica-faucet-topup \
         --user 0:0 \
         --network container:kovanica-chain2-node1 \
         --env-file /root/kovanica-chain2-rpc.env \
         -v /root/faucet-topup/miner.keystore:/keystore:ro \
         -v /root/faucet-topup/miner.pass:/pass:ro \
         --entrypoint kovanica-faucet kovanica-node:local \
         --chain-id 2 \
         --keystore /keystore \
         --passphrase-file /pass \
         --rpc-url http://127.0.0.1:8545/rpc \
         --listen 127.0.0.1:18500 \
         --address-max-requests 1 \
         --dispense-kovanica 500
       ```
       Then trigger the single payout from inside the node namespace and verify `/health` and `kovanica_getBalance`:
       ```sh
       docker exec kovanica-chain2-node1 curl -s \
         -X POST -H 'content-type: application/json' \
         -d "{\"address\":\"$NEW_FAUCET_ADDR\"}" \
         http://127.0.0.1:18500/faucet
       ```

## Faucet Telemetry, Headers & Monitoring

### OpenMetrics (`GET /metrics`)

`kovanica-faucet` exposes OpenMetrics counters and gauges at `GET /metrics` on its HTTP listener:

| Metric | Type | Description |
|---|---|---|
| `faucet_drips_succeeded_total` | Counter | Total number of successful faucet drips. |
| `faucet_drips_rejected_total` | Counter | Total number of rejected faucet drip requests (e.g., invalid address, RPC error, or balance below floor). |
| `faucet_rate_limited_total` | Counter | Total number of faucet drip requests rejected by IP or per-address rate limits. |
| `faucet_balance_atoms` | Gauge | Last known faucet account balance in atoms (`1 KVNC = 10^9` atoms). |

### Identity Headers (`GET /health` & `POST /faucet`)

Both `GET /health` and `POST /faucet` return network identity headers (also exposed via CORS `Access-Control-Expose-Headers`):

- `X-Kovanica-Chain-Id`: active chain ID (`2` on testnet).
- `X-Kovanica-Network-Tag`: canonical network tag (`2-24cdb5fadd98b207` on Chain 2).

### Prometheus Alerting & Cluster Monitor

- Prometheus alert rules for the faucet (and indexer) live in [`ops/monitoring/kovanica-faucet-indexer-alerts.yml`](../ops/monitoring/kovanica-faucet-indexer-alerts.yml), including `FaucetLowBalance` (`faucet_balance_atoms < 100000000000`, i.e. 100 KVNC), `FaucetHighRejectionRate`, and `FaucetRateLimitSpike`.
- Automated health verification can be run with [`ops/monitoring/check-cluster.py`](../ops/monitoring/check-cluster.py) using `--faucet-health-url <url>`, which checks `/health` status, `X-Kovanica-Chain-Id`, canonical tag `2-24cdb5fadd98b207`, and the minimum balance floor.

## Secret hygiene findings (resolved in P3-6)

- `ops/docker/chain2/faucet.keystore`, `ops/docker/chain2/faucet_passphrase`, and `ops/docker/chain2/node1_p2p.key` have been **untracked from git** and ignored via `.gitignore`, with local operator instructions in `ops/docker/chain2/README.md`.
- The misleading `.gitleaks.toml` "encrypted keystore test fixtures" allowlist entries for `ops/docker/chain2/faucet.keystore` and `ops/docker/chain2/node1_p2p.key` have been removed.
- Any previously committed values in git history must still be treated as public.
