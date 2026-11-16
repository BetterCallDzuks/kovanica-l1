# Faucet funding (chain 2, post-genesis top-up)

The chain-2 genesis is frozen. `testnet/chain2/funded_accounts.toml` is a genesis
input: its balances are baked into the genesis digest, and the digest is what
produces the network tag `2-acfdf6a6c80fd28a`. Adding the current faucet address
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
| Genesis validators (mining reward) | `kvncda8z9…`, `kvnc8kscelhl…`, `kvnc30f77rhd…` | 630 / 735 / 772.5 KVNC | reward recipients; no host seed derives to them |
| Treasury | `kvncqctcedn…` | `0x0` | pre-funded only on mainnet |

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

Run on seed1 (values are placeholders for the copy actually in use):

```sh
docker run -d --name kovanica-faucet-topup \
  --network container:kovanica-chain2-node1 \
  --user 0:0 \
  --env-file /root/kovanica-chain2-rpc.env \
  -v /root/faucet-topup/sender.json:/k.json:ro \
  -v /root/faucet-topup/passphrase:/p.txt:ro \
  --entrypoint kovanica-faucet kovanica-node:local \
  --chain-id 2 \
  --keystore /k.json \
  --passphrase-file /p.txt \
  --rpc-url http://127.0.0.1:8545/rpc \
  --listen 127.0.0.1:18500 \
  --dispense-kovanica 99999
```

- `--user 0:0` is required: the bind-mounted keystore/passphrase are root-owned
  `0600`, and the `--passphrase-file` check runs as the container user. (The
  long-running compose faucet runs as uid 10001 and therefore takes its
  passphrase from the env instead.)
- `--dispense-kovanica 99999` drains the sender down to the 0.001 KVNC fee plus
  dust. Use any amount ≤ `balance − 0.001`.
- There is no per-request cap and the request body's `amount` is ignored; the
  dispense size is fixed by this flag.

Then request the single dispense from inside the node's namespace (the funder is
not reachable from the host):

```sh
docker exec kovanica-chain2-node1 curl -s \
  -X POST -H 'content-type: application/json' \
  -d '{"address":"kvnc8a4atp0g5tngcua9h90anhel7233alyd5y88h0yc592cv8adu5uyz46d3dag"}' \
  http://127.0.0.1:18500/faucet
```

The response carries `tx_hash`. Verify:

```sh
docker exec kovanica-chain2-faucet curl -s -o /dev/null -w '%{http_code}\n' \
  http://127.0.0.1:3000/health
# balance for the faucet address via kovanica_getBalance on 127.0.0.1:8545/rpc
```

Clean up: `docker rm -f kovanica-faucet-topup`, and delete the copied keystore
and passphrase file. Do **not** start the funder with `--rm`: its log has to
survive long enough to read the `tx_hash` and any error.

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
- Fund **last**. If the live faucet's passphrase has ever been handled in a way
  that could have echoed it (a pty wrapper, a shell with tracing, a pasted
  command line), rotate the faucet keystore *before* the top-up lands, not after:
  an empty faucet is the cheapest possible moment to rotate.

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

Nothing else on the host can sign: founder/operator wallet seeds, node-volume
validator keys, and the `etc-kovanica` validator keys all derive to accounts with
`0x0`, and `founder_premine.hex` is a placeholder, not a seed. The three genesis
validators hold 2 137.5 KVNC between them, but no host seed derives to them.

### Unblock options

1. Operator supplies the pre-rotation passphrase in a `0600` file on seed1 →
   run the procedure above and record the `tx_hash`.
2. Operator supplies any other funded, signable key on chain 2 → same procedure
   with that keystore.
3. Accept a faucet at `0` for now → the faucet stays healthy but dispenses
   nothing; `STATE.md` gap #5 stays open.

Only option 1 recovers the 100 000 KVNC already sitting in the genesis-funded
account.

## Secret hygiene findings (follow-up, needs its own PR)

- `ops/docker/chain2/faucet.keystore`, `ops/docker/chain2/faucet_passphrase`, and
  `ops/docker/chain2/node1_p2p.key` are **tracked in git**. The keystore and the
  p2p key are allowlisted in `.gitleaks.toml` (described as "encrypted keystore
  test fixtures" — they are not fixtures).
- The tracked passphrase file is not the passphrase the faucet ever used, which
  is worse than either extreme: it looks like a working secret, so it hides the
  fact that the real one was never in the repo.
- Removing or rotating these files touches genesis-adjacent ops state and CI
  gating config, so it needs an explicit decision, not a drive-by edit. Until
  then: treat the tracked values as public.
