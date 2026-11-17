# kovanica-faucet

Rate-limited testnet faucet (`POST /faucet`, `GET /health`).

```
kovanica-faucet --chain-id 2 --keystore faucet.keystore --rpc-url http://127.0.0.1:8545 --listen 0.0.0.0:8080 \
            [--dispense-kovanica 10] \
            [--rate-limit-window 3600] [--max-requests 3] \
            [--address-rate-limit-window 86400] [--address-max-requests 1]
```

`--chain-id` is **required** (no default): 1 mainnet, 2 testnet, 3 devnet. Any other value is rejected at startup.

## Rate limits: per IP and per address, configured separately

Two independent limiters run on every request, each with its own window and cap:

| Limiter | Flags | Env | Default |
|---|---|---|---|
| Client IP | `--rate-limit-window`, `--max-requests` | — | 3600 s / 3 |
| Destination address | `--address-rate-limit-window`, `--address-max-requests` | `KOVANICA_FAUCET_ADDRESS_RATE_LIMIT_WINDOW`, `KOVANICA_FAUCET_ADDRESS_MAX_REQUESTS` | 86400 s / 1 |

The address limiter is what stops a single address being drained by rotating IPs: with the defaults,
one address receives one dispense per 24 h no matter how many clients ask for it. The IP limiter is the
per-caller budget. Both are checked before any node RPC call, so a refused request costs nothing.

The reference testnet deployment runs 5 requests per hour per IP and 1 per 24 h per address
(`ops/docker/docker-compose.chain2.yml`).

## Mainnet guard

`--chain-id 1` (mainnet) is **refused by default**: the faucet would dispense real KVNC. To run it on
mainnet anyway you must pass the explicit, loudly-named `--allow-mainnet` flag or set
`KOVANICA_FAUCET_ALLOW_MAINNET=1`. Both print a startup warning; without one the process exits with a
clear error before loading the keystore.

## Rate limiting behind a reverse proxy

The per-IP rate limiter keys on the client IP. `X-Forwarded-For` is **only** trusted when the socket
peer is a configured trusted proxy:

```
kovanica-faucet --chain-id 2 --trusted-proxies 10.0.0.0/8,127.0.0.1 ...
# or: KOVANICA_FAUCET_TRUSTED_PROXIES=10.0.0.0/8,127.0.0.1
```

When the flag/env is unset — or the peer is not in the list — the socket peer IP is used and any
client-supplied `X-Forwarded-For` is ignored. In a trusted chain the header is walked right-to-left,
skipping trusted hops; the first untrusted address is the real client. A malformed list fails startup.

If no trusted proxy is configured while the faucet listens on a loopback/private address, it logs one
startup warning: in that setup every caller shares a single IP bucket, because all requests arrive from
the proxy. Set `KOVANICA_FAUCET_TRUSTED_PROXIES` (or `--trusted-proxies`) to the proxy's address/CIDR.

## Low-balance guard (optional)

`--min-balance-ku <n>` makes the faucet return HTTP 503 instead of attempting a transfer when its own
balance drops below `n` KVNC. The default `0` disables the check.

## Keystore passphrase

There is **no `--passphrase` flag**. Command-line arguments are visible in `ps` and shell history.
For an encrypted keystore, the passphrase is taken from the first of these that is available:

1. `--passphrase-file <path>`: the file's contents, with trailing `\n`/`\r\n` trimmed. On unix the file
   must be mode `0600` or `0400`; otherwise the faucet refuses to start.
2. env `KOVANICA_FAUCET_PASSPHRASE` (non-empty).
3. an interactive no-echo prompt, but only when stdin is a TTY.

If none is available, the faucet exits with an error. The passphrase is never logged. It is kept in
zeroizing memory and wiped right after the keystore is decrypted.

Docker/compose: mount a secret file (e.g. `/run/secrets/faucet_passphrase`, mode 0400) and pass
`--passphrase-file /run/secrets/faucet_passphrase`.

The reference testnet compose service (`ops/docker/docker-compose.chain2.yml`) takes the passphrase from
`KOVANICA_FAUCET_PASSPHRASE`, which is passed through from the host env file as
`"${KOVANICA_FAUCET_PASSPHRASE:-}"`. The value must therefore be present in the host env file at the
deploy that includes this change; it is never written into the compose file or the repo. With `:-` a
missing value only leaves the faucet unhealthy, it never blocks `docker compose up` for the nodes.


## Post-reset refill runbook

1. Ensure faucet balance > `min_balance_atoms`.
2. Restart faucet; verify `/health` and low-balance guard (503 when low).
3. Monitor metrics and refill before depletion.
