# `ops/docker/chain2/` — Local Operator Secret Material (Untracked)

`ops/docker/docker-compose.chain2.yml` bind-mounts three operator-supplied files from this directory:

- `node1_p2p.key` — libp2p identity key for `kovanica-chain2-node1` (mounted at `/etc/kovanica/node1_p2p.key:ro`)
- `faucet.keystore` — encrypted keystore for `kovanica-chain2-faucet` (mounted at `/var/lib/kovanica/faucet.keystore:ro`)
- `faucet_passphrase` — passphrase file for `faucet.keystore` (mounted at `/var/lib/kovanica/faucet_passphrase:ro`; compose also accepts `KOVANICA_FAUCET_PASSPHRASE` via host env)

These three files are **untracked and gitignored** (`.gitignore`). Supply them locally on the deploy host with restrictive permissions (`0600` for `faucet_passphrase` and key material) before starting the compose stack — never commit them to git.
