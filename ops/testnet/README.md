# kovanica-testnet public seeds (seed1..3)
1. `./gen-p2p-key.sh /etc/kovanica/seedN.p2p.key` on each host (keys are never stored in git).
2. Copy `seedN.env.example` -> `/etc/kovanica/seedN.env`, install `ops/systemd/kovanica-seed@.service`.
3. `sudo ./firewall.sh`; include `nginx-ratelimit.conf` and `ops/ingress/setup-nginx.sh seedN`.
4. Enable the seeder on one seed; publish the generated zone file for `seed.kovanica.online`.
5. Faucet: `kovanica-faucet --chain-id 2 --rate-limit-window 3600 --max-requests 5 --address-rate-limit-window 86400 --address-max-requests 1` (per-IP and per-address limits are configured separately; see `crates/kovanica-faucet/README.md`).
Credentials are not kept in this repo.
