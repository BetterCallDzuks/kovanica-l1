# kovanica-l1 – OpenCode Agent Instructions

> **Project identity (NE MJEŠAJ S DRUGIM PROJEKTIMA)**

**kovanica-l1** is a clean, from-scratch Rust Layer-1 blockchain repository (`KovanicaDAG/kovanica-l1`, renamed from `kovanica`, #243). Apps live in `KovanicaDAG/kovanica-apps`, web in `KovanicaDAG/kovanica-web`.

**Agent project-manager docs (read first):**
- [`docs/AGENT-RULES.md`](docs/AGENT-RULES.md) — frozen values, what agents may/must not touch, consensus-change rule, live seed1 state.
- [`docs/PLAN-2026-11.md`](docs/PLAN-2026-11.md) — current priorities (P0–P5), open PRs, mainnet prep, non-goals.
These two replace Gazda for day-to-day agent work. If a prompt conflicts with them, stop and ask Toni.

**Naming (zaključano):** chain = **Kovanica**, native coin ticker = **KVNC** (9 decimals; preimenovano natrag iz KUNA per Toni 2026-11-05),
codebase/binary/env prefiks = **kovanica** (`kovanica-*` crate-ovi, `kovanica-node`, `KOVANICA_*`). Adresa je
`kvnc` + 57 base32 znakova (bech32 abeceda, samo mala slova) + `dag` = 64 znaka (PRO-21: 32 B ključ ‖ prvih 29 bitova blake3(ključ)); `FromStr` je samo taj oblik. Legacy `kvnc<hex>dag` i hex (heks znamenke case-insensitive, affixi i `0x` mala slova) na kovanica-devnet (chain ID 3) i local (chain ID 1337), odbijeni na kovanica-mainnet (chain ID 1), kovanica-testnet (chain ID 2) i svakom drugom id-u. Adresni prefiks `kvnc`...`dag` je usklađen s KVNC tickerom.

**Chain ID Registry (4 Registered Chains: 2 Canonical Public + 2 Dev):**
- `1` = **kovanica-mainnet** (chain ID 1) (`MAINNET`) — canonical PRO-21 base32 address, Hybrid PoW + GHOSTDAG (NO stake for consensus, KovanicaHash, target block 4 s, GHOSTDAG K=5). `funded_accounts.toml` strictly forbidden. Fee split: 3/4 burned, 1/4 miner (`NoStake82M`). DAA: easiest target `0x1f00_ffff`.
- `2` = **kovanica-testnet** (chain ID 2) (`TESTNET`) — official Hybrid PoW + GHOSTDAG testnet (KovanicaHash, target block 4 s, GHOSTDAG K=5, NO stake for consensus; canonical PRO-21 base32 addresses strictly enforced; `funded_accounts.toml` and faucet allowed; legacy alias HYBRID_TESTNET=2). Official network tag: `2-acfdf6a6c80fd28a`. Host topology is seed1-only (`seed1.kovanica.online`; seed2 and seed3 are no longer hosts; seed3 / seed-extra remain only as bootstrap identities in genesis). Fee split: 3/4 burned, 1/4 miner (`NoStake82M`). DAA: easiest target `0x1f7f_ffff`, hardest `0x1e00_ffff` (#242).
- `3` = **kovanica-devnet** (chain ID 3) (`DEVNET`) — devnet; legacy hex addresses allowed, dev parameter overrides. Fees 100% burned. DAA: easiest target `0x1f7f_ffff`, hardest `0x1e00_ffff`.
- `1337` = **local** (chain ID 1337) (`LOCAL`) — single-node / local cluster testing (legacy hex allowed). Fees 100% burned.

*Params SoT:* `kovanica-params`. `funded_accounts.toml` allowed on every chain except kovanica-mainnet (chain ID 1).
*RPC Authentication:* RPC writes require bearer auth (#234); `KOVANICA_RPC_AUTH` must never be documented as something to disable.
*Public Launch:* Planned 1.1.2027.

| Layer              | Choice                                      |
|--------------------|---------------------------------------------|
| Consensus          | Hybrid PoW + GHOSTDAG (NO stake for consensus; target block 4 s, GHOSTDAG K=5; PoW hash: KovanicaHash) |
| Execution          | Wasmi (deterministic WASM)                  |
| Account model      | Account-based                               |
| Resource target    | Comfortable on 2–4 GB RAM VPS               |
| Native token       | KVNC (9 decimals)                           |

## HARD RULES (NEKRŠIVA)

1. **NE** uvozi, kopiraj, referenciraj ili miješaj bilo kakav kod/dizajn iz `kovanica-protocol`, starijih Kovanica repozitorija ili bilo kojeg drugog lanca.
2. Ovo je **nezavisan** codebase. Sve odluke moraju biti konzistentne s ovim dokumentom i postojećim crate-ovima.
3. Preferiraj **male, fokusirane, auditabilne** promjene. Jedan PR = jedna jasna namjera.
4. Ne diraj tokenomics parametre bez eksplicitnog odobrenja.
5. Ciljaj uvijek na 2–4 GB RAM footprint.
6. **Read `docs/AGENT-RULES.md` before any change.** Frozen values and live seed1 state are listed there. Consensus changes need an activation plan and must not be deployed without Toni.

## Consensus & PoW Hash (zaključano Toni 2026-11-05)

- **Product-of-record consensus:** Hybrid PoW + GHOSTDAG; **NO stake for consensus** (odluka Toni 2026-11-05); stake/delegate/unstake/claim/commission are refused fail-closed (#233).
- **PoW Hash:** **KovanicaHash** (striktno NE KunaHash; blake3 + 2 MiB memory mix; audit obavezan prije mainneta).
- **Consensus defaults:** `TARGET_BLOCK_MS = 4000` (4 s) i `GHOSTDAG_K = 5`.
- **Legacy Mysticeti constants (still in tree until hybrid flag):** `WAVE_LENGTH = 3`, `EPOCH_ROUNDS = 7200`, `LEADER_INTERVAL_SECS = 12`, `ROUND_SECS = 4`.
- **Legacy / non-consensus under hybrid:** `MIN_VALIDATOR_STAKE`, `MIN_DELEGATION`, `JAIL_ROUNDS` (raniji Mysticeti-C parametri više nisu u konsenzusnom putu pod hibridom; staking pozivi odbijaju se fail-closed).
- **Launch gating:** Javni launch je planiran za 1.1.2027.
- **PRO-7 Status:** FROZEN za hibridni konsenzus (Mysticeti VRF leader put je napušten u korist PoW + GHOSTDAG).

## Tokenomics (zaključano)

> Revidirano 2026-10-13 / Ažurirano 2026-11-05 / no-stake 2026-11-06: ticker KVNC, s₀=2,5 KVNC, era=8 200 000 rewarded blokova, budget=82M, genesis validatorska alokacija 0 (1M vraćen u mining emission), target block 4 s (`TARGET_BLOCK_MS = 4000`), GHOSTDAG K=5. kovanica-mainnet (chain ID 1) i kovanica-testnet (chain ID 2) su oba hybrid (`NoStake82M`) s fee splitom 3/4 burn, 1/4 miner (#239, #245); kovanica-devnet (chain ID 3) i local (chain ID 1337) ostaju 100% burn; legacy `Legacy81M` konstante ostaju u kodu samo za postojeće baze i dev chainove.

| Parameter                  | Value                                          |
|---------------------------|------------------------------------------------|
| Total supply              | **90 200 000 KVNC**                            |
| Decimals                  | 9                                              |
| Founder premine           | 200 000 KVNC                                   |
| Treasury                  | 8 000 000 KVNC (1 M/year × 8 years, linear)    |
| Genesis validator alloc.  | **0 KVNC** (ukinuto — nema stakea u konsenzusu; **genesis bootstrap seeds 1..=20**, bez stakea i bez alokacije; bivši 1M vraćen u mining emission) |
| Mining subsidy budget     | **82 000 000 KVNC** (= 90.2M − 0.2M − 8M) |
| Initial block reward      | **2,5 KVNC** (paid to committed block author)  |
| Subsidy era length        | **8 200 000** rewarded blocks (`SUBSIDY_ERA_BLOCKS_NO_STAKE_82M`, legacy 8.1M ostaje za `Legacy81M`) |
| Decay                     | **× 3/4** each era                             |
| Target block time         | 4 s (`TARGET_BLOCK_MS = 4000`)                 |
| GHOSTDAG parameter K      | 5 (`GHOSTDAG_K = 5`)                           |
| Epoch (legacy Mysticeti)  | epoch = 8 h = 7 200 DAG rundi = 2 400 leader visina (legacy Mysticeti constant) |
| Min validator stake       | 50 000 KVNC (`MIN_VALIDATOR_STAKE`; legacy / non-consensus) |
| Min delegation            | 50 000 KVNC (`MIN_DELEGATION`; legacy / non-consensus)      |
| Jail duration             | 7 200 heights (`JAIL_ROUNDS`; legacy / non-consensus)       |

Reward se mint-a na committed blokove, autoru bloka. Genesis bootstrap seeds (1..=20) ne drže stake i ne dobivaju alokaciju; `[[validator]]` u genesis datoteci je samo zapis bootstrap identiteta (zaostali naziv tablice).

## Workspace structure (poštuj postojeće)

```
crates/ (47 crates: 41 active, 6 stubs)
├── kovanica-bench             # Benchmark suite
├── kovanica-cli               # CLI client & wallet
├── kovanica-codec             # Stub (minimal versioned blob wrapper around bincode)
├── kovanica-common            # Common primitives & WASM host traits
├── kovanica-comms-core        # Canonical comms identity derivation
├── kovanica-comms-crypto      # E2E message encryption (X25519 + XChaCha20-Poly1305)
├── kovanica-comms-relay       # Store-and-forward relay server
├── kovanica-consensus         # GHOSTDAG ordering & committer
├── kovanica-consensus-sim     # Stub (simulation scenario harness placeholder)
├── kovanica-contract-sdk      # WASM contract SDK & storage
├── kovanica-crypto            # Ed25519, BLAKE3, Ristretto255 VRF
├── kovanica-dag               # Causal history DAG & mergesets
├── kovanica-devnet            # Devnet config generation
├── kovanica-escrow            # Lightnode reward escrow
├── kovanica-execution         # State transitions, WASM runtime host, fee split
├── kovanica-faucet            # Rate-limited token faucet service
├── kovanica-fee               # Fee schedule & gas estimation
├── kovanica-governance        # Stub (in-memory proposal placeholder)
├── kovanica-htlc              # Hash time-locked contract
├── kovanica-hw-signer         # Stub (hardware signer interface demo)
├── kovanica-indexer           # Block indexer & scanner
├── kovanica-keystore          # Keystore v2 (Argon2id + XChaCha20-Poly1305)
├── kovanica-light             # Light client verification engine
├── kovanica-light-ffi         # UniFFI mobile language bindings
├── kovanica-light-proofs      # Blake3 Merkle inclusion proofs
├── kovanica-lightnode         # Lightnode daemon binary
├── kovanica-mempool           # Nonce-tracking transaction pool
├── kovanica-migrate           # State migration framework & CLI
├── kovanica-multisig          # Threshold multi-signature contract
├── kovanica-name-registry     # RFC-008 decentralized naming contract
├── kovanica-network           # libp2p P2P networking & block sync
├── kovanica-nft               # Non-fungible token contract
├── kovanica-node              # Full-node daemon binary & genesis tooling
├── kovanica-oracle            # Stub (in-memory price feed placeholder)
├── kovanica-p2p-identity      # Peer identity & key derivation
├── kovanica-params            # Protocol parameters, tokenomics & DAA targets
├── kovanica-rpc               # JSON-RPC 2.0 & WebSocket server
├── kovanica-runtime           # Wasmi WebAssembly engine
├── kovanica-sdk               # Client SDK & contract interfaces
├── kovanica-snapshot          # State export/import snapshot CLI
├── kovanica-staking           # Emission curves & historical staking state
├── kovanica-storage           # redb embedded storage engines
├── kovanica-sync              # Stub (block/snapshot sync trait definitions)
├── kovanica-token             # Fungible token contract & AMM pool
├── kovanica-types             # Core types (Block, Transaction, Address)
├── kovanica-vault             # Linear/cliff vesting vaults
└── kovanica-wallet-core       # Wallet account management & derivation
```

Packages (TypeScript):
- `packages/api-client`
- `packages/console`
- `packages/signer`
- `packages/web` (Client apps live in `KovanicaDAG/kovanica-apps`, web in `KovanicaDAG/kovanica-web`)

Contracts (već implementirani): HTLC, Vault, Multisig, Token + Host trait.

## Snapshot (current workspace)

- Workspace crates: 47 total (41 active, 6 stubs; 27 in the 2026-10-24 @ dd3aff9 historical snapshot)
- Rust source: ~90.5k LOC (crates) / ~95.5k LOC (repo) across 163 `.rs` files
- TypeScript packages: 4 in repo (`api-client`, `console`, `signer`, `web`)
- Default P2P listen: `0.0.0.0:8000`
- Default RPC bind: `127.0.0.1:8545`
- Target block time: 4000 ms (`TARGET_BLOCK_MS`); legacy 12 s leader cadence is retired
- Max peers: 50 (`config.example.toml`)
- Workspace tests: 1,101+ tests passing (100% pass in verified crate suites)
- Public launch: Planned 1.1.2027

## Coding standards

- Rust 2021 / 2024 edition po Cargo.toml
- Prefer `thiserror` + `anyhow` gdje ima smisla
- Determinističko ponašanje svugdje (Wasmi, consensus, rewards)
- Unit + integration testovi za svaku novu logiku
- Ne dodavaj nepotrebne dependencies
- Dokumentiraj javne API-je (rustdoc)
- Imena: snake_case, jasna, bez prefiksa "kovanica"

## Preferred next focus areas (prioritet)

See `docs/PLAN-2026-11.md` for the current ordered list (P0 live stability → P1 DAA #259 → P3 ops polish → P4 mainnet prep → P5 codebase polish).

Historical focus areas (still valid as themes):
A. Network & Node hardening (P2P, sync, snapshot/pruning, genesis)
B. Hybrid PoW & GHOSTDAG consensus & mining operations (KovanicaHash, DAA, GHOSTDAG K=5)
C. Execution & Contract UX (gas metering, ABI, deployment)
D. Observability (logging, metrics, indexer hooks)
E. Testnet readiness (multi-node, faucet, chaos)

## Kako raditi s Grok-om

- Grok = arhitekt + reviewer + planer
- OpenCode (ti) = implementator (file edit + shell + testovi)
- Kad dobiješ plan od Grok-a → izvrši ga u ovom sessionu
- Nakon implementacije vrati diff / test output za review
- Prije rada pročitaj `docs/AGENT-RULES.md` i `docs/PLAN-2026-11.md`.

## Zabranjeno

- Miješanje s kovanica-protocol
- Promjena tokenomics bez odobrenja
- Veliki refaktori bez plana
- Dodavanje novih crate-ova bez opravdanja
- Non-deterministički kod u consensus/execution putu
- Deploy consensus promjena (npr. #259 DAA) bez Toni odluke o aktivaciji
- Dirati seed1 docker/volumes/nginx osim ako je prompt eksplicitni ops zadatak
