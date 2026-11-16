# @kovanica/comms

TypeScript glue for the Kovanica comms client: identity, end-to-end message
sealing, the relay HTTP client, and name-registry call encoding. The package
is private (`@kovanica/comms`) and is consumed by other packages in this
repository.

The Comms application (desktop, Android, and the related app sources) lives in
[KovanicaDAG/kovanica-apps](https://github.com/KovanicaDAG/kovanica-apps).
Normative Comms interface documents were removed from this repository in #247.
No equivalent spec file is present in `kovanica-apps` (its `docs/` tree holds
app build notes only).

## Scripts

From `packages/comms`, using the scripts in `package.json`:

- `npm run build` runs `tsc --noEmit` (typecheck, no emit).
- `npm test` runs `vitest run`.

## Status

The package remains client-side glue next to `crates/kovanica-comms-crypto`,
`crates/kovanica-comms-relay`, and `crates/kovanica-name-registry`. It does not
run a relay or a node.
