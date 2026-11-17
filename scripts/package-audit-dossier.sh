#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

COMMIT_SHA="$(git rev-parse HEAD)"
SHORT_SHA="$(git rev-parse --short HEAD)"
TIMESTAMP="$(date -u +"%Y%m%d_%H%M%SZ")"
OUT_DIR="${REPO_ROOT}/target/audit-package"
ARCHIVE_NAME="kovanica-audit-dossier-${SHORT_SHA}.tar.gz"
ARCHIVE_PATH="${OUT_DIR}/${ARCHIVE_NAME}"

echo "============================================================"
echo " Packaging Kovanica External Audit Dossier"
echo " Commit: ${COMMIT_SHA} (${SHORT_SHA})"
echo " Timestamp: ${TIMESTAMP}"
echo "============================================================"

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}/staging"

echo "[1/4] Exporting clean git archive at ${SHORT_SHA}..."
git archive --format=tar "${COMMIT_SHA}" | tar -xf - -C "${OUT_DIR}/staging"

echo "[2/4] Generating auditor one-step reproduction harness..."
cat << 'EOF' > "${OUT_DIR}/staging/scripts/auditor-reproduce.sh"
#!/usr/bin/env bash
set -euo pipefail

echo "============================================================"
echo " Kovanica L1 — External Auditor Verification Suite"
echo "============================================================"

echo "[1/6] Checking Rust toolchain..."
rustc --version
cargo --version

echo "[2/6] Verifying workspace code formatting and clippy..."
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

echo "[3/6] Running Fuzz parser & deserialization smoke suite (14 boundaries)..."
bash scripts/run-fuzz-smoke.sh

echo "[4/6] Running Core Invariant Tests (Consensus, Wasmi, Crypto, Network)..."
cargo test -p kovanica-types --test pow
cargo test -p kovanica-crypto
cargo test -p kovanica-consensus --test hybrid_pow_simulation
cargo test -p kovanica-execution --test wasmi_gas_memory_metering
cargo test -p kovanica-network --test peer_reputation_scoring

echo "[5/6] Running Full Workspace Test Suite..."
cargo test --workspace

echo "[6/6] Verifying Security Advisories and Policy Gates..."
cargo deny check
cargo audit

echo "============================================================"
echo " ALL AUDITOR VERIFICATION GATES PASSED (CLEAN BILL OF HEALTH)"
echo "============================================================"
EOF
chmod +x "${OUT_DIR}/staging/scripts/auditor-reproduce.sh"

echo "[3/4] Packaging compressed audit archive..."
tar -czf "${ARCHIVE_PATH}" -C "${OUT_DIR}/staging" .

echo "[4/4] Computing cryptographic checksums..."
SHA256="$(sha256sum "${ARCHIVE_PATH}" | awk '{print $1}')"
echo "${SHA256}  ${ARCHIVE_NAME}" > "${OUT_DIR}/${ARCHIVE_NAME}.sha256"

echo "============================================================"
echo " Audit Dossier Successfully Packaged!"
echo " Location: ${ARCHIVE_PATH}"
echo " Size: $(du -h "${ARCHIVE_PATH}" | cut -f1)"
echo " SHA-256: ${SHA256}"
echo "============================================================"
