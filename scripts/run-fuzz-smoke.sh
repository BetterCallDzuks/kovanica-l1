#!/usr/bin/env bash
# Automated Fuzz Smoke Test Suite and Runner
#
# Runs fast, deterministic fuzz smoke tests against the parser boundaries
# (StatementBlock, Transaction, Vote, and ConsensusBlock) without requiring
# cargo-fuzz or libfuzzer runtime binaries.
#
# Usage:
#   bash scripts/run-fuzz-smoke.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FUZZ_MANIFEST="${REPO_ROOT}/fuzz/Cargo.toml"

echo "=========================================================="
echo " Kovanica Fuzz Smoke Test Runner"
echo " Manifest: ${FUZZ_MANIFEST}"
echo "=========================================================="

echo "==> Step 1/2: Checking fuzz targets and workspace..."
cargo check --manifest-path "${FUZZ_MANIFEST}"
echo "✓ cargo check passed for all fuzz targets."

echo ""
echo "==> Step 2/2: Executing fuzz smoke integration tests..."
TEST_OUTPUT=$(cargo test --manifest-path "${FUZZ_MANIFEST}" --test smoke_tests -- --nocapture 2>&1)
echo "${TEST_OUTPUT}"

# Extract test results summary from cargo test output
PASSED_COUNT=$(echo "${TEST_OUTPUT}" | grep -oE '[0-9]+ passed' | head -n 1 | awk '{print $1}')
FAILED_COUNT=$(echo "${TEST_OUTPUT}" | grep -oE '[0-9]+ failed' | head -n 1 | awk '{print $1}')

echo ""
echo "=========================================================="
if [ "${FAILED_COUNT:-0}" -eq 0 ] && [ -n "${PASSED_COUNT}" ] && [ "${PASSED_COUNT}" -gt 0 ]; then
    echo "✓ Fuzz smoke tests SUCCEEDED: ${PASSED_COUNT} passed, 0 failed."
    echo "=========================================================="
    exit 0
else
    echo "✗ Fuzz smoke tests FAILED (${FAILED_COUNT:-0} failed)."
    echo "=========================================================="
    exit 1
fi
