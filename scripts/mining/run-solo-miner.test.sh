#!/usr/bin/env bash
# Test suite for run-solo-miner.sh script validation rules.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_SCRIPT="${SCRIPT_DIR}/run-solo-miner.sh"

echo "Testing run-solo-miner.sh..."

# 1. Missing address should fail
set +e
"${TARGET_SCRIPT}" >/dev/null 2>&1
STATUS=$?
set -e
if [[ ${STATUS} -eq 0 ]]; then
    echo "FAIL: Expected failure when missing address" >&2
    exit 1
fi
echo "✓ Rejects missing address"

# 2. Invalid address format should fail
set +e
"${TARGET_SCRIPT}" --address "0x1234567890abcdef" >/dev/null 2>&1
STATUS=$?
set -e
if [[ ${STATUS} -eq 0 ]]; then
    echo "FAIL: Expected failure with non-PRO-21 address on chain 2" >&2
    exit 1
fi
echo "✓ Rejects non-PRO-21 address on chain 2"

# 3. Help flag should exit 0
"${TARGET_SCRIPT}" --help >/dev/null 2>&1
echo "✓ --help exits successfully"

echo "All run-solo-miner.sh tests passed!"
