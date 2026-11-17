#!/usr/bin/env bash
# Task SIM-1: Multi-threaded transaction spam, Wasmi contract execution, and mempool soak runner
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

echo "=== Running Task SIM-1 Soak Simulation ==="
cargo test -p kovanica-node --test sim1_soak_simulation -- --nocapture

if [ -f "$REPO_ROOT/ops/soak/reports/sim1_soak_report.json" ]; then
    echo ""
    echo "=== SIM-1 Soak Report Summary ==="
    cat "$REPO_ROOT/ops/soak/reports/sim1_soak_report.json"
    echo ""
fi
