#!/usr/bin/env bash
# ==============================================================================
# Kovanica Solo Miner Production Runner
#
# Production launch script for standalone multithreaded solo and Stratum mining
# on the Kovanica Layer-1 blockchain (Hybrid PoW + GHOSTDAG, KovanicaHash).
#
# Usage:
#   ./scripts/mining/run-solo-miner.sh --address kvnc1...dag [OPTIONS]
#
# Options:
#   -a, --address <addr>      Payout address (canonical PRO-21 base32 kvnc...dag)
#   -t, --threads <num>       Worker threads (default: all logical cores)
#   -r, --rpc-url <url>       Node JSON-RPC endpoint (default: http://127.0.0.1:8545)
#   -s, --stratum <endpoint>  Optional Stratum V1 TCP endpoint (e.g. 127.0.0.1:3333)
#   -w, --worker <name>       Worker rig name for Stratum pool (default: default)
#   -c, --chain-id <id>       Chain ID (1: mainnet, 2: testnet [default], 3: devnet)
#   -p, --poll-ms <ms>        Candidate work polling interval (default: 1000)
#   -h, --help                Show this help message and exit
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

ADDRESS="${KOVANICA_MINER_ADDRESS:-}"
THREADS=""
RPC_URL="${KOVANICA_RPC_URL:-http://127.0.0.1:8545}"
STRATUM="${KOVANICA_STRATUM_ENDPOINT:-}"
WORKER="default"
CHAIN_ID="${KOVANICA_CHAIN_ID:-2}"
POLL_MS="1000"

print_usage() {
    sed -n '3,21p' "$0" | sed 's/^# \{0,1\}//'
}

# Parse Command-Line Options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -a|--address)
            ADDRESS="$2"
            shift 2
            ;;
        -t|--threads)
            THREADS="$2"
            shift 2
            ;;
        -r|--rpc-url)
            RPC_URL="$2"
            shift 2
            ;;
        -s|--stratum)
            STRATUM="$2"
            shift 2
            ;;
        -w|--worker)
            WORKER="$2"
            shift 2
            ;;
        -c|--chain-id)
            CHAIN_ID="$2"
            shift 2
            ;;
        -p|--poll-ms)
            POLL_MS="$2"
            shift 2
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo "Error: Unknown argument: $1" >&2
            print_usage
            exit 1
            ;;
    esac
done

if [[ -z "${ADDRESS}" ]]; then
    echo "Error: Missing required payout address (--address or KOVANICA_MINER_ADDRESS)." >&2
    echo "Use --help for usage information." >&2
    exit 1
fi

# Detect Logical CPU Cores if not explicitly set
if [[ -z "${THREADS}" ]]; then
    if command -v nproc >/dev/null 2>&1; then
        THREADS="$(nproc)"
    elif command -v sysctl >/dev/null 2>&1; then
        THREADS="$(sysctl -n hw.ncpu 2>/dev/null || echo 1)"
    else
        THREADS=1
    fi
fi

# Validate Address format for Chains 1 & 2 (PRO-21: starts with kvnc, ends with dag, 64 chars)
if [[ "${CHAIN_ID}" == "1" || "${CHAIN_ID}" == "2" ]]; then
    if [[ ! "${ADDRESS}" =~ ^kvnc[0-9a-z]{57}dag$ ]]; then
        echo "Error: Invalid PRO-21 address '${ADDRESS}'." >&2
        echo "On chains 1 and 2, mining rewards require a canonical 64-character base32 address (kvnc...dag)." >&2
        exit 1
    fi
fi

# Locate or build the kovanica binary
BIN_PATH=""
if [[ -x "${WORKSPACE_ROOT}/target/release/kovanica" ]]; then
    BIN_PATH="${WORKSPACE_ROOT}/target/release/kovanica"
elif [[ -x "${WORKSPACE_ROOT}/target/debug/kovanica" ]]; then
    BIN_PATH="${WORKSPACE_ROOT}/target/debug/kovanica"
elif command -v kovanica >/dev/null 2>&1; then
    BIN_PATH="$(command -v kovanica)"
else
    echo "Building release binary for kovanica-cli..."
    (cd "${WORKSPACE_ROOT}" && cargo build --release -p kovanica-cli)
    BIN_PATH="${WORKSPACE_ROOT}/target/release/kovanica"
fi

SCRATCHPAD_MB=$((THREADS * 2))

echo "============================================================"
echo "          Kovanica Hybrid PoW Solo Mining Runner            "
echo "============================================================"
echo " Consensus:           Hybrid PoW + GHOSTDAG (zero stake)"
echo " PoW Algorithm:       KovanicaHash (BLAKE3 + 2 MiB mix)"
echo " Network Tag:         2-24cdb5fadd98b207 (Chain ID ${CHAIN_ID})"
echo " Payout Address:      ${ADDRESS}"
echo " Worker Threads:      ${THREADS}"
echo " Scratchpad Memory:   ${SCRATCHPAD_MB} MiB total (2 MiB per thread)"
if [[ -n "${STRATUM}" ]]; then
echo " Mode:                Stratum V1 Pool Client"
echo " Stratum Endpoint:    ${STRATUM}"
echo " Worker ID:           ${ADDRESS}.${WORKER}"
else
echo " Mode:                Direct HTTP Solo Miner"
echo " Node RPC URL:        ${RPC_URL}"
echo " Poll Interval:       ${POLL_MS} ms"
fi
echo "============================================================"

# Prepare arguments
CMD_ARGS=(
    "miner" "run"
    "--address" "${ADDRESS}"
    "--threads" "${THREADS}"
    "--chain-id" "${CHAIN_ID}"
)

if [[ -n "${STRATUM}" ]]; then
    CMD_ARGS+=("--stratum" "${STRATUM}" "--worker" "${WORKER}")
else
    CMD_ARGS+=("--rpc-url" "${RPC_URL}" "--poll-interval-ms" "${POLL_MS}")
fi

trap 'echo ""; echo "Shutting down Kovanica miner..."; exit 0' SIGINT SIGTERM

exec "${BIN_PATH}" "${CMD_ARGS[@]}"
