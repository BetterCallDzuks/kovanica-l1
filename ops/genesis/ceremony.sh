#!/usr/bin/env bash
# Genesis ceremony for the Kovanica canonical networks:
#
#   kovanica-mainnet (chain ID 1)   hybrid PoW + GHOSTDAG, no-stake-82m
#   kovanica-testnet (chain ID 2)   hybrid PoW + GHOSTDAG, no-stake-82m
#   kovanica-devnet  (chain ID 3)   legacy policy, dev overrides
#
# DRAFT tooling: the procedure is documented in docs/GENESIS-CEREMONY.md. It
# produces the genesis file set a node needs (genesis.json preview,
# genesis_validators.toml, founder_premine.hex, bootnodes.toml, SHA256SUMS), never a
# published network. The official genesis waits on the owner's real founder,
# treasury and bootstrap-seed addresses (addresses only, never private keys).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

NETWORK="testnet"
VALIDATORS_FILE=""
OUTPUT_DIR="./genesis-out"
TREASURY_ADDRESS=""
FOUNDER_ADDRESS=""
CHAIN_ID=""
FORCE=false
GENERATE_KEYS=false

die() {
    echo "ERROR: $*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: ops/genesis/ceremony.sh --network <mainnet|testnet|devnet> [OPTIONS]

Required for every network:
  --treasury-address <address>  Real treasury address (owner-supplied).
  --founder-address <address>   Real founder premine address (owner-supplied).

Options:
  --validators <file.json>      Input validator set (default: <network>/validators/validators.json)
  --output <dir>                Output directory (default: ./genesis-out)
  --chain-id <id>               Override the network's chain id (1, 2, 3)
  --generate-keys               Write throwaway validator keys under <output>/keys (refused on kovanica-mainnet)
  --force                       Overwrite files inside <output>
  -h, --help                    This message

kovanica-mainnet (chain ID 1) and kovanica-testnet (chain ID 2) are hybrid (PoW + GHOSTDAG):
the ceremony passes --emission-policy no-stake-82m, writes no stake field, and requires every
validator, founder and treasury address to already be a canonical PRO-21 kvnc...dag address.
Legacy hex is refused, not converted.
EOF
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --network) NETWORK="$2"; shift 2 ;;
        --validators) VALIDATORS_FILE="$2"; shift 2 ;;
        --output) OUTPUT_DIR="$2"; shift 2 ;;
        --treasury-address) TREASURY_ADDRESS="$2"; shift 2 ;;
        --founder-address) FOUNDER_ADDRESS="$2"; shift 2 ;;
        --chain-id) CHAIN_ID="$2"; shift 2 ;;
        --force) FORCE=true; shift ;;
        --generate-keys) GENERATE_KEYS=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "$CHAIN_ID" ]]; then
    case "$NETWORK" in
        mainnet|kovanica-mainnet) CHAIN_ID=1 ;;
        testnet|kovanica-testnet) CHAIN_ID=2 ;;
        hybrid-testnet|hybrid_testnet) CHAIN_ID=2 ;;
        devnet|kovanica-devnet) CHAIN_ID=3 ;;
        *) die "unknown --network '$NETWORK'; use mainnet, testnet or devnet" ;;
    esac
fi

case "$CHAIN_ID" in
    1|2) HYBRID=true ;;
    3) HYBRID=false ;;
    *) die "chain id $CHAIN_ID is not a canonical chain; use 1 (kovanica-mainnet), 2 (kovanica-testnet) or 3 (kovanica-devnet)" ;;
esac

if [[ "$CHAIN_ID" -eq 1 ]] && $GENERATE_KEYS; then
    die "kovanica-mainnet (chain ID 1) refuses --generate-keys: mainnet private keys must be generated offline by Toni; the ceremony tool accepts public addresses and public keys only"
fi

# PRO-21: "kvnc" + 57 bech32 characters + "dag" = 64 characters, lower case.
is_pro21_address() {
    [[ "$1" =~ ^kvnc[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{57}dag$ ]]
}

is_hex_address() {
    [[ "$1" =~ ^[0-9a-fA-F]{64}$ ]]
}

if [[ -z "$TREASURY_ADDRESS" ]]; then
    die "--treasury-address is required and must be the owner's real address; the ceremony writes no placeholder treasury"
fi
if [[ -z "$FOUNDER_ADDRESS" ]]; then
    die "--founder-address is required and must be the owner's real address; the ceremony writes no placeholder founder"
fi

check_address() {
    local label=$1 value=$2
    if is_pro21_address "$value"; then
        return 0
    fi
    if [[ "$HYBRID" == false ]] && is_hex_address "$value"; then
        return 0
    fi
    if [[ "$HYBRID" == true ]]; then
        die "$label address '$value' is not a canonical PRO-21 kvnc...dag address; chain $CHAIN_ID accepts only PRO-21 addresses and the ceremony will not convert legacy hex or invent keys"
    fi
    die "$label address '$value' is neither a canonical PRO-21 kvnc...dag address nor a 32-byte hex address"
}

check_address treasury "$TREASURY_ADDRESS"
check_address founder "$FOUNDER_ADDRESS"

if [[ -z "$VALIDATORS_FILE" ]]; then
    if [[ -f "$REPO_ROOT/$NETWORK/validators/validators.json" ]]; then
        VALIDATORS_FILE="$REPO_ROOT/$NETWORK/validators/validators.json"
    elif [[ -f "./validators.json" ]]; then
        VALIDATORS_FILE="./validators.json"
    else
        die "--validators <file.json> required or could not find validators.json for network $NETWORK"
    fi
fi

if [[ ! -f "$VALIDATORS_FILE" ]]; then
    die "validators file not found: $VALIDATORS_FILE"
fi

# Never write over a committed artefact. Those files belong to historical
# networks; a new ceremony output goes to --output only.
if ! command -v realpath >/dev/null 2>&1; then
    die "realpath not found in PATH (coreutils)"
fi
ABS_OUTPUT="$(realpath -m -- "$OUTPUT_DIR")"
case "$ABS_OUTPUT/genesis.json" in
    "$REPO_ROOT/testnet/genesis.json" \
    |"$REPO_ROOT/testnet/node-data/genesis.json" \
    |"$REPO_ROOT/mainnet/genesis.json" \
    |"$REPO_ROOT/ops/docker/validators/genesis.json")
        die "--output $OUTPUT_DIR would overwrite a committed genesis artefact; write the ceremony output somewhere else (the default ./genesis-out is fine)"
        ;;
esac
case "$ABS_OUTPUT/" in
    "$REPO_ROOT/testnet/chain4/"* \
    |"$REPO_ROOT/testnet/validators/"* \
    |"$REPO_ROOT/testnet/node-data/"* \
    |"$REPO_ROOT/mainnet/"* \
    |"$REPO_ROOT/ops/docker/validators/"* \
    |"$REPO_ROOT/ops/docker/chain2/"*)
        die "--output $OUTPUT_DIR is inside a committed genesis/key directory; write the ceremony output somewhere else (the default ./genesis-out is fine)"
        ;;
esac

if [[ -d "$OUTPUT_DIR" ]] && [[ -n "$(ls -A "$OUTPUT_DIR" 2>/dev/null)" ]] && ! $FORCE; then
    die "output directory $OUTPUT_DIR exists and is not empty; use --force to overwrite"
fi

TEMP_OUTPUT="$(mktemp -d "${TMPDIR:-/tmp}/kovanica-ceremony.XXXXXX")"
cleanup() {
    rm -rf "$TEMP_OUTPUT"
}
trap cleanup EXIT

KEYS_DIR="$TEMP_OUTPUT/keys"

echo "=== Kovanica Genesis Ceremony ==="
echo "Network: $NETWORK (Chain ID: $CHAIN_ID)"
echo "Policy: $(if [[ "$HYBRID" == true ]]; then echo "no-stake-82m (hybrid PoW + GHOSTDAG)"; else echo "node default (legacy-81m)"; fi)"
echo "Validators: $VALIDATORS_FILE"
echo "Treasury: $TREASURY_ADDRESS"
echo "Founder: $FOUNDER_ADDRESS"
echo "Output: $OUTPUT_DIR"
echo ""

# Prefer a binary the caller built; KOVANICA_NODE_BIN lets the test suite point
# at the binary cargo just built.
NODE_CMD=()
if [[ -n "${KOVANICA_NODE_BIN:-}" ]]; then
    if [[ ! -x "$KOVANICA_NODE_BIN" ]]; then
        die "KOVANICA_NODE_BIN=$KOVANICA_NODE_BIN is not an executable file"
    fi
    NODE_CMD=("$KOVANICA_NODE_BIN")
elif [[ -x "$REPO_ROOT/target/release/kovanica-node" ]]; then
    NODE_CMD=("$REPO_ROOT/target/release/kovanica-node")
elif [[ -x "$REPO_ROOT/target/debug/kovanica-node" ]]; then
    NODE_CMD=("$REPO_ROOT/target/debug/kovanica-node")
else
    NODE_CMD=(cargo run --release -p kovanica-node --)
fi

# Step 1: genesis_validators.toml plus founder_premine.hex. Written (and every
# address validated) before the node runs, so a refused input leaves no output.
echo "[1/4] Writing genesis_validators.toml and founder_premine.hex..."
python3 - "$VALIDATORS_FILE" "$TEMP_OUTPUT/genesis_validators.toml" \
    "$NETWORK" "$CHAIN_ID" "$HYBRID" "$TREASURY_ADDRESS" <<'PY'
import json
import re
import sys

validators_file, out_path, network, chain_id, hybrid, treasury = sys.argv[1:7]
chain_id = int(chain_id)
hybrid = hybrid == "true"

PRO21 = re.compile(r"^kvnc[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{57}dag$")
HEX = re.compile(r"^[0-9a-fA-F]{64}$")


def fail(message):
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


def check(label, address):
    if PRO21.match(address):
        return
    if not hybrid and HEX.match(address):
        return
    if hybrid:
        fail(
            f"{label} address '{address}' is not a canonical PRO-21 kvnc...dag "
            f"address; chain {chain_id} accepts only PRO-21 addresses and the "
            "ceremony will not convert legacy hex or invent keys"
        )
    fail(f"{label} address '{address}' is neither PRO-21 nor 32-byte hex")


def check_public_key(label, pk):
    if not isinstance(pk, str) or not HEX.match(pk):
        fail(
            f"{label} public_key '{pk}' is not a valid 32-byte hex string (64 hex characters)"
        )


try:
    with open(validators_file, encoding="utf-8") as handle:
        validators = json.load(handle)
except (OSError, json.JSONDecodeError) as error:
    fail(f"reading validators {validators_file}: {error}")

if not isinstance(validators, list):
    fail(f"{validators_file} must be a JSON array of validator entries")
if not validators:
    fail(f"{validators_file} declares no validators; a genesis needs at least one")

check("treasury", treasury)
for index, entry in enumerate(validators):
    if not isinstance(entry, dict) or "address" not in entry:
        fail(f"{validators_file}: entry {index} has no address")
    check(f"validator {index}", entry["address"])
    pk = entry.get("public_key")
    if pk is not None:
        check_public_key(f"validator {index}", pk)

lines = [
    f"# Kovanica {network} genesis validators (generated by ops/genesis/ceremony.sh)",
    f"# Network: {network} (chain_id = {chain_id})",
    f"chain_id = {chain_id}",
]
if hybrid:
    # Hybrid PoW + GHOSTDAG: no stake in the consensus path, no genesis
    # validator allocation. The entry list is bootstrap seed nodes only.
    lines.append('emission_policy = "no-stake-82m"')
# The treasury is bound into the genesis digest by KOVANICA_TREASURY_ADDRESS.
# Recording it here is what lets the ops step set the same value on every node;
# the node reads the configured address only, never this file.
lines.append(f'treasury_address = "{treasury}"')
lines.append("")

for entry in validators:
    lines.append("[[validator]]")
    lines.append(f'address = "{entry["address"]}"')
    if entry.get("public_key"):
        lines.append(f'public_key = "{entry["public_key"]}"')
    # No stake field: under no-stake-82m nothing is locked, and on a legacy
    # genesis the node applies MIN_VALIDATOR_STAKE itself.
    lines.append("")

with open(out_path, "w", encoding="utf-8") as handle:
    handle.write("\n".join(lines))
PY

# init_genesis mints the founder premine only when this file is in the data
# directory, and the genesis digest binds the address inside it.
printf '%s\n' "$FOUNDER_ADDRESS" >"$TEMP_OUTPUT/founder_premine.hex"

# Step 2: genesis.json (staking/tokenomics preview; the node derives state from
# the file set above, not from this JSON).
echo "[2/4] Generating genesis.json..."
GENESIS_ARGS=(
    genesis
    --chain-id "$CHAIN_ID"
    --validators "$VALIDATORS_FILE"
    --treasury-address "$TREASURY_ADDRESS"
    --founder-address "$FOUNDER_ADDRESS"
    --output "$TEMP_OUTPUT/genesis.json"
)
# Hybrid chains have no stake in the consensus path and no genesis validator
# allocation; a legacy-81m genesis would mint the retired 1M on top of the 82M
# mining budget. The node refuses that combination, so pass the policy here.
if [[ "$HYBRID" == true ]]; then
    GENESIS_ARGS+=(--emission-policy no-stake-82m)
fi
if $FORCE; then
    GENESIS_ARGS+=(--force)
fi
if $GENERATE_KEYS; then
    GENESIS_ARGS+=(--validator-keys-out "$KEYS_DIR")
fi

"${NODE_CMD[@]}" "${GENESIS_ARGS[@]}"

# Step 3: key generation or verification
if $GENERATE_KEYS; then
    echo "[3/4] Generated throwaway validator keys in $OUTPUT_DIR/keys (never commit them)"
else
    echo "[3/4] Validator keys preserved from input ceremony configuration"
fi

# Step 4: Create bootnode config
echo "[4/5] Creating bootnode config..."
if [[ "$NETWORK" == "mainnet" || "$NETWORK" == "kovanica-mainnet" || "$CHAIN_ID" -eq 1 ]]; then
    SEED="mainnet.kovanica.online:8000"
else
    SEED="testnet.kovanica.online:8000"
fi

cat > "$TEMP_OUTPUT/bootnodes.toml" << EOF
# Kovanica $NETWORK bootnodes
# All nodes should use this seed
bootnodes = ["$SEED"]
EOF

# Step 5: Generate SHA-256 manifest
echo "[5/5] Generating SHA256SUMS manifest..."
(
    cd "$TEMP_OUTPUT"
    if [[ "$CHAIN_ID" -eq 1 ]]; then
        FILES=(genesis_validators.toml founder_premine.hex genesis.json bootnodes.toml)
        sha256sum "${FILES[@]}" > SHA256SUMS
    else
        FILES=(genesis_validators.toml founder_premine.hex)
        [[ -f funded_accounts.toml ]] && FILES+=(funded_accounts.toml)
        sha256sum "${FILES[@]}" > SHA256SUMS
    fi
)

# Move outputs to target directory
mkdir -p -- "$OUTPUT_DIR"
cp -a "$TEMP_OUTPUT"/. "$OUTPUT_DIR"/
rm -rf "$TEMP_OUTPUT"
trap - EXIT

echo ""
echo "=== Genesis Ceremony Complete ==="
echo "Files generated:"
echo "  $OUTPUT_DIR/genesis.json"
echo "  $OUTPUT_DIR/genesis_validators.toml"
echo "  $OUTPUT_DIR/founder_premine.hex"
echo "  $OUTPUT_DIR/bootnodes.toml"
echo "  $OUTPUT_DIR/SHA256SUMS"
if $GENERATE_KEYS; then
    echo "  $OUTPUT_DIR/keys/ (throwaway validator keys — never commit)"
fi
echo ""
echo "Next steps:"
echo "1. Copy the bundle-legal genesis files into every node's KOVANICA_DATA_DIR"
echo "   (genesis_validators.toml, founder_premine.hex, and funded_accounts.toml on chains that allow it)"
echo "2. Set KOVANICA_TREASURY_ADDRESS=$TREASURY_ADDRESS on every node (the digest binds it),"
echo "   or use node/scripts/install.sh, which writes the address the bundle records into a new config"
echo "3. Cut the published bundle from a directory that holds only genesis files"
echo "   (genesis.json and bootnodes.toml are previews and are refused by genesis-bundle):"
echo "   mkdir -p ./genesis-bundle-src"
echo "   cp $OUTPUT_DIR/genesis_validators.toml $OUTPUT_DIR/founder_premine.hex ./genesis-bundle-src/"
echo "   # add funded_accounts.toml on chains that allow it (never chain 1)"
echo "   kovanica-node genesis-bundle --chain-id $CHAIN_ID --source ./genesis-bundle-src"
echo "4. Configure bootnodes = [\"$SEED\"] before the first start"
