//! OpenAPI / JSON Schema generation for Kovanica JSON-RPC.
//!
//! Generates an OpenAPI 3.1 specification from the RPC method definitions.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// OpenAPI 3.1 specification structure.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OpenApiSpec {
    pub openapi: String,
    pub info: OpenApiInfo,
    pub servers: Vec<OpenApiServer>,
    pub paths: BTreeMap<String, OpenApiPathItem>,
    pub components: OpenApiComponents,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OpenApiInfo {
    pub title: String,
    pub version: String,
    pub description: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OpenApiServer {
    pub url: String,
    pub description: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OpenApiPathItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get: Option<OpenApiOperation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post: Option<OpenApiOperation>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OpenApiOperation {
    pub summary: String,
    pub description: String,
    #[serde(rename = "operationId")]
    pub operation_id: String,
    pub tags: Vec<String>,
    #[serde(rename = "requestBody", skip_serializing_if = "Option::is_none")]
    pub request_body: Option<OpenApiRequestBody>,
    pub responses: BTreeMap<String, OpenApiResponse>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OpenApiRequestBody {
    pub required: bool,
    pub content: BTreeMap<String, OpenApiMediaType>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OpenApiMediaType {
    pub schema: Value,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OpenApiHeader {
    pub description: String,
    pub schema: Value,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OpenApiResponse {
    pub description: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, OpenApiHeader>,
    pub content: BTreeMap<String, OpenApiMediaType>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OpenApiComponents {
    pub schemas: BTreeMap<String, Value>,
}

/// Generate the OpenAPI 3.1 specification for Kovanica JSON-RPC.
pub fn generate_openapi_spec() -> OpenApiSpec {
    let mut spec = OpenApiSpec {
        openapi: "3.1.0".to_string(),
        info: OpenApiInfo {
            title: "Kovanica JSON-RPC API".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            description: "JSON-RPC API for Kovanica (kovanica) node. All methods use JSON-RPC 2.0 over HTTP POST to /rpc endpoint.".to_string(),
        },
        servers: vec![
            OpenApiServer {
                url: "http://localhost:8545/rpc".to_string(),
                description: "Local development node".to_string(),
            },
            OpenApiServer {
                url: "https://rpc.kovanica.example/rpc".to_string(),
                description: "Public testnet node (placeholder — replaced at launch)".to_string(),
            },
        ],
        paths: BTreeMap::new(),
        components: OpenApiComponents {
            schemas: BTreeMap::new(),
        },
    };

    // Add common schemas
    spec.components.schemas.insert(
        "JsonRpcRequest".to_string(),
        json!({
            "type": "object",
            "required": ["jsonrpc", "method"],
            "properties": {
                "jsonrpc": { "type": "string", "const": "2.0" },
                "method": { "type": "string" },
                "params": { "type": "array", "items": {} },
                "id": { "type": ["string", "number", "null"] }
            }
        }),
    );

    spec.components.schemas.insert(
        "JsonRpcResponse".to_string(),
        json!({
            "type": "object",
            "properties": {
                "jsonrpc": { "type": "string", "const": "2.0" },
                "result": {},
                "error": { "$ref": "#/components/schemas/JsonRpcError" },
                "id": { "type": ["string", "number", "null"] }
            }
        }),
    );

    spec.components.schemas.insert(
        "JsonRpcError".to_string(),
        json!({
            "type": "object",
            "required": ["code", "message"],
            "properties": {
                "code": { "type": "integer" },
                "message": { "type": "string" },
                "data": {}
            }
        }),
    );

    spec.components.schemas.insert(
        "Address".to_string(),
        json!({
            "type": "string",
            "pattern": "^kvnc[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{57}dag$",
            "description": "Canonical Kovanica PRO-21 base32 address format (kvnc + 57 base32 + dag = 64 chars)"
        }),
    );

    spec.components.schemas.insert(
        "Hash".to_string(),
        json!({
            "type": "string",
            "pattern": "^0x[a-f0-9]{64}$",
            "description": "32-byte hash as 0x-prefixed hex"
        }),
    );

    spec.components.schemas.insert(
        "Quantity".to_string(),
        json!({
            "type": "string",
            "pattern": "^0x[a-f0-9]+$",
            "description": "Ethereum-style quantity (minimal hex). Response fields use this form."
        }),
    );

    spec.components.schemas.insert(
        "QuantityParam".to_string(),
        json!({
            "description": "Request quantity. A JSON integer, or an Ethereum-style 0x hex quantity.",
            "oneOf": [
                { "type": "integer", "minimum": 0 },
                { "type": "string", "pattern": "^0x[a-fA-F0-9]+$" }
            ]
        }),
    );

    spec.components.schemas.insert(
        "Transaction".to_string(),
        json!({
            "type": "object",
            "properties": {
                "hash": { "$ref": "#/components/schemas/Hash" },
                "sender": { "$ref": "#/components/schemas/Address" },
                "nonce": { "$ref": "#/components/schemas/Quantity" },
                "fee": { "$ref": "#/components/schemas/Quantity" },
                "kind": { "$ref": "#/components/schemas/TransactionKind" },
                "signature": { "type": "string", "pattern": "^0x[a-f0-9]{128}$" }
            }
        }),
    );

    spec.components.schemas.insert("TransactionKind".to_string(), json!({
        "oneOf": [
            { "type": "object", "properties": { "type": { "const": "transfer" }, "to": { "$ref": "#/components/schemas/Address" }, "amount": { "$ref": "#/components/schemas/Quantity" } } },
            { "type": "object", "properties": { "type": { "const": "stake" }, "amount": { "$ref": "#/components/schemas/Quantity" } } },
            { "type": "object", "properties": { "type": { "const": "unstake" }, "amount": { "$ref": "#/components/schemas/Quantity" } } },
            { "type": "object", "properties": { "type": { "const": "delegate" }, "validator": { "$ref": "#/components/schemas/Address" }, "amount": { "$ref": "#/components/schemas/Quantity" } } },
            { "type": "object", "properties": { "type": { "const": "claim_rewards" }, "validator": { "type": ["string", "null"] } } },
            { "type": "object", "properties": { "type": { "const": "deploy" }, "code": { "type": "string", "pattern": "^0x[a-f0-9]+$" } } },
            { "type": "object", "properties": { "type": { "const": "call" }, "contract": { "$ref": "#/components/schemas/Address" }, "method": { "type": "string" }, "args": { "type": "string", "pattern": "^0x[a-f0-9]*$" }, "gas_limit": { "$ref": "#/components/schemas/Quantity" } } },
            { "type": "object", "properties": { "type": { "const": "register_light_node" }, "vrf_public_key": { "$ref": "#/components/schemas/Hash" }, "stake": { "$ref": "#/components/schemas/Quantity" } } },
            { "type": "object", "properties": { "type": { "const": "exit_light_node" } } },
            { "type": "object", "properties": { "type": { "const": "submit_light_witness" }, "epoch": { "$ref": "#/components/schemas/Quantity" }, "vrf_output": { "$ref": "#/components/schemas/Hash" }, "vrf_proof": { "type": "string" } } },
            { "type": "object", "properties": { "type": { "const": "set_commission" }, "validator": { "$ref": "#/components/schemas/Address" }, "commission_bps": { "type": "integer" } } },
            { "type": "object", "properties": { "type": { "const": "claim_treasury" }, "amount": { "$ref": "#/components/schemas/Quantity" } } },
            { "type": "object", "properties": { "type": { "const": "evidence" }, "evidence": { "type": "object" } } }
        ]
    }));

    spec.components.schemas.insert("Block".to_string(), json!({
        "type": "object",
        "properties": {
            "hash": { "$ref": "#/components/schemas/Hash" },
            "digest": { "$ref": "#/components/schemas/Hash" },
            "author": { "type": "integer" },
            "number": { "$ref": "#/components/schemas/Quantity" },
            "height": { "oneOf": [{ "$ref": "#/components/schemas/Quantity" }, { "type": "null" }] },
            "round": { "$ref": "#/components/schemas/Quantity" },
            "parents": { "type": "array", "items": { "$ref": "#/components/schemas/Hash" } },
            "parent_hashes": { "type": "array", "items": { "$ref": "#/components/schemas/Hash" } },
            "transactions": {
                "type": "array",
                "items": {
                    "oneOf": [
                        { "$ref": "#/components/schemas/Hash" },
                        { "$ref": "#/components/schemas/Transaction" }
                    ]
                }
            },
            "statements": { "type": "string" },
            "signature": { "type": "string" },
            "timestamp": { "type": ["integer", "null"] },
            "pow_timestamp": { "type": ["integer", "null"] },
            "powTimestamp": { "oneOf": [{ "$ref": "#/components/schemas/Quantity" }, { "type": "null" }] },
            "target_bits": { "oneOf": [{ "$ref": "#/components/schemas/Quantity" }, { "type": "null" }] },
            "nonce": { "type": ["integer", "null"] },
            "pow_hash": { "oneOf": [{ "$ref": "#/components/schemas/Hash" }, { "type": "null" }] },
            "payout": { "type": ["string", "null"] },
            "state_root": { "oneOf": [{ "$ref": "#/components/schemas/Hash" }, { "type": "null" }] },
            "tx_merkle_root": { "oneOf": [{ "$ref": "#/components/schemas/Hash" }, { "type": "null" }] }
        }
    }));

    spec.components.schemas.insert(
        "Account".to_string(),
        json!({
            "type": "object",
            "properties": {
                "address": { "$ref": "#/components/schemas/Address" },
                "balance": { "$ref": "#/components/schemas/Quantity" },
                "nonce": { "$ref": "#/components/schemas/Quantity" },
                "code_hash": { "$ref": "#/components/schemas/Hash" },
                "is_contract": { "type": "boolean" }
            }
        }),
    );

    spec.components.schemas.insert(
        "Validator".to_string(),
        json!({
            "type": "object",
            "properties": {
                "address": { "$ref": "#/components/schemas/Address" },
                "public_key": { "type": "string", "pattern": "^0x[a-f0-9]{64}$" },
                "stake": { "$ref": "#/components/schemas/Quantity" },
                "active": { "type": "boolean" },
                "commission_bps": { "type": "integer" }
            }
        }),
    );

    spec.components.schemas.insert(
        "GetLogsFilter".to_string(),
        json!({
            "type": "object",
            "properties": {
                "fromBlock": {
                    "oneOf": [
                        { "type": "string", "enum": ["latest", "earliest", "pending", "safe", "finalized"] },
                        { "$ref": "#/components/schemas/QuantityParam" }
                    ],
                    "description": "Start committed-leader height (default: latest). pending, safe, and finalized alias the committed tip."
                },
                "toBlock": {
                    "oneOf": [
                        { "type": "string", "enum": ["latest", "earliest", "pending", "safe", "finalized"] },
                        { "$ref": "#/components/schemas/QuantityParam" }
                    ],
                    "description": "End committed-leader height (default: latest). pending, safe, and finalized alias the committed tip."
                },
                "address": {
                    "oneOf": [
                        { "$ref": "#/components/schemas/Address" },
                        { "type": "array", "items": { "$ref": "#/components/schemas/Address" } }
                    ]
                },
                "topics": {
                    "type": "array",
                    "items": {
                        "oneOf": [
                            { "type": "null" },
                            { "type": "string" },
                            { "type": "array", "items": { "type": "string" } }
                        ]
                    }
                },
                "cursor": {
                    "type": "string",
                    "pattern": "^(0x[a-fA-F0-9]+|[0-9]+):(0x[a-fA-F0-9]+|[0-9]+)$",
                    "description": "Optional pagination cursor ('<height>:<logIndex>') resuming strictly after the given log entry. Queries spanning more than 500 blocks are rejected."
                }
            }
        }),
    );

    spec.components.schemas.insert(
        "Log".to_string(),
        json!({
            "type": "object",
            "properties": {
                "address": { "$ref": "#/components/schemas/Address" },
                "topics": { "type": "array", "items": { "type": "string", "pattern": "^0x[a-f0-9]*$" } },
                "data": { "type": "string", "pattern": "^0x[a-f0-9]*$" },
                "blockNumber": { "$ref": "#/components/schemas/Quantity" },
                "blockHash": { "type": ["string", "null"] },
                "transactionHash": { "$ref": "#/components/schemas/Hash" },
                "transactionIndex": { "$ref": "#/components/schemas/Quantity" },
                "logIndex": { "$ref": "#/components/schemas/Quantity" },
                "removed": { "type": "boolean" }
            }
        }),
    );

    spec.components.schemas.insert(
        "SyncStatus".to_string(),
        json!({
            "type": "object",
            "description": "Node sync / catch-up and peer status (kovanica_syncStatus)",
            "properties": {
                "localTipRound": { "type": ["integer", "null"], "description": "Local DAG tip round" },
                "committedHeight": { "type": ["integer", "null"], "description": "Committed leader height" },
                "catchingUp": { "type": "boolean" },
                "catchUpTarget": { "type": ["integer", "null"], "description": "Peer-advertised tip being chased" },
                "behindBy": { "type": ["integer", "null"], "description": "Rounds behind the catch-up target" },
                "peerCount": { "type": "integer" },
                "networkTag": {
                    "type": "string",
                    "description": "Network tag (<chain_id>-<16 hex of the genesis digest>) this node logs at startup. Peers must share it."
                },
                "peers": {
                    "type": "array",
                    "items": { "$ref": "#/components/schemas/SyncPeerStatus" }
                }
            },
            "required": ["catchingUp", "peerCount", "peers"]
        }),
    );

    spec.components.schemas.insert(
        "SyncPeerStatus".to_string(),
        json!({
            "type": "object",
            "properties": {
                "peerId": { "type": "string" },
                "listenAddr": { "type": ["string", "null"] },
                "reportedTipRound": { "type": ["integer", "null"] }
            },
            "required": ["peerId"]
        }),
    );

    spec.components.schemas.insert(
        "MempoolStats".to_string(),
        json!({
            "type": "object",
            "description": "Read-only mempool size and fee-per-byte percentile snapshot (kovanica_mempoolStats)",
            "properties": {
                "pending_count": { "type": "integer", "minimum": 0 },
                "total_bytes": { "type": "integer", "minimum": 0 },
                "min_fee_per_byte": { "type": ["integer", "null"], "minimum": 0 },
                "p50_fee_per_byte": { "type": ["integer", "null"], "minimum": 0 },
                "p90_fee_per_byte": { "type": ["integer", "null"], "minimum": 0 },
                "max_fee_per_byte": { "type": ["integer", "null"], "minimum": 0 }
            },
            "required": [
                "pending_count",
                "total_bytes",
                "min_fee_per_byte",
                "p50_fee_per_byte",
                "p90_fee_per_byte",
                "max_fee_per_byte"
            ]
        }),
    );

    spec.components.schemas.insert(
        "HealthResponse".to_string(),
        json!({
            "type": "object",
            "description": "Node health probe response (/health)",
            "properties": {
                "status": { "type": "string", "enum": ["ok", "degraded"] },
                "peer_count": { "type": "integer", "minimum": 0 },
                "mempool_pending": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Number of pending transactions currently in the mempool"
                },
                "rpc_version": {
                    "type": "string",
                    "description": "kovanica-rpc crate version serving this endpoint"
                },
                "syncing": {
                    "type": "boolean",
                    "description": "Whether the node is actively catching up or behind its sync target"
                },
                "indexer_attached": {
                    "type": "boolean",
                    "description": "Whether an event/log subscriber or indexer is currently attached to the node EventBus"
                },
                "healthy": { "type": "boolean" }
            },
            "required": [
                "status",
                "peer_count",
                "mempool_pending",
                "rpc_version",
                "syncing",
                "indexer_attached",
                "healthy"
            ]
        }),
    );

    // Define all RPC methods
    let methods = vec![
        (
            "kovanica_getBlockByHash",
            "Get block by hash",
            "Chain",
            json!({
                "type": "array",
                "items": [
                    { "$ref": "#/components/schemas/Hash" },
                    { "type": "boolean" }
                ],
                "minItems": 1,
                "maxItems": 2
            }),
            json!({
                "oneOf": [
                    { "$ref": "#/components/schemas/Block" },
                    { "type": "null" }
                ]
            }),
        ),
        (
            "kovanica_getBlockByNumber",
            "Get block by committed height",
            "Chain",
            json!({
                "type": "array",
                "items": [
                    {
                        "oneOf": [
                            { "$ref": "#/components/schemas/QuantityParam" },
                            { "type": "string", "enum": ["latest", "earliest"] }
                        ]
                    },
                    { "type": "boolean" }
                ],
                "minItems": 1,
                "maxItems": 2
            }),
            json!({
                "oneOf": [
                    { "$ref": "#/components/schemas/Block" },
                    { "type": "null" }
                ]
            }),
        ),
        (
            "kovanica_sendRawTransaction",
            "Submit signed transaction",
            "Transactions",
            json!({
                "type": "array",
                "items": { "type": "string", "pattern": "^0x[a-f0-9]+$" },
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "type": "string",
                "pattern": "^0x[a-f0-9]{64}$",
                "description": "Transaction hash"
            }),
        ),
        (
            "kovanica_getTransactionReceipt",
            "Get transaction receipt",
            "Transactions",
            json!({
                "type": "array",
                "items": { "$ref": "#/components/schemas/Hash" },
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "type": "object",
                "properties": {
                    "tx_hash": { "$ref": "#/components/schemas/Hash" },
                    "success": { "type": "boolean" },
                    "gas_used": { "$ref": "#/components/schemas/Quantity" },
                    "error": { "type": ["string", "null"] },
                    "events": { "type": "array", "items": { "type": "object" } }
                }
            }),
        ),
        (
            "kovanica_getTransactionByHash",
            "Get transaction by hash",
            "Transactions",
            json!({
                "type": "array",
                "items": { "$ref": "#/components/schemas/Hash" },
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "$ref": "#/components/schemas/Transaction"
            }),
        ),
        (
            "kovanica_getTransactionHistory",
            "Newest-first committed transactions for an address",
            "Transactions",
            json!({
                "type": "object",
                "required": ["address"],
                "properties": {
                    "address": { "$ref": "#/components/schemas/Address" },
                    "limit": {
                        "$ref": "#/components/schemas/Quantity",
                        "description": "Page size. Default 20, hard max 100."
                    },
                    "cursor": {
                        "type": "string",
                        "description": "Opaque cursor from a previous next_cursor."
                    },
                    "direction": {
                        "type": "string",
                        "enum": ["sent", "received", "all"],
                        "default": "all"
                    }
                }
            }),
            json!({
                "type": "object",
                "required": ["entries", "next_cursor"],
                "properties": {
                    "entries": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["hash", "height", "timestamp", "from", "to", "amount", "fee", "kind", "status"],
                            "properties": {
                                "hash": { "$ref": "#/components/schemas/Hash" },
                                "height": { "$ref": "#/components/schemas/Quantity" },
                                "timestamp": { "type": ["string", "null"] },
                                "from": { "$ref": "#/components/schemas/Address" },
                                "to": { "type": ["string", "null"] },
                                "amount": { "$ref": "#/components/schemas/Quantity" },
                                "fee": { "$ref": "#/components/schemas/Quantity" },
                                "kind": { "type": "string" },
                                "status": { "type": "string", "enum": ["success", "failed"] }
                            }
                        }
                    },
                    "next_cursor": { "type": ["string", "null"] }
                }
            }),
        ),
        (
            "kovanica_getLogs",
            "Query transaction logs by block range, address and topics",
            "Transactions",
            json!({
                "type": "array",
                "items": { "$ref": "#/components/schemas/GetLogsFilter" },
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "type": "array",
                "items": { "$ref": "#/components/schemas/Log" }
            }),
        ),
        (
            "kovanica_getBalance",
            "Get account balance",
            "Accounts",
            json!({
                "type": "array",
                "items": { "$ref": "#/components/schemas/Address" },
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "$ref": "#/components/schemas/Quantity"
            }),
        ),
        (
            "kovanica_requestAirdrop",
            "Request testnet tokens (airdrop). Strictly forbidden on mainnet (chain 1).",
            "Accounts",
            json!({
                "type": "array",
                "items": [
                    { "$ref": "#/components/schemas/Address" },
                    { "type": "integer", "description": "Optional amount in atoms (default 10 KVNC, max 100 KVNC)" }
                ],
                "minItems": 1,
                "maxItems": 2
            }),
            json!({
                "type": "object",
                "properties": {
                    "success": { "type": "boolean" },
                    "address": { "type": "string" },
                    "amount": { "type": "integer" },
                    "amount_atoms": { "type": "integer" },
                    "balance": { "type": "integer" },
                    "balance_atoms": { "type": "integer" },
                    "chain_id": { "type": "integer" },
                    "message": { "type": "string" }
                },
                "required": ["success", "address", "amount", "balance", "chain_id"]
            }),
        ),
        (
            "kovanica_getNonce",
            "Get account nonce",
            "Accounts",
            json!({
                "type": "array",
                "items": { "$ref": "#/components/schemas/Address" },
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "$ref": "#/components/schemas/Quantity"
            }),
        ),
        (
            "kovanica_getCode",
            "Get contract code",
            "Contracts",
            json!({
                "type": "array",
                "items": { "$ref": "#/components/schemas/Address" },
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "type": "string",
                "pattern": "^0x[a-f0-9]*$"
            }),
        ),
        (
            "kovanica_getStorageAt",
            "Get contract storage slot",
            "Contracts",
            json!({
                "type": "array",
                "items": [
                    { "$ref": "#/components/schemas/Address" },
                    { "$ref": "#/components/schemas/Hash" }
                ],
                "minItems": 2,
                "maxItems": 2
            }),
            json!({
                "type": "string",
                "pattern": "^0x[a-f0-9]{64}$"
            }),
        ),
        (
            "kovanica_getValidators",
            "List recorded staking validators (legacy; chains 1/2 select block authors by PoW)",
            "Staking",
            json!({
                "type": "array",
                "items": {}
            }),
            json!({
                "type": "array",
                "items": { "$ref": "#/components/schemas/Validator" }
            }),
        ),
        (
            "kovanica_getStake",
            "Get total recorded stake for an address (legacy ledger value)",
            "Staking",
            json!({
                "type": "array",
                "items": { "$ref": "#/components/schemas/Address" },
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "$ref": "#/components/schemas/Quantity"
            }),
        ),
        (
            "kovanica_getRewards",
            "Get cumulative recorded staking rewards (legacy)",
            "Staking",
            json!({
                "type": "array",
                "items": { "$ref": "#/components/schemas/Address" },
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "$ref": "#/components/schemas/Quantity"
            }),
        ),
        (
            "kovanica_getPendingTransactions",
            "Get pending transaction hashes",
            "Mempool",
            json!({
                "type": "array",
                "items": {}
            }),
            json!({
                "type": "array",
                "items": { "$ref": "#/components/schemas/Hash" }
            }),
        ),
        (
            "kovanica_estimateFee",
            "Estimate fee rate",
            "Mempool",
            json!({
                "type": "array",
                "items": {}
            }),
            json!({
                "$ref": "#/components/schemas/Quantity"
            }),
        ),
        (
            "kovanica_getFeeSchedule",
            "Get canonical fixed operation fee floors, fee split, and activation status",
            "Mempool",
            json!({
                "type": "array",
                "items": {},
                "maxItems": 0
            }),
            json!({
                "type": "object"
            }),
        ),
        (
            "kovanica_getBaseFee",
            "Get current EIP-1559 dynamic base fee per byte and storage deposit parameters",
            "Mempool",
            json!({
                "type": "array",
                "items": {},
                "maxItems": 0
            }),
            json!({
                "type": "object"
            }),
        ),
        (
            "kovanica_getStorageDeposit",
            "Get refundable storage deposit accounting for a contract address",
            "Accounts",
            json!({
                "type": "array",
                "items": { "type": "string" },
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "type": "object"
            }),
        ),
        (
            "kovanica_getSessionKey",
            "Get a persisted scoped session key policy for (owner, session_pubkey)",
            "Accounts",
            json!({
                "type": "array",
                "items": { "type": "string" },
                "minItems": 2,
                "maxItems": 2
            }),
            json!({
                "type": ["object", "null"]
            }),
        ),
        (
            "kovanica_mempoolStats",
            "Get mempool pending count, total bytes, and fee-per-byte percentiles",
            "Mempool",
            json!({
                "type": "array",
                "items": {},
                "maxItems": 0
            }),
            json!({
                "$ref": "#/components/schemas/MempoolStats"
            }),
        ),
        (
            "kovanica_getLeaderSchedule",
            "Get the provisional legacy leader schedule (chains 1/2 author blocks by PoW)",
            "Consensus",
            json!({
                "type": "array",
                "items": { "type": "integer" },
                "minItems": 0,
                "maxItems": 1
            }),
            json!({
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "round": { "$ref": "#/components/schemas/Quantity" },
                        "leader": { "$ref": "#/components/schemas/Address" }
                    }
                }
            }),
        ),
        (
            "kovanica_getCommittee",
            "Get the legacy committee snapshot (chains 1/2 have no validator committee)",
            "Consensus",
            json!({
                "type": "array",
                "items": {}
            }),
            json!({
                "type": "object",
                "properties": {
                    "epoch": { "$ref": "#/components/schemas/Quantity" },
                    "authorities": {
                        "type": "array",
                        "items": { "$ref": "#/components/schemas/Validator" }
                    }
                }
            }),
        ),
        (
            "kovanica_blockNumber",
            "Get committed leader height",
            "Chain",
            json!({
                "type": "array",
                "items": {}
            }),
            json!({
                "$ref": "#/components/schemas/Quantity"
            }),
        ),
        (
            "kovanica_syncStatus",
            "Get node sync / catch-up and peer status",
            "Chain",
            json!({
                "type": "array",
                "items": {}
            }),
            json!({
                "$ref": "#/components/schemas/SyncStatus"
            }),
        ),
        (
            "kovanica_getBlockHeaderByNumber",
            "Get block header by committed height",
            "Chain",
            json!({
                "type": "array",
                "items": [{
                    "oneOf": [
                        { "$ref": "#/components/schemas/QuantityParam" },
                        { "type": "string", "enum": ["latest", "earliest"] }
                    ]
                }],
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "oneOf": [
                    { "type": "object" },
                    { "type": "null" }
                ]
            }),
        ),
        (
            "kovanica_estimateGas",
            "Estimate gas required for a transaction or contract call",
            "Execution",
            json!({ "type": "array", "items": { "type": "object" } }),
            json!({ "$ref": "#/components/schemas/Quantity" }),
        ),
        (
            "eth_estimateGas",
            "EVM-compatible alias for kovanica_estimateGas",
            "Execution",
            json!({ "type": "array", "items": { "type": "object" } }),
            json!({ "$ref": "#/components/schemas/Quantity" }),
        ),
        (
            "kovanica_call",
            "Simulate a read-only contract call against current state",
            "Execution",
            json!({ "type": "array", "items": { "type": "object" } }),
            json!({ "type": "object" }),
        ),
        (
            "eth_call",
            "EVM-compatible alias for kovanica_call",
            "Execution",
            json!({ "type": "array", "items": { "type": "object" } }),
            json!({ "type": "object" }),
        ),
        (
            "kovanica_getCommitteeInfo",
            "Get current committee epoch and metadata",
            "Consensus",
            json!({ "type": "array", "items": {} }),
            json!({ "type": "object" }),
        ),
        (
            "kovanica_getLeaderHeader",
            "Get sealed leader header by committed height",
            "LightClient",
            json!({ "type": "array", "items": [{ "$ref": "#/components/schemas/Quantity" }] }),
            json!({ "type": ["object", "null"] }),
        ),
        (
            "kovanica_getCommitSeals",
            "Get commit seals for a committed leader height",
            "LightClient",
            json!({ "type": "array", "items": [{ "$ref": "#/components/schemas/Quantity" }] }),
            json!({ "type": "object" }),
        ),
        (
            "kovanica_getTxProof",
            "Get Merkle inclusion proof for a transaction",
            "LightClient",
            json!({ "type": "array", "items": [{ "$ref": "#/components/schemas/Hash" }] }),
            json!({ "type": ["object", "null"] }),
        ),
        (
            "kovanica_getAccountProof",
            "Get state Merkle proof for an account",
            "LightClient",
            json!({ "type": "array", "items": [{ "$ref": "#/components/schemas/Address" }] }),
            json!({ "type": ["object", "null"] }),
        ),
        (
            "kovanica_getLightSet",
            "Get registered light-node witness set",
            "LightClient",
            json!({ "type": "array", "items": {} }),
            json!({ "type": "object" }),
        ),
        (
            "kovanica_lightClientCheckpoint",
            "Get light-client verification checkpoint",
            "LightClient",
            json!({ "type": "array", "items": {} }),
            json!({ "type": ["object", "null"] }),
        ),
        (
            "kovanica_getWork",
            "Get PoW candidate block work template",
            "Mining",
            json!({ "type": "array", "items": {} }),
            json!({ "type": "object" }),
        ),
        (
            "kovanica_submitWork",
            "Submit solved PoW block header",
            "Mining",
            json!({ "type": "array", "items": [{ "type": "object" }] }),
            json!({ "type": "object" }),
        ),
        (
            "kovanica_getMiningInfo",
            "Get PoW mining status and network difficulty metrics",
            "Mining",
            json!({ "type": "array", "items": {} }),
            json!({ "type": "object" }),
        ),
        (
            "kovanica_getDagTips",
            "Get current GHOSTDAG tips",
            "Mining",
            json!({ "type": "array", "items": {} }),
            json!({ "type": "object" }),
        ),
        (
            "htlc_create",
            "Built-in HTLC create helper",
            "Contracts",
            json!({ "type": "object" }),
            json!({ "type": "object" }),
        ),
        (
            "htlc_claim",
            "Built-in HTLC claim helper",
            "Contracts",
            json!({ "type": "object" }),
            json!({ "type": "object" }),
        ),
        (
            "htlc_refund",
            "Built-in HTLC refund helper",
            "Contracts",
            json!({ "type": "object" }),
            json!({ "type": "object" }),
        ),
        (
            "vault_create",
            "Built-in Vault create helper",
            "Contracts",
            json!({ "type": "object" }),
            json!({ "type": "object" }),
        ),
        (
            "vault_claim",
            "Built-in Vault claim helper",
            "Contracts",
            json!({ "type": "object" }),
            json!({ "type": "object" }),
        ),
        (
            "vault_cancel",
            "Built-in Vault cancel helper",
            "Contracts",
            json!({ "type": "object" }),
            json!({ "type": "object" }),
        ),
        (
            "multisig_create",
            "Built-in Multisig create helper",
            "Contracts",
            json!({ "type": "object" }),
            json!({ "type": "object" }),
        ),
        (
            "multisig_propose",
            "Built-in Multisig propose helper",
            "Contracts",
            json!({ "type": "object" }),
            json!({ "type": "object" }),
        ),
        (
            "multisig_confirm",
            "Built-in Multisig confirm helper",
            "Contracts",
            json!({ "type": "object" }),
            json!({ "type": "object" }),
        ),
        (
            "multisig_execute",
            "Built-in Multisig execute helper",
            "Contracts",
            json!({ "type": "object" }),
            json!({ "type": "object" }),
        ),
        (
            "token_create",
            "Built-in Token create helper",
            "Contracts",
            json!({ "type": "object" }),
            json!({ "type": "object" }),
        ),
        (
            "token_transfer",
            "Built-in Token transfer helper",
            "Contracts",
            json!({ "type": "object" }),
            json!({ "type": "object" }),
        ),
        (
            "token_mint",
            "Built-in Token mint helper",
            "Contracts",
            json!({ "type": "object" }),
            json!({ "type": "object" }),
        ),
        (
            "token_burn",
            "Built-in Token burn helper",
            "Contracts",
            json!({ "type": "object" }),
            json!({ "type": "object" }),
        ),
        (
            "token_balance",
            "Built-in Token balance helper",
            "Contracts",
            json!({ "type": "object" }),
            json!({ "type": "object" }),
        ),
        // WebSocket subscription methods
        (
            "kovanica_subscribe",
            "Subscribe to events",
            "PubSub",
            json!({
                "type": "array",
                "items": { "type": "string", "enum": ["newHeads", "newCommittedLeader", "pendingTransactions", "logs", "newSealedHeader"] },
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "type": "string",
                "description": "Subscription ID"
            }),
        ),
        (
            "kovanica_unsubscribe",
            "Unsubscribe from events",
            "PubSub",
            json!({
                "type": "array",
                "items": { "type": "string" },
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "type": "boolean"
            }),
        ),
    ];

    // Create method enum schema for oneOf discriminator
    let mut method_variants = Vec::new();
    for (method, summary, tag, params_schema, _result_schema) in &methods {
        method_variants.push(json!({
            "type": "object",
            "required": ["jsonrpc", "method", "params", "id"],
            "properties": {
                "jsonrpc": { "type": "string", "const": "2.0" },
                "method": { "type": "string", "const": method },
                "params": params_schema,
                "id": { "type": ["string", "number", "null"] }
            },
            "description": format!("{} - {}", method, summary),
            "x-tag": tag
        }));
    }

    // Create request body schema with oneOf for all methods
    let request_body_schema = json!({
        "oneOf": method_variants,
        "discriminator": {
            "propertyName": "method",
            "mapping": method_variants.iter().map(|v| {
                let method = v["properties"]["method"]["const"].as_str().unwrap();
                (method.to_string(), format!("#/components/schemas/JsonRpcRequest{}", method.replace("kovanica_", "")))
            }).collect::<std::collections::BTreeMap<_, _>>()
        }
    });

    // Create response schema with oneOf for all result types
    let mut response_variants = Vec::new();
    for (method, _, _, _, result_schema) in &methods {
        let result_schema_name =
            format!("{}Result", method.replace("kovanica_", "").replace(".", ""));
        // Add result schema to components
        spec.components
            .schemas
            .insert(result_schema_name.clone(), result_schema.clone());
        response_variants.push(json!({
            "type": "object",
            "required": ["jsonrpc", "result", "id"],
            "properties": {
                "jsonrpc": { "type": "string", "const": "2.0" },
                "result": { "$ref": format!("#/components/schemas/{}", result_schema_name) },
                "error": { "$ref": "#/components/schemas/JsonRpcError" },
                "id": { "type": ["string", "number", "null"] }
            }
        }));
    }

    let response_body_schema = json!({
        "oneOf": response_variants,
        "discriminator": {
            "propertyName": "result",
            "mapping": methods.iter().map(|(m, _, _, _, _)| {
                let name = m.replace("kovanica_", "").replace(".", "");
                (name.clone(), format!("#/components/schemas/{}Result", name))
            }).collect::<std::collections::BTreeMap<_, _>>()
        }
    });

    let mut identity_headers = BTreeMap::new();
    identity_headers.insert(
        "X-Kovanica-Chain-Id".to_string(),
        OpenApiHeader {
            description:
                "Decimal chain ID served by this node (e.g. 1 mainnet, 2 testnet, 3 devnet)."
                    .to_string(),
            schema: json!({ "type": "string", "pattern": "^[0-9]+$" }),
        },
    );
    identity_headers.insert(
        "X-Kovanica-Network-Tag".to_string(),
        OpenApiHeader {
            description: "Canonical network tag (<chain_id>-<16 hex of genesis digest>) advertised by this node.".to_string(),
            schema: json!({ "type": "string" }),
        },
    );
    identity_headers.insert(
        "X-Kovanica-Rpc-Version".to_string(),
        OpenApiHeader {
            description: "kovanica-rpc crate version serving this endpoint.".to_string(),
            schema: json!({ "type": "string" }),
        },
    );

    // Add the single /rpc endpoint
    let path = "/rpc";
    let operation = OpenApiOperation {
        summary: "Kovanica JSON-RPC endpoint".to_string(),
        description: "All Kovanica JSON-RPC 2.0 methods are available via this single endpoint. The method is specified in the request body's 'method' field.".to_string(),
        operation_id: "jsonrpc".to_string(),
        tags: vec!["JSON-RPC".to_string()],
        request_body: Some(OpenApiRequestBody {
            required: true,
            content: {
                let mut content = BTreeMap::new();
                content.insert("application/json".to_string(), OpenApiMediaType {
                    schema: request_body_schema
                });
                content
            },
        }),
        responses: {
            let mut responses = BTreeMap::new();
            responses.insert("200".to_string(), OpenApiResponse {
                description: "Successful response".to_string(),
                headers: identity_headers.clone(),
                content: {
                    let mut content = BTreeMap::new();
                    content.insert("application/json".to_string(), OpenApiMediaType {
                        schema: response_body_schema
                    });
                    content
                },
            });
            responses
        },
    };

    spec.paths.entry(path.to_string()).or_default().post = Some(operation);

    // Add the /health probe endpoint
    let health_content = || {
        let mut content = BTreeMap::new();
        content.insert(
            "application/json".to_string(),
            OpenApiMediaType {
                schema: json!({ "$ref": "#/components/schemas/HealthResponse" }),
            },
        );
        content
    };
    let health_operation = OpenApiOperation {
        summary: "Node health probe".to_string(),
        description:
            "Returns HTTP 200 while execution and consensus are healthy, or HTTP 503 when degraded."
                .to_string(),
        operation_id: "health".to_string(),
        tags: vec!["Health".to_string()],
        request_body: None,
        responses: {
            let mut responses = BTreeMap::new();
            responses.insert(
                "200".to_string(),
                OpenApiResponse {
                    description: "Node is healthy".to_string(),
                    headers: identity_headers.clone(),
                    content: health_content(),
                },
            );
            responses.insert(
                "503".to_string(),
                OpenApiResponse {
                    description: "Node is degraded".to_string(),
                    headers: identity_headers,
                    content: health_content(),
                },
            );
            responses
        },
    };

    spec.paths.entry("/health".to_string()).or_default().get = Some(health_operation);

    spec
}

/// Write OpenAPI spec to JSON file.
pub fn write_openapi_json(path: &std::path::Path) -> Result<(), std::io::Error> {
    let spec = generate_openapi_spec();
    let json = serde_json::to_string_pretty(&spec)?;
    std::fs::write(path, json)
}

/// Write OpenAPI spec to YAML file.
pub fn write_openapi_yaml(path: &std::path::Path) -> Result<(), std::io::Error> {
    let spec = generate_openapi_spec();
    let yaml = serde_yaml::to_string(&spec).map_err(std::io::Error::other)?;
    std::fs::write(path, yaml)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openapi_generation() {
        let spec = generate_openapi_spec();
        assert_eq!(spec.openapi, "3.1.0");
        assert_eq!(spec.info.title, "Kovanica JSON-RPC API");
        assert!(spec.paths.contains_key("/rpc"));
        assert!(spec.components.schemas.contains_key("Transaction"));
        assert!(spec.components.schemas.contains_key("Address"));
    }

    #[test]
    fn test_openapi_json_serialization() {
        let spec = generate_openapi_spec();
        let json = serde_json::to_string_pretty(&spec).unwrap();
        // The method name appears in the request body schema as a const value
        assert!(
            json.contains("\"kovanica_getBlockByHash\""),
            "Missing kovanica_getBlockByHash"
        );
        assert!(
            json.contains("\"kovanica_sendRawTransaction\""),
            "Missing kovanica_sendRawTransaction"
        );
        assert!(
            json.contains("\"kovanica_subscribe\""),
            "Missing kovanica_subscribe"
        );
        assert!(
            json.contains("\"kovanica_getTransactionHistory\""),
            "Missing kovanica_getTransactionHistory"
        );
        assert!(
            json.contains("\"kovanica_requestAirdrop\""),
            "Missing kovanica_requestAirdrop"
        );
        assert!(
            json.contains("\"kovanica_mempoolStats\""),
            "Missing kovanica_mempoolStats"
        );
        assert!(
            spec.components.schemas.contains_key("MempoolStats"),
            "Missing MempoolStats schema"
        );

        let rpc_headers = &spec.paths["/rpc"]
            .post
            .as_ref()
            .expect("/rpc POST operation")
            .responses["200"]
            .headers;
        let health_headers = &spec.paths["/health"]
            .get
            .as_ref()
            .expect("/health GET operation")
            .responses["200"]
            .headers;

        for header in [
            "X-Kovanica-Chain-Id",
            "X-Kovanica-Network-Tag",
            "X-Kovanica-Rpc-Version",
        ] {
            assert!(
                rpc_headers.contains_key(header),
                "Missing {header} on /rpc 200 response"
            );
            assert!(
                health_headers.contains_key(header),
                "Missing {header} on /health 200 response"
            );
        }

        let health_schema = &spec.components.schemas["HealthResponse"];
        assert!(
            health_schema["properties"].get("mempool_pending").is_some(),
            "HealthResponse schema must document mempool_pending"
        );
        assert!(
            health_schema["properties"].get("rpc_version").is_some(),
            "HealthResponse schema must document rpc_version"
        );
        assert_eq!(
            health_schema["properties"]["syncing"]["type"],
            json!("boolean"),
            "HealthResponse schema must document syncing as boolean"
        );
        assert_eq!(
            health_schema["properties"]["indexer_attached"]["type"],
            json!("boolean"),
            "HealthResponse schema must document indexer_attached as boolean"
        );
        let required = health_schema["required"]
            .as_array()
            .expect("HealthResponse.required array");
        assert!(required.contains(&json!("mempool_pending")));
        assert!(required.contains(&json!("rpc_version")));
        assert!(required.contains(&json!("syncing")));
        assert!(required.contains(&json!("indexer_attached")));

        let get_logs_filter = &spec.components.schemas["GetLogsFilter"];
        assert!(
            get_logs_filter["properties"].get("cursor").is_some(),
            "GetLogsFilter schema must document cursor"
        );
    }
}
