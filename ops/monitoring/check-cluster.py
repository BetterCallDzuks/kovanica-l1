#!/usr/bin/env python3
"""
Kovanica Chain 2 Testnet Health & Consensus Monitor.
Queries all seed endpoints for /health and JSON-RPC consensus status,
verifies RPC identity headers and JSON-RPC 2.0 batch responses, and
optionally evaluates Stratum gateway /health drain & share rejection telemetry.
Alerts if seconds_since_last_commit exceeds threshold or peer count drops below quorum.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from typing import Any

ENDPOINTS = [
    {"name": "seed1", "url": "https://seed1.kovanica.online"},
    {"name": "seed3", "url": "https://seed3.kovanica.online"},
    {"name": "rpc-testnet", "url": "https://rpc-testnet.kovanica.online"},
]

STALL_THRESHOLD_SECS = 60
MIN_PEERS = 3

CANONICAL_NETWORK_TAGS: dict[int, str] = {
    1: "1-f35df34c92001436",
    2: "2-24cdb5fadd98b207",
}

NETWORK_TAG_HEADER = "x-kovanica-network-tag"
RPC_VERSION_HEADER = "x-kovanica-rpc-version"
_NETWORK_TAG_RE = re.compile(r"^(\d+)-([0-9a-f]{16})$")
_HEX_QUANTITY_RE = re.compile(r"^0[xX][0-9a-fA-F]+$")

DEFAULT_BATCH_REQUEST: list[dict[str, Any]] = [
    {"jsonrpc": "2.0", "method": "kovanica_chainId", "params": [], "id": 1},
    {"jsonrpc": "2.0", "method": "kovanica_blockNumber", "params": [], "id": 2},
    {"jsonrpc": "2.0", "method": "kovanica_estimateFee", "params": [], "id": 3},
]

BATCH_ID_TO_METHOD: dict[int, str] = {
    1: "kovanica_chainId",
    2: "kovanica_blockNumber",
    3: "kovanica_estimateFee",
}

STRATUM_MAX_REJECTION_RATIO = 0.10


def _is_non_negative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _parse_hex_quantity(value: Any) -> int | None:
    if not isinstance(value, str) or not _HEX_QUANTITY_RE.match(value):
        return None
    try:
        parsed = int(value, 16)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def verify_rpc_identity_headers(
    headers: dict[str, Any] | Any,
    expected_chain_id: int | None = None,
) -> dict[str, Any]:
    """Verify X-Kovanica-Network-Tag and X-Kovanica-Rpc-Version response headers."""
    errors: list[str] = []
    expected_tag = (
        CANONICAL_NETWORK_TAGS.get(expected_chain_id)
        if expected_chain_id is not None
        else None
    )

    if headers is None or not hasattr(headers, "items"):
        return {
            "ok": False,
            "network_tag": None,
            "rpc_version": None,
            "expected_chain_id": expected_chain_id,
            "expected_network_tag": expected_tag,
            "errors": ["Invalid headers object: expected mapping"],
        }

    lowered: dict[str, Any] = {}
    for key, value in headers.items():
        if isinstance(key, str):
            lowered[key.lower()] = value

    raw_version = lowered.get(RPC_VERSION_HEADER)
    rpc_version = raw_version.strip() if isinstance(raw_version, str) else None
    if not rpc_version:
        errors.append("Missing or empty X-Kovanica-Rpc-Version header")

    raw_tag = lowered.get(NETWORK_TAG_HEADER)
    network_tag = raw_tag.strip() if isinstance(raw_tag, str) else None
    if not network_tag:
        errors.append("Missing or empty X-Kovanica-Network-Tag header")
    else:
        match = _NETWORK_TAG_RE.match(network_tag)
        if not match:
            errors.append(
                f"Malformed X-Kovanica-Network-Tag header: {network_tag!r} "
                "(expected '<chain_id>-<16 lowercase hex chars>')"
            )
        else:
            tag_chain_id = int(match.group(1))
            if expected_chain_id is not None:
                if expected_chain_id in CANONICAL_NETWORK_TAGS:
                    canonical = CANONICAL_NETWORK_TAGS[expected_chain_id]
                    if network_tag != canonical:
                        errors.append(
                            f"Canonical network tag mismatch for chain {expected_chain_id}: "
                            f"got {network_tag!r}, expected {canonical!r}"
                        )
                elif tag_chain_id != expected_chain_id:
                    errors.append(
                        f"Network tag chain ID mismatch: got {tag_chain_id}, "
                        f"expected {expected_chain_id}"
                    )
            elif tag_chain_id in CANONICAL_NETWORK_TAGS:
                canonical = CANONICAL_NETWORK_TAGS[tag_chain_id]
                expected_tag = canonical
                if network_tag != canonical:
                    errors.append(
                        f"Canonical network tag mismatch for chain {tag_chain_id}: "
                        f"got {network_tag!r}, expected {canonical!r}"
                    )

    return {
        "ok": len(errors) == 0,
        "network_tag": network_tag,
        "rpc_version": rpc_version,
        "expected_chain_id": expected_chain_id,
        "expected_network_tag": expected_tag,
        "errors": errors,
    }


def verify_jsonrpc_batch_response(response_payload: Any) -> dict[str, Any]:
    """
    Verify a single-POST JSON-RPC 2.0 batch response array containing
    kovanica_chainId (id=1), kovanica_blockNumber (id=2), and kovanica_estimateFee (id=3).
    """
    errors: list[str] = []
    decoded_results: dict[str, int | None] = {
        "kovanica_chainId": None,
        "kovanica_blockNumber": None,
        "kovanica_estimateFee": None,
    }

    if not isinstance(response_payload, list):
        return {
            "ok": False,
            "errors": ["Batch response must be a JSON array"],
            "results": decoded_results,
            "chain_id": None,
            "block_height": None,
            "estimate_fee": None,
        }

    if not response_payload:
        return {
            "ok": False,
            "errors": ["Batch response array is empty"],
            "results": decoded_results,
            "chain_id": None,
            "block_height": None,
            "estimate_fee": None,
        }

    seen_ids: set[int] = set()

    for idx, item in enumerate(response_payload):
        if not isinstance(item, dict):
            errors.append(f"Batch item at index {idx} is not a JSON object")
            continue

        if item.get("jsonrpc") != "2.0":
            errors.append(
                f"Batch item at index {idx} has invalid jsonrpc version: {item.get('jsonrpc')!r}"
            )

        item_id = item.get("id")
        if isinstance(item_id, bool) or not isinstance(item_id, int):
            errors.append(f"Batch item at index {idx} has invalid id: {item_id!r}")
            continue

        if item_id not in BATCH_ID_TO_METHOD:
            errors.append(f"Unexpected batch response id: {item_id}")
            continue

        if item_id in seen_ids:
            errors.append(f"Duplicate batch response id: {item_id}")
            continue
        seen_ids.add(item_id)

        method = BATCH_ID_TO_METHOD[item_id]

        if "error" in item and item["error"] is not None:
            errors.append(f"Batch item {method} (id={item_id}) returned error: {item['error']}")
            continue

        if "result" not in item:
            errors.append(f"Batch item {method} (id={item_id}) missing 'result' field")
            continue

        quantity = _parse_hex_quantity(item["result"])
        if quantity is None:
            errors.append(
                f"Batch item {method} (id={item_id}) has invalid hex quantity: {item['result']!r}"
            )
            continue

        if method == "kovanica_chainId" and quantity == 0:
            errors.append("kovanica_chainId returned 0x0 (expected positive chain ID)")
            continue

        decoded_results[method] = quantity

    for expected_id, method in BATCH_ID_TO_METHOD.items():
        if expected_id not in seen_ids:
            errors.append(f"Missing batch response for {method} (id={expected_id})")

    return {
        "ok": len(errors) == 0,
        "errors": errors,
        "results": decoded_results,
        "chain_id": decoded_results["kovanica_chainId"],
        "block_height": decoded_results["kovanica_blockNumber"],
        "estimate_fee": decoded_results["kovanica_estimateFee"],
    }


def evaluate_stratum_health(health_payload: Any) -> dict[str, Any]:
    """
    Evaluate a Stratum gateway /health payload for:
    - status == "draining" (alert)
    - active_workers == 0 (warning)
    - rejected / (accepted + rejected) > 0.10 (high rejection ratio alert)
    """
    alerts: list[str] = []
    warnings: list[str] = []

    if not isinstance(health_payload, dict):
        return {
            "ok": False,
            "status": None,
            "draining": False,
            "active_workers": None,
            "accepted": None,
            "rejected": None,
            "rejection_ratio": None,
            "alerts": ["Malformed Stratum health payload: expected JSON object"],
            "warnings": warnings,
        }

    raw_status = health_payload.get("status")
    status = raw_status.strip().lower() if isinstance(raw_status, str) and raw_status.strip() else None
    if status is None:
        alerts.append("Malformed Stratum health payload: missing or invalid 'status'")
    elif status == "draining":
        alerts.append("Stratum gateway is draining (status == 'draining')")
    elif status not in ("ok", "healthy"):
        alerts.append(f"Unexpected Stratum gateway status: {raw_status!r}")

    active_workers: int | None = None
    if "active_workers" in health_payload and health_payload["active_workers"] is not None:
        raw_workers = health_payload["active_workers"]
        if not _is_non_negative_int(raw_workers):
            alerts.append(
                f"Malformed Stratum health payload: invalid 'active_workers' value {raw_workers!r}"
            )
        else:
            active_workers = raw_workers
            if active_workers == 0:
                warnings.append("Stratum active_workers is 0 (no active miners connected)")

    # Support top-level accepted/rejected, shares_accepted/shares_rejected, or nested shares dict.
    accepted_raw: Any = None
    rejected_raw: Any = None
    has_share_fields = False

    if "accepted" in health_payload or "rejected" in health_payload:
        has_share_fields = True
        accepted_raw = health_payload.get("accepted")
        rejected_raw = health_payload.get("rejected")
    elif "shares_accepted" in health_payload or "shares_rejected" in health_payload:
        has_share_fields = True
        accepted_raw = health_payload.get("shares_accepted")
        rejected_raw = health_payload.get("shares_rejected")
    elif "shares" in health_payload:
        has_share_fields = True
        shares_obj = health_payload.get("shares")
        if isinstance(shares_obj, dict):
            accepted_raw = shares_obj.get("accepted")
            rejected_raw = shares_obj.get("rejected")
        else:
            alerts.append("Malformed Stratum health payload: 'shares' must be a JSON object")

    accepted: int | None = None
    rejected: int | None = None
    rejection_ratio: float | None = None

    if has_share_fields and not (
        "shares" in health_payload and not isinstance(health_payload.get("shares"), dict)
    ):
        if not _is_non_negative_int(accepted_raw) or not _is_non_negative_int(rejected_raw):
            alerts.append(
                "Malformed Stratum health payload: 'accepted' and 'rejected' must be non-negative integers"
            )
        else:
            accepted = accepted_raw
            rejected = rejected_raw
            total_shares = accepted + rejected
            rejection_ratio = (rejected / total_shares) if total_shares > 0 else 0.0
            if rejection_ratio > STRATUM_MAX_REJECTION_RATIO:
                alerts.append(
                    f"High Stratum share rejection ratio: {rejection_ratio:.2%} "
                    f"({rejected}/{total_shares} > {STRATUM_MAX_REJECTION_RATIO:.0%})"
                )

    return {
        "ok": len(alerts) == 0,
        "status": status,
        "draining": status == "draining",
        "active_workers": active_workers,
        "accepted": accepted,
        "rejected": rejected,
        "rejection_ratio": rejection_ratio,
        "alerts": alerts,
        "warnings": warnings,
    }


def check_health(base_url: str, timeout: float = 5) -> dict[str, Any]:
    health_url = f"{base_url}/health"
    req = urllib.request.Request(health_url, headers={"User-Agent": "Kovanica-Monitor/1.0"})
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            latency_ms = int((time.time() - start) * 1000)
            headers = dict(resp.headers.items())
            data = json.loads(resp.read().decode("utf-8"))
            return {"status": "ok", "latency_ms": latency_ms, "data": data, "headers": headers}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def check_rpc(base_url: str, timeout: float = 5) -> dict[str, Any]:
    rpc_url = f"{base_url}/rpc"
    payload = json.dumps({
        "jsonrpc": "2.0",
        "method": "kovanica_blockNumber",
        "params": [],
        "id": 1,
    }).encode("utf-8")
    req = urllib.request.Request(
        rpc_url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "Kovanica-Monitor/1.0"},
    )
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            latency_ms = int((time.time() - start) * 1000)
            headers = dict(resp.headers.items())
            res = json.loads(resp.read().decode("utf-8"))
            block_hex = res.get("result", "0x0")
            block_num = int(block_hex, 16)
            return {
                "status": "ok",
                "latency_ms": latency_ms,
                "block_height": block_num,
                "headers": headers,
            }
    except Exception as e:
        return {"status": "error", "error": str(e)}


def check_rpc_batch(base_url: str, timeout: float = 5) -> dict[str, Any]:
    rpc_url = f"{base_url}/rpc"
    payload = json.dumps(DEFAULT_BATCH_REQUEST).encode("utf-8")
    req = urllib.request.Request(
        rpc_url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "Kovanica-Monitor/1.0"},
    )
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            latency_ms = int((time.time() - start) * 1000)
            headers = dict(resp.headers.items())
            body = json.loads(resp.read().decode("utf-8"))
            verification = verify_jsonrpc_batch_response(body)
            return {
                "status": "ok" if verification["ok"] else "error",
                "latency_ms": latency_ms,
                "headers": headers,
                "verification": verification,
            }
    except Exception as e:
        return {"status": "error", "error": str(e)}


def check_stratum_health(health_url: str, timeout: float = 5) -> dict[str, Any]:
    req = urllib.request.Request(health_url, headers={"User-Agent": "Kovanica-Monitor/1.0"})
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            latency_ms = int((time.time() - start) * 1000)
            payload = json.loads(resp.read().decode("utf-8"))
            evaluation = evaluate_stratum_health(payload)
            return {
                "status": "ok" if evaluation["ok"] else "error",
                "latency_ms": latency_ms,
                "evaluation": evaluation,
            }
    except Exception as e:
        return {"status": "error", "error": str(e)}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Kovanica Chain 2 Testnet Health, RPC Batch/Header & Stratum Monitor"
    )
    parser.add_argument(
        "--stratum-health-url",
        default=None,
        help="Optional Stratum gateway /health URL to check for drain and share rejection health.",
    )
    parser.add_argument(
        "--expected-chain-id",
        type=int,
        default=2,
        help="Expected chain ID for X-Kovanica-Network-Tag verification (default: 2).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="HTTP request timeout in seconds (default: 5).",
    )
    parser.add_argument(
        "--skip-header-check",
        action="store_true",
        help="Skip X-Kovanica-Network-Tag and X-Kovanica-Rpc-Version header verification.",
    )
    parser.add_argument(
        "--skip-batch-check",
        action="store_true",
        help="Skip JSON-RPC 2.0 batch verification (chainId, blockNumber, estimateFee).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    print("=" * 70)
    print("KOVANICA CHAIN 2 TESTNET CLUSTER HEALTH MONITOR")
    print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    print("=" * 70)

    overall_healthy = True
    results = []

    for ep in ENDPOINTS:
        name = ep["name"]
        url = ep["url"]
        health = check_health(url, timeout=args.timeout)
        rpc = check_rpc(url, timeout=args.timeout)

        endpoint_ok = True
        warnings = []

        if health["status"] != "ok":
            endpoint_ok = False
            warnings.append(f"Health check failed: {health.get('error')}")
        else:
            hdata = health["data"]
            peer_count = hdata.get("peer_count", 0)
            if peer_count < MIN_PEERS:
                warnings.append(f"Low peers: {peer_count} < {MIN_PEERS}")
                endpoint_ok = False

            consensus = hdata.get("consensus", {})
            stall_secs = consensus.get("seconds_since_last_commit", 999)
            if stall_secs > STALL_THRESHOLD_SECS:
                warnings.append(
                    f"Consensus stalled: {stall_secs}s since last commit (> {STALL_THRESHOLD_SECS}s)"
                )
                endpoint_ok = False

        if rpc["status"] != "ok":
            endpoint_ok = False
            warnings.append(f"RPC blockNumber failed: {rpc.get('error')}")
        elif not args.skip_header_check:
            header_check = verify_rpc_identity_headers(
                rpc.get("headers", {}),
                expected_chain_id=args.expected_chain_id,
            )
            if not header_check["ok"]:
                endpoint_ok = False
                for err in header_check["errors"]:
                    warnings.append(f"RPC header check failed: {err}")

        if not args.skip_batch_check:
            batch = check_rpc_batch(url, timeout=args.timeout)
            if batch["status"] != "ok":
                endpoint_ok = False
                if "error" in batch:
                    warnings.append(f"RPC batch request failed: {batch['error']}")
                else:
                    for err in batch.get("verification", {}).get("errors", []):
                        warnings.append(f"RPC batch check failed: {err}")

        status_sym = "[OK]" if endpoint_ok else "[FAIL]"
        if not endpoint_ok:
            overall_healthy = False

        block_height = rpc.get("block_height", "N/A")
        peers = health.get("data", {}).get("peer_count", "N/A")
        last_commit_secs = (
            health.get("data", {}).get("consensus", {}).get("seconds_since_last_commit", "N/A")
        )
        lat = health.get("latency_ms", "N/A")

        print(
            f"{status_sym:6} {name:<12} | Block: {str(block_height):<6} | "
            f"Peers: {str(peers):<3} | Last Commit: {str(last_commit_secs):>2}s ago | Latency: {lat}ms"
        )
        for w in warnings:
            print(f"       -> WARNING: {w}")

        results.append({
            "name": name,
            "url": url,
            "healthy": endpoint_ok,
            "block_height": block_height,
            "peer_count": peers,
            "seconds_since_last_commit": last_commit_secs,
            "warnings": warnings,
        })

    if args.stratum_health_url:
        stratum = check_stratum_health(args.stratum_health_url, timeout=args.timeout)
        stratum_ok = stratum["status"] == "ok"
        if not stratum_ok:
            overall_healthy = False

        status_sym = "[OK]" if stratum_ok else "[FAIL]"
        if "error" in stratum:
            print(f"{status_sym:6} {'stratum':<12} | URL: {args.stratum_health_url}")
            print(f"       -> ALERT: Stratum health check failed: {stratum['error']}")
        else:
            ev = stratum["evaluation"]
            lat = stratum.get("latency_ms", "N/A")
            workers = ev["active_workers"] if ev["active_workers"] is not None else "N/A"
            ratio = (
                f"{ev['rejection_ratio']:.2%}"
                if ev["rejection_ratio"] is not None
                else "N/A"
            )
            print(
                f"{status_sym:6} {'stratum':<12} | Status: {str(ev['status']):<8} | "
                f"Workers: {str(workers):<4} | Reject Ratio: {ratio:<7} | Latency: {lat}ms"
            )
            for alert in ev["alerts"]:
                print(f"       -> ALERT: {alert}")
            for warning in ev["warnings"]:
                print(f"       -> WARNING: {warning}")

    print("=" * 70)
    if overall_healthy:
        print("CLUSTER STATUS: ALL NODES HEALTHY AND CONSENSUS PROGRESSING NORMAL.")
        sys.exit(0)
    else:
        print("CLUSTER STATUS: ISSUES DETECTED. CHECK WARNINGS ABOVE.")
        sys.exit(1)


if __name__ == "__main__":
    main()
