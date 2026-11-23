#!/usr/bin/env python3
"""Unit tests for ops/monitoring/check-cluster.py (stdlib unittest only)."""

from __future__ import annotations

import importlib.util
import pathlib
import unittest

_MODULE_PATH = pathlib.Path(__file__).resolve().parent / "check-cluster.py"
_SPEC = importlib.util.spec_from_file_location("check_cluster", _MODULE_PATH)
assert _SPEC is not None and _SPEC.loader is not None
check_cluster = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(check_cluster)


class TestVerifyRpcIdentityHeaders(unittest.TestCase):
    def test_canonical_tags_constant(self) -> None:
        self.assertEqual(
            check_cluster.CANONICAL_NETWORK_TAGS,
            {
                1: "1-f35df34c92001436",
                2: "2-24cdb5fadd98b207",
            },
        )

    def test_valid_chain1_headers_case_insensitive(self) -> None:
        headers = {
            "x-kovanica-network-tag": "1-f35df34c92001436",
            "X-KOVANICA-RPC-VERSION": "0.9.1",
        }
        res = check_cluster.verify_rpc_identity_headers(headers, expected_chain_id=1)
        self.assertTrue(res["ok"])
        self.assertEqual(res["errors"], [])
        self.assertEqual(res["network_tag"], "1-f35df34c92001436")
        self.assertEqual(res["rpc_version"], "0.9.1")
        self.assertEqual(res["expected_network_tag"], "1-f35df34c92001436")

    def test_valid_chain2_headers_without_expected_chain_id(self) -> None:
        headers = {
            "X-Kovanica-Network-Tag": "2-24cdb5fadd98b207",
            "X-Kovanica-Rpc-Version": "1.0.0",
        }
        res = check_cluster.verify_rpc_identity_headers(headers)
        self.assertTrue(res["ok"])
        self.assertEqual(res["errors"], [])
        self.assertEqual(res["expected_network_tag"], "2-24cdb5fadd98b207")

    def test_chain1_canonical_tag_mismatch(self) -> None:
        headers = {
            "X-Kovanica-Network-Tag": "1-0000000000000000",
            "X-Kovanica-Rpc-Version": "1.0.0",
        }
        res = check_cluster.verify_rpc_identity_headers(headers, expected_chain_id=1)
        self.assertFalse(res["ok"])
        self.assertTrue(any("Canonical network tag mismatch" in e for e in res["errors"]))

    def test_chain2_canonical_tag_mismatch_even_without_expected_chain_id(self) -> None:
        headers = {
            "X-Kovanica-Network-Tag": "2-deadbeefcafebabe",
            "X-Kovanica-Rpc-Version": "1.0.0",
        }
        res = check_cluster.verify_rpc_identity_headers(headers)
        self.assertFalse(res["ok"])
        self.assertTrue(any("Canonical network tag mismatch for chain 2" in e for e in res["errors"]))

    def test_cross_chain_mismatch(self) -> None:
        headers = {
            "X-Kovanica-Network-Tag": "1-f35df34c92001436",
            "X-Kovanica-Rpc-Version": "1.0.0",
        }
        res = check_cluster.verify_rpc_identity_headers(headers, expected_chain_id=2)
        self.assertFalse(res["ok"])
        self.assertTrue(any("Canonical network tag mismatch for chain 2" in e for e in res["errors"]))

    def test_missing_headers_and_malformed_tag(self) -> None:
        res_empty = check_cluster.verify_rpc_identity_headers({}, expected_chain_id=2)
        self.assertFalse(res_empty["ok"])
        self.assertEqual(len(res_empty["errors"]), 2)

        res_bad_format = check_cluster.verify_rpc_identity_headers(
            {
                "X-Kovanica-Network-Tag": "chain2-nothex",
                "X-Kovanica-Rpc-Version": "   ",
            },
            expected_chain_id=2,
        )
        self.assertFalse(res_bad_format["ok"])
        self.assertEqual(len(res_bad_format["errors"]), 2)

    def test_non_mapping_headers(self) -> None:
        res = check_cluster.verify_rpc_identity_headers(None, expected_chain_id=2)
        self.assertFalse(res["ok"])
        self.assertTrue(res["errors"])


class TestVerifyJsonRpcBatchResponse(unittest.TestCase):
    def test_valid_batch_response_out_of_order(self) -> None:
        payload = [
            {"jsonrpc": "2.0", "id": 3, "result": "0x64"},
            {"jsonrpc": "2.0", "id": 1, "result": "0x2"},
            {"jsonrpc": "2.0", "id": 2, "result": "0x1a4"},
        ]
        res = check_cluster.verify_jsonrpc_batch_response(payload)
        self.assertTrue(res["ok"])
        self.assertEqual(res["errors"], [])
        self.assertEqual(res["chain_id"], 2)
        self.assertEqual(res["block_height"], 0x1A4)
        self.assertEqual(res["estimate_fee"], 0x64)

    def test_batch_partial_error(self) -> None:
        payload = [
            {"jsonrpc": "2.0", "id": 1, "result": "0x2"},
            {"jsonrpc": "2.0", "id": 2, "result": "0x10"},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "error": {"code": -32000, "message": "mempool unavailable"},
            },
        ]
        res = check_cluster.verify_jsonrpc_batch_response(payload)
        self.assertFalse(res["ok"])
        self.assertTrue(any("kovanica_estimateFee" in e and "error" in e for e in res["errors"]))
        self.assertEqual(res["chain_id"], 2)
        self.assertEqual(res["block_height"], 16)
        self.assertIsNone(res["estimate_fee"])

    def test_batch_missing_and_duplicate_ids(self) -> None:
        payload = [
            {"jsonrpc": "2.0", "id": 1, "result": "0x2"},
            {"jsonrpc": "2.0", "id": 1, "result": "0x2"},
            {"jsonrpc": "2.0", "id": 2, "result": "0x5"},
        ]
        res = check_cluster.verify_jsonrpc_batch_response(payload)
        self.assertFalse(res["ok"])
        self.assertTrue(any("Duplicate batch response id: 1" in e for e in res["errors"]))
        self.assertTrue(any("Missing batch response for kovanica_estimateFee" in e for e in res["errors"]))

    def test_batch_invalid_quantities_and_non_array(self) -> None:
        res_not_list = check_cluster.verify_jsonrpc_batch_response({"jsonrpc": "2.0", "id": 1, "result": "0x2"})
        self.assertFalse(res_not_list["ok"])

        res_bad_qty = check_cluster.verify_jsonrpc_batch_response([
            {"jsonrpc": "2.0", "id": 1, "result": "0x0"},
            {"jsonrpc": "2.0", "id": 2, "result": "12345"},
            {"jsonrpc": "2.0", "id": 3, "result": "0xzz"},
        ])
        self.assertFalse(res_bad_qty["ok"])
        self.assertEqual(len(res_bad_qty["errors"]), 3)


class TestEvaluateStratumHealth(unittest.TestCase):
    def test_healthy_stratum_payload(self) -> None:
        payload = {
            "status": "healthy",
            "active_workers": 12,
            "accepted": 95,
            "rejected": 5,
        }
        res = check_cluster.evaluate_stratum_health(payload)
        self.assertTrue(res["ok"])
        self.assertFalse(res["draining"])
        self.assertEqual(res["alerts"], [])
        self.assertEqual(res["warnings"], [])
        self.assertEqual(res["active_workers"], 12)
        self.assertAlmostEqual(res["rejection_ratio"], 0.05)

    def test_boundary_ten_percent_rejection_ratio_is_ok(self) -> None:
        payload = {
            "status": "ok",
            "active_workers": 4,
            "accepted": 90,
            "rejected": 10,
        }
        res = check_cluster.evaluate_stratum_health(payload)
        self.assertTrue(res["ok"])
        self.assertEqual(res["alerts"], [])
        self.assertAlmostEqual(res["rejection_ratio"], 0.10)

    def test_draining_status_alerts(self) -> None:
        payload = {
            "status": "draining",
            "active_workers": 3,
            "accepted": 100,
            "rejected": 1,
        }
        res = check_cluster.evaluate_stratum_health(payload)
        self.assertFalse(res["ok"])
        self.assertTrue(res["draining"])
        self.assertTrue(any("draining" in a for a in res["alerts"]))

    def test_zero_active_workers_warns(self) -> None:
        payload = {
            "status": "healthy",
            "active_workers": 0,
            "accepted": 0,
            "rejected": 0,
        }
        res = check_cluster.evaluate_stratum_health(payload)
        self.assertTrue(res["ok"])
        self.assertEqual(res["alerts"], [])
        self.assertTrue(any("active_workers is 0" in w for w in res["warnings"]))
        self.assertEqual(res["rejection_ratio"], 0.0)

    def test_high_rejection_ratio_alerts(self) -> None:
        payload = {
            "status": "healthy",
            "active_workers": 5,
            "accepted": 89,
            "rejected": 11,
        }
        res = check_cluster.evaluate_stratum_health(payload)
        self.assertFalse(res["ok"])
        self.assertAlmostEqual(res["rejection_ratio"], 0.11)
        self.assertTrue(any("High Stratum share rejection ratio" in a for a in res["alerts"]))

    def test_malformed_stratum_payloads(self) -> None:
        for bad in (None, [], "healthy", 42):
            res = check_cluster.evaluate_stratum_health(bad)
            self.assertFalse(res["ok"])
            self.assertTrue(res["alerts"])

        res_missing_status = check_cluster.evaluate_stratum_health({"active_workers": 2})
        self.assertFalse(res_missing_status["ok"])

        res_bad_types = check_cluster.evaluate_stratum_health({
            "status": "healthy",
            "active_workers": True,
            "accepted": -1,
            "rejected": "5",
        })
        self.assertFalse(res_bad_types["ok"])
        self.assertGreaterEqual(len(res_bad_types["alerts"]), 2)


class TestCliArgs(unittest.TestCase):
    def test_defaults_preserve_backwards_compatibility(self) -> None:
        args = check_cluster.parse_args([])
        self.assertIsNone(args.stratum_health_url)
        self.assertEqual(args.expected_chain_id, 2)
        self.assertFalse(args.skip_header_check)
        self.assertFalse(args.skip_batch_check)

    def test_stratum_health_url_flag(self) -> None:
        args = check_cluster.parse_args(
            ["--stratum-health-url", "http://127.0.0.1:9100/health", "--expected-chain-id", "1"]
        )
        self.assertEqual(args.stratum_health_url, "http://127.0.0.1:9100/health")
        self.assertEqual(args.expected_chain_id, 1)


if __name__ == "__main__":
    unittest.main()
