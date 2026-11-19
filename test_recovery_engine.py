#!/usr/bin/env python3

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from pathlib import Path
from http.server import HTTPServer
from unittest import mock

import recovery_engine
import recovery_agent


class RecoveryDecisionTests(unittest.TestCase):

    def test_all_seven_categories_have_policies(self):
        self.assertEqual(len(recovery_engine.RECOVERY_POLICIES), 7)

    def test_all_seven_categories_create_plans(self):
        for classification in recovery_engine.RECOVERY_POLICIES:
            with self.subTest(classification=classification):
                plan = recovery_engine.plan_recovery({
                    "classification": classification,
                    "classification_confidence": 1.0,
                    "detection_status": "detected",
                })

                self.assertIsNotNone(plan)
                self.assertEqual(plan["status"], "planned")
                self.assertFalse(plan["automatic_execution"])

    def test_unknown_classification_is_rejected(self):
        self.assertIsNone(recovery_engine.plan_recovery({
            "classification": "unknown_fault",
            "classification_confidence": 1.0,
        }))

    def test_unclassified_fault_is_rejected(self):
        self.assertIsNone(recovery_engine.plan_recovery({
            "classification": "unclassified",
            "classification_confidence": 1.0,
        }))

    def test_low_confidence_is_rejected(self):
        self.assertIsNone(recovery_engine.plan_recovery({
            "classification": "service_stopped",
            "classification_confidence": 0.50,
        }))

    def test_missing_confidence_is_rejected(self):
        self.assertIsNone(recovery_engine.plan_recovery({
            "classification": "service_stopped",
        }))

    def test_undetected_incident_is_rejected(self):
        self.assertIsNone(recovery_engine.plan_recovery({
            "classification": "service_stopped",
            "classification_confidence": 1.0,
            "detection_status": "suspected",
        }))

    def test_batch_planning_skips_invalid_incidents(self):
        plans = recovery_engine.plan_recoveries([
            {
                "classification": "service_stopped",
                "classification_confidence": 1.0,
            },
            {
                "classification": "unknown",
                "classification_confidence": 1.0,
            },
        ])
        self.assertEqual(len(plans), 1)

    def test_non_list_input_is_safe(self):
        self.assertEqual(recovery_engine.plan_recoveries(None), [])


class RecoveryAgentApiTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)

        self.token_file = root / "token"
        self.config_file = root / "service.conf"

        self.token_file.write_text("test-secret-token\n")
        self.config_file.write_text("mode=broken\n")

        self.token_patch = mock.patch.object(
            recovery_agent, "TOKEN_FILE", self.token_file
        )
        self.config_patch = mock.patch.object(
            recovery_agent, "CONFIG_FILE", self.config_file
        )

        self.token_patch.start()
        self.config_patch.start()

        self.server = HTTPServer(
            ("127.0.0.1", 0),
            recovery_agent.RecoveryHandler,
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )
        self.thread.start()

        self.base = "http://127.0.0.1:%s" % self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.token_patch.stop()
        self.config_patch.stop()
        self.tmp.cleanup()

    def request(self, path, token=None, payload=None):
        data = None if payload is None else json.dumps(payload).encode()

        headers = {}
        if token is not None:
            headers["X-Recovery-Token"] = token
        if data is not None:
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(
            self.base + path,
            data=data,
            headers=headers,
            method="POST" if path.startswith("/recover") else "GET",
        )

        try:
            with urllib.request.urlopen(req, timeout=3) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_health_endpoint(self):
        status, body = self.request("/health")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])

    def test_valid_token_restores_config(self):
        status, body = self.request(
            "/recover",
            token="test-secret-token",
        )
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(
            self.config_file.read_text().strip(),
            "mode=ok",
        )

    def test_explicit_action_restores_config(self):
        status, body = self.request(
            "/recover/config",
            token="test-secret-token",
            payload={"action": "restore_service_config"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["action"], "restore_service_config")

    def test_invalid_token_is_rejected(self):
        status, _ = self.request(
            "/recover",
            token="wrong-token",
        )
        self.assertEqual(status, 403)
        self.assertEqual(
            self.config_file.read_text().strip(),
            "mode=broken",
        )

    def test_unsupported_action_is_rejected(self):
        status, _ = self.request(
            "/recover",
            token="test-secret-token",
            payload={"action": "restart_switch"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(
            self.config_file.read_text().strip(),
            "mode=broken",
        )

    def test_unknown_endpoint_is_rejected(self):
        status, _ = self.request(
            "/recover/anything",
            token="test-secret-token",
        )
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
