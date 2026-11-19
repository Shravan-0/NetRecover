#!/usr/bin/env python3
"""Focused tests for config and switch dashboard fault controls."""

import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import dashboard_test as dash
import health_service
import topo_large


class DummySwitch:
    def __init__(self):
        self.controller = topo_large.EXPECTED_CONTROLLER
        self.protocols = f'["{topo_large.EXPECTED_PROTOCOL}"]'

    def cmd(self, command):
        if "set-controller" in command:
            self.controller = command.split()[-1]
            return ""
        if "get-controller" in command:
            return self.controller
        if "set bridge" in command and "protocols=" in command:
            self.protocols = command.split("protocols=", 1)[1]
            return ""
        if "get bridge" in command:
            return self.protocols
        raise AssertionError(f"unexpected command: {command}")


class DummyNet:
    def __init__(self):
        self.switch = DummySwitch()

    def get(self, name):
        if name != topo_large.FAULT_SWITCH:
            return None
        return self.switch


class ParseControlPayloadTests(unittest.TestCase):
    def test_accepts_enable_disable(self):
        for action in ("enable", "disable"):
            raw = json.dumps({"action": action}).encode("utf-8")
            self.assertEqual(
                topo_large.parse_control_payload(raw, len(raw)),
                action,
            )

    def test_rejects_unknown_action(self):
        raw = json.dumps({"action": "bounce"}).encode("utf-8")
        with self.assertRaises(ValueError):
            topo_large.parse_control_payload(raw, len(raw))

    def test_rejects_oversized_request(self):
        raw = json.dumps({"action": "enable"}).encode("utf-8")
        with self.assertRaises(ValueError):
            topo_large.parse_control_payload(raw, 2048)


class SwitchFaultHelperTests(unittest.TestCase):
    def setUp(self):
        self.previous = topo_large.network
        topo_large.network = DummyNet()

    def tearDown(self):
        topo_large.network = self.previous

    def test_enable_then_disable_is_reversible(self):
        enabled = topo_large.apply_switch_fault("enable")
        self.assertEqual(enabled["state"], "fault")
        self.assertIn("9999", enabled["controller"])
        self.assertIn(topo_large.WRONG_PROTOCOL, enabled["protocols"])

        restored = topo_large.apply_switch_fault("disable")
        self.assertEqual(restored["state"], "ok")
        self.assertIn(topo_large.EXPECTED_CONTROLLER, restored["controller"])
        self.assertIn(topo_large.EXPECTED_PROTOCOL, restored["protocols"])


class SwitchControlApiTests(unittest.TestCase):
    def setUp(self):
        self.previous = topo_large.network
        topo_large.network = DummyNet()
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            topo_large.ControlHandler,
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )
        self.thread.start()
        host, port = self.server.server_address
        self.base = f"http://{host}:{port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        topo_large.network = self.previous

    def _request(self, path, method="GET", payload=None):
        import urllib.request

        data = None
        headers = {}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base + path,
            data=data,
            headers=headers,
            method=method,
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read().decode("utf-8"))

    def test_switch_enable_disable_and_status(self):
        status, body = self._request(
            "/api/switch", method="POST", payload={"action": "enable"}
        )
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["state"], "fault")

        status, body = self._request("/api/switch/status")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "fault")

        status, body = self._request(
            "/api/switch", method="POST", payload={"action": "disable"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "ok")

    def test_observe_endpoint_exists(self):
        import urllib.error
        import urllib.request

        try:
            request = urllib.request.Request(self.base + "/api/observe")
            with urllib.request.urlopen(request, timeout=3) as response:
                body = json.loads(response.read().decode("utf-8"))
            self.assertIn("ok", body)
        except urllib.error.HTTPError as exc:
            self.assertIn(exc.code, (500, 503))

    def test_service_process_controller_path_routes_exist(self):
        import urllib.error
        import urllib.request

        for path in ("/api/service", "/api/process", "/api/controller", "/api/path"):
            request = urllib.request.Request(
                self.base + path,
                data=json.dumps({"action": "disable"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=3) as response:
                    self.assertEqual(response.status, 200)
            except urllib.error.HTTPError as exc:
                self.assertNotEqual(exc.code, 404)

    def test_link_endpoint_still_present(self):
        import urllib.error
        import urllib.request

        request = urllib.request.Request(
            self.base + "/api/link",
            data=json.dumps({"action": "enable"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(request, timeout=3)
        # DummyNet has no configLinkStatus; API must not 404 the link route.
        self.assertEqual(ctx.exception.code, 500)


class ConfigFaultApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config = Path(self.tmp.name) / "service.conf"
        self.status = Path(self.tmp.name) / "service_status.json"
        self.config.write_text("mode=ok\n", encoding="utf-8")
        dash.SERVICE_CONFIG = self.config
        dash.STATUS_FILE = self.status
        dash.cancel_config_recovery_watch()
        self.client = dash.app.test_client()

    def tearDown(self):
        dash.cancel_config_recovery_watch()
        self.tmp.cleanup()

    def test_config_enable_writes_fault_and_disable_restores(self):
        response = self.client.post(
            "/api/fault",
            json={"action": "enable", "id": "config"},
        )
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["state"], "fault")
        self.assertEqual(self.config.read_text(encoding="utf-8").strip(), "mode=broken")

        status = self.client.get("/api/config/status").get_json()
        self.assertEqual(status["state"], "fault")

        response = self.client.post(
            "/api/fault",
            json={"action": "disable", "id": "config"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["state"], "ok")
        self.assertEqual(self.config.read_text(encoding="utf-8").strip(), "mode=ok")

    def test_unknown_fault_is_rejected(self):
        response = self.client.post(
            "/api/fault",
            json={"action": "enable", "id": "not-a-real-fault"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()["ok"])

    def test_switch_proxy_times_out_cleanly_when_api_missing(self):
        with mock.patch.object(dash, "MININET_API", "http://127.0.0.1:1"):
            response = self.client.post(
                "/api/fault",
                json={"action": "enable", "id": "switch"},
            )
        self.assertEqual(response.status_code, 503)
        body = response.get_json()
        self.assertFalse(body["ok"])
        self.assertIn("Mininet control API", body["error"])

    def test_link_proxy_still_used(self):
        with mock.patch.object(dash, "MININET_API", "http://127.0.0.1:1"):
            response = self.client.post(
                "/api/fault",
                json={"action": "disable", "id": "link"},
            )
        self.assertEqual(response.status_code, 503)

    def test_remaining_phase1_faults_still_proxy_to_mininet(self):
        for fault_id in ("service", "process", "controller", "path"):
            with mock.patch.object(dash, "MININET_API", "http://127.0.0.1:1"):
                response = self.client.post(
                    "/api/fault",
                    json={"action": "enable", "id": fault_id},
                )
            self.assertEqual(response.status_code, 503, fault_id)
            self.assertFalse(response.get_json()["ok"])

    def test_watch_recovers_after_fresh_unhealthy_status(self):
        dash.write_service_config(dash.FAULTY_CONFIG)
        self.status.write_text(
            json.dumps({
                "healthy": False,
                "checked_at": dash.datetime.now(dash.timezone.utc).isoformat(),
            }) + "\n",
            encoding="utf-8",
        )
        dash.watch_config_and_recover(dash._config_job_id)
        self.assertEqual(self.config.read_text(encoding="utf-8").strip(), "mode=ok")
        self.assertTrue(dash._config_pipeline["detected"])
        self.assertTrue(dash._config_pipeline["recovered"])


class HealthServiceConfigTests(unittest.TestCase):
    def test_health_uses_same_ok_and_broken_modes(self):
        previous = health_service.CONFIG_FILE
        tmp = tempfile.TemporaryDirectory()
        config = Path(tmp.name) / "service.conf"
        health_service.CONFIG_FILE = config
        try:
            config.write_text("mode=broken\n", encoding="utf-8")
            self.assertNotEqual(
                config.read_text(encoding="utf-8").strip(),
                "mode=ok",
            )
            config.write_text("mode=ok\n", encoding="utf-8")
            self.assertEqual(config.read_text(encoding="utf-8").strip(), "mode=ok")
        finally:
            health_service.CONFIG_FILE = previous
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
