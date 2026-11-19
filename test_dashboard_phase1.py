"""Production-dashboard Phase 1 tests; temporary files, no live faults."""
import json
import power_control
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import dashboard as dash


class DashboardPhase1Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        for name, filename in (
            ("STATUS_FILE", "service_status.json"),
            ("POWER_FILE", "recovery_power.json"),
            ("RECOVERY_STATUS_FILE", "recovery_status.json"),
            ("SERVICE_CONFIG", "service.conf"),
            ("FAULT_LOG", "faults.jsonl"),
        ):
            patcher = mock.patch.object(dash, name, root / filename)
            patcher.start()
            self.addCleanup(patcher.stop)
        proxy = mock.patch.object(dash, "proxy_mininet", return_value=({"ok": False}, 503))
        proxy.start()
        self.addCleanup(proxy.stop)
        self.client = dash.app.test_client()
        dash.SERVICE_CONFIG.write_text("mode=ok\n")
        self.set_health(True)

    def set_health(self, healthy, checked_at=None):
        dash.STATUS_FILE.write_text(json.dumps({
            "healthy": healthy,
            "checked_at": checked_at or dash.datetime.now(
                dash.timezone.utc
            ).isoformat(),
        }))

    def snapshot(self, gate):
        return {
            "checked_at": dash.datetime.now(dash.timezone.utc).isoformat(),
            "engine": "detect_service",
            "automatic_recovery_enabled": gate,
            "observe_available": True,
            "healthy": True,
            "active": [],
        }

    def test_detector_gate_reaches_real_status_route(self):
        for gate in (False, True):
            power_control.set_enabled(gate, path=dash.POWER_FILE)
            with self.subTest(gate=gate), \
                 mock.patch.dict(os.environ, {
                     "ACN_ENABLE_AUTO_RECOVERY": "0" if gate else "1"
                 }), \
                 mock.patch.object(
                     dash, "read_detection_status",
                     return_value=self.snapshot(gate)
                 ):
                response = self.client.get("/api/status")
                self.assertEqual(response.status_code, 200)
                body = response.get_json()
                self.assertIs(body["automatic_recovery"]["enabled"], gate)
                self.assertEqual(
                    body["automatic_recovery"]["source"], "shared_power_file"
                )
                self.assertTrue(body["service"]["healthy"])
                self.assertEqual(body["detection"]["status"], "healthy")

    def test_missing_history_does_not_make_healthy_service_unhealthy(self):
        self.assertFalse(dash.RECOVERY_STATUS_FILE.exists())
        result = dash.read_recovery_status()
        self.assertEqual(result["status"], "HEALTHY")
        self.assertEqual(result["attempts"], [])
        self.assertTrue(dash.check_service())

    def test_stale_health_is_not_claimed_healthy(self):
        self.set_health(True, "2020-01-01T00:00:00+00:00")
        self.assertFalse(dash.check_service())
        self.assertEqual(dash.read_recovery_status()["status"], "UNKNOWN")

    def test_injection_proxies_to_mininet_without_dashboard_recovery(self):
        upstream = {
            "ok": True, "id": "config",
            "state": "fault", "config": "mode=broken"
        }
        with mock.patch.object(
            dash, "proxy_mininet", return_value=(upstream, 200)
        ) as proxy, mock.patch.object(
            dash, "start_config_recovery_watch"
        ) as start:
            response = self.client.post(
                "/api/fault", json={"action": "enable", "id": "config"}
            )

        self.assertEqual(response.status_code, 200)
        proxy.assert_called_once_with(
            "/api/config", method="POST", payload={"action": "enable"}
        )
        self.assertEqual(dash.SERVICE_CONFIG.read_text().strip(), "mode=ok")
        start.assert_not_called()

    def test_manual_disable_proxies_to_mininet(self):
        dash.SERVICE_CONFIG.write_text("mode=broken\n")
        upstream = {
            "ok": True, "id": "config",
            "state": "ok", "config": "mode=ok"
        }
        with mock.patch.object(
            dash, "proxy_mininet", return_value=(upstream, 200)
        ) as proxy:
            response = self.client.post(
                "/api/fault", json={"action": "disable", "id": "config"}
            )

        self.assertEqual(response.status_code, 200)
        proxy.assert_called_once_with(
            "/api/config", method="POST", payload={"action": "disable"}
        )
        self.assertEqual(dash.SERVICE_CONFIG.read_text().strip(), "mode=broken")
        self.assertTrue(dash._config_pipeline["recovered"])

    def test_config_status_is_proxied_to_mininet(self):
        upstream = {
            "ok": True, "config": "mode=broken", "state": "fault"
        }
        with mock.patch.object(
            dash, "proxy_mininet", return_value=(upstream, 200)
        ) as proxy, mock.patch.object(
            dash, "check_service", return_value=False
        ):
            response = self.client.get("/api/config/status")

        self.assertEqual(response.status_code, 200)
        proxy.assert_called_once_with("/api/config/status", timeout=3)
        body = response.get_json()
        self.assertEqual(body["config"], "mode=broken")
        self.assertEqual(body["state"], "fault")

    def test_legacy_watcher_cannot_execute_recovery(self):
        with mock.patch.object(dash, "restore_service_config") as restore:
            dash.watch_config_and_recover(dash._config_job_id)
        restore.assert_not_called()

    def test_readable_ui_has_one_large_toggle_and_collapsed_manual_controls(self):
        self.assertEqual(dash.PAGE.count('id="mainPower"'), 1)
        self.assertIn('<details class="advanced-controls">', dash.PAGE)
        self.assertIn('ACN_READABLE_UI_V2', dash.PAGE)
        sizes = [float(value) for value in re.findall(r'font-size\s*:\s*(\d+(?:\.\d+)?)px', dash.PAGE)]
        self.assertTrue(sizes)
        self.assertTrue(all(size >= 16 for size in sizes))
        self.assertIn('.main-power{font-size:24px', dash.PAGE)

    def test_javascript_syntax(self):
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node.js required for this test")
        scripts = re.findall(
            r"<script[^>]*>(.*?)</script>", dash.PAGE, flags=re.S
        )
        self.assertTrue(scripts)
        result = subprocess.run(
            [node, "--check"],
            input="\n;\n".join(scripts),
            text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_monitor_renders_healthy_without_overwriting_recovery(self):
        start = dash.PAGE.index("let powerView = null")
        end = dash.PAGE.index("let operationBusy", start)
        function = dash.PAGE[start:end]
        harness = r"""
const assert = require("assert");
const elements = new Map();
const document = {
  getElementById(id) {
    if (!elements.has(id)) elements.set(id, {setAttribute(){},addEventListener(){}});
    return elements.get(id);
  }
};
const active = new Set();
const esc = value => String(value);
let detectionView = {
  status: "healthy", active: [], detected_count: 0,
  classified_count: 0, service_healthy: true
};
document.getElementById("step3state").textContent = "SUCCESS";
document.getElementById("step4state").textContent = "VERIFIED";
"""
        assertions = r"""
renderMonitor();
assert.equal(document.getElementById("heroBadge").textContent, "UNKNOWN");
// Service-only health and historical SUCCESS must never make overall health green.
systemView={overall:"HEALTHY",detail:"Independent check fixture",stages:{detection:"LIVE",classification:"CLEAR",execution:"READY",verification:"VERIFIED"}};
renderMonitor();
renderMonitor();
assert.equal(document.getElementById("heroTitle").textContent, "System Healthy");
assert.equal(document.getElementById("heroBadge").textContent, "HEALTHY");
assert.equal(document.getElementById("activeCount").textContent, "0 / 7");
assert.equal(document.getElementById("step3state").textContent, "READY");
assert.equal(document.getElementById("step4state").textContent, "VERIFIED");
console.log("PASS: healthy rendering and recovery status survive refreshes");
"""
        result = subprocess.run(
            [shutil.which("node"), "-e", harness + function + assertions],
            text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
