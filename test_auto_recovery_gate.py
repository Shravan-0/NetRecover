from test_power_support import temporary_gate
import power_control
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import recovery_executor as executor
import dashboard_test as dashboard


INCIDENT = {
    "incident_key": "link_failure:s2-s3",
    "classification": "link_failure",
    "target": "s2-s3",
    "classification_confidence": 0.95,
    "detection_status": "detected",
}


class ExecutorSafetyGateTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.object(executor, "STATUS_FILE", Path(self.tmp.name) / "recovery_status.json")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_unset_environment_disables_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            status_file = Path(tmp) / "recovery_status.json"

            with mock.patch.dict(os.environ):
                os.environ.pop("ACN_ENABLE_AUTO_RECOVERY", None)

                with mock.patch.dict(executor.ACTIVE_ATTEMPTS, {}, clear=True), \
                     mock.patch.object(executor, "STATUS_FILE", status_file), \
                     mock.patch.object(executor, "execute_plan") as run_plan:

                    result = executor.execute_recoveries([INCIDENT])

            self.assertEqual(result, [])
            run_plan.assert_not_called()
            self.assertTrue(status_file.exists())
            saved = json.loads(status_file.read_text())
            self.assertEqual(saved["attempt_count"], 0)
            self.assertEqual(saved["incidents"][0]["status"], "CLASSIFIED")
            self.assertFalse(saved["incidents"][0]["automatic_recovery_enabled"])

    def test_explicit_zero_disables_recovery(self):
        with temporary_gate(False), \
             mock.patch.dict(executor.ACTIVE_ATTEMPTS, {}, clear=True), \
             mock.patch.object(executor, "execute_plan") as run_plan:

            result = executor.execute_recoveries([INCIDENT])

        self.assertEqual(result, [])
        run_plan.assert_not_called()

    def test_explicit_one_allows_recovery_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            status_file = Path(tmp) / "recovery_status.json"

            with temporary_gate(True, status_file), \
                 mock.patch.dict(executor.ACTIVE_ATTEMPTS, {}, clear=True), \
                 mock.patch.object(executor, "STATUS_FILE", status_file), \
                 mock.patch.object(
                     executor, "execute_plan", return_value={"ok": True, "verified": True}
                 ) as run_plan:

                result = executor.execute_recoveries([INCIDENT])

            run_plan.assert_called_once()
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["status"], "success")
            self.assertTrue(result[0]["verified"])

            saved = json.loads(status_file.read_text(encoding="utf-8"))
            self.assertEqual(saved["attempt_count"], 1)


class DashboardSafetyStatusTests(unittest.TestCase):

    def get_status(self, detection_payload, environment_value):
        with mock.patch.dict(
            os.environ,
            {"ACN_ENABLE_AUTO_RECOVERY": environment_value}
        ), mock.patch.object(
            dashboard, "read_faults", return_value=[]
        ), mock.patch.object(
            dashboard, "read_recovery_status",
            return_value={"status": "UNKNOWN", "detail": "No recovery yet."}
        ), mock.patch.object(
            dashboard, "build_detection_payload",
            return_value=detection_payload
        ), mock.patch.object(
            dashboard, "check_service", return_value=False
        ):
            response = dashboard.app.test_client().get("/api/status")

        self.assertEqual(response.status_code, 200)
        return response.get_json()["automatic_recovery"]

    def test_dashboard_uses_detector_published_gate_state(self):
        result = self.get_status(
            {
                "engine": "detect_service",
                "classified_count": 0,
                "active": [],
                "automatic_recovery_enabled": True,
            },
            "0",
        )

        self.assertTrue(result["enabled"])
        self.assertEqual(result["source"], "detector_snapshot")

    def test_dashboard_falls_back_to_disabled_environment(self):
        result = self.get_status(
            {
                "engine": "none",
                "classified_count": 0,
                "active": [],
            },
            "0",
        )

        self.assertFalse(result["enabled"])
        self.assertEqual(result["source"], "dashboard_environment")


if __name__ == "__main__":
    unittest.main(verbosity=2)
