import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import dashboard_test


class DashboardRecoveryTests(unittest.TestCase):

    def test_successful_verified_recovery_is_reported(self):
        record = {
            "incident_key": "link_failure:s2-s3",
            "classification": "link_failure",
            "action": "restore_link",
            "status": "success",
            "verified": True,
        }

        with tempfile.TemporaryDirectory() as tmp:
            status_file = Path(tmp) / "recovery_status.json"
            status_file.write_text(json.dumps({
                "active_attempts": [record],
                "updated_at": "test",
            }))

            with mock.patch.object(
                dashboard_test,
                "RECOVERY_STATUS_FILE",
                status_file,
            ):
                result = dashboard_test.read_recovery_status()

        self.assertEqual(result["status"], "SUCCESS")
        self.assertIn("verified", result["detail"])

    def test_failed_recovery_is_reported(self):
        record = {
            "classification": "process_failure",
            "action": "restart_process",
            "status": "failed",
            "verified": False,
            "error": "Process restart failed",
        }

        with tempfile.TemporaryDirectory() as tmp:
            status_file = Path(tmp) / "recovery_status.json"
            status_file.write_text(json.dumps({
                "active_attempts": [record],
            }))

            with mock.patch.object(
                dashboard_test,
                "RECOVERY_STATUS_FILE",
                status_file,
            ):
                result = dashboard_test.read_recovery_status()

        self.assertEqual(result["status"], "FAILED")

    def test_missing_recovery_file_is_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            status_file = Path(tmp) / "missing_recovery_status.json"
            with mock.patch.object(
                dashboard_test,
                "RECOVERY_STATUS_FILE",
                status_file,
            ), mock.patch.object(
                dashboard_test,
                "check_service",
                return_value=False,
            ):
                result = dashboard_test.read_recovery_status()

        self.assertEqual(result["status"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main(verbosity=2)
