import power_control
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import recovery_executor as executor


class RecoveryExecutorTests(unittest.TestCase):

    def setUp(self):
        self.auto_recovery_patcher = mock.patch.dict(
            os.environ, {"ACN_ENABLE_AUTO_RECOVERY": "1"}
        )
        self.auto_recovery_patcher.start()
        self.tmp = tempfile.TemporaryDirectory()
        self.old_status = executor.STATUS_FILE
        executor.STATUS_FILE = Path(self.tmp.name) / "recovery_status.json"
        power_control.set_enabled(True, path=executor.STATUS_FILE.with_name("recovery_power.json"))
        executor.ACTIVE_ATTEMPTS = {}

    def tearDown(self):
        executor.STATUS_FILE = self.old_status
        executor.ACTIVE_ATTEMPTS = {}
        self.tmp.cleanup()
        self.auto_recovery_patcher.stop()

    def incident(self):
        return {
            "classification": "link_failure",
            "target": "s2-s3",
            "classification_confidence": 1.0,
            "detection_status": "detected",
            "incident_key": "link_failure:s2-s3",
        }

    def test_duplicate_active_incident_executes_once(self):
        item = self.incident()

        with mock.patch.object(
            executor, "execute_plan", return_value={"verified": True}
        ) as run:
            first = executor.execute_recoveries([item])
            second = executor.execute_recoveries([item])

        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        run.assert_called_once()

    def test_cleared_incident_can_be_attempted_again(self):
        item = self.incident()

        with mock.patch.object(
            executor, "execute_plan", return_value={"verified": True}
        ) as run:
            executor.execute_recoveries([item])
            executor.execute_recoveries([])
            again = executor.execute_recoveries([item])

        self.assertEqual(len(again), 1)
        self.assertEqual(run.call_count, 2)

    def test_failed_attempt_is_not_repeated_while_active(self):
        item = self.incident()

        with mock.patch.object(
            executor, "execute_plan",
            side_effect=RuntimeError("API unavailable")
        ) as run:
            first = executor.execute_recoveries([item])
            second = executor.execute_recoveries([item])

        self.assertEqual(first[0]["status"], "failed")
        self.assertEqual(second, [])
        run.assert_called_once()

    def test_low_confidence_is_rejected(self):
        item = self.incident()
        item["classification_confidence"] = 0.2

        with mock.patch.object(executor, "execute_plan") as run:
            result = executor.execute_recoveries([item])

        self.assertEqual(result, [])
        run.assert_not_called()

    def test_status_file_is_written(self):
        with mock.patch.object(
            executor, "execute_plan", return_value={"verified": True}
        ):
            executor.execute_recoveries([self.incident()])

        self.assertTrue(executor.STATUS_FILE.exists())
        data = json.loads(executor.STATUS_FILE.read_text())
        self.assertIn("active_attempts", data)

    def test_network_recovery_requires_healthy_api(self):
        with mock.patch.object(
            executor, "request_json", return_value=(503, {"ok": False})
        ):
            with self.assertRaises(RuntimeError):
                executor.execute_network_recovery("restore_link")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class RecoveryPersistenceTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_status = executor.STATUS_FILE
        self.old_attempts = executor.ACTIVE_ATTEMPTS
        executor.STATUS_FILE = Path(self.tmp.name) / "recovery_status.json"
        power_control.set_enabled(True, path=executor.STATUS_FILE.with_name("recovery_power.json"))
        executor.ACTIVE_ATTEMPTS = {}

    def tearDown(self):
        executor.STATUS_FILE = self.old_status
        executor.ACTIVE_ATTEMPTS = self.old_attempts
        self.tmp.cleanup()

    def test_attempts_load_after_restart(self):
        record = {
            "incident_key": "link_failure:s2-s3",
            "classification": "link_failure",
            "action": "restore_link",
            "status": "success",
            "verified": True,
        }

        executor.ACTIVE_ATTEMPTS = {
            record["incident_key"]: record
        }

        executor.save_status({
            "updated_at": "test",
            "active_attempts": [record],
            "attempt_count": 1,
        })

        restored = executor.load_attempts()

        self.assertIn("link_failure:s2-s3", restored)
        self.assertTrue(restored["link_failure:s2-s3"]["verified"])

    def test_failed_attempts_are_persisted(self):
        record = {
            "incident_key": "process_failure:h3",
            "classification": "process_failure",
            "action": "restart_process",
            "status": "failed",
            "verified": False,
        }

        executor.ACTIVE_ATTEMPTS = {
            record["incident_key"]: record
        }

        executor.save_status({
            "updated_at": "test",
            "active_attempts": [record],
            "attempt_count": 1,
        })

        restored = executor.load_attempts()

        self.assertEqual(
            restored["process_failure:h3"]["status"],
            "failed",
        )
