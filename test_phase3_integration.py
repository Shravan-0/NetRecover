import power_control
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import recovery_executor as executor
import recovery_engine


class Phase3IntegrationTests(unittest.TestCase):

    def setUp(self):
        self.auto_recovery_patcher = mock.patch.dict(
            "os.environ", {"ACN_ENABLE_AUTO_RECOVERY": "1"}
        )
        self.auto_recovery_patcher.start()
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
        self.auto_recovery_patcher.stop()

    def incident(self, classification, target, key):
        return {
            "classification": classification,
            "target": target,
            "classification_confidence": 0.95,
            "detection_status": "detected",
            "incident_key": key,
        }

    def test_detection_to_recovery_plan(self):
        item = self.incident(
            "link_failure", "s2-s3", "link_failure:s2-s3"
        )

        plan = recovery_engine.plan_recovery(item)

        self.assertIsNotNone(plan)
        self.assertEqual(plan["action"], "restore_link")

    def test_recovery_result_is_persisted(self):
        item = self.incident(
            "link_failure", "s2-s3", "link_failure:s2-s3"
        )

        with mock.patch.object(
            executor,
            "execute_plan",
            return_value={"verified": True},
        ):
            result = executor.execute_recoveries([item])

        self.assertEqual(result[0]["status"], "success")

        saved = json.loads(executor.STATUS_FILE.read_text())
        self.assertEqual(saved["attempt_count"], 1)

    def test_failed_recovery_is_reported(self):
        item = self.incident(
            "process_failure",
            "h3:sleep-worker",
            "process_failure:h3",
        )

        with mock.patch.object(
            executor,
            "execute_plan",
            side_effect=RuntimeError("Test failure"),
        ):
            result = executor.execute_recoveries([item])

        self.assertEqual(result[0]["status"], "failed")
        self.assertFalse(result[0]["verified"])

    def test_independent_faults_are_both_planned(self):
        incidents = [
            self.incident(
                "switch_config_failure", "s4",
                "switch_config_failure:s4"
            ),
            self.incident(
                "controller_disconnection", "s1,s2,s3,s4,s5",
                "controller_disconnection:all"
            ),
        ]

        plans = recovery_engine.plan_recoveries(incidents)

        self.assertEqual(len(plans), 2)

    def test_recovery_action_allowlist(self):
        expected = {
            "restore_service_config",
            "restore_switch_config",
            "restore_link",
            "restore_path",
            "restart_service",
            "restart_process",
            "restore_controller",
        }

        self.assertEqual(
            set(executor.NETWORK_ACTIONS.keys()),
            expected,
        )

    def test_unknown_network_action_is_rejected(self):
        with self.assertRaises(RuntimeError):
            executor.execute_network_recovery("unknown_action")

    def test_duplicate_attempt_survives_reload(self):
        item = self.incident(
            "link_failure", "s2-s3", "link_failure:s2-s3"
        )

        with mock.patch.object(
            executor,
            "execute_plan",
            return_value={"verified": True},
        ) as run:
            executor.execute_recoveries([item])

            executor.ACTIVE_ATTEMPTS = executor.load_attempts()

            second = executor.execute_recoveries([item])

        self.assertEqual(second, [])
        run.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
