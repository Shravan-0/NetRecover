#!/usr/bin/env python3
"""Phase 2 classification, detection payload, and duplicate-incident tests."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import classify_fault
import common
import dashboard_test as dash
import detect_service


def evidence(**kwargs):
    base = {
        "health_unhealthy": False,
        "health_fresh": True,
        "service_config": "mode=ok",
        "service_running": True,
        "process_running": True,
        "switch_protocols": '["OpenFlow13"]',
        "switch_controller": classify_fault.EXPECTED_CONTROLLER,
        "controllers": {
            name: classify_fault.EXPECTED_CONTROLLER
            for name in ("s1", "s2", "s3", "s4", "s5")
        },
        "links": {"s2-s3": "up", "s3-s5": "up"},
    }
    base.update(kwargs)
    return base


def labels(results):
    return [item["classification"] for item in results]


class ClassifySevenCategoriesTests(unittest.TestCase):
    def test_config_failure(self):
        results = classify_fault.classify_evidence(evidence(
            health_unhealthy=True,
            service_config="mode=broken",
            service_running=True,
        ))
        self.assertEqual(labels(results), ["config_failure"])
        self.assertEqual(results[0]["target"], "h2:8080")
        self.assertEqual(results[0]["classification_confidence"], 1.0)

    def test_switch_config_failure(self):
        results = classify_fault.classify_evidence(evidence(
            switch_protocols="OpenFlow10",
            switch_controller="tcp:127.0.0.1:9999",
            controllers={
                "s1": classify_fault.EXPECTED_CONTROLLER,
                "s2": classify_fault.EXPECTED_CONTROLLER,
                "s3": classify_fault.EXPECTED_CONTROLLER,
                "s4": "tcp:127.0.0.1:9999",
                "s5": classify_fault.EXPECTED_CONTROLLER,
            },
        ))
        self.assertEqual(labels(results), ["switch_config_failure"])

    def test_link_failure(self):
        results = classify_fault.classify_evidence(evidence(
            links={"s2-s3": "down", "s3-s5": "up"},
        ))
        self.assertEqual(labels(results), ["link_failure"])
        self.assertEqual(results[0]["target"], "s2-s3")

    def test_service_stopped(self):
        results = classify_fault.classify_evidence(evidence(
            health_unhealthy=True,
            service_running=False,
            service_config="mode=ok",
        ))
        self.assertEqual(labels(results), ["service_stopped"])

    def test_process_failure(self):
        results = classify_fault.classify_evidence(evidence(
            process_running=False,
        ))
        self.assertEqual(labels(results), ["process_failure"])

    def test_controller_disconnection(self):
        wrong = "tcp:127.0.0.1:9999"
        results = classify_fault.classify_evidence(evidence(
            switch_controller=wrong,
            controllers={name: wrong for name in ("s1", "s2", "s3", "s4", "s5")},
        ))
        self.assertEqual(labels(results), ["controller_disconnection"])

    def test_path_failure(self):
        results = classify_fault.classify_evidence(evidence(
            links={"s2-s3": "up", "s3-s5": "down"},
        ))
        self.assertEqual(labels(results), ["path_failure"])

    def test_switch_and_controller_together(self):
        wrong = "tcp:127.0.0.1:9999"
        results = classify_fault.classify_evidence(evidence(
            switch_protocols="OpenFlow10",
            switch_controller=wrong,
            controllers={name: wrong for name in ("s1", "s2", "s3", "s4", "s5")},
        ))
        self.assertEqual(
            set(labels(results)),
            {"switch_config_failure", "controller_disconnection"},
        )


class ClassifyAmbiguityTests(unittest.TestCase):
    def test_unknown_evidence_is_unclassified(self):
        results = classify_fault.classify_evidence(evidence(
            health_unhealthy=True,
            service_running=True,
            service_config="mode=ok",
        ))
        self.assertEqual(labels(results), ["unclassified"])
        self.assertIn("not enough", results[0]["explanation"].lower())

    def test_health_only_without_process_or_config(self):
        results = classify_fault.classify_evidence({
            "health_unhealthy": True,
            "health_fresh": True,
        })
        self.assertEqual(labels(results), ["unclassified"])

    def test_non_mapping_evidence(self):
        results = classify_fault.classify_evidence(None)
        self.assertEqual(labels(results), ["unclassified"])

    def test_healthy_baseline_has_no_detections(self):
        results = classify_fault.classify_evidence(evidence())
        self.assertEqual(results, [])

    def test_empty_evidence_is_idle_not_detected(self):
        self.assertEqual(classify_fault.classify_evidence({}), [])

    def test_injection_config_without_health_failure_is_not_detected(self):
        results = classify_fault.classify_evidence(evidence(
            health_unhealthy=False,
            service_config="mode=broken",
        ))
        self.assertEqual(results, [])

    def test_log_server_failure_maps_to_service_stopped(self):
        mapped = classify_fault.classify_log_record({
            "fault_type": "server_failure",
            "target": "h2",
            "detail": "stopped",
        })
        self.assertEqual(mapped["classification"], "service_stopped")

    def test_status_payload_uses_running_not_injection_state(self):
        ev = {}
        classify_fault.apply_topology_payload(ev, {
            "ok": True,
            "id": "controller",
            "state": "fault",
            "controllers": {
                "s1": classify_fault.EXPECTED_CONTROLLER,
                "s2": classify_fault.EXPECTED_CONTROLLER,
                "s3": classify_fault.EXPECTED_CONTROLLER,
                "s4": classify_fault.EXPECTED_CONTROLLER,
                "s5": classify_fault.EXPECTED_CONTROLLER,
            },
        })
        results = classify_fault.classify_evidence(evidence(**ev))
        self.assertEqual(results, [])

    def test_malformed_log_record(self):
        mapped = classify_fault.classify_log_record("not-json-object")
        self.assertEqual(mapped["classification"], "unclassified")


class DetectServiceDedupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = Path(self.tmp.name) / "faults.jsonl"
        self.previous_log = common.FAULT_LOG
        common.FAULT_LOG = str(self.log)
        detect_service.active_incidents = {}

    def tearDown(self):
        common.FAULT_LOG = self.previous_log
        detect_service.active_incidents = {}
        self.tmp.cleanup()

    def test_duplicate_active_fault_is_recorded_once(self):
        results = classify_fault.classify_evidence(evidence(process_running=False))
        first = detect_service.sync_incidents(results)
        second = detect_service.sync_incidents(results)
        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        lines = self.log.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 1)

    def test_unclassified_is_not_written_to_history(self):
        results = classify_fault.classify_evidence({
            "health_unhealthy": True,
            "health_fresh": True,
        })
        detect_service.sync_incidents(results)
        self.assertFalse(self.log.exists())

    def test_cleared_fault_can_be_recorded_again(self):
        results = classify_fault.classify_evidence(evidence(process_running=False))
        detect_service.sync_incidents(results)
        detect_service.sync_incidents([])
        again = detect_service.sync_incidents(results)
        self.assertEqual(len(again), 1)
        lines = self.log.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 2)


class DashboardDetectionApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.status = Path(self.tmp.name) / "service_status.json"
        self.config = Path(self.tmp.name) / "service.conf"
        self.log = Path(self.tmp.name) / "faults.jsonl"
        self.config.write_text("mode=ok\n", encoding="utf-8")
        dash.STATUS_FILE = self.status
        dash.SERVICE_CONFIG = self.config
        dash.FAULT_LOG = self.log
        self.client = dash.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def test_healthy_baseline_when_health_is_fresh(self):
        self.status.write_text(json.dumps({
            "healthy": True,
            "checked_at": dash.datetime.now(dash.timezone.utc).isoformat(),
        }) + "\n", encoding="utf-8")
        with mock.patch.object(dash, "read_detection_status", return_value=None), \
             mock.patch.object(dash, "proxy_mininet", return_value=({"ok": False}, 503)):
            body = self.client.get("/api/status").get_json()
        self.assertTrue(body["service"]["healthy"])
        self.assertEqual(body["detection"]["status"], "healthy")
        self.assertEqual(body["detection"]["detected_count"], 0)

    def test_injected_config_without_detection_is_not_detected(self):
        self.config.write_text("mode=broken\n", encoding="utf-8")
        self.status.write_text(json.dumps({
            "healthy": True,
            "checked_at": dash.datetime.now(dash.timezone.utc).isoformat(),
        }) + "\n", encoding="utf-8")
        with mock.patch.object(dash, "read_detection_status", return_value=None), \
             mock.patch.object(dash, "proxy_mininet", return_value=({"ok": False}, 503)):
            body = self.client.get("/api/status").get_json()
        self.assertEqual(body["detection"]["detected_count"], 0)
        self.assertNotIn("config_failure", body["classification"]["labels"])

    def test_classification_from_detector_snapshot(self):
        snapshot = {
            "checked_at": dash.datetime.now(dash.timezone.utc).isoformat(),
            "engine": "detect_service",
            "observe_available": True,
            "active": [{
                "fault_type": "link_failure",
                "classification": "link_failure",
                "target": "s2-s3",
                "detected_at": "2026-10-29T00:00:00+00:00",
                "explanation": "Observed datapath interface for s2-s3 is down.",
                "detection_status": "detected",
            }],
        }
        with mock.patch.object(dash, "read_detection_status", return_value=snapshot):
            body = self.client.get("/api/status").get_json()
        self.assertEqual(body["detection"]["status"], "detected")
        self.assertEqual(body["detection"]["classified_count"], 1)
        self.assertTrue(body["classification"]["available"])
        self.assertEqual(body["classification"]["labels"], ["link_failure"])

    def test_stale_snapshot_falls_back_to_live_evidence(self):
        stale = {
            "checked_at": "2020-01-01T00:00:00+00:00",
            "engine": "detect_service",
            "active": [{"classification": "link_failure", "target": "s2-s3"}],
        }
        observe = {
            "ok": True,
            "service_running": False,
            "process_running": True,
            "switch": {
                "controller": classify_fault.EXPECTED_CONTROLLER,
                "protocols": '["OpenFlow13"]',
            },
            "controllers": {
                name: classify_fault.EXPECTED_CONTROLLER
                for name in ("s1", "s2", "s3", "s4", "s5")
            },
            "links": {"s2-s3": "up", "s3-s5": "up"},
        }
        self.status.write_text(json.dumps({
            "healthy": False,
            "checked_at": dash.datetime.now(dash.timezone.utc).isoformat(),
        }) + "\n", encoding="utf-8")
        with mock.patch.object(dash, "read_detection_status", return_value=stale), \
             mock.patch.object(dash, "proxy_mininet", return_value=(observe, 200)):
            body = self.client.get("/api/status").get_json()
        self.assertEqual(body["detection"]["source"], "live_eval")
        self.assertIn("service_stopped", body["classification"]["labels"])

    def test_malformed_status_and_log_are_safe(self):
        self.status.write_text("{not-json", encoding="utf-8")
        self.log.write_text(
            "{bad\n"
            "{\"fault_type\":\"config_failure\",\"target\":\"h2:8080\",\"detail\":\"x\","
            "\"detected_at\":\"2026-10-25T12:35:15.179015+00:00\"}\n",
            encoding="utf-8",
        )
        with mock.patch.object(dash, "read_detection_status", return_value=None), \
             mock.patch.object(dash, "proxy_mininet", return_value=({"ok": False}, 503)):
            response = self.client.get("/api/status")
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertFalse(body["service"]["healthy"])
        self.assertEqual(len(body["faults"]), 1)
        self.assertEqual(body["faults"][0]["classification"], "config_failure")
        self.assertIn(body["detection"]["status"], ("idle", "healthy"))

    def test_classification_unavailable_when_no_engine_and_no_health(self):
        with mock.patch.object(dash, "read_detection_status", return_value=None), \
             mock.patch.object(dash, "proxy_mininet", return_value=({"ok": False}, 503)), \
             mock.patch.object(dash, "check_service", return_value=False):
            body = self.client.get("/api/status").get_json()
        self.assertEqual(body["detection"]["detected_count"], 0)
        self.assertEqual(body["detection"]["status"], "idle")


class CommonEventFormatTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.previous = common.FAULT_LOG
        common.FAULT_LOG = str(Path(self.tmp.name) / "faults.jsonl")

    def tearDown(self):
        common.FAULT_LOG = self.previous
        self.tmp.cleanup()

    def test_report_fault_includes_phase2_fields(self):
        record = common.report_fault(
            "link_failure",
            "s2-s3",
            "down",
            classification="link_failure",
            explanation="interface down",
        )
        self.assertIn("event_id", record)
        self.assertEqual(record["detection_status"], "detected")
        self.assertEqual(record["classification"], "link_failure")
        stored = json.loads(Path(common.FAULT_LOG).read_text(encoding="utf-8"))
        self.assertEqual(stored["incident_key"], "link_failure:s2-s3")

    def test_legacy_type_still_accepted(self):
        record = common.report_fault("server_failure", "h2", "stopped")
        self.assertEqual(record["classification"], "service_stopped")


if __name__ == "__main__":
    unittest.main()
