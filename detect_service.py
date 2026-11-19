#!/usr/bin/env python3
"""Observe health and topology signals, classify faults, and record incidents.

Recovery is opt-in. Incidents are persisted even when automatic recovery is OFF.
"""

import json
import power_control
import time
import urllib.error
import urllib.request
from pathlib import Path
import os
from datetime import datetime, timezone

from classify_fault import (
    apply_topology_payload,
    classify_evidence,
    summarize_classifications,
)
from recovery_executor import execute_recoveries, automatic_recovery_enabled
from recovery_history import atomic_json

from common import (
    DETECTION_STATUS_FILE,
    report_fault,
    utc_now,
    write_detection_status,
)

SERVICE_URL = "http://127.0.0.1:8765/api/health-probe"
RECOVERY_URL = "http://10.0.0.2:8090/recover"
MININET_API = "http://127.0.0.1:8765"
OBSERVE_URL = MININET_API + "/api/observe"
STATUS_URLS = (
    MININET_API + "/api/switch/status",
    MININET_API + "/api/controller/status",
    MININET_API + "/api/service/status",
    MININET_API + "/api/process/status",
)
SERVICE_CONFIG = Path("/tmp/service.conf")
BASE_DIR = Path(__file__).resolve().parent
TOKEN_FILE = BASE_DIR / "recovery.token"
STATUS_FILE = BASE_DIR / "logs" / "service_status.json"

CHECK_INTERVAL = 1
FAILURES_REQUIRED = 2
RECOVERY_WAIT = 1

consecutive_failures = 0
fault_reported = False
active_incidents = {}
latest_health_probe = None


def check_health():
    global latest_health_probe
    latest_health_probe = None
    try:
        try:
            response = urllib.request.urlopen(SERVICE_URL, timeout=4)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            data = json.loads(response.read().decode("utf-8"))
            if isinstance(data, dict) and data.get("target") == "h2:8080":
                latest_health_probe = dict(data, api_http_status=response.status)
                return (response.status == 200 and data.get("healthy") is True
                        and str(data.get("http_status")) == "200")
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        pass
    return False


def write_status(healthy):
    atomic_json(STATUS_FILE, {
        "healthy": bool(healthy),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    })


def read_service_config():
    try:
        return SERVICE_CONFIG.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def fetch_json(url, timeout=2):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
        if isinstance(data, dict):
            return data
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        return None
    return None


def fetch_observe():
    data = fetch_json(OBSERVE_URL)
    if data and data.get("ok"):
        return data
    combined = {"ok": True, "fallback": True}
    got = False
    for url in STATUS_URLS:
        payload = fetch_json(url)
        if payload and payload.get("ok"):
            apply_topology_payload(combined, payload)
            got = True
    return combined if got else None


def build_evidence(healthy, observe):
    evidence = {
        "health_unhealthy": not bool(healthy),
        "health_fresh": True,
        "service_config": read_service_config(),
        "health_local_probe_failed": bool(latest_health_probe
                                          and latest_health_probe.get("api_http_status") == 503
                                          and latest_health_probe.get("healthy") is False),
    }
    if observe:
        apply_topology_payload(evidence, observe)
    return evidence


def request_recovery():
    """Retired bypass: classified recovery must use execute_recoveries and durable claims."""
    return False


def publish_snapshot(healthy, observe, results, observe_error=False):
    summary = summarize_classifications(results)
    snapshot = {
        "checked_at": utc_now(),
        "engine": "detect_service",
        "power_revision": power_control.raw_state()["revision"],
        "detector_pid": os.getpid(),
        "automatic_recovery_enabled": automatic_recovery_enabled(),
        "healthy": bool(healthy),
        "observe_available": bool(observe),
        "observe_error": bool(observe_error),
        "active": [
            {key: value for key, value in item.items() if key != "evidence"}
            for item in results
        ],
        "detected_count": summary["detected_count"],
        "classified_count": summary["classified_count"],
        "status_file": str(STATUS_FILE),
        "detection_status_file": DETECTION_STATUS_FILE,
    }
    write_detection_status(snapshot)
    return snapshot


def sync_incidents(results):
    """Record a JSONL incident once per continuously active classification+target."""
    global active_incidents
    seen = set()
    recorded = []
    for item in results:
        key = item.get("incident_key")
        if not key or item.get("classification") == "unclassified":
            continue
        seen.add(key)
        if key in active_incidents:
            item["event_id"] = active_incidents[key]
            continue
        record = report_fault(
            item.get("fault_type") or item.get("classification"),
            item.get("target"),
            item.get("detail"),
            event_id=item.get("event_id"),
            classification=item.get("classification"),
            classification_confidence=item.get("classification_confidence"),
            explanation=item.get("explanation"),
            incident_key=key,
            detection_status=item.get("detection_status", "detected"),
        )
        active_incidents[key] = record["event_id"]
        recorded.append(record)
    active_incidents = {
        key: event_id
        for key, event_id in active_incidents.items()
        if key in seen
    }
    return recorded


if __name__ == "__main__":
    print(f"[MONITOR] Monitoring {SERVICE_URL}", flush=True)
    print("[MONITOR] Classification enabled; topology observe at %s" % OBSERVE_URL, flush=True)

    while True:
        healthy = check_health()
        write_status(healthy)
        if healthy:
            consecutive_failures = 0
            if fault_reported:
                print("[HEALTHY] Service recovered", flush=True)
                fault_reported = False
        else:
            consecutive_failures += 1
            print(
                f"[UNHEALTHY] Consecutive failures: {consecutive_failures}",
                flush=True,
            )

        # Debounce health-based classification; topology signals are used as observed.
        health_unhealthy = consecutive_failures >= FAILURES_REQUIRED
        observe = fetch_observe()
        evidence = build_evidence(not health_unhealthy, observe)
        if not healthy and not health_unhealthy:
            evidence["health_unhealthy"] = False
        results = classify_evidence(evidence)
        sync_incidents(results)
        publish_snapshot(healthy, observe, results, observe_error=observe is None)

        # Persist before execution; partial/missing observations must not clear incidents.
        try:
            recovery_outcomes = execute_recoveries(
                results,
                observation_complete=bool(observe and not observe.get("fallback")
                                          and (healthy or health_unhealthy)),
            )
        except Exception as exc:
            # History unavailable/corrupt: fail closed, but keep detecting/classifying.
            print("[RECOVERY BLOCKED] History/executor error: %s" % exc, flush=True)
            recovery_outcomes = []

        for outcome in recovery_outcomes:
            print(
                "[RECOVERY %s] %s"
                % (
                    "VERIFIED" if outcome.get("verified") else "FAILED",
                    outcome.get("classification"),
                ),
                flush=True,
            )

        if any(
            item.get("classification") == "config_failure"
            and item.get("status") == "success"
            for item in recovery_outcomes
        ):
            time.sleep(RECOVERY_WAIT)
            if check_health():
                consecutive_failures = 0
                print("[RECOVERY VERIFIED] Service is healthy", flush=True)
            else:
                print("[RECOVERY FAILED] Service remains unhealthy", flush=True)

        time.sleep(CHECK_INTERVAL)
