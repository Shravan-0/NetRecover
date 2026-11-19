#!/usr/bin/env python3
"""Host-side allowlisted recovery execution with deduplication and verification."""

import json
import fcntl
import os
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import power_control
from recovery_engine import plan_recovery
from recovery_history import History, atomic_json

BASE_DIR = Path(__file__).resolve().parent
TOKEN_FILE = BASE_DIR / "recovery.token"
STATUS_FILE = BASE_DIR / "logs" / "recovery_status.json"

RECOVERY_URL = "http://10.0.0.2:8090/recover"
MININET_API = "http://127.0.0.1:8765"

LOCK = threading.Lock()
def load_attempts():
    """Load previously recorded recovery attempts after restart."""
    try:
        data = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
        records = data.get("active_attempts", [])
        if not isinstance(records, list):
            return {}
        return {
            item["incident_key"]: item
            for item in records
            if isinstance(item, dict) and item.get("incident_key")
        }
    except (OSError, ValueError, TypeError):
        return {}


ACTIVE_ATTEMPTS = load_attempts()


NETWORK_ACTIONS = {
    "restore_service_config": {"post": "/api/recovery/config", "verify": "/api/health-probe", "kind": "config"},
    "restore_switch_config": {
        "post": "/api/recovery/switch",
        "verify": "/api/switch/status",
        "kind": "switch",
    },
    "restore_link": {
        "post": "/api/recovery/link",
        "verify": "/api/link/status",
        "kind": "link",
    },
    "restore_path": {
        "post": "/api/recovery/path",
        "verify": "/api/path/status",
        "kind": "path",
    },
    "restart_service": {
        "post": "/api/recovery/service",
        "verify": "/api/service/status",
        "kind": "service",
    },
    "restart_process": {
        "post": "/api/recovery/process",
        "verify": "/api/process/status",
        "kind": "process",
    },
    "restore_controller": {
        "post": "/api/recovery/controller",
        "verify": "/api/controller/status",
        "kind": "controller",
    },
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def save_status(data):
    atomic_json(STATUS_FILE, data)


def request_json(url, method="GET", payload=None, headers=None, timeout=4):
    body = None
    request_headers = dict(headers or {})

    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        request_headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        url,
        data=body,
        headers=request_headers,
        method=method,
    )

    try:
        response = urllib.request.urlopen(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        raw = response.read().decode("utf-8").strip()
        return response.status, json.loads(raw) if raw else {}


def verify_network_action(action, data):
    if not isinstance(data, dict) or not data.get("ok"):
        return False

    if action == "restore_link":
        return data.get("state") == "up"

    if action == "restore_path":
        return data.get("state") == "ok"

    if action == "restore_switch_config":
        return data.get("state") == "ok"

    if action == "restart_service":
        return data.get("running") is True

    if action == "restart_process":
        return data.get("running") is True

    if action == "restore_controller":
        return data.get("state") == "ok"

    return False


def execute_config_recovery(incident_id=None):
    # Configuration uses the same claimed, power-gated root boundary as every policy.
    return execute_network_recovery("restore_service_config", incident_id=incident_id)


def execute_network_recovery(action, incident_id=None):
    policy = NETWORK_ACTIONS.get(action)
    if policy is None:
        raise RuntimeError("Action is not allowlisted")

    # Preflight: never execute network recovery without a live topology API.
    status, health = request_json(
        MININET_API + "/health",
        timeout=3,
    )
    if status != 200 or health.get("ok") is not True:
        raise RuntimeError("Mininet control API is not healthy")

    guarded = {
        "restore_link": ("alternate_link_v1", "/api/recovery/link"),
        "restore_service_config": ("classified_recovery_v3", "/api/recovery/config"),
        "restore_switch_config": ("classified_recovery_v3", "/api/recovery/switch"),
        "restore_path": ("classified_recovery_v3", "/api/recovery/path"),
        "restart_process": ("classified_recovery_v3", "/api/recovery/process"),
        "restart_service": ("namespace_service_v1", "/api/recovery/service"),
        "restore_controller": ("owned_controller_v1", "/api/recovery/controller"),
    }
    if action in guarded:
        capability, endpoint = guarded[action]
        if capability not in health.get("recovery_capabilities", []):
            raise RuntimeError("Running topology lacks %s; no legacy fallback executed" % capability)
        if not automatic_recovery_enabled():
            raise RuntimeError("Automatic recovery is disabled")
        if not incident_id:
            raise RuntimeError("Durable incident claim required")
        token = TOKEN_FILE.read_text(encoding="utf-8").strip()
        if not token:
            raise RuntimeError("Recovery token unavailable")
        code, result = request_json(
            MININET_API + endpoint, method="POST",
            payload={"incident_id": incident_id},
            headers={"X-Recovery-Token": token}, timeout=360,
        )
        if code != 200:
            raise RuntimeError("Recovery endpoint rejected request (%s)" % code)
        if action == "restart_service" and result.get("verified") is True:
            # Independently verify through the actual public Mininet health-probe API.
            probe_code, probe = request_json(MININET_API + "/api/health-probe", timeout=6)
            result = dict(result)
            result["verification"] = dict(result.get("verification", {}), api_health_probe=probe,
                                          api_health_probe_http_status=probe_code)
            if not (probe_code == 200 and probe.get("healthy") is True
                    and str(probe.get("http_status")) == "200"):
                result.update(ok=False, verified=False, recovery_status="FAILED",
                              failure_reason="Independent Mininet health-probe API did not return healthy HTTP 200")
        return result

    raise RuntimeError("No guarded route; legacy mutation is forbidden")


def execute_plan(plan):
    if not automatic_recovery_enabled():
        raise RuntimeError("Automatic recovery is disabled")
    action = plan["action"]

    if action == "restore_service_config":
        return execute_config_recovery(incident_id=plan.get("incident_id"))

    return execute_network_recovery(action, incident_id=plan.get("incident_id"))


def automatic_recovery_enabled():
    """The persistent shared gate is authoritative; environment cannot override OFF."""
    return power_control.is_enabled(STATUS_FILE.with_name("recovery_power.json"))


def execute_recoveries(incidents, observation_complete=True):
    """Record regardless of gate, claim durably, and never turn an ACK into success.

    ACTIVE_ATTEMPTS is compatibility-only. SQLite controls deduplication across restarts.
    A file lock serializes automatic network operations across detector processes.
    """
    global ACTIVE_ATTEMPTS
    if not isinstance(incidents, (list, tuple)):
        return []
    outcomes = []
    with LOCK:
        store = History(STATUS_FILE.with_name("recovery_history.sqlite3"))
        store.import_legacy(STATUS_FILE)
        store.reconcile()
        enabled = automatic_recovery_enabled()
        observed = store.observe(incidents, enabled, complete=observation_complete)
        store.export(STATUS_FILE)
        if not enabled:
            return []
        lock_path = STATUS_FILE.with_name("recovery_execution.lock")
        with lock_path.open("a") as process_lock:
            try:
                fcntl.flock(process_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return []
            try:
                for iid, incident in observed:
                    plan = plan_recovery(incident)
                    if plan is None or not automatic_recovery_enabled():
                        continue
                    try:
                        permission = power_control.execution_permit(STATUS_FILE.with_name("recovery_power.json"))
                        permit = permission.__enter__()
                    except power_control.PowerDisabled:
                        break
                    try:
                        plan = dict(plan, power_revision=permit["revision"])
                        claim = store.claim(iid, plan, True)
                        if claim is None:
                            continue
                        plan = dict(plan, incident_id=iid, attempt_id=claim["attempt_id"])
                        store.export(STATUS_FILE)
                        try:
                            # The root endpoint independently checks the gate immediately before mutation.
                            result = execute_plan(plan)
                            if not isinstance(result, dict):
                                raise ValueError("Recovery returned invalid verification evidence")
                            verified = result.get("verified") is True
                            state = "RECOVERED" if verified else result.get("recovery_status", "UNVERIFIED")
                            if state not in {"RECOVERED", "FAILED", "UNVERIFIED"} or (state == "RECOVERED" and not verified):
                                state = "UNVERIFIED"
                            record = store.finish(iid, state, result=result,
                                                  reason=None if verified else result.get("failure_reason", "Real verification was not confirmed"))
                        except Exception as exc:
                            # A timed-out response can conceal an applied action: never replay it automatically.
                            ambiguous = isinstance(exc, (urllib.error.URLError, TimeoutError, ConnectionError, ValueError, OSError))
                            record = store.finish(iid, "UNVERIFIED" if ambiguous else "FAILED", reason=str(exc))
                        outcomes.append(record)
                        store.export(STATUS_FILE)
                        print("[RECOVERY %s] %s" % (record["recovery_status"], record["classification"]), flush=True)
                    finally:
                        permission.__exit__(None, None, None)
            finally:
                fcntl.flock(process_lock.fileno(), fcntl.LOCK_UN)
        store.export(STATUS_FILE)
        ACTIVE_ATTEMPTS = load_attempts()
    return outcomes
