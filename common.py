#!/usr/bin/env python3
"""Shared fault-event schema and JSONL reporting.

Event fields (new records):
  event_id, detected_at, fault_type, target, detail, detection_status,
  classification, classification_confidence, explanation, incident_key

Historical lines may only contain fault_type, target, detail, detected_at.
"""

import json
import os
import uuid
from pathlib import Path
from datetime import datetime, timezone
from recovery_history import atomic_json

FAULT_LOG = str(Path(__file__).resolve().parent / "logs" / "faults.jsonl")
DETECTION_STATUS_FILE = str(
    Path(__file__).resolve().parent / "logs" / "detection_status.json"
)

# Historical identifiers kept for logs written before Phase 2.
LEGACY_FAULT_TYPES = {
    "link_failure",
    "config_failure",
    "server_failure",
    "process_failure",
}

# Phase 2 classification labels. server_failure is an alias of service_stopped.
CLASSIFICATION_LABELS = {
    "config_failure",
    "switch_config_failure",
    "link_failure",
    "service_stopped",
    "process_failure",
    "controller_disconnection",
    "path_failure",
    "unclassified",
}

VALID_FAULT_TYPES = set(LEGACY_FAULT_TYPES) | CLASSIFICATION_LABELS

SCENARIO_CLASSIFICATIONS = {
    "config": "config_failure",
    "switch": "switch_config_failure",
    "link": "link_failure",
    "service": "service_stopped",
    "process": "process_failure",
    "controller": "controller_disconnection",
    "path": "path_failure",
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def new_event_id():
    return uuid.uuid4().hex


def incident_key(classification, target):
    return f"{classification}:{target}"


def normalize_classification(fault_type):
    if fault_type == "server_failure":
        return "service_stopped"
    if fault_type in CLASSIFICATION_LABELS:
        return fault_type
    if fault_type in LEGACY_FAULT_TYPES:
        return fault_type
    return "unclassified"


def report_fault(fault_type, target, detail, **extra):
    """Append one standardized fault record to the JSONL log."""

    if fault_type not in VALID_FAULT_TYPES:
        raise ValueError(f"Invalid fault type: {fault_type}")

    classification = extra.pop("classification", None) or normalize_classification(
        fault_type
    )
    record = {
        "event_id": extra.pop("event_id", None) or new_event_id(),
        "fault_type": fault_type,
        "target": str(target),
        "detail": str(detail),
        "detected_at": extra.pop("detected_at", None) or utc_now(),
        "detection_status": extra.pop("detection_status", "detected"),
        "classification": classification,
        "classification_confidence": extra.pop("classification_confidence", None),
        "explanation": extra.pop("explanation", str(detail)),
        "incident_key": extra.pop(
            "incident_key", None
        ) or incident_key(classification, target),
    }
    record.update(extra)

    os.makedirs(os.path.dirname(FAULT_LOG), exist_ok=True)
    with open(FAULT_LOG, "a", encoding="utf-8") as log_file:
        import fcntl
        fcntl.flock(log_file.fileno(), fcntl.LOCK_EX)
        try:
            log_file.write(json.dumps(record) + "\n")
            log_file.flush()
            os.fsync(log_file.fileno())
        finally:
            fcntl.flock(log_file.fileno(), fcntl.LOCK_UN)

    print(f"[FAULT] {record['fault_type']} target={record['target']}")
    return record


def write_detection_status(payload):
    """Atomically replace the current detection snapshot (not a history log)."""
    atomic_json(DETECTION_STATUS_FILE, payload)


def read_detection_status():
    path = Path(DETECTION_STATUS_FILE)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except (OSError, ValueError, json.JSONDecodeError, TypeError):
        pass
    return None


if __name__ == "__main__":
    print("Fault reporting module loaded successfully.")
    print("Supported fault types:")
    for fault_type in sorted(VALID_FAULT_TYPES):
        print(f"  - {fault_type}")
