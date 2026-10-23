#!/usr/bin/env python3

import json
import os
from datetime import datetime, timezone

FAULT_LOG = "/tmp/faults.jsonl"

VALID_FAULT_TYPES = {
    "link_failure",
    "config_failure",
    "server_failure",
    "process_failure",
}


def report_fault(fault_type, target, detail):
    """Append one standardized fault record to the JSONL log."""

    if fault_type not in VALID_FAULT_TYPES:
        raise ValueError(f"Invalid fault type: {fault_type}")

    record = {
        "fault_type": fault_type,
        "target": str(target),
        "detail": str(detail),
        "detected_at": datetime.now(timezone.utc).isoformat(),
    }

    # Append safely, even when multiple detectors report concurrently.
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


if __name__ == "__main__":
    print("Fault reporting module loaded successfully.")
    print("Supported fault types:")
    for fault_type in sorted(VALID_FAULT_TYPES):
        print(f"  - {fault_type}")
