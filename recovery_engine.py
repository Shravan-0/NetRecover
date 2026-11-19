#!/usr/bin/env python3
"""Allowlisted recovery decision engine.

This module plans recovery actions only.
It does not execute recovery automatically.
"""

from copy import deepcopy


RECOVERY_POLICIES = {
    "config_failure": {
        "action": "restore_service_config",
        "target": "h2:8080",
        "requires_mininet": False,
    },
    "switch_config_failure": {
        "action": "restore_switch_config",
        "target": "s4",
        "requires_mininet": True,
    },
    "link_failure": {
        "action": "restore_link",
        "target": "s2-s3",
        "requires_mininet": True,
    },
    "path_failure": {
        "action": "restore_path",
        "target": "s3-s5",
        "requires_mininet": True,
    },
    "service_stopped": {
        "action": "restart_service",
        "target": "h2:health_service",
        "requires_mininet": True,
    },
    "process_failure": {
        "action": "restart_process",
        "target": "h3:sleep-worker",
        "requires_mininet": True,
    },
    "controller_disconnection": {
        "action": "restore_controller",
        "target": "s1,s2,s3,s4,s5",
        "requires_mininet": True,
    },
}


def plan_recovery(incident):
    """Return a validated recovery plan, or None if unsafe/unsupported."""

    if not isinstance(incident, dict):
        return None

    classification = incident.get("classification")

    if classification not in RECOVERY_POLICIES:
        return None

    confidence = incident.get("classification_confidence")

    if (
        not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or not 0.80 <= confidence <= 1.0
    ):
        return None

    if incident.get("detection_status", "detected") != "detected":
        return None

    policy = deepcopy(RECOVERY_POLICIES[classification])

    return {
        "classification": classification,
        "action": policy["action"],
        "target": policy["target"],
        "requires_mininet": policy["requires_mininet"],
        "confidence": float(confidence),
        "status": "planned",
        "automatic_execution": False,
    }


def plan_recoveries(incidents):
    """Create plans for supported incidents, skipping unsafe entries."""

    if not isinstance(incidents, (list, tuple)):
        return []

    plans = []

    for incident in incidents:
        plan = plan_recovery(incident)
        if plan is not None:
            plans.append(plan)

    return plans
