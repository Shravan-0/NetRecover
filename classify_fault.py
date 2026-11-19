#!/usr/bin/env python3
"""Map observed evidence to Phase 2 fault classifications.

This module does not read injection-button state. Callers must pass
signals that were actually observed (health results, OVS state, process
checks, interface state). Missing signals stay unknown instead of being
treated as healthy or faulty.
"""

from common import incident_key, new_event_id, utc_now

EXPECTED_CONTROLLER = "tcp:127.0.0.1:6633"
EXPECTED_PROTOCOL = "OpenFlow13"
FAULT_SWITCH = "s4"
LINK_FAILURE_ID = "s2-s3"
PATH_FAILURE_IDS = ("s3-s5",)

# Rule matches are deterministic; confidence is omitted unless a unique
# signature is present. None means "no meaningful numeric score".
UNIQUE_MATCH_CONFIDENCE = 1.0


def _text(value):
    if value is None:
        return ""
    return str(value)


def _protocol_ok(protocols):
    return EXPECTED_PROTOCOL.lower() in _text(protocols).lower()


def _controller_ok(controller):
    return EXPECTED_CONTROLLER in _text(controller)


def _link_down(links, link_id):
    if not isinstance(links, dict) or link_id not in links:
        return None
    state = _text(links.get(link_id)).lower()
    if state in ("down", "up"):
        return state == "down"
    return None


def _result(
    classification,
    target,
    explanation,
    evidence,
    confidence=None,
    fault_type=None,
):
    label = classification
    return {
        "event_id": new_event_id(),
        "fault_type": fault_type or classification,
        "target": str(target),
        "detail": explanation,
        "detected_at": utc_now(),
        "detection_status": "detected" if classification != "unclassified" else "unclassified",
        "classification": label,
        "classification_confidence": confidence,
        "explanation": explanation,
        "incident_key": incident_key(label, target),
        "evidence": evidence,
    }


def apply_topology_payload(evidence, payload):
    """Copy observable fields from Mininet API JSON. Ignore injection-only flags."""
    if not isinstance(evidence, dict) or not isinstance(payload, dict):
        return evidence
    if payload.get("ok") is False:
        return evidence
    if "service_running" in payload:
        evidence["service_running"] = payload.get("service_running")
    elif payload.get("id") == "service" and "running" in payload:
        evidence["service_running"] = bool(payload.get("running"))
    if "process_running" in payload and payload.get("id") != "controller":
        evidence["process_running"] = payload.get("process_running")
    elif payload.get("id") == "process" and "running" in payload:
        evidence["process_running"] = bool(payload.get("running"))
    for key in ("controller_process_running", "controller_port_listening", "controller_port_owned"):
        if payload.get(key) is True or payload.get(key) is False:
            evidence[key] = payload[key]
    if isinstance(payload.get("controller_connections"), dict):
        evidence["controller_connections"] = payload["controller_connections"]
    # /api/controller/status provides the same actual evidence in compatibility names.
    if payload.get("id") == "controller":
        for source, target in (("process_running", "controller_process_running"),
                               ("port_listening", "controller_port_listening"),
                               ("port_owned_by_expected_ryu", "controller_port_owned")):
            if payload.get(source) is True or payload.get(source) is False:
                evidence[target] = payload[source]
        if isinstance(payload.get("switch_connections"), dict):
            evidence["controller_connections"] = {
                name: row.get("is_connected") for name, row in payload["switch_connections"].items()
                if isinstance(row, dict)
            }
    nested_switch = payload.get("switch")
    if isinstance(nested_switch, dict):
        if nested_switch.get("protocols") is not None:
            evidence["switch_protocols"] = nested_switch.get("protocols")
        if nested_switch.get("controller") is not None:
            evidence["switch_controller"] = nested_switch.get("controller")
    elif payload.get("protocols") is not None and payload.get("controller") is not None:
        evidence["switch_protocols"] = payload.get("protocols")
        evidence["switch_controller"] = payload.get("controller")
    controllers = payload.get("controllers")
    if isinstance(controllers, dict):
        evidence["controllers"] = controllers
    links = payload.get("links")
    if isinstance(links, dict):
        observed = {
            name: str(value).lower()
            for name, value in links.items()
            if str(value).lower() in ("up", "down")
        }
        if observed:
            evidence["links"] = observed
    return evidence


def classify_evidence(evidence):
    """Return zero or more classification records from observed evidence.

    Expected evidence keys (all optional):
      health_unhealthy: bool
      health_fresh: bool
      service_config: str
      service_running: bool | None
      process_running: bool | None
      switch_protocols: str | None
      switch_controller: str | None
      controllers: dict[str, str] | None
      links: dict[str, "up"|"down"] | None
    """
    if not isinstance(evidence, dict):
        return [_result(
            "unclassified",
            "unknown",
            "Evidence was missing or not a mapping, so no category was assigned.",
            {"invalid_evidence": True},
        )]

    results = []
    health_unhealthy = bool(evidence.get("health_unhealthy"))
    health_fresh = evidence.get("health_fresh")
    service_config = evidence.get("service_config")
    service_running = evidence.get("service_running")
    process_running = evidence.get("process_running")
    protocols = evidence.get("switch_protocols")
    switch_controller = evidence.get("switch_controller")
    controllers = evidence.get("controllers")
    links = evidence.get("links")

    protocol_observed = protocols is not None
    protocol_bad = protocol_observed and not _protocol_ok(protocols)

    controllers_wrong = []
    if isinstance(controllers, dict) and controllers:
        controllers_wrong = [
            name for name, value in controllers.items()
            if not _controller_ok(value)
        ]
    elif switch_controller is not None:
        if not _controller_ok(switch_controller):
            controllers_wrong = [FAULT_SWITCH]

    other_wrong = [name for name in controllers_wrong if name != FAULT_SWITCH]
    s4_controller_bad = FAULT_SWITCH in controllers_wrong

    if protocol_bad:
        results.append(_result(
            "switch_config_failure",
            FAULT_SWITCH,
            (
                f"Switch {FAULT_SWITCH} OpenFlow protocol is "
                f"{protocols!r} instead of {EXPECTED_PROTOCOL}."
            ),
            {
                "switch_protocols": protocols,
                "switch_controller": switch_controller
                or (controllers or {}).get(FAULT_SWITCH),
            },
            confidence=UNIQUE_MATCH_CONFIDENCE,
        ))

    controller_disconnect = False
    if other_wrong:
        controller_disconnect = True
        target = ",".join(sorted(controllers_wrong))
        explanation = (
            "One or more switches besides s4 are not using "
            f"{EXPECTED_CONTROLLER}: {sorted(controllers_wrong)}."
        )
    elif s4_controller_bad and not protocol_bad and protocol_observed:
        controller_disconnect = True
        target = FAULT_SWITCH
        explanation = (
            f"Switch {FAULT_SWITCH} controller is "
            f"{(controllers or {}).get(FAULT_SWITCH, switch_controller)!r} "
            f"while the protocol is still {EXPECTED_PROTOCOL}."
        )
    elif s4_controller_bad and not protocol_observed and not other_wrong:
        # Controller-only evidence on s4 is ambiguous with switch config.
        results.append(_result(
            "unclassified",
            FAULT_SWITCH,
            (
                "s4 controller target is not the expected Ryu address, but the "
                "OpenFlow protocol was not observed, so switch configuration "
                "cannot be distinguished from controller disconnection."
            ),
            {"switch_controller": switch_controller, "controllers": controllers},
        ))

    actual_down = any(evidence.get(key) is False for key in (
        "controller_process_running", "controller_port_listening", "controller_port_owned"))
    connection_evidence = evidence.get("controller_connections", {})
    disconnected = [name for name, connected in connection_evidence.items()
                    if connected is False and not (name == FAULT_SWITCH and protocol_bad)]
    actual_disconnect = actual_down or bool(disconnected)
    if actual_disconnect:
        controller_disconnect = True
        target = "s1,s2,s3,s4,s5"
        explanation = ("Actual Ryu process/listener/ownership or OVS is_connected failure observed. "
                       "Disconnected switches: %s" % sorted(disconnected))
    if controller_disconnect:
        results.append(_result(
            "controller_disconnection",
            target,
            explanation,
            {"controllers": controllers or {FAULT_SWITCH: switch_controller},
             "controller_process_running": evidence.get("controller_process_running"),
             "controller_port_listening": evidence.get("controller_port_listening"),
             "controller_port_owned": evidence.get("controller_port_owned"),
             "controller_connections": connection_evidence},
            confidence=UNIQUE_MATCH_CONFIDENCE if other_wrong or actual_disconnect else None,
        ))

    link_down = _link_down(links, LINK_FAILURE_ID)
    if link_down is True:
        results.append(_result(
            "link_failure",
            LINK_FAILURE_ID,
            f"Observed datapath interface for {LINK_FAILURE_ID} is down.",
            {"links": {LINK_FAILURE_ID: "down"}},
            confidence=UNIQUE_MATCH_CONFIDENCE,
        ))

    path_hits = []
    if isinstance(links, dict):
        for path_id in PATH_FAILURE_IDS:
            if _link_down(links, path_id) is True:
                path_hits.append(path_id)
    if path_hits:
        results.append(_result(
            "path_failure",
            ",".join(path_hits),
            (
                "Observed primary path segment "
                f"{', '.join(path_hits)} is down; this is distinct from {LINK_FAILURE_ID}."
            ),
            {"links": {name: "down" for name in path_hits}},
            confidence=UNIQUE_MATCH_CONFIDENCE,
        ))

    if process_running is False:
        results.append(_result(
            "process_failure",
            "h3:sleep-worker",
            "Monitored process acn_fault_worker is not running on h3.",
            {"process_running": False},
            confidence=UNIQUE_MATCH_CONFIDENCE,
        ))

    if service_running is False:
        results.append(_result(
            "service_stopped",
            "h2:health_service",
            "health_service.py is not running on h2.",
            {"service_running": False},
            confidence=UNIQUE_MATCH_CONFIDENCE,
            fault_type="service_stopped",
        ))
    elif health_unhealthy and health_fresh is not False:
        config_text = _text(service_config).strip()
        if service_running is True and config_text and config_text != "mode=ok":
            results.append(_result(
                "config_failure",
                "h2:8080",
                (
                    "Health endpoint is unhealthy while the health service is "
                    f"running and configuration is {config_text!r}."
                ),
                {
                    "health_unhealthy": True,
                    "service_running": True,
                    "service_config": config_text,
                },
                confidence=UNIQUE_MATCH_CONFIDENCE,
            ))
        elif (service_running is True and config_text == "mode=ok"
              and evidence.get("health_local_probe_failed") is True):
            results.append(_result(
                "service_stopped", "h2:health_service",
                "h2-local health-probe API confirmed failure with mode=ok; service process is present but unhealthy.",
                {"health_local_probe_failed": True, "service_running": True, "service_config": config_text},
                confidence=UNIQUE_MATCH_CONFIDENCE, fault_type="service_stopped",
            ))
        elif service_running is True and config_text == "mode=ok":
            results.append(_result(
                "unclassified",
                "h2:8080",
                (
                    "Health endpoint is unhealthy while the process is running "
                    "and configuration is mode=ok. This is not enough to choose "
                    "among config, path, and service faults."
                ),
                {
                    "health_unhealthy": True,
                    "service_running": True,
                    "service_config": config_text,
                },
            ))
        elif config_text and config_text != "mode=ok":
            results.append(_result(
                "config_failure",
                "h2:8080",
                (
                    "Health endpoint is unhealthy and /tmp/service.conf is "
                    f"{config_text!r}. The health-service process was not observed."
                ),
                {
                    "health_unhealthy": True,
                    "service_config": config_text,
                    "service_running": service_running,
                },
            ))
        else:
            results.append(_result(
                "unclassified",
                "h2:8080",
                (
                    "Health endpoint is unhealthy, but the service process and "
                    "configuration were not observed together, so config_failure "
                    "cannot be distinguished from service_stopped."
                ),
                {
                    "health_unhealthy": True,
                    "service_config": service_config,
                    "service_running": service_running,
                },
            ))

    if not results and not any(
        value not in (None, {}, "", False)
        for key, value in (evidence or {}).items()
        if key not in ("health_fresh",)
    ) and not health_unhealthy:
        return []

    return results


def classify_log_record(record):
    """Classify a stored JSONL record using its own fields, not injection UI state."""
    if not isinstance(record, dict):
        return _result(
            "unclassified",
            "unknown",
            "Log record was not an object.",
            {"malformed": True},
        )

    existing = record.get("classification")
    fault_type = record.get("fault_type")
    if existing in {"config_failure", "switch_config_failure", "link_failure",
                    "service_stopped", "process_failure", "controller_disconnection",
                    "path_failure", "unclassified"}:
        classification = existing
    elif fault_type == "server_failure":
        classification = "service_stopped"
    elif fault_type in {
        "config_failure", "link_failure", "process_failure",
        "switch_config_failure", "controller_disconnection", "path_failure",
        "service_stopped",
    }:
        classification = fault_type
    else:
        classification = "unclassified"

    target = record.get("target") or "unknown"
    detail = record.get("detail") or record.get("explanation") or ""
    explanation = record.get("explanation") or detail or (
        "No supporting evidence was stored with this log record."
        if classification == "unclassified"
        else f"Stored fault_type {fault_type!r} mapped to {classification}."
    )
    return {
        "event_id": record.get("event_id") or new_event_id(),
        "fault_type": fault_type or classification,
        "target": str(target),
        "detail": detail,
        "detected_at": record.get("detected_at") or utc_now(),
        "detection_status": record.get("detection_status") or "detected",
        "classification": classification,
        "classification_confidence": record.get("classification_confidence"),
        "explanation": explanation,
        "incident_key": record.get("incident_key") or incident_key(classification, target),
    }


def summarize_classifications(results):
    classified = [
        item for item in results
        if item.get("classification") and item.get("classification") != "unclassified"
    ]
    return {
        "detected_count": len(results),
        "classified_count": len(classified),
        "labels": [item.get("classification") for item in results],
    }
