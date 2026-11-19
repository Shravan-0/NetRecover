"""Independent, read-only system checks and freshness rules. No activity on import."""
from datetime import datetime, timezone
import os
import json
from pathlib import Path
import threading
import time

from link_recovery import ping_pair
from recovery_verification import connectivity, http_probe

MAX_AGE = 45


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def age_seconds(stamp, now=None):
    try:
        when = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
        if when.tzinfo is None:
            return None
        return ((now or datetime.now(timezone.utc)) - when).total_seconds()
    except (AttributeError, ValueError, TypeError):
        return None


def fresh(stamp, limit=MAX_AGE, now=None):
    age = age_seconds(stamp, now)
    return age is not None and 0 <= age <= limit


def worker_pids(network, proc_root=Path('/proc')):
    """Identify the exact worker executable/arguments inside CURRENT h3, not a pidfile."""
    host = network.get('h3')
    namespace = os.readlink(str(proc_root / str(host.pid) / 'ns/net'))
    found = []
    for item in proc_root.iterdir():
        if not item.name.isdigit():
            continue
        try:
            args = item.joinpath('cmdline').read_bytes().split(b'\0')
            args = [os.fsdecode(arg) for arg in args if arg]
            if args != ['acn_fault_worker', '86400']:
                continue
            if os.readlink(str(item / 'ns/net')) != namespace:
                continue
            if Path(os.readlink(str(item / 'exe'))).name != 'sleep':
                continue
            found.append(int(item.name))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return sorted(found)


def switch_configuration_ok(row):
    protocols = row.get('protocols', '')
    try:
        parsed = json.loads(protocols) if isinstance(protocols, str) and protocols.startswith('[') else [protocols]
    except ValueError:
        # ovs-vsctl emits OVSDB string sets as [OpenFlow13], not necessarily JSON.
        parsed = ['OpenFlow13'] if protocols.strip() == '[OpenFlow13]' else []
    return parsed == ['OpenFlow13'] and row.get('controller', '').splitlines() == ['tcp:127.0.0.1:6633']


def collect_health(network, controller, service, switch, edges, workers,
                   config=Path('/tmp/service.conf'), ping=ping_pair, probe=http_probe):
    # All checks are independent of injection flags and old recovery records.
    started = utc_now()
    controllers = controller()
    service_state = service()
    sw = switch()
    edge_states = edges()
    pids = workers()
    config_ok = config.read_text().strip() == 'mode=ok'
    network_check = connectivity(network.hosts, ping, timeout=12)
    http = [probe(host, 'http://127.0.0.1:8080/health' if host.name == 'h2'
                  else 'http://10.0.0.2:8080/health') for host in sorted(network.hosts, key=lambda h: h.name)]
    connections = controllers.get('switch_connections', {})
    checks = dict(
        connectivity=network_check.get('verified') is True,
        service_http=len(http) == 8 and all(row.get('passed') is True for row in http),
        service_namespace=service_state.get('healthy') is True and bool(service_state.get('service_pids')),
        controller=controllers.get('runtime', controllers).get('healthy') is True and len(connections) == 5
                   and all(row.get('is_connected') is True for row in connections.values()),
        switch_config=switch_configuration_ok(sw),
        service_config=config_ok,
        process_namespace=len(pids) == 1,
        path=edge_states.get('s3-s5') == 'up',
        # A failed primary edge may remain isolated while a VERIFIED alternate route carries traffic.
        primary_link_known=edge_states.get('s2-s3') in ('up', 'down'),
    )
    verified = all(checks.values())
    return dict(ok=True, verified=verified, state='HEALTHY' if verified else 'UNHEALTHY',
                probe_started_at=started, checked_at=utc_now(), checks=checks,
                evidence=dict(connectivity=network_check, http=http, controller=controllers,
                              service=service_state, switch=sw, links=edge_states, worker_pids=pids),
                source='independent_live_probes', max_age_seconds=MAX_AGE)


class HealthCache:
    """Only the topology worker probes; browser requests read a fast cached snapshot."""
    def __init__(self):
        self.lock = threading.Lock()
        self.value = dict(ok=False, verified=False, state='UNKNOWN', error='No completed independent check yet')

    def get(self):
        with self.lock:
            result = dict(self.value)
        result['fresh'] = fresh(result.get('checked_at'))
        if not result['fresh']:
            result.update(verified=False, state='UNKNOWN')
        return result

    def invalidate(self):
        with self.lock:
            self.value = dict(ok=False, verified=False, state='VERIFYING',
                              error='Recovery action completed; waiting for a new independent check')

    def run(self, collect, network_lock, stopped, interval=10):
        while not stopped.is_set():
            try:
                with network_lock:
                    result = collect()
                # Never stamp an obsolete sweep as a fresh successful check.
                if not fresh(result.get('probe_started_at')):
                    result.update(verified=False, state='UNKNOWN', error='Probe sweep took too long')
            except Exception as exc:
                result = dict(ok=False, verified=False, state='UNKNOWN', checked_at=utc_now(), error=str(exc))
            with self.lock:
                self.value = result
            stopped.wait(interval)


def build_monitor(detection, recovery, health, power, now=None):
    detected_fresh = fresh(detection.get('checked_at'), 15, now)
    observing = detected_fresh and detection.get('engine') == 'detect_service' and detection.get('observe_available') is True and not detection.get('observe_error')
    verified_fresh = (health.get('ok') is True and health.get('verified') is True
                      and health.get('source') == 'independent_live_probes'
                      and fresh(health.get('checked_at'), MAX_AGE, now)
                      and bool(health.get('checks')) and all(v is True for v in health['checks'].values()))
    history_ready = isinstance(recovery.get('incidents'), list) and isinstance(recovery.get('attempts'), list)
    active = detection.get('active') or []
    attempts = recovery.get('attempts') or []
    incidents = recovery.get('incidents') or []
    running = power.get('in_flight') or any(row.get('recovery_status', row.get('status')) == 'RECOVERING'
                                           for row in incidents if row.get('active'))
    latest = attempts[-1] if attempts else None
    # A live primary-link fault is only mitigated by its own active verified incident,
    # never by an unrelated or already-cleared historical recovery.
    mitigated = []
    unresolved = []
    for fault in active:
        matching = [row for row in incidents if row.get('active') and row.get('classification') == fault.get('classification')
                    and row.get('target') == fault.get('target') and row.get('status') == 'RECOVERED'
                    and row.get('verified') is True]
        if fault.get('classification') == 'link_failure' and matching and verified_fresh:
            mitigated.append(fault.get('classification'))
        else:
            unresolved.append(fault.get('classification', 'unclassified'))
    # Neither an old check nor an action acknowledgement may turn the screen green.
    anchors = []
    if latest:
        anchors.append(latest.get('completed_at') or latest.get('finished_at'))
    # Clearing a fault manually must ALSO wait for a probe taken after the clear.
    # Do not use last_seen_at for a continuously mitigated primary link: that
    # timestamp changes every detector tick even while its alternate route works.
    anchors.extend(row.get('cleared_at') or row.get('detected_at') for row in incidents)
    anchors = [stamp for stamp in anchors if stamp]
    probe_age = age_seconds(health.get('probe_started_at'), now)
    post_action = not anchors or (probe_age is not None and all(
        age_seconds(stamp, now) is not None and probe_age <= age_seconds(stamp, now)
        for stamp in anchors))
    overall = ('RECOVERING' if running else 'UNKNOWN' if not observing else 'UNHEALTHY' if unresolved else 'UNKNOWN' if not history_ready else
               'HEALTHY' if verified_fresh and post_action else
               'UNHEALTHY' if health.get('state') == 'UNHEALTHY' and fresh(health.get('checked_at'), MAX_AGE, now) else 'UNKNOWN')
    classification = ('UNAVAILABLE' if not observing else '%s ACTIVE' % len(active) if active else 'CLEAR')
    execution = ('STOPPING' if power.get('state') == 'STOPPING' else 'RUNNING' if running else
                 'OFF — OBSERVING ONLY' if not power.get('enabled') else
                 'BLOCKED — HISTORY UNAVAILABLE' if not history_ready else 'READY' if not latest else str(latest.get('recovery_status', latest.get('status', 'UNKNOWN'))).upper())
    verification = ('VERIFIED' if verified_fresh and post_action and not running else
                    'CHECKING' if running or not post_action else 'FAILED' if health.get('state') == 'UNHEALTHY' else 'UNKNOWN')
    return dict(overall=overall, stages=dict(detection='LIVE' if observing else 'STALE / UNAVAILABLE',
                classification=classification, execution=execution, verification=verification),
                detection_fresh=observing, independent_verified=verified_fresh and post_action,
                unresolved=unresolved, mitigated=mitigated, checked_at=health.get('checked_at'),
                detail=('Fresh independent network, HTTP, namespace/process, configuration and controller checks passed.'
                        + (' Primary link remains isolated; alternate route verified.' if mitigated else '') if overall == 'HEALTHY' else
                        'Unresolved observed fault(s): ' + ', '.join(unresolved) if unresolved else
                        'An accepted operation is finishing; OFF blocks all new automatic actions.' if running and not power.get('enabled') else
                        'Waiting for fresh detection and independent post-action verification; no health is inferred from flags or history.'))
