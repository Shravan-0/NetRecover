"""Guarded implementations of the four additional existing recovery policies.

Call only behind the topology's token/claim/power/NETWORK_LOCK boundary.
The proven link, service and controller algorithms are not replaced here.
"""
import os
from pathlib import Path
import tempfile
import time

from recovery_verification import connectivity, http_probe
from link_recovery import ping_pair
from system_health import switch_configuration_ok


def restore_config(config=Path('/tmp/service.conf')):
    # Use a fresh exclusive temporary file: never follow a pre-created /tmp symlink.
    fd, temporary = tempfile.mkstemp(prefix='.acn-config-', dir=str(config.parent))
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write('mode=ok\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, config)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return config.read_text().strip() == 'mode=ok'


def recover_classified(action, network, switch_apply, path_apply, process_start,
                       switch_read, edges, workers, controller_health, service_health,
                       config=Path('/tmp/service.conf'), ping=ping_pair, probe=http_probe,
                       timeout=30, clock=time.monotonic, sleep=time.sleep):
    before = {}
    if action == 'restore_service_config':
        before['config'] = config.read_text().strip() if config.exists() else None
        restore_config(config)
    elif action == 'restore_switch_config':
        before['switch'] = switch_read()
        switch_apply('disable')  # Existing predefined s4 controller/protocol restoration only.
    elif action == 'restore_path':
        before['links'] = edges()
        path_apply('disable')  # Existing predefined s3-s5 segment only; no topology changes.
    elif action == 'restart_process':
        before['worker_pids'] = workers()
        if len(before['worker_pids']) > 1:
            raise RuntimeError('Multiple h3 workers; refusing an ambiguous automatic operation')
        if not before['worker_pids']:
            process_start()  # Start only; never kill a PID taken from an untrusted pidfile.
    else:
        raise RuntimeError('Unsupported classified action')

    def component():
        if action == 'restore_service_config':
            return dict(passed=config.read_text().strip() == 'mode=ok' and service_health().get('healthy') is True)
        if action == 'restore_switch_config':
            row = switch_read()
            connections = controller_health().get('switch_connections', {})
            return dict(passed=switch_configuration_ok(row)
                        and connections.get('s4', {}).get('is_connected') is True, switch=row)
        if action == 'restore_path':
            rows = edges()
            return dict(passed=rows.get('s3-s5') == 'up', links=rows)
        pids = workers()
        return dict(passed=len(pids) == 1, namespace_verified_pids=pids)

    deadline = clock() + timeout
    after = component()
    while not after['passed'] and clock() < deadline:
        sleep(.25)
        after = component()
    traffic = connectivity(network.hosts, ping, timeout=max(.01, deadline - clock()))
    http = [probe(host, 'http://127.0.0.1:8080/health' if host.name == 'h2'
                  else 'http://10.0.0.2:8080/health') for host in network.hosts]
    final = component()
    verified = (after['passed'] and final['passed'] and traffic.get('verified') is True
                and len(http) == 8 and all(row.get('passed') is True for row in http))
    return dict(ok=verified, verified=verified, action=action,
                recovery_status='RECOVERED' if verified else 'FAILED',
                failure_reason=None if verified else 'Actual component state, connectivity or HTTP verification failed',
                verification=dict(before=before, component=final, connectivity=traffic, http=http))
