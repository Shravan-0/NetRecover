"""Namespace service recovery and safe, same-user Ryu recovery for the ACN topology.

All mutable operations are called under topo_large.NETWORK_LOCK and require a live
SQLite claim at the HTTP boundary. This module never injects faults.
"""
import json
import os
from pathlib import Path
import pwd
import signal
import subprocess
import time

from link_recovery import command, ping_pair
from recovery_history import owner_identity, owner_alive
from recovery_verification import connectivity, http_probe

EXPECTED = 'tcp:127.0.0.1:6633'
SWITCHES = ('s1', 's2', 's3', 's4', 's5')


def service_health(network, service_pids, probe=http_probe):
    host = network.get('h2')
    pids = service_pids()
    check = probe(host, 'http://127.0.0.1:8080/health')
    namespace = os.readlink('/proc/%s/ns/net' % host.pid)
    healthy = bool(pids) and check.get('passed') is True
    return dict(ok=healthy, healthy=healthy, http_status=check.get('http_status', '000'),
                target='h2:8080', service_pids=pids, namespace=namespace, probe=check)


def recover_service(network, service_pids, apply, health=None, probe=http_probe,
                    clock=time.monotonic, sleep=time.sleep, timeout=20):
    if health is None:
        health = lambda: service_health(network, service_pids, probe)
    before = health()
    action = 'already_healthy_no_restart'
    if not before.get('healthy'):
        # apply() is the existing namespace-scoped implementation: no host-level pkill.
        if service_pids():
            stopped = apply('enable')
            if stopped.get('running'):
                return dict(ok=False, verified=False, recovery_status='FAILED',
                            failure_reason='Scoped service did not stop; duplicate start refused',
                            verification={'before': before, 'stop_result': stopped})
        action = 'restart_h2_health_service'
        apply('disable')
    deadline = clock() + timeout
    after = health()
    while not after.get('healthy') and clock() < deadline:
        sleep(min(.25, max(0, deadline - clock())))
        after = health()
    checks = []
    if after.get('healthy'):
        for host in sorted(network.hosts, key=lambda node: node.name):
            if host.name != 'h2':
                checks.append(probe(host, 'http://10.0.0.2:8080/health'))
    final = health()
    verified = (after.get('healthy') is True and final.get('healthy') is True
                and bool(final.get('service_pids')) and len(checks) == 7
                and all(check.get('passed') is True for check in checks))
    return dict(ok=verified, verified=verified, recovery_status='RECOVERED' if verified else 'FAILED',
                action=action, failure_reason=None if verified else 'h2 namespace/process, HTTP 200, or host reachability verification failed',
                verification=dict(before=before, health_probe=final, reachability=checks,
                                  namespace=final.get('namespace'), service_pids=final.get('service_pids')))


def ovs_value(value):
    if isinstance(value, list) and len(value) == 2:
        tag, data = value
        if tag in ('uuid', 'named-uuid'):
            return data
        if tag == 'set':
            return [ovs_value(item) for item in data]
        if tag == 'map':
            return {ovs_value(key): ovs_value(item) for key, item in data}
    return value


def ovs_rows(table, columns, run=command):
    data = json.loads(run(['ovs-vsctl', '--timeout=4', '--format=json',
                          '--columns=' + ','.join(columns), 'list', table]))
    return [dict(zip(data['headings'], (ovs_value(v) for v in row))) for row in data['data']]


def switch_connections(run=command):
    controllers = {row['_uuid']: row for row in ovs_rows('Controller', ['_uuid', 'target', 'is_connected', 'status'], run)}
    bridges = {row['name']: row for row in ovs_rows('Bridge', ['name', 'controller'], run)}
    result = {}
    for name in SWITCHES:
        refs = bridges.get(name, {}).get('controller', [])
        refs = refs if isinstance(refs, list) else [refs]
        rows = [controllers[ref] for ref in refs if ref in controllers]
        result[name] = dict(targets=[row['target'] for row in rows],
                            is_connected=any(row['target'] == EXPECTED and row['is_connected'] is True for row in rows),
                            details=rows, bridge_present=name in bridges)
    return result


class ControllerManager:
    """Only the observed project launcher/application is eligible for restart."""
    def __init__(self, base, run=command, clock=time.monotonic, sleep=time.sleep):
        self.base = Path(base).resolve()
        self.uid = self.base.stat().st_uid
        self.argv = [str(self.base / '.ryu39/bin/python'), str(self.base / '.ryu39/bin/ryu-manager'),
                     '--ofp-tcp-listen-port', '6633', 'ryu.app.simple_switch_stp_13']
        self.run, self.clock, self.sleep = run, clock, sleep

    def _is_expected_command(self, args):
        # Accept two invocation forms:
        # 1. Executable form: [python, ryu-manager, --ofp-tcp-listen-port, 6633, app]
        #    — this is what _spawn() uses (self.argv), and what an operator would launch directly.
        # 2. Module form: [python, -m, ryu.cmd.manager, app, ...]
        #    — this is what PID 29875 (the running controller) uses. Both forms launch
        #    the same Ryu application and must be treated as equivalent to avoid a false
        #    "no controller found" reading while the real controller is healthy.
        # args[:4] covers both: for the executable form ryu-manager is at index 1; for the
        # module form ryu.cmd.manager is at index 2 (python -m ryu.cmd.manager …).
        if args == self.argv:
            return True
        if not args:
            return False
        has_manager = any(Path(arg).name == 'ryu-manager' or arg == 'ryu.cmd.manager' for arg in args[:4])
        if not has_manager:
            return False
        if 'ryu.app.simple_switch_stp_13' not in args:
            return False
        if '--ofp-tcp-listen-port' in args:
            idx = args.index('--ofp-tcp-listen-port')
            if idx + 1 < len(args) and args[idx + 1] != '6633':
                return False
        return True

    def process_rows(self):
        expected, unknown = [], []
        own_ns = os.readlink('/proc/self/ns/net')
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit():
                continue
            try:
                args = [os.fsdecode(x) for x in (proc / 'cmdline').read_bytes().split(b'\0') if x]
                relevant = any(Path(arg).name == 'ryu-manager' or arg == 'ryu.cmd.manager' for arg in args[:4])
                if not relevant or os.readlink(str(proc / 'ns/net')) != own_ns:
                    continue
                pid = int(proc.name)
                sockets = set()
                for fd in (proc / 'fd').iterdir():
                    try:
                        target = os.readlink(str(fd))
                        if target.startswith('socket:['):
                            sockets.add(target[8:-1])
                    except OSError:
                        pass
                row = dict(pid=pid, uid=proc.stat().st_uid, identity=owner_identity(pid), sockets=sorted(sockets))
                if self._is_expected_command(args) and row['uid'] == self.uid:
                    expected.append(row)
                else:
                    unknown.append(dict(pid=pid, uid=row['uid']))
            except (FileNotFoundError, ProcessLookupError):
                continue
            # Other permission/read errors are not converted to 'no controller'.
        return expected, unknown

    def runtime(self):
        expected, unknown = self.process_rows()
        listeners = set()
        for name in ('tcp', 'tcp6'):
            path = Path('/proc/self/net') / name
            if not path.exists():
                continue
            for line in path.read_text().splitlines()[1:]:
                fields = line.split()
                if len(fields) >= 10 and int(fields[1].rsplit(':', 1)[1], 16) == 6633 and fields[3] == '0A':
                    listeners.add(fields[9])
        owned_sockets = {inode for row in expected for inode in row['sockets']}
        owned = bool(listeners) and listeners.issubset(owned_sockets)
        return dict(expected_processes=expected, unknown_ryu_processes=unknown,
                    process_running=bool(expected), port_listening=bool(listeners),
                    port_owned_by_expected_ryu=owned, healthy=bool(expected) and owned,
                    expected_uid=self.uid, expected_command=self.argv)

    def _stop_known(self, row):
        current, unknown = self.process_rows()
        match = next((item for item in current if item['identity']['pid'] == row['identity']['pid']
                      and item['identity']['start'] == row['identity']['start']
                      and item['identity']['boot'] == row['identity']['boot']), None)
        if match is None:
            return
        # Final socket check: a controller that became healthy must not be stopped.
        if self.runtime()['healthy']:
            raise RuntimeError('Controller became healthy; restart cancelled')
        os.kill(row['pid'], signal.SIGTERM)
        deadline = self.clock() + 5
        while owner_alive(row['identity']) and self.clock() < deadline:
            self.sleep(.1)
        if owner_alive(row['identity']):
            raise RuntimeError('Owned Ryu did not stop after SIGTERM; no SIGKILL or duplicate start')

    def _spawn(self):
        if self.uid == 0:
            raise RuntimeError('Project owner is root; refusing to start Ryu with root privileges')
        account = pwd.getpwuid(self.uid)
        if os.geteuid() not in (0, self.uid):
            raise RuntimeError('Cannot launch Ryu as the observed project owner')
        for item in self.argv[:2]:
            if not Path(item).is_file() or not os.access(item, os.X_OK):
                raise RuntimeError('Observed Ryu launcher missing or not executable')
        options = {}
        if os.geteuid() == 0:
            options.update(user=self.uid, group=account.pw_gid, extra_groups=os.getgrouplist(account.pw_name, account.pw_gid))
        env = dict(HOME=account.pw_dir, USER=account.pw_name, LOGNAME=account.pw_name,
                   PATH=str(self.base / '.ryu39/bin') + ':/usr/bin:/bin', LANG='C.UTF-8',
                   EVENTLET_NO_GREENDNS='yes')
        logpath = self.base / 'logs/ryu.log'
        logpath.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(logpath), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            if os.geteuid() == 0:
                os.fchown(fd, self.uid, account.pw_gid)
            proc = subprocess.Popen(self.argv, cwd=str(self.base), env=env,
                                    stdin=subprocess.DEVNULL, stdout=fd, stderr=subprocess.STDOUT,
                                    start_new_session=True, **options)
        finally:
            os.close(fd)
        return proc

    def ensure_running(self):
        before = self.runtime()
        if before['healthy']:
            return dict(action='healthy_controller_not_restarted', before=before, after=before)
        if before['port_listening']:
            raise RuntimeError('Port 6633 is occupied without verified ownership by the expected Ryu; no process killed')
        if before['unknown_ryu_processes'] or len(before['expected_processes']) > 1:
            raise RuntimeError('Ambiguous Ryu processes; automatic restart refused')
        # Give an already-starting controller a grace period before any signal.
        if before['expected_processes']:
            deadline = self.clock() + 3
            while self.clock() < deadline:
                self.sleep(.25)
                current = self.runtime()
                if current['healthy']:
                    return dict(action='controller_became_healthy_not_restarted', before=before, after=current)
                if current['port_listening']:
                    raise RuntimeError('Port ownership changed during preflight')
            self._stop_known(before['expected_processes'][0])
        # Recheck after waiting/stopping. Never spawn into a now-occupied port.
        current = self.runtime()
        if current['healthy']:
            return dict(action='controller_became_healthy_not_restarted', before=before, after=current)
        if current['port_listening'] or current['expected_processes'] or current['unknown_ryu_processes']:
            raise RuntimeError('Controller preflight changed; duplicate launch refused')
        proc = self._spawn()
        deadline = self.clock() + 20
        while self.clock() < deadline:
            after = self.runtime()
            if after['healthy']:
                return dict(action='started_observed_ryu_as_project_owner', started_pid=proc.pid, before=before, after=after)
            if proc.poll() is not None:
                raise RuntimeError('Ryu exited during startup; inspect logs/ryu.log')
            self.sleep(.25)
        raise RuntimeError('Ryu startup did not produce an owned listener on port 6633')


def controller_health(manager, connections=switch_connections):
    runtime = manager.runtime()
    switches = connections()
    connected = all(switches[name]['is_connected'] is True for name in SWITCHES)
    return dict(ok=True, id='controller', state='ok' if runtime['healthy'] and connected else 'fault',
                controllers={name: '\n'.join(switches[name]['targets']) for name in SWITCHES},
                process_running=runtime['process_running'], port_listening=runtime['port_listening'],
                port_owned_by_expected_ryu=runtime['port_owned_by_expected_ryu'],
                switch_connections=switches, runtime=runtime)


def recover_controller(network, manager, connections=switch_connections, run=command,
                       clock=time.monotonic, sleep=time.sleep, ping=ping_pair,
                       connection_timeout=45, convergence_timeout=90):
    action = manager.ensure_running()
    before = connections()
    repaired = []
    for name in SWITCHES:
        row = before[name]
        if not row['bridge_present']:
            raise RuntimeError('Expected OVS bridge missing: ' + name)
        if not row['is_connected']:
            if name == 's4':
                # Preserve the separate switch-configuration fault category.
                protocols = run(['ovs-vsctl', '--timeout=4', 'get', 'Bridge', name, 'protocols'])
                if 'OpenFlow13' not in protocols:
                    raise RuntimeError('s4 has a separate protocol fault; controller action will not overwrite it')
            if row['targets'] == [EXPECTED]:
                run(['ovs-vsctl', '--timeout=4', 'del-controller', name])
            run(['ovs-vsctl', '--timeout=4', 'set-controller', name, EXPECTED])
            repaired.append(name)
    deadline = clock() + connection_timeout
    after = connections()
    while not all(after[name]['is_connected'] is True for name in SWITCHES) and clock() < deadline:
        sleep(min(.25, max(0, deadline - clock())))
        after = connections()
    actual_connections = all(after[name]['is_connected'] is True for name in SWITCHES)
    connectivity_result = (connectivity(network.hosts, ping, timeout=convergence_timeout, clock=clock, sleep=sleep)
                           if actual_connections else dict(verified=False, checks=[], passed=0, total=0))
    final_runtime = manager.runtime()
    final_connections = connections()
    verified = (final_runtime['healthy'] is True and actual_connections
                and all(final_connections[name]['is_connected'] is True for name in SWITCHES)
                and connectivity_result['verified'] is True)
    return dict(ok=verified, verified=verified, recovery_status='RECOVERED' if verified else 'FAILED',
                action=action['action'], repaired_switches=repaired,
                failure_reason=None if verified else 'Controller process, owned port 6633, switch reconnections, or connectivity failed verification',
                verification=dict(controller_action=action, runtime=final_runtime,
                                  switch_connections=final_connections, connectivity=connectivity_result))
