"""Isolated controller safety, process/OVS evidence, and convergence tests."""
import copy
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

from classify_fault import apply_topology_payload, classify_evidence
import recovery_executor as executor
from recovery_history import History
from recovery_verification import connectivity
import runtime_recovery as runtime


class Clock:
    def __init__(self):
        self.value = 0
    def __call__(self):
        return self.value
    def sleep(self, delay):
        self.value += max(delay, .01)


def state(healthy=True):
    return dict(healthy=healthy, process_running=healthy, port_listening=healthy,
                port_owned_by_expected_ryu=healthy, expected_processes=[], unknown_ryu_processes=[])


def connections(connected=True):
    return {name: dict(targets=[runtime.EXPECTED], is_connected=connected, bridge_present=True)
            for name in runtime.SWITCHES}


def hosts():
    return [types.SimpleNamespace(name='h%s' % n) for n in range(1, 9)]


def ping(a, b):
    return dict(source=a.name, target=b.name, passed=True)


class ControllerManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.clock = Clock()
        self.manager = runtime.ControllerManager(self.tmp.name, clock=self.clock, sleep=self.clock.sleep)
        self.manager._spawn = mock.Mock(return_value=types.SimpleNamespace(pid=456, poll=lambda: None))
        self.manager._stop_known = mock.Mock()

    def test_observed_launcher_and_stp_app_are_preserved(self):
        self.assertEqual(self.manager.argv[-3:], ['--ofp-tcp-listen-port', '6633', 'ryu.app.simple_switch_stp_13'])
        self.assertTrue(self.manager.argv[0].endswith('/.ryu39/bin/python'))

    def test_healthy_controller_never_restarted(self):
        self.manager.runtime = mock.Mock(return_value=state())
        result = self.manager.ensure_running()
        self.manager._stop_known.assert_not_called()
        self.manager._spawn.assert_not_called()
        self.assertEqual(result['action'], 'healthy_controller_not_restarted')

    def test_unknown_port_owner_is_never_killed(self):
        row = state(False)
        row['port_listening'] = True
        self.manager.runtime = mock.Mock(return_value=row)
        with self.assertRaisesRegex(RuntimeError, 'occupied'):
            self.manager.ensure_running()
        self.manager._stop_known.assert_not_called()
        self.manager._spawn.assert_not_called()

    def test_unknown_ryu_process_refuses_automatic_restart(self):
        row = state(False)
        row['unknown_ryu_processes'] = [{'pid': 1}]
        self.manager.runtime = mock.Mock(return_value=row)
        with self.assertRaisesRegex(RuntimeError, 'Ambiguous'):
            self.manager.ensure_running()
        self.manager._spawn.assert_not_called()

    def test_stopped_controller_starts_once_and_requires_owned_listener(self):
        self.manager.runtime = mock.Mock(side_effect=[state(False), state(False), state()])
        result = self.manager.ensure_running()
        self.manager._spawn.assert_called_once()
        self.assertEqual(result['started_pid'], 456)
        self.assertTrue(result['after']['port_owned_by_expected_ryu'])

    def test_port_race_before_spawn_refuses_duplicate_start(self):
        occupied = state(False)
        occupied['port_listening'] = True
        self.manager.runtime = mock.Mock(side_effect=[state(False), occupied])
        with self.assertRaisesRegex(RuntimeError, 'duplicate launch'):
            self.manager.ensure_running()
        self.manager._spawn.assert_not_called()

    def test_exited_child_is_not_success(self):
        self.manager.runtime = mock.Mock(return_value=state(False))
        self.manager._spawn.return_value = types.SimpleNamespace(pid=456, poll=lambda: 1)
        with self.assertRaisesRegex(RuntimeError, 'exited'):
            self.manager.ensure_running()

    def test_hung_startup_is_not_success(self):
        self.manager.runtime = mock.Mock(return_value=state(False))
        with self.assertRaisesRegex(RuntimeError, 'did not produce'):
            self.manager.ensure_running()

    def test_starting_controller_that_becomes_healthy_is_not_signalled(self):
        starting = state(False)
        starting['expected_processes'] = [{'pid': 456}]
        self.manager.runtime = mock.Mock(side_effect=[starting, state()])
        result = self.manager.ensure_running()
        self.manager._stop_known.assert_not_called()
        self.manager._spawn.assert_not_called()
        self.assertIn('not_restarted', result['action'])

    def test_signal_guard_rechecks_identity_and_health(self):
        # Exercise the real stop guard while replacing every OS-affecting operation.
        manager = runtime.ControllerManager(self.tmp.name)
        row = dict(pid=456, identity={'pid': 456, 'start': '100', 'boot': 'boot'})
        manager.process_rows = mock.Mock(return_value=([row], []))
        manager.runtime = mock.Mock(return_value=state())
        with mock.patch.object(runtime.os, 'kill') as kill:
            with self.assertRaisesRegex(RuntimeError, 'became healthy'):
                manager._stop_known(row)
        kill.assert_not_called()

    def test_reused_pid_is_not_signalled(self):
        manager = runtime.ControllerManager(self.tmp.name)
        old = dict(pid=456, identity={'pid': 456, 'start': '100', 'boot': 'boot'})
        new = dict(pid=456, identity={'pid': 456, 'start': '200', 'boot': 'boot'})
        manager.process_rows = mock.Mock(return_value=([new], []))
        with mock.patch.object(runtime.os, 'kill') as kill:
            manager._stop_known(old)
        kill.assert_not_called()


    def test_launch_drops_privileges_and_uses_only_observed_launcher(self):
        manager = runtime.ControllerManager(self.tmp.name)
        manager.uid = 1000
        for item in manager.argv[:2]:
            path = Path(item)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('unit-test fixture; never executed')
            path.chmod(0o755)
        account = types.SimpleNamespace(pw_gid=1000, pw_dir='/home/sk', pw_name='sk')
        with mock.patch.object(runtime.os, 'geteuid', return_value=0), \
             mock.patch.object(runtime.os, 'getgrouplist', return_value=[1000]), \
             mock.patch.object(runtime.os, 'fchown'), \
             mock.patch.object(runtime.pwd, 'getpwuid', return_value=account), \
             mock.patch.object(runtime.subprocess, 'Popen') as spawn:
            manager._spawn()
        self.assertEqual(spawn.call_args.args[0], manager.argv)
        self.assertEqual(spawn.call_args.kwargs['user'], 1000)
        self.assertEqual(spawn.call_args.kwargs['group'], 1000)
        self.assertTrue(spawn.call_args.kwargs['start_new_session'])
        self.assertNotIn('shell', spawn.call_args.kwargs)
        self.assertNotIn('X-Recovery-Token', spawn.call_args.kwargs['env'])

    def test_no_sigkill_if_owned_controller_will_not_stop(self):
        manager = runtime.ControllerManager(self.tmp.name, clock=self.clock, sleep=self.clock.sleep)
        row = dict(pid=456, identity={'pid': 456, 'start': '100', 'boot': 'boot'})
        manager.process_rows = mock.Mock(return_value=([row], []))
        manager.runtime = mock.Mock(return_value=state(False))
        with mock.patch.object(runtime.os, 'kill') as kill, \
             mock.patch.object(runtime, 'owner_alive', return_value=True):
            with self.assertRaisesRegex(RuntimeError, 'no SIGKILL'):
                manager._stop_known(row)
        kill.assert_called_once_with(456, runtime.signal.SIGTERM)

    def test_listener_ownership_is_verified_using_socket_inodes(self):
        manager = runtime.ControllerManager(self.tmp.name)
        process = dict(pid=123, sockets=['777'])
        manager.process_rows = mock.Mock(return_value=([process], []))
        header = 'header\n'
        tcp = header + '0: 00000000:19E9 00000000:0000 0A 0:0 00:0 0 1000 0 777 1\n'
        def read(path, *args, **kwargs):
            return tcp if path.name == 'tcp' else header
        with mock.patch.object(Path, 'read_text', autospec=True, side_effect=read):
            self.assertTrue(manager.runtime()['port_owned_by_expected_ryu'])
            process['sockets'] = ['999']
            self.assertFalse(manager.runtime()['port_owned_by_expected_ryu'])


class ControllerVerificationTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.network = types.SimpleNamespace(hosts=hosts())
        self.manager = types.SimpleNamespace(ensure_running=mock.Mock(return_value={'action': 'healthy_controller_not_restarted'}),
                                             runtime=mock.Mock(return_value=state()))
        self.rows = connections()
        self.commands = []

    def run_command(self, argv):
        self.commands.append(argv)
        if argv[-1] == 'protocols':
            return '[OpenFlow13]'
        if 'set-controller' in argv:
            name = argv[-2]
            self.rows[name].update(targets=[runtime.EXPECTED], is_connected=True)
        return ''

    def recover(self, ping_fn=ping):
        return runtime.recover_controller(self.network, self.manager,
                                           connections=lambda: copy.deepcopy(self.rows), run=self.run_command,
                                           clock=self.clock, sleep=self.clock.sleep, ping=ping_fn,
                                           connection_timeout=1, convergence_timeout=0)

    def test_process_and_port_without_connections_are_not_success(self):
        self.rows = connections(False)
        # OVS acknowledges every command but never reconnects.
        self.run_command = lambda args: '[OpenFlow13]' if args[-1] == 'protocols' else ''
        result = self.recover()
        self.assertFalse(result['verified'])
        self.assertEqual(result['verification']['connectivity']['total'], 0)

    def test_only_disconnected_switches_are_reconnected(self):
        self.rows['s3'].update(targets=['tcp:127.0.0.1:9999'], is_connected=False)
        result = self.recover()
        self.assertTrue(result['verified'])
        self.assertEqual(result['repaired_switches'], ['s3'])
        self.assertEqual(len(self.commands), 1)
        self.assertEqual(self.commands[0][-3:], ['set-controller', 's3', runtime.EXPECTED])

    def test_healthy_connections_are_not_modified(self):
        result = self.recover()
        self.assertTrue(result['verified'])
        self.assertEqual(self.commands, [])
        self.assertEqual(result['verification']['connectivity']['passed'], 56)

    def test_correct_target_but_disconnected_is_actually_reconnected(self):
        self.rows['s2']['is_connected'] = False
        result = self.recover()
        self.assertTrue(result['verified'])
        self.assertTrue(any('del-controller' in command for command in self.commands))
        self.assertTrue(any('set-controller' in command for command in self.commands))

    def test_other_switch_protocol_fault_is_not_overwritten(self):
        self.rows['s4']['is_connected'] = False
        self.run_command = lambda args: '[OpenFlow10]'
        with self.assertRaisesRegex(RuntimeError, 'separate protocol fault'):
            self.recover()

    def test_switch_connections_without_connectivity_are_not_success(self):
        result = self.recover(ping_fn=lambda a, b: {'passed': False})
        self.assertFalse(result['verified'])
        self.assertEqual(result['verification']['connectivity']['total'], 56)

    def test_final_controller_regression_is_not_success(self):
        self.manager.runtime.return_value = state(False)
        result = self.recover()
        self.assertFalse(result['verified'])

    def test_ovs_uuid_mapping_uses_real_is_connected_not_configured_address(self):
        controllers = dict(headings=['_uuid', 'target', 'is_connected', 'status'], data=[
            [['uuid', 'uuid1'], runtime.EXPECTED, False, ['map', [['state', 'BACKOFF']]]],
            [['uuid', 'uuid2'], runtime.EXPECTED, True, ['map', [['state', 'ACTIVE']]]],
        ])
        bridges = dict(headings=['name', 'controller'], data=[
            ['s1', ['uuid', 'uuid1']], ['s2', ['set', [['uuid', 'uuid2']]]],
        ])
        run = mock.Mock(side_effect=[json.dumps(controllers), json.dumps(bridges)])
        rows = runtime.switch_connections(run)
        self.assertFalse(rows['s1']['is_connected'])
        self.assertTrue(rows['s2']['is_connected'])
        self.assertFalse(rows['s3']['bridge_present'])
        self.assertEqual(rows['s1']['details'][0]['status']['state'], 'BACKOFF')


class ActualControllerClassificationTests(unittest.TestCase):
    def classify(self, **extra):
        evidence = dict(controllers={name: runtime.EXPECTED for name in runtime.SWITCHES},
                        switch_protocols='[OpenFlow13]', **extra)
        return classify_evidence(evidence)

    def test_dead_process_detected_even_if_all_addresses_look_correct(self):
        rows = self.classify(controller_process_running=False)
        self.assertEqual(rows[0]['classification'], 'controller_disconnection')
        self.assertEqual(rows[0]['classification_confidence'], 1.0)

    def test_missing_port_is_controller_failure(self):
        self.assertEqual(self.classify(controller_port_listening=False)[0]['classification'], 'controller_disconnection')

    def test_wrong_port_owner_is_controller_failure_not_success(self):
        self.assertEqual(self.classify(controller_port_owned=False)[0]['classification'], 'controller_disconnection')

    def test_actual_disconnection_with_correct_configuration(self):
        rows = self.classify(controller_connections={'s2': False})
        self.assertEqual(rows[0]['classification'], 'controller_disconnection')

    def test_unknown_evidence_is_not_treated_as_failure(self):
        self.assertEqual(self.classify(controller_process_running=None, controller_connections={'s2': None}), [])

    def test_healthy_actual_controller_is_not_a_fault(self):
        self.assertEqual(self.classify(controller_process_running=True, controller_port_listening=True,
                                       controller_port_owned=True, controller_connections={name: True for name in runtime.SWITCHES}), [])

    def test_controller_status_fallback_preserves_actual_evidence(self):
        evidence = {}
        apply_topology_payload(evidence, dict(ok=True, id='controller', process_running=False,
                                             port_listening=False, port_owned_by_expected_ryu=False,
                                             switch_connections=connections(False)))
        self.assertFalse(evidence['controller_process_running'])
        self.assertFalse(evidence['controller_connections']['s1'])

    def test_controller_process_failure_does_not_become_worker_process_failure(self):
        evidence = {'process_running': True}
        apply_topology_payload(evidence, {'ok': True, 'id': 'controller', 'process_running': False,
                                          'port_listening': False})
        self.assertTrue(evidence['process_running'])
        self.assertFalse(evidence['controller_process_running'])
        self.assertNotIn('process_failure', [row['classification'] for row in classify_evidence(evidence)])

    def test_gate_off_records_controller_incident_without_execution(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(executor, 'STATUS_FILE', Path(tmp) / 'status.json'), \
             mock.patch.dict(os.environ, {'ACN_ENABLE_AUTO_RECOVERY': '0'}), \
             mock.patch.object(executor, 'execute_plan') as execute:
            executor.execute_recoveries(self.classify(controller_process_running=False))
            saved = json.loads(executor.STATUS_FILE.read_text())
        execute.assert_not_called()
        self.assertEqual(saved['incidents'][0]['status'], 'CLASSIFIED')
        self.assertEqual(saved['attempts'], [])

    def test_controller_has_no_legacy_disable_fallback(self):
        with mock.patch.object(executor, 'request_json', return_value=(200, {'ok': True})) as request:
            with self.assertRaisesRegex(RuntimeError, 'no legacy fallback'):
                executor.execute_network_recovery('restore_controller', 'a' * 32)
        self.assertEqual(request.call_count, 1)


class ConvergenceTests(unittest.TestCase):
    def test_retries_complete_sweep_after_stp_convergence(self):
        clock = Clock()
        count = [0]
        def eventual(a, b):
            count[0] += 1
            return dict(passed=count[0] > 56)
        result = connectivity(hosts(), eventual, timeout=5, clock=clock, sleep=clock.sleep)
        self.assertTrue(result['verified'])
        self.assertEqual(len(result['sweeps']), 2)
        self.assertEqual(result['passed'], 56)

    def test_old_successes_are_not_combined_across_different_sweeps(self):
        clock = Clock()
        count = [0]
        def alternating(a, b):
            count[0] += 1
            sweep = (count[0] - 1) // 56
            position = (count[0] - 1) % 56
            return dict(passed=(position < 28) == (sweep % 2 == 0))
        result = connectivity(hosts(), alternating, timeout=2, clock=clock, sleep=clock.sleep)
        self.assertFalse(result['verified'])
        self.assertLess(result['passed'], 56)


if __name__ == '__main__':
    unittest.main(verbosity=2)
