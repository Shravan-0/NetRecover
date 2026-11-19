"""Read-only health and additional recovery algorithms on fake nodes/probes only."""
from datetime import datetime, timezone, timedelta
import copy
import json
import os
from pathlib import Path
import tempfile
import threading
import types
import unittest
from unittest import mock

import classified_recovery as recovery
import system_health as health


def hosts():
    return [types.SimpleNamespace(name='h%s' % number) for number in range(1, 9)]


def passing(a, b):
    return dict(source=a.name, target=b.name, passed=True)


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.stamp = self.now.isoformat()
        self.detector = dict(engine='detect_service', checked_at=self.stamp, observe_available=True, active=[])
        self.health = dict(ok=True, verified=True, source='independent_live_probes', state='HEALTHY',
                           checked_at=self.stamp, probe_started_at=self.stamp, checks={'actual_checks': True})
        self.power = dict(enabled=False, state='OFF', in_flight=False)
        self.history = dict(incidents=[], attempts=[])

    def monitor(self):
        return health.build_monitor(self.detector, self.history, self.health, self.power, self.now)

    def test_healthy_requires_fresh_independent_evidence_even_with_power_off(self):
        result = self.monitor()
        self.assertEqual(result['overall'], 'HEALTHY')
        self.assertEqual(result['stages']['execution'], 'OFF — OBSERVING ONLY')

    def test_no_health_check_is_unknown_not_healthy(self):
        self.health = {}
        self.assertEqual(self.monitor()['overall'], 'UNKNOWN')

    def test_stale_and_future_health_are_unknown(self):
        for seconds in (-46, 5):
            with self.subTest(seconds=seconds):
                self.health['checked_at'] = (self.now + timedelta(seconds=seconds)).isoformat()
                self.assertEqual(self.monitor()['overall'], 'UNKNOWN')

    def test_stale_missing_future_and_fallback_detection_are_not_live(self):
        for delta, engine in [(-16, 'detect_service'), (5, 'detect_service'), (0, 'live_eval')]:
            self.detector.update(checked_at=(self.now + timedelta(seconds=delta)).isoformat(), engine=engine)
            self.assertEqual(self.monitor()['overall'], 'UNKNOWN')
            self.assertFalse(self.monitor()['detection_fresh'])

    def test_observation_error_blocks_healthy(self):
        self.detector['observe_error'] = True
        self.assertEqual(self.monitor()['overall'], 'UNKNOWN')

    def test_failed_actual_check_is_not_healthy(self):
        self.health.update(verified=False, state='UNHEALTHY', checks={'actual_checks': False})
        self.assertEqual(self.monitor()['overall'], 'UNHEALTHY')

    def test_ack_and_historical_success_do_not_change_unknown_health(self):
        self.health = {'ok': True, 'verified': True}
        self.history['attempts'] = [{'verified': True, 'status': 'success'}]
        self.assertEqual(self.monitor()['overall'], 'UNKNOWN')

    def test_unresolved_classification_overrides_healthy_service(self):
        self.detector['active'] = [{'classification': 'process_failure', 'target': 'h3'}]
        self.assertEqual(self.monitor()['overall'], 'UNHEALTHY')

    def test_only_active_matching_verified_link_can_be_mitigated(self):
        self.detector['active'] = [{'classification': 'link_failure', 'target': 's2-s3'}]
        record = dict(classification='link_failure', target='s2-s3', active=True, status='RECOVERED', verified=True)
        self.history['incidents'] = [record]
        self.assertEqual(self.monitor()['overall'], 'HEALTHY')
        self.assertIn('alternate route', self.monitor()['detail'])
        for change in ({'active': False}, {'target': 'other'}, {'verified': False}, {'status': 'UNVERIFIED'}):
            self.history['incidents'] = [dict(record, **change)]
            self.assertEqual(self.monitor()['overall'], 'UNHEALTHY')

    def test_pre_action_success_cannot_verify_new_recovery(self):
        self.health['probe_started_at'] = (self.now - timedelta(seconds=10)).isoformat()
        self.history['attempts'] = [dict(status='success', verified=True, completed_at=(self.now - timedelta(seconds=2)).isoformat())]
        self.assertEqual(self.monitor()['overall'], 'UNKNOWN')
        self.assertEqual(self.monitor()['stages']['verification'], 'CHECKING')
        self.health['probe_started_at'] = self.stamp
        self.assertEqual(self.monitor()['overall'], 'HEALTHY')

    def test_manual_fault_clear_also_requires_a_new_independent_probe(self):
        self.history['incidents'] = [dict(active=False, status='CLASSIFIED',
            detected_at=(self.now-timedelta(seconds=20)).isoformat(),
            cleared_at=(self.now-timedelta(seconds=2)).isoformat())]
        self.health['probe_started_at'] = (self.now-timedelta(seconds=10)).isoformat()
        self.assertEqual(self.monitor()['overall'], 'UNKNOWN')
        self.health['probe_started_at'] = self.stamp
        self.assertEqual(self.monitor()['overall'], 'HEALTHY')

    def test_stopping_is_honest_and_never_displays_healthy_during_action(self):
        self.power.update(state='STOPPING', enabled=False, in_flight=True)
        result = self.monitor()
        self.assertEqual(result['overall'], 'RECOVERING')
        self.assertEqual(result['stages']['execution'], 'STOPPING')
        self.assertNotEqual(result['stages']['verification'], 'VERIFIED')

    def test_missing_history_blocks_healthy_pipeline_readiness(self):
        self.history = {}
        self.power['enabled'] = True
        self.assertEqual(self.monitor()['overall'], 'UNKNOWN')
        self.assertIn('HISTORY UNAVAILABLE', self.monitor()['stages']['execution'])

    def test_health_cache_invalidated_after_recovery_and_stale_data_expires(self):
        cache = health.HealthCache()
        self.assertFalse(cache.get()['verified'])
        cache.value = self.health
        self.assertTrue(cache.get()['verified'])
        cache.invalidate()
        self.assertFalse(cache.get()['verified'])
        self.assertEqual(cache.get()['state'], 'UNKNOWN')

    def test_switch_protocol_parsing_accepts_actual_ovs_list_only(self):
        for value in ('OpenFlow13', '["OpenFlow13"]', '[OpenFlow13]'):
            self.assertTrue(health.switch_configuration_ok(dict(protocols=value, controller='tcp:127.0.0.1:6633')))
        for value in ('OpenFlow10', '["OpenFlow10","OpenFlow13"]', '[]', '[bad'):
            self.assertFalse(health.switch_configuration_ok(dict(protocols=value, controller='tcp:127.0.0.1:6633')))


class ActualProbeAssemblyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.config = Path(self.tmp.name) / 'service.conf'; self.config.write_text('mode=ok\n')
        self.network = types.SimpleNamespace(hosts=hosts())
        self.controller = dict(healthy=True, switch_connections={name: {'is_connected': True} for name in ('s1','s2','s3','s4','s5')})
        self.service = dict(healthy=True, service_pids=[111])
        self.switch = dict(controller='tcp:127.0.0.1:6633', protocols='["OpenFlow13"]')
        self.edges = {'s2-s3': 'up', 's3-s5': 'up'}
        self.ping = mock.Mock(side_effect=passing)
        self.probe = mock.Mock(side_effect=lambda host, url: dict(source=host.name, http_status='200', passed=True))

    def collect(self):
        return health.collect_health(self.network, lambda: self.controller, lambda: self.service,
                                     lambda: self.switch, lambda: self.edges, lambda: [222],
                                     config=self.config, ping=self.ping, probe=self.probe)

    def test_real_collector_requires_56_distinct_pairs_and_eight_http_checks(self):
        result = self.collect()
        self.assertTrue(result['verified'])
        self.assertEqual(self.ping.call_count, 56)
        self.assertEqual(len({(call.args[0].name, call.args[1].name) for call in self.ping.call_args_list}), 56)
        self.assertEqual(self.probe.call_count, 8)

    def test_collector_accepts_actual_runtime_controller_health_schema(self):
        import runtime_recovery
        runtime = dict(healthy=True, process_running=True, port_listening=True, port_owned_by_expected_ryu=True)
        manager = mock.Mock()
        manager.runtime.return_value = runtime
        connections = {name: dict(is_connected=True, targets=['tcp:127.0.0.1:6633'])
                       for name in ('s1','s2','s3','s4','s5')}
        self.controller = runtime_recovery.controller_health(manager, connections=lambda: connections)
        self.assertNotIn('healthy', self.controller)
        self.assertTrue(self.collect()['verified'])
        self.controller['runtime']['healthy'] = False
        self.assertFalse(self.collect()['verified'])

    def test_service_only_health_does_not_hide_broken_controller_or_switch(self):
        self.controller['switch_connections']['s4']['is_connected'] = False
        self.assertFalse(self.collect()['verified'])
        self.controller['switch_connections']['s4']['is_connected'] = True
        self.switch['protocols'] = '["OpenFlow10"]'
        self.assertFalse(self.collect()['verified'])

    def test_http_503_prevents_healthy(self):
        self.probe.side_effect = lambda host, url: dict(passed=host.name != 'h8', http_status='503' if host.name == 'h8' else '200')
        result = self.collect()
        self.assertFalse(result['verified'])
        self.assertFalse(result['checks']['service_http'])

    def test_missing_service_pid_prevents_namespace_success(self):
        self.service['service_pids'] = []
        self.assertFalse(self.collect()['verified'])

    def test_primary_link_isolation_can_be_healthy_but_failed_path_cannot(self):
        self.edges['s2-s3'] = 'down'
        self.assertTrue(self.collect()['verified'])
        self.edges['s3-s5'] = 'down'
        self.assertFalse(self.collect()['verified'])


class AdditionalRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.config = Path(self.tmp.name) / 'service.conf'; self.config.write_text('mode=ok\n')
        self.network = types.SimpleNamespace(hosts=hosts())
        self.switch = dict(controller='tcp:127.0.0.1:6633', protocols='["OpenFlow13"]')
        self.edges = {'s3-s5': 'up'}
        self.workers = [222]
        self.switch_apply = mock.Mock()
        self.path_apply = mock.Mock()
        self.start = mock.Mock(side_effect=lambda: self.workers.append(222))
        self.clock_value = 0

    def clock(self):
        return self.clock_value

    def sleep(self, seconds):
        self.clock_value += seconds

    def run_action(self, action, **kw):
        return recovery.recover_classified(action, self.network, self.switch_apply, self.path_apply, self.start,
            lambda: self.switch, lambda: self.edges, lambda: self.workers,
            lambda: dict(switch_connections={'s4': {'is_connected': True}}), lambda: dict(healthy=True),
            config=self.config, ping=passing, probe=kw.get('probe', lambda host,url: dict(passed=True)),
            timeout=0, clock=self.clock, sleep=self.sleep)

    def test_configuration_restores_actual_file_and_verifies_http(self):
        self.config.write_text('mode=broken\n')
        result = self.run_action('restore_service_config')
        self.assertEqual(self.config.read_text(), 'mode=ok\n')
        self.assertTrue(result['verified'])
        self.switch_apply.assert_not_called(); self.path_apply.assert_not_called(); self.start.assert_not_called()

    def test_configuration_atomic_replace_does_not_follow_a_symlink(self):
        unrelated = self.config.with_name('unrelated.txt'); unrelated.write_text('preserve')
        self.config.unlink(); self.config.symlink_to(unrelated)
        recovery.restore_config(self.config)
        self.assertFalse(self.config.is_symlink())
        self.assertEqual(unrelated.read_text(), 'preserve')

    def test_switch_calls_only_existing_s4_restoration_and_verifies_protocol(self):
        self.assertTrue(self.run_action('restore_switch_config')['verified'])
        self.switch_apply.assert_called_once_with('disable')
        self.switch['protocols'] = '["OpenFlow10"]'
        self.assertFalse(self.run_action('restore_switch_config')['verified'])

    def test_path_ack_without_actual_up_state_is_failure(self):
        self.edges['s3-s5'] = 'down'
        self.assertFalse(self.run_action('restore_path')['verified'])
        self.path_apply.assert_called_once_with('disable')
        self.edges['s3-s5'] = 'up'
        self.assertTrue(self.run_action('restore_path')['verified'])

    def test_process_starts_missing_worker_once_never_kills(self):
        self.workers = []
        result = self.run_action('restart_process')
        self.assertTrue(result['verified'])
        self.start.assert_called_once_with()
        self.run_action('restart_process')
        self.start.assert_called_once_with()

    def test_ambiguous_duplicate_workers_are_not_restarted(self):
        self.workers = [222,333]
        with self.assertRaisesRegex(RuntimeError, 'Multiple h3'):
            self.run_action('restart_process')
        self.start.assert_not_called()

    def test_successful_component_ack_without_http_verification_fails(self):
        for action in ('restore_service_config','restore_switch_config','restore_path','restart_process'):
            with self.subTest(action=action):
                result = self.run_action(action, probe=lambda host,url: dict(passed=False))
                self.assertFalse(result['verified'])
                self.assertEqual(result['recovery_status'], 'FAILED')

    def test_unknown_action_cannot_mutate(self):
        with self.assertRaises(RuntimeError):
            self.run_action('arbitrary_shell')
        self.switch_apply.assert_not_called(); self.path_apply.assert_not_called(); self.start.assert_not_called()


class WorkerNamespaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.proc = Path(self.tmp.name)
        self.net = types.SimpleNamespace(get=lambda name: types.SimpleNamespace(pid=100))
        self.add_process(100, 'net:[h3]', ['mininet:h3'])

    def add_process(self, pid, namespace, args, exe='/usr/bin/sleep'):
        path = self.proc / str(pid); (path / 'ns').mkdir(parents=True)
        (path / 'ns/net').symlink_to(namespace)
        (path / 'exe').symlink_to(exe)
        (path / 'cmdline').write_bytes(b'\0'.join(os.fsencode(arg) for arg in args) + b'\0')

    def test_only_exact_sleep_worker_in_current_h3_is_observed(self):
        self.add_process(201, 'net:[h3]', ['acn_fault_worker', '86400'])
        self.add_process(202, 'net:[host]', ['acn_fault_worker', '86400'])
        self.add_process(203, 'net:[old_h3]', ['acn_fault_worker', '86400'])
        self.add_process(204, 'net:[h3]', ['acn_fault_worker', '86400'], '/usr/bin/not-sleep')
        self.add_process(205, 'net:[h3]', ['sleep', '86400'])
        self.assertEqual(health.worker_pids(self.net, self.proc), [201])


class ReadSerializationTests(unittest.TestCase):
    def test_cached_health_get_does_not_wait_on_network_operation_lock(self):
        import ast
        source = ast.parse(Path(__file__).with_name('topo_large.py').read_text())
        handler = next(n for n in source.body if isinstance(n, ast.ClassDef) and n.name == 'ControlHandler')
        get = next(n for n in handler.body if isinstance(n, ast.FunctionDef) and n.name == 'do_GET')
        self.assertEqual(get.decorator_list, [])
        env = dict(SYSTEM_HEALTH=mock.Mock())
        env['SYSTEM_HEALTH'].get.return_value={'state':'UNKNOWN'}
        exec(compile(ast.Module(body=[get],type_ignores=[]),'topo_large.py','exec'),env)
        request = mock.Mock(path='/api/recovery/health')
        env['do_GET'](request)
        request.send_json.assert_called_once_with(200, {'state':'UNKNOWN'})

    def test_reads_fail_promptly_when_busy_and_are_reentrant_for_probe_worker(self):
        import ast
        import functools
        source = ast.parse(Path(__file__).with_name('topo_large.py').read_text())
        node = next(node for node in source.body if isinstance(node, ast.FunctionDef) and node.name == 'observed_network')
        lock = threading.RLock()
        env = dict(functools=functools, NETWORK_LOCK=lock)
        exec(compile(ast.Module(body=[node], type_ignores=[]), 'topo_large.py', 'exec'), env)
        read = mock.Mock(return_value='observed')
        guarded = env['observed_network'](read)
        with lock:
            self.assertEqual(guarded(), 'observed')
            errors = []
            def busy_reader():
                try: guarded()
                except RuntimeError as exc: errors.append(str(exc))
            thread = threading.Thread(target=busy_reader); thread.start(); thread.join(2)
            self.assertFalse(thread.is_alive(), 'Read blocked behind an in-flight operation')
            self.assertIn('unavailable', errors[0])
        read.assert_called_once()


if __name__ == '__main__':
    unittest.main(verbosity=2)
