from test_power_support import temporary_gate
import power_control
"""Service recovery tests use fake nodes/probes only; no live ACN traffic."""
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock
import urllib.error

from classify_fault import classify_evidence
import detect_service
import recovery_executor as executor
import runtime_recovery as runtime
from recovery_verification import http_probe


def healthy():
    return dict(healthy=True, http_status='200', service_pids=[123], namespace='net:[h2]')


def unhealthy():
    return dict(healthy=False, http_status='000', service_pids=[], namespace='net:[h2]')


class ServiceRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.hosts = [types.SimpleNamespace(name='h%s' % n, pid=100 + n) for n in range(1, 9)]
        self.network = types.SimpleNamespace(hosts=self.hosts, get=lambda name: next(n for n in self.hosts if n.name == name))
        self.probe = mock.Mock(side_effect=lambda host, url: dict(source=host.name, http_status='200', passed=True))

    def test_stopped_service_starts_in_existing_scoped_implementation(self):
        apply = mock.Mock(return_value={'running': True})
        health = mock.Mock(side_effect=[unhealthy(), healthy(), healthy()])
        result = runtime.recover_service(self.network, lambda: [], apply, health=health, probe=self.probe, timeout=0)
        apply.assert_called_once_with('disable')
        self.assertTrue(result['verified'])
        self.assertEqual(len(result['verification']['reachability']), 7)
        self.assertTrue(all(call.args[1] == 'http://10.0.0.2:8080/health' for call in self.probe.call_args_list))

    def test_running_unhealthy_service_only_uses_scoped_stop_start(self):
        apply = mock.Mock(side_effect=[{'running': False}, {'running': True}])
        result = runtime.recover_service(self.network, lambda: [123], apply,
                                         health=mock.Mock(side_effect=[unhealthy(), healthy(), healthy()]),
                                         probe=self.probe, timeout=0)
        self.assertEqual(apply.call_args_list, [mock.call('enable'), mock.call('disable')])
        self.assertTrue(result['verified'])

    def test_healthy_service_is_not_restarted(self):
        apply = mock.Mock()
        result = runtime.recover_service(self.network, lambda: [123], apply,
                                         health=healthy, probe=self.probe, timeout=0)
        apply.assert_not_called()
        self.assertTrue(result['verified'])
        self.assertEqual(result['action'], 'already_healthy_no_restart')

    def test_scoped_stop_failure_refuses_duplicate_start(self):
        apply = mock.Mock(return_value={'running': True})
        result = runtime.recover_service(self.network, lambda: [123], apply,
                                         health=unhealthy, probe=self.probe, timeout=0)
        apply.assert_called_once_with('enable')
        self.assertFalse(result['verified'])

    def test_process_start_ack_without_http_is_not_success(self):
        result = runtime.recover_service(self.network, lambda: [], mock.Mock(return_value={'running': True}),
                                         health=unhealthy, probe=self.probe, timeout=0)
        self.assertEqual(result['recovery_status'], 'FAILED')
        self.assertEqual(result['verification']['reachability'], [])

    def test_one_unreachable_host_prevents_success(self):
        self.probe.side_effect = lambda host, url: {'passed': host.name != 'h8'}
        result = runtime.recover_service(self.network, lambda: [123], mock.Mock(),
                                         health=healthy, probe=self.probe, timeout=0)
        self.assertFalse(result['verified'])

    def test_final_health_regression_prevents_success(self):
        result = runtime.recover_service(self.network, lambda: [123], mock.Mock(),
                                         health=mock.Mock(side_effect=[healthy(), healthy(), unhealthy()]),
                                         probe=self.probe, timeout=0)
        self.assertFalse(result['verified'])

    def test_no_scoped_pid_means_unhealthy_even_with_http_200(self):
        with mock.patch.object(runtime.os, 'readlink', return_value='net:[h2]'):
            result = runtime.service_health(self.network, lambda: [], probe=self.probe)
        self.assertFalse(result['healthy'])
        self.assertEqual(result['http_status'], '200')

    def test_namespace_is_read_from_current_h2_shell(self):
        with mock.patch.object(runtime.os, 'readlink', return_value='net:[current-h2]') as read:
            result = runtime.service_health(self.network, lambda: [123], probe=self.probe)
        read.assert_called_once_with('/proc/102/ns/net')
        self.assertEqual(result['namespace'], 'net:[current-h2]')
        self.assertTrue(result['healthy'])

    def test_probe_uses_namespace_popen_and_requires_curl_success(self):
        proc = mock.Mock(returncode=7)
        proc.communicate.return_value = (b'200', b'connection error')
        host = types.SimpleNamespace(name='h1', popen=mock.Mock(return_value=proc))
        result = http_probe(host, 'http://10.0.0.2:8080/health')
        self.assertFalse(result['passed'])
        self.assertEqual(host.popen.call_args.args[0][0], 'curl')
        self.assertNotIn('shell', host.popen.call_args.kwargs)


class ServiceClassificationAndExecutorTests(unittest.TestCase):
    def test_stopped_process_classified_service(self):
        result = classify_evidence({'service_running': False})
        self.assertEqual(result[0]['classification'], 'service_stopped')

    def test_actual_local_http_failure_with_good_config_classified_service(self):
        results = classify_evidence({'service_running': True, 'health_unhealthy': True,
                                     'service_config': 'mode=ok', 'health_local_probe_failed': True})
        self.assertEqual(results[0]['classification'], 'service_stopped')
        self.assertEqual(results[0]['classification_confidence'], 1.0)

    def test_transport_failure_without_local_probe_is_not_service_proof(self):
        results = classify_evidence({'service_running': True, 'health_unhealthy': True,
                                     'service_config': 'mode=ok', 'health_local_probe_failed': False})
        self.assertEqual(results[0]['classification'], 'unclassified')

    def test_bad_config_still_uses_original_category(self):
        results = classify_evidence({'service_running': True, 'health_unhealthy': True,
                                     'service_config': 'mode=broken', 'health_local_probe_failed': True})
        self.assertEqual(results[0]['classification'], 'config_failure')

    def test_detector_transport_error_clears_old_local_failure_evidence(self):
        with mock.patch.object(detect_service.urllib.request, 'urlopen', side_effect=urllib.error.URLError('offline')):
            detect_service.latest_health_probe = {'api_http_status': 503, 'healthy': False}
            self.assertFalse(detect_service.check_health())
            self.assertIsNone(detect_service.latest_health_probe)

    def test_detector_parses_actual_503_probe_body(self):
        body = json.dumps(dict(target='h2:8080', healthy=False, http_status='000')).encode()
        error = urllib.error.HTTPError('http://unit-test', 503, 'Unhealthy', {}, io.BytesIO(body))
        with mock.patch.object(detect_service.urllib.request, 'urlopen', side_effect=error), \
             mock.patch.object(detect_service, 'read_service_config', return_value='mode=ok'):
            self.assertFalse(detect_service.check_health())
            evidence = detect_service.build_evidence(False, {'ok': True, 'service_running': True})
            self.assertTrue(evidence['health_local_probe_failed'])
        detect_service.latest_health_probe = None

    def test_executor_independently_checks_real_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            token = Path(tmp) / 'token'
            token.write_text('test-token')
            response = dict(verified=True, verification={'namespace': 'net:[h2]'})
            with temporary_gate(True, Path(tmp) / "recovery_status.json"), \
                 mock.patch.object(executor, 'TOKEN_FILE', token), \
                 mock.patch.object(executor, 'request_json', side_effect=[
                     (200, {'ok': True, 'recovery_capabilities': ['namespace_service_v1']}),
                     (200, response), (503, {'healthy': False, 'http_status': '000'})]) as requests:
                result = executor.execute_network_recovery('restart_service', 'a' * 32)
            self.assertFalse(result['verified'])
            self.assertEqual(result['recovery_status'], 'FAILED')
            self.assertTrue(requests.call_args.args[0].endswith('/api/health-probe'))

    def test_service_has_no_legacy_fallback(self):
        with mock.patch.object(executor, 'request_json', return_value=(200, {'ok': True})) as request:
            with self.assertRaisesRegex(RuntimeError, 'no legacy fallback'):
                executor.execute_network_recovery('restart_service', 'a' * 32)
        self.assertEqual(request.call_count, 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
