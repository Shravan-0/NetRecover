"""Isolated power/dispatch tests. Real gate/history files, fake actions, NO live APIs."""
from datetime import datetime, timezone, timedelta
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

import dashboard as dash
import power_control as power
import recovery_executor as executor
from recovery_engine import RECOVERY_POLICIES
from recovery_history import History
from classify_fault import classify_evidence


def incident(label='link_failure'):
    return dict(classification=label, target=RECOVERY_POLICIES[label]['target'],
                classification_confidence=.95, detection_status='detected', incident_key=label + ':test')


class PowerFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / 'recovery_power.json'

    def test_missing_file_is_off_even_with_old_environment_on(self):
        with mock.patch.dict(os.environ, ACN_ENABLE_AUTO_RECOVERY='1'):
            self.assertFalse(power.is_enabled(self.path))
            with self.assertRaises(power.PowerDisabled):
                with power.execution_permit(self.path):
                    self.fail('No permit should be granted')

    def test_malformed_file_is_fail_closed(self):
        for content in ('broken', 'null', '[]', '{"enabled":1,"revision":1}', '{"enabled":true,"revision":true}'):
            with self.subTest(content=content):
                self.path.write_text(content)
                self.assertFalse(power.is_enabled(self.path))

    def test_persistent_on_and_off_are_authoritative(self):
        power.set_enabled(False, path=self.path)
        with mock.patch.dict(os.environ, ACN_ENABLE_AUTO_RECOVERY='1'):
            self.assertFalse(power.is_enabled(self.path))
        power.set_enabled(True, path=self.path)
        with mock.patch.dict(os.environ, ACN_ENABLE_AUTO_RECOVERY='0'):
            self.assertTrue(power.is_enabled(self.path))
        power.set_enabled(False, path=self.path)
        self.assertEqual(power.status(self.path)['state'], 'OFF')

    def test_compare_and_swap_and_idempotent_off(self):
        first = power.set_enabled(False, path=self.path)
        same = power.set_enabled(False, first['revision'], self.path)
        self.assertEqual(first['revision'], same['revision'])
        power.set_enabled(True, first['revision'], self.path)
        with self.assertRaises(power.PowerConflict):
            power.set_enabled(False, first['revision'], self.path)
        self.assertTrue(power.is_enabled(self.path))

    def test_explicit_boolean_required(self):
        for value in ('true', 'false', 1, 0, None, [], {}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                power.set_enabled(value, path=self.path)

    def test_private_gate_and_audit_without_token(self):
        power.set_enabled(False, path=self.path)
        power.set_enabled(True, path=self.path)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        audit = [json.loads(line) for line in self.path.with_suffix('.audit.jsonl').read_text().splitlines()]
        self.assertEqual([row['enabled'] for row in audit], [False, True])
        self.assertEqual([row['revision'] for row in audit], [1, 2])
        self.assertNotIn('token', json.dumps(audit).lower())

    def test_cross_process_off_stops_new_work_and_drains_existing_permit(self):
        power.set_enabled(True, path=self.path)
        code = '''import sys
from pathlib import Path
import power_control as p
with p.execution_permit(Path(sys.argv[1])):
 print('ACCEPTED', flush=True)
 sys.stdin.read(1)
print('DRAINED', flush=True)
'''
        child = subprocess.Popen([sys.executable, '-c', code, str(self.path)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                 cwd=Path(executor.__file__).resolve().parent)
        try:
            self.assertEqual(child.stdout.readline().strip(), 'ACCEPTED')
            state = power.set_enabled(False, path=self.path)
            self.assertEqual(state['state'], 'STOPPING')
            self.assertFalse(state['accepting_new_recoveries'])
            with self.assertRaises(power.PowerDisabled):
                with power.execution_permit(self.path):
                    self.fail('OFF accepted new work')
            with self.assertRaises(power.PowerConflict):
                power.set_enabled(True, path=self.path)
            output, error = child.communicate('x', timeout=8)
            self.assertEqual(child.returncode, 0, error)
            self.assertIn('DRAINED', output)
            self.assertEqual(power.status(self.path)['state'], 'OFF')
        finally:
            if child.poll() is None:
                child.communicate('x', timeout=8)


class ExecutorPowerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.status = self.root / 'recovery_status.json'
        self.gate = self.root / 'recovery_power.json'
        patch = mock.patch.object(executor, 'STATUS_FILE', self.status)
        patch.start()
        self.addCleanup(patch.stop)

    def test_off_classifies_all_seven_but_executes_none(self):
        power.set_enabled(False, path=self.gate)
        with mock.patch.dict(os.environ, ACN_ENABLE_AUTO_RECOVERY='1'), mock.patch.object(executor, 'execute_plan') as action:
            self.assertEqual(executor.execute_recoveries([incident(label) for label in RECOVERY_POLICIES]), [])
        action.assert_not_called()
        saved = json.loads(self.status.read_text())
        self.assertEqual(len(saved['incidents']), 7)
        self.assertTrue(all(row['status'] == 'CLASSIFIED' for row in saved['incidents']))
        self.assertEqual(saved['attempt_count'], 0)

    def test_on_routes_all_seven_once_and_preserves_history_across_off(self):
        power.set_enabled(False, path=self.gate)
        items = [incident(label) for label in RECOVERY_POLICIES]
        executor.execute_recoveries(items)
        ids = {row['incident_id'] for row in json.loads(self.status.read_text())['incidents']}
        power.set_enabled(True, path=self.gate)
        with mock.patch.object(executor, 'execute_plan', return_value=dict(verified=True)) as action:
            first = executor.execute_recoveries(items)
            executor.ACTIVE_ATTEMPTS = {}
            self.assertEqual(executor.execute_recoveries(items), [])
            power.set_enabled(False, path=self.gate)
            executor.execute_recoveries(items)
        self.assertEqual(action.call_count, 7)
        self.assertEqual({call.args[0]['action'] for call in action.call_args_list},
                         {policy['action'] for policy in RECOVERY_POLICIES.values()})
        self.assertEqual({row['incident_id'] for row in first}, ids)
        self.assertTrue(all(row['power_revision'] == 2 for row in first))
        self.assertEqual(json.loads(self.status.read_text())['attempt_count'], 7)

    def test_off_during_first_action_blocks_second_and_does_not_interrupt(self):
        power.set_enabled(True, path=self.gate)
        def action(plan):
            self.assertEqual(power.set_enabled(False, path=self.gate)['state'], 'STOPPING')
            return dict(verified=True)
        with mock.patch.object(executor, 'execute_plan', side_effect=action) as run:
            executor.execute_recoveries([incident('link_failure'), incident('service_stopped')])
        run.assert_called_once()
        saved = json.loads(self.status.read_text())
        self.assertEqual([row['status'] for row in saved['incidents']], ['RECOVERED', 'CLASSIFIED'])
        self.assertEqual(power.status(self.gate)['state'], 'OFF')

    def test_actual_classifier_results_flow_to_the_corresponding_engine_actions(self):
        from test_classify_fault import evidence
        observations = [
            evidence(health_unhealthy=True, service_config='mode=broken'),
            evidence(switch_protocols='OpenFlow10'),
            evidence(links={'s2-s3':'down', 's3-s5':'up'}),
            evidence(links={'s2-s3':'up', 's3-s5':'down'}),
            evidence(health_unhealthy=True, service_running=False),
            evidence(process_running=False),
            evidence(controller_process_running=False),
        ]
        items = [row for observed in observations for row in classify_evidence(observed)]
        self.assertEqual({row['classification'] for row in items}, set(RECOVERY_POLICIES))
        power.set_enabled(False, path=self.gate)
        with mock.patch.object(executor, 'execute_plan', return_value={'verified': True}) as run:
            executor.execute_recoveries(items)
            run.assert_not_called()
            power.set_enabled(True, path=self.gate)
            executor.execute_recoveries(items)
        self.assertEqual(run.call_count, 7)
        for call in run.call_args_list:
            plan = call.args[0]
            self.assertEqual(plan['action'], RECOVERY_POLICIES[plan['classification']]['action'])

    def test_unknown_and_low_confidence_never_dispatch(self):
        power.set_enabled(True, path=self.gate)
        low = incident(); low['classification_confidence'] = .2
        unknown = dict(incident(), classification='unknown')
        with mock.patch.object(executor, 'execute_plan') as action:
            executor.execute_recoveries([low, unknown])
        action.assert_not_called()

    def test_cross_process_duplicate_dispatch_is_prevented(self):
        power.set_enabled(True, path=self.gate)
        code = '''import sys,time,json
from pathlib import Path
import recovery_executor as e
e.STATUS_FILE=Path(sys.argv[1])
def action(plan):
 with open(sys.argv[2],'a') as f: f.write(plan['incident_id']+'\\n')
 time.sleep(.15)
 return {'verified':True}
e.execute_plan=action
e.execute_recoveries([json.loads(sys.argv[3])])
'''
        argv = [sys.executable, '-c', code, str(self.status), str(self.root / 'fake_effects.txt'), json.dumps(incident())]
        children = [subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                     cwd=Path(executor.__file__).resolve().parent) for _ in range(2)]
        for child in children:
            output, error = child.communicate(timeout=15)
            self.assertEqual(child.returncode, 0, output + error)
        self.assertEqual(len((self.root / 'fake_effects.txt').read_text().splitlines()), 1)
        self.assertEqual(json.loads(self.status.read_text())['attempt_count'], 1)

    def test_ack_is_unverified_and_never_replayed(self):
        power.set_enabled(True, path=self.gate)
        with mock.patch.object(executor, 'execute_plan', return_value={'ok': True}) as action:
            first = executor.execute_recoveries([incident()])
            executor.execute_recoveries([incident()])
        self.assertEqual(first[0]['recovery_status'], 'UNVERIFIED')
        action.assert_called_once()

    def test_each_policy_uses_guarded_root_route_not_legacy_endpoints(self):
        power.set_enabled(True, path=self.gate)
        token = self.root / 'test.token'; token.write_text('unit-only')
        caps = ['alternate_link_v1', 'namespace_service_v1', 'owned_controller_v1', 'classified_recovery_v3']
        for label, policy in RECOVERY_POLICIES.items():
            with self.subTest(label=label), mock.patch.object(executor, 'TOKEN_FILE', token), \
                 mock.patch.object(executor, 'request_json', side_effect=[(200, dict(ok=True, recovery_capabilities=caps)),
                        (200, dict(verified=False, recovery_status='FAILED'))]) as transport:
                executor.execute_plan(dict(policy, incident_id='a' * 32))
                call = transport.call_args
                self.assertIn('/api/recovery/', call.args[0])
                self.assertEqual(call.kwargs['payload'], {'incident_id': 'a' * 32})


class DashboardPowerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name, filename in [('POWER_FILE', 'recovery_power.json'), ('RECOVERY_STATUS_FILE', 'history.json')]:
            patch = mock.patch.object(dash, name, self.root / filename); patch.start(); self.addCleanup(patch.stop)
        power.set_enabled(False, path=dash.POWER_FILE)
        self.snapshot = dict(engine='detect_service', power_revision=1, checked_at=datetime.now(timezone.utc).isoformat(),
                             observe_available=True, active=[])
        self.caps = dict(ok=True, recovery_capabilities=['shared_power_v1', 'classified_recovery_v3', 'independent_health_v1'])
        for name, value in [('read_detection_status', self.snapshot), ('build_detection_payload', self.snapshot),
                            ('read_faults', []), ('check_service', False), ('read_recovery_status', dict(status='UNKNOWN', detail='test')),
                            ('proxy_mininet', (self.caps, 200))]:
            patch = mock.patch.object(dash, name, return_value=value); patch.start(); self.addCleanup(patch.stop)
        self.client = dash.app.test_client()

    def post(self, enabled=True, revision=1, **kw):
        headers = kw.pop('headers', {'X-Power-CSRF': dash.POWER_NONCE})
        return self.client.post('/api/power', json=dict(enabled=enabled, expected_revision=revision), headers=headers, **kw)

    def test_button_is_rendered_with_csrf_and_initial_unknown_health(self):
        page = self.client.get('/').get_data(as_text=True)
        self.assertIn('id="mainPower"', page)
        self.assertIn('MAIN POWER', page)
        self.assertIn(dash.POWER_NONCE, page)
        self.assertNotIn('__ACN_POWER_NONCE__', page)
        self.assertIn('class="badge wait">UNKNOWN', page)

    def test_real_endpoint_toggles_persistent_gate_both_states(self):
        result = self.post(); self.assertEqual(result.status_code, 200)
        self.assertTrue(power.is_enabled(dash.POWER_FILE))
        result = self.post(False, 2); self.assertEqual(result.status_code, 200)
        self.assertFalse(power.is_enabled(dash.POWER_FILE))
        self.assertEqual(self.client.get('/api/power').get_json()['power']['state'], 'OFF')

    def test_get_has_no_side_effect_and_lists_all_seven_policies(self):
        before = dash.POWER_FILE.read_bytes()
        result = self.client.get('/api/power')
        self.assertEqual(len(result.get_json()['policies']), 7)
        self.assertEqual(dash.POWER_FILE.read_bytes(), before)
        self.assertEqual(result.headers['Cache-Control'], 'no-store')

    def test_missing_csrf_is_rejected_without_mutation(self):
        self.assertEqual(self.post(headers={}).status_code, 403)
        self.assertFalse(power.is_enabled(dash.POWER_FILE))

    def test_cross_origin_with_valid_nonce_is_rejected(self):
        self.assertEqual(self.post(headers={'X-Power-CSRF': dash.POWER_NONCE, 'Origin': 'https://evil.example'}).status_code, 403)
        self.assertFalse(power.is_enabled(dash.POWER_FILE))

    def test_invalid_boolean_and_missing_revision_are_rejected(self):
        for payload in ({'enabled': 'false', 'expected_revision': 1}, {'enabled': True},
                        {'enabled': True, 'expected_revision': True}, {'enabled': 1, 'expected_revision': 1}):
            with self.subTest(payload=payload):
                result = self.client.post('/api/power', json=payload, headers={'X-Power-CSRF': dash.POWER_NONCE})
                self.assertEqual(result.status_code, 400)
        self.assertFalse(power.is_enabled(dash.POWER_FILE))

    def test_stale_browser_revision_does_not_override_new_state(self):
        self.assertEqual(self.post().status_code, 200)
        self.assertEqual(self.post(False, 1).status_code, 409)
        self.assertTrue(power.is_enabled(dash.POWER_FILE))

    def test_missing_stale_or_old_detector_blocks_on_but_never_blocks_off(self):
        for snapshot in ({}, dict(self.snapshot, checked_at='2020-01-01T00:00:00Z'), dict(self.snapshot, power_revision=None)):
            with self.subTest(snapshot=snapshot), mock.patch.object(dash, 'read_detection_status', return_value=snapshot):
                self.assertEqual(self.post().status_code, 409)
                self.assertEqual(self.post(False).status_code, 200)
        self.assertFalse(power.is_enabled(dash.POWER_FILE))

    def test_old_topology_capabilities_block_on(self):
        with mock.patch.object(dash, 'proxy_mininet', return_value=({'ok': True}, 200)):
            self.assertEqual(self.post().status_code, 503)
        self.assertFalse(power.is_enabled(dash.POWER_FILE))

    def test_status_ignores_stale_detector_gate_and_environment(self):
        with mock.patch.dict(os.environ, ACN_ENABLE_AUTO_RECOVERY='1'), \
             mock.patch.object(dash, 'build_detection_payload', return_value=dict(self.snapshot, automatic_recovery_enabled=True)):
            result = self.client.get('/api/status').get_json()
        self.assertFalse(result['automatic_recovery']['enabled'])
        self.assertEqual(result['automatic_recovery']['source'], 'shared_power_file')
        self.assertEqual(result['system_health']['overall'], 'UNKNOWN')

    def test_off_does_not_call_network_or_recovery_or_restart(self):
        power.set_enabled(True, path=dash.POWER_FILE)
        with mock.patch.object(dash, 'proxy_mininet') as api, mock.patch.object(dash.subprocess, 'Popen') as spawn:
            self.assertEqual(self.post(False, 2).status_code, 200)
        api.assert_not_called(); spawn.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
