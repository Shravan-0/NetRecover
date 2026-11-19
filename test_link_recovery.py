from test_power_support import temporary_gate
import power_control
"""Real algorithm tested with fake nodes/commands; no live faults or OVS changes."""
import ast
import hmac
import http.server
import json
import re
from pathlib import Path
import sqlite3
import tempfile
import threading
import types
import unittest
import urllib.error
import urllib.request
from unittest import mock

import link_recovery as lr
from recovery_history import History, owner_alive
import recovery_executor as executor


class Node:
    def __init__(self, name):
        self.name = name
    def IP(self):
        return '10.0.0.' + self.name[1:]


class Intf:
    def __init__(self, node, port):
        self.node = node
        self.name = '%s-eth%s' % (node.name, port)
        self.up = True
    def isUp(self):
        return self.up


def fake_network():
    nodes = {n: Node(n) for n in ['s1', 's2', 's3', 's4', 's5'] + ['h%s' % i for i in range(1, 9)]}
    ports = {n: 0 for n in nodes}
    links = []
    def add(a, b):
        ports[a] += 1
        ports[b] += 1
        x, y = Intf(nodes[a], ports[a]), Intf(nodes[b], ports[b])
        link = types.SimpleNamespace(intf1=x, intf2=y)
        links.append(link)
        if {a, b} == {'s2', 's3'}:
            x.up = y.up = False
    for a, b in [('s1', 's2'), ('s2', 's3'), ('s2', 's4'), ('s3', 's5'), ('s4', 's5')]:
        add(a, b)
    for h, s in [('h1','s1'), ('h2','s2'), ('h3','s3'), ('h4','s1'),
                 ('h5','s4'), ('h6','s5'), ('h7','s4'), ('h8','s5')]:
        add(h, s)
    return types.SimpleNamespace(links=links, switches=[nodes[n] for n in nodes if n.startswith('s')])


def passing_ping(source, target):
    return dict(source=source.name, target=target.name, passed=True)


class LinkRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.network = fake_network()
        real = lr.recover_link
        self.patch_recovery = mock.patch.object(lr, 'recover_link', side_effect=lambda *a, **kw: real(*a, verification_timeout=0, **kw))
        self.patch_recovery.start()
        self.addCleanup(self.patch_recovery.stop)
        def attachments():
            return {intf.name: dict(bridge=intf.node.name, ofport=1, admin_state='up', link_state='up')
                    for link in self.network.links for intf in (link.intf1, link.intf2)
                    if intf.node.name.startswith('s') and getattr(intf, 'attached', True)}
        patch = mock.patch.object(lr, 'read_ports', side_effect=attachments)
        patch.start()
        self.addCleanup(patch.stop)
        self.commands = []
        self.iid = 'a' * 32

    def run_command(self, args, stdin=None, timeout=6):
        self.commands.append((args, stdin))
        if args[0] == 'ovs-vsctl':
            return args[-2].rsplit('eth', 1)[1]
        if 'dump-flows' in args:
            return ('%s, n_packets=10, actions=output:1\n' % args[-1].split('/')[0]) * 16
        return ''

    def test_real_graph_selects_existing_alternate_route(self):
        result = lr.recover_link(self.network, self.iid, run=self.run_command, ping=passing_ping)
        self.assertTrue(result['verified'])
        evidence = result['verification']
        self.assertEqual(evidence['alternate_path'], ['s2', 's4', 's5', 's3'])
        self.assertEqual(evidence['passed'], 56)
        self.assertTrue(evidence['failed_link_still_down'])
        self.assertIn('h3', evidence['affected_hosts'])
        self.assertEqual(evidence['forwarding']['s2:h3']['path'], ['s2', 's4', 's5', 's3'])
        self.assertEqual(evidence['forwarding']['s2:h3']['ofport'], 3)

    def test_bidirectional_ip_and_arp_rules_and_flow_readback(self):
        lr.recover_link(self.network, self.iid, run=self.run_command, ping=passing_ping)
        additions = [(args, data) for args, data in self.commands if 'add-flows' in args]
        self.assertEqual(len(additions), 5)
        self.assertEqual(sum(len(data.splitlines()) for _, data in additions), 80)
        self.assertEqual(sum('dump-flows' in args for args, _ in self.commands), 5)
        for _, rules in additions:
            self.assertIn('ip,nw_dst=', rules)
            self.assertIn('arp,arp_tpa=', rules)
            self.assertIn('cookie=0xac4e', rules)
            self.assertNotIn('actions=NORMAL', rules)

    def test_no_alternate_path_executes_no_ovs_commands(self):
        for link in self.network.links:
            if {link.intf1.node.name, link.intf2.node.name} == {'s4', 's5'}:
                link.intf1.up = False
        with self.assertRaisesRegex(RuntimeError, 'No available alternate'):
            lr.recover_link(self.network, self.iid, run=self.run_command, ping=passing_ping)
        self.assertEqual(self.commands, [])

    def test_kernel_up_but_detached_ovs_ports_are_a_real_down_edge(self):
        for link in self.network.links:
            if {link.intf1.node.name, link.intf2.node.name} == {'s2', 's3'}:
                link.intf1.up = link.intf2.up = True
                link.intf1.attached = link.intf2.attached = False
        result = lr.recover_link(self.network, self.iid, run=self.run_command, ping=passing_ping)
        self.assertTrue(result['verified'])
        self.assertTrue(result['verification']['failed_link_still_down'])
        self.assertEqual(result['verification']['alternate_path'], ['s2', 's4', 's5', 's3'])

    def test_healthy_link_does_not_change_forwarding(self):
        for link in self.network.links:
            link.intf1.up = link.intf2.up = True
        with self.assertRaisesRegex(RuntimeError, 'not observed down'):
            lr.recover_link(self.network, self.iid, run=self.run_command, ping=passing_ping)
        self.assertEqual(self.commands, [])

    def test_one_sided_link_failure_is_detected(self):
        for link in self.network.links:
            if {link.intf1.node.name, link.intf2.node.name} == {'s2', 's3'}:
                link.intf1.up = True
                link.intf2.up = False
        result = lr.recover_link(self.network, self.iid, run=self.run_command, ping=passing_ping)
        self.assertTrue(result['verified'])

    def test_successful_commands_without_connectivity_are_failed(self):
        ping = lambda a, b: dict(source=a.name, target=b.name, passed=False)
        result = lr.recover_link(self.network, self.iid, run=self.run_command, ping=ping)
        self.assertFalse(result['verified'])
        self.assertEqual(result['recovery_status'], 'FAILED')
        deletes = [args for args, _ in self.commands if 'del-flows' in args]
        self.assertEqual(len(deletes), 5)
        self.assertTrue(all('cookie=' in args[-1] for args in deletes))

    def test_incomplete_rollback_is_unverified(self):
        def run(args, **kwargs):
            if 'del-flows' in args:
                raise RuntimeError('OVS unavailable')
            return self.run_command(args, **kwargs)
        result = lr.recover_link(self.network, self.iid, run=run,
                                 ping=lambda a, b: {'passed': False})
        self.assertEqual(result['recovery_status'], 'UNVERIFIED')
        self.assertTrue(result['verification']['rollback_errors'])

    def test_partial_flow_installation_is_rolled_back(self):
        def run(args, **kwargs):
            if 'add-flows' in args and 's3' in args:
                raise RuntimeError('OVS rejected flow batch')
            return self.run_command(args, **kwargs)
        result = lr.recover_link(self.network, self.iid, run=run, ping=passing_ping)
        self.assertFalse(result['verified'])
        self.assertEqual(result['verification']['checks'], [])
        self.assertEqual(sum('del-flows' in args for args, _ in self.commands), 3)

    def test_missing_flow_readback_is_not_success(self):
        def run(args, **kwargs):
            if 'dump-flows' in args:
                return ''
            return self.run_command(args, **kwargs)
        result = lr.recover_link(self.network, self.iid, run=run, ping=passing_ping)
        self.assertFalse(result['verified'])
        self.assertFalse(result['verification']['flow_rules_present'])

    def test_zero_flow_counters_are_not_success(self):
        def run(args, **kwargs):
            return self.run_command(args, **kwargs).replace('n_packets=10', 'n_packets=0')
        result = lr.recover_link(self.network, self.iid, run=run, ping=passing_ping)
        self.assertFalse(result['verified'])
        self.assertFalse(result['verification']['alternate_path_counters_positive'])

    def test_invalid_incident_id_rejected(self):
        with self.assertRaises(ValueError):
            lr.recover_link(self.network, 'bad;command', run=self.run_command, ping=passing_ping)
        self.assertEqual(self.commands, [])

    def test_disconnected_host_attachment_rejected(self):
        self.network.links[-1].intf1.up = False
        with self.assertRaisesRegex(RuntimeError, 'host attachment'):
            lr.recover_link(self.network, self.iid, run=self.run_command, ping=passing_ping)
        self.assertEqual(self.commands, [])

    def test_failed_link_restoring_during_verification_is_not_success(self):
        def ping(a, b):
            for link in self.network.links:
                if {link.intf1.node.name, link.intf2.node.name} == {'s2', 's3'}:
                    link.intf1.up = link.intf2.up = True
            return passing_ping(a, b)
        result = lr.recover_link(self.network, self.iid, run=self.run_command, ping=ping)
        self.assertFalse(result['verified'])
        self.assertFalse(result['verification']['failed_link_still_down'])

    def test_old_running_topology_has_no_unsafe_legacy_fallback(self):
        with mock.patch.object(executor, 'request_json', return_value=(200, {'ok': True})) as request:
            with self.assertRaisesRegex(RuntimeError, 'no legacy fallback'):
                executor.execute_network_recovery('restore_link', self.iid)
        self.assertEqual(request.call_count, 1)

    def test_endpoint_result_is_returned_not_assumed_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            token = Path(tmp) / 'token'
            token.write_text('unit-test-token')
            result = {'ok': False, 'verified': False, 'recovery_status': 'FAILED'}
            with mock.patch.object(executor, 'TOKEN_FILE', token), \
                 temporary_gate(True, Path(tmp) / "recovery_status.json"), \
                 mock.patch.object(executor, 'request_json', side_effect=[
                     (200, {'ok': True, 'recovery_capabilities': ['alternate_link_v1']}),
                     (200, result)]) as request:
                self.assertEqual(executor.execute_network_recovery('restore_link', self.iid), result)
                self.assertEqual(request.call_args.kwargs['payload']['incident_id'], self.iid)


class RecoveryEndpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        (base / 'recovery.token').write_text('test-only-token')
        self.store = History(base / 'logs/recovery_history.sqlite3')
        power_control.set_enabled(True, path=base / 'logs/recovery_power.json')
        item = dict(classification='link_failure', target='s2-s3', classification_confidence=1.0)
        self.iid = self.store.observe([item], True)[0][0]
        self.run = mock.Mock(return_value={'ok': True, 'verified': True})
        source = Path(__file__).with_name('topo_large.py').read_text()
        tree = ast.parse(source)
        selected = ast.Module(body=[node for node in tree.body
                                    if isinstance(node, ast.ClassDef) and node.name == 'ControlHandler'],
                              type_ignores=[])
        self.env = dict(BaseHTTPRequestHandler=http.server.BaseHTTPRequestHandler,
                        serialized_network=lambda f: f, Path=Path, json=json, hmac=hmac,
                        sqlite3=sqlite3, re=re, owner_alive=owner_alive, __file__=str(base / 'topo_large.py'),
                        network=object(), LINK_RESULTS={}, recover_link=self.run,
                        execution_permit=power_control.execution_permit, PowerDisabled=power_control.PowerDisabled,
                        SYSTEM_HEALTH=mock.Mock(),
                        info=lambda *args: None)
        exec(compile(selected, 'topo_large.py', 'exec'), self.env)
        self.server = http.server.HTTPServer(('127.0.0.1', 0), self.env['ControlHandler'])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def request(self, token):
        req = urllib.request.Request(('http://127.0.0.1:%s' % self.server.server_port) + getattr(self, 'endpoint', '/api/recovery/link'),
                                     data=json.dumps({'incident_id': self.iid}).encode(),
                                     headers={'X-Recovery-Token': token}, method='POST')
        try:
            response = urllib.request.urlopen(req, timeout=3)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            return response.status, json.loads(response.read())

    def test_invalid_token_cannot_execute(self):
        self.assertEqual(self.request('wrong')[0], 403)
        self.run.assert_not_called()

    def test_unclaimed_gate_off_incident_cannot_execute(self):
        self.assertEqual(self.request('test-only-token')[0], 409)
        self.run.assert_not_called()

    def test_valid_live_claim_executes_once_even_if_request_repeated(self):
        self.store.claim(self.iid, {'action': 'restore_link'}, True)
        self.assertEqual(self.request('test-only-token')[0], 200)
        self.assertEqual(self.request('test-only-token')[0], 200)
        self.run.assert_called_once()

    def test_completed_claim_cannot_execute_again(self):
        self.store.claim(self.iid, {'action': 'restore_link'}, True)
        self.store.finish(self.iid, 'RECOVERED', {'verified': True})
        self.assertEqual(self.request('test-only-token')[0], 409)
        self.run.assert_not_called()


    def configure_runtime_endpoint(self, classification, action, endpoint):
        item = dict(classification=classification, target='runtime-test', classification_confidence=1.0)
        self.iid = self.store.observe([item], True, complete=False)[0][0]
        self.store.claim(self.iid, {'action': action}, True)
        self.endpoint = endpoint
        self.runtime_run = mock.Mock(return_value={'ok': True, 'verified': True})
        self.env.update(recover_service=self.runtime_run, recover_controller=self.runtime_run,
                        service_process_pids=mock.Mock(), apply_service_fault=mock.Mock(),
                        ControllerManager=mock.Mock())

    def test_service_endpoint_requires_and_accepts_matching_claim(self):
        self.configure_runtime_endpoint('service_stopped', 'restart_service', '/api/recovery/service')
        self.assertEqual(self.request('test-only-token')[0], 200)
        self.runtime_run.assert_called_once()
        self.run.assert_not_called()

    def test_controller_endpoint_requires_and_accepts_matching_claim(self):
        self.configure_runtime_endpoint('controller_disconnection', 'restore_controller', '/api/recovery/controller')
        self.assertEqual(self.request('test-only-token')[0], 200)
        self.runtime_run.assert_called_once()
        self.assertFalse(self.env['controller_is_disconnected'])

    def test_claim_cannot_be_used_for_a_different_action(self):
        self.store.claim(self.iid, {'action': 'restore_link'}, True)
        self.endpoint = '/api/recovery/controller'
        self.assertEqual(self.request('test-only-token')[0], 409)
        self.run.assert_not_called()

    def test_interrupted_runtime_operation_is_never_reported_success(self):
        self.configure_runtime_endpoint('service_stopped', 'restart_service', '/api/recovery/service')
        self.runtime_run.side_effect = RuntimeError('Operation interrupted after it may have acted')
        code, result = self.request('test-only-token')
        self.assertEqual(code, 200)
        self.assertFalse(result['verified'])
        self.assertEqual(result['recovery_status'], 'UNVERIFIED')
        self.request('test-only-token')
        self.runtime_run.assert_called_once()

    def test_current_power_off_rejects_even_a_live_previously_enabled_claim(self):
        self.store.claim(self.iid, {'action': 'restore_link'}, True)
        power_control.set_enabled(False, path=self.store.path.with_name('recovery_power.json'))
        code, result = self.request('test-only-token')
        self.assertEqual(code, 403)
        self.assertEqual(result['code'], 'POWER_OFF')
        self.assertFalse(result['action_started'])
        self.run.assert_not_called()

    def test_all_four_additional_routes_require_matching_claim_and_cache_once(self):
        for classification, action, endpoint in [
            ('config_failure', 'restore_service_config', '/api/recovery/config'),
            ('switch_config_failure', 'restore_switch_config', '/api/recovery/switch'),
            ('path_failure', 'restore_path', '/api/recovery/path'),
            ('process_failure', 'restart_process', '/api/recovery/process'),
        ]:
            with self.subTest(classification=classification):
                self.configure_runtime_endpoint(classification, action, endpoint)
                self.env.update(recover_classified=self.runtime_run, apply_switch_fault=mock.Mock(),
                                apply_path_fault=mock.Mock(), start_process_worker=mock.Mock(),
                                read_switch_state=mock.Mock(), current_edge_states=mock.Mock(),
                                worker_pids=mock.Mock(), current_controller_health=mock.Mock(),
                                current_service_health=mock.Mock())
                self.assertEqual(self.request('test-only-token')[0], 200)
                self.assertEqual(self.request('test-only-token')[0], 200)
                self.runtime_run.assert_called_once()
                self.assertEqual(self.runtime_run.call_args.args[0], action)


if __name__ == '__main__':
    unittest.main(verbosity=2)
