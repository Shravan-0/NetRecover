"""Isolated actual-attachment sensor and fault-injection contract tests."""
import copy
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import link_state as ls
from classify_fault import apply_topology_payload, classify_evidence


class Endpoint:
    def __init__(self, name, number):
        self.name = name + '-eth' + str(number)
        self.node = types.SimpleNamespace(name=name, ports={})
        self.node.ports[self] = number
        self.up = True
    def isUp(self):
        return self.up


def row(intf, number):
    return dict(name=intf.name, bridge=intf.node.name, ofport=number, type='',
                options={}, other_config={}, external_ids={}, admin_state='up', link_state='up',
                port_config=dict(interfaces=['uuid-' + intf.name], tag=[], trunks=[],
                                 vlan_mode=[], qos=[], other_config={}, external_ids={}))


class LinkStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.a, self.b = Endpoint('s2', 2), Endpoint('s3', 1)
        self.network = types.SimpleNamespace(links=[types.SimpleNamespace(intf1=self.a, intf2=self.b)])
        self.ports = {self.a.name: row(self.a, 2), self.b.name: row(self.b, 1)}
        self.original = copy.deepcopy(self.ports)
        self.calls = []
        self.saved = {}

    def read(self):
        return copy.deepcopy(self.ports)

    def run_ovs(self, args):
        self.calls.append(args)
        if 'del-port' in args:
            self.ports.pop(args[-1], None)
        elif 'add-port' in args:
            name = args[args.index('add-port') + 2]
            self.ports[name] = copy.deepcopy(self.original[name])
        return ''

    def inject(self, action='enable', run=None):
        return ls.set_link_fault(self.network, action, self.tmp.name, self.saved,
                                 run=run or self.run_ovs, read=self.read)

    def test_kernel_up_but_detached_port_is_down(self):
        self.assertTrue(self.a.isUp())
        self.ports.pop(self.a.name)
        self.assertEqual(ls.edge_state(self.network, 's2', 's3', self.ports), 'down')

    def test_present_and_healthy_both_ends_are_up(self):
        self.assertEqual(ls.edge_state(self.network, 's2', 's3', self.ports), 'up')

    def test_wrong_bridge_is_not_usable(self):
        self.ports[self.a.name]['bridge'] = 'unrelated'
        self.assertFalse(ls.port_available(self.a, self.ports))

    def test_unassigned_openflow_port_is_not_usable(self):
        self.ports[self.a.name]['ofport'] = -1
        self.assertFalse(ls.port_available(self.a, self.ports))

    def test_carrier_down_is_not_usable(self):
        self.ports[self.a.name]['link_state'] = 'down'
        self.assertFalse(ls.port_available(self.a, self.ports))

    def test_kernel_admin_down_is_not_usable(self):
        self.a.up = False
        self.assertFalse(ls.port_available(self.a, self.ports))

    def test_detach_both_exact_ports_and_save_backup_before_action(self):
        def run(args):
            self.assertEqual(len(list((Path(self.tmp.name) / 'logs').glob('link_fault_ports_*.json'))), 1)
            return self.run_ovs(args)
        result = self.inject(run=run)
        self.assertTrue(result['ok'])
        self.assertEqual(result['state'], 'down')
        self.assertEqual(self.ports, {})
        self.assertEqual({args[-1] for args in self.calls}, {self.a.name, self.b.name})
        self.assertTrue(self.a.isUp() and self.b.isUp())
        self.assertFalse(result['actual_attachments_present'])

    def test_command_ack_without_detachment_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'injection not confirmed'):
            self.inject(run=lambda argv: '')

    def test_plain_port_validation_precedes_any_change(self):
        self.ports[self.b.name]['port_config']['tag'] = 100
        with self.assertRaisesRegex(RuntimeError, 'Custom port configuration'):
            self.inject()
        self.assertEqual(self.calls, [])
        self.assertEqual(len(self.ports), 2)

    def test_partial_detach_failure_restores_original_ports(self):
        def run(args):
            if 'del-port' in args and args[-1] == self.b.name:
                raise RuntimeError('Second endpoint failed')
            return self.run_ovs(args)
        with self.assertRaisesRegex(RuntimeError, 'Injection failed'):
            self.inject(run=run)
        self.assertEqual(self.ports, self.original)

    def test_explicit_restore_reuses_original_ofport_numbers(self):
        self.inject()
        self.calls.clear()
        result = self.inject('disable')
        self.assertEqual(result['state'], 'up')
        self.assertEqual(self.ports, self.original)
        additions = [args for args in self.calls if 'add-port' in args]
        self.assertEqual(len(additions), 2)
        self.assertEqual({args[-1] for args in additions}, {'ofport_request=1', 'ofport_request=2'})

    def test_restore_does_not_move_foreign_bridge_port(self):
        self.ports[self.a.name]['bridge'] = 'foreign'
        with self.assertRaisesRegex(RuntimeError, 'another bridge'):
            self.inject('disable')
        self.assertEqual(self.calls, [])

    def test_restore_refuses_port_number_conflict(self):
        self.inject()
        self.ports['other'] = dict(bridge='s2', ofport=2)
        with self.assertRaisesRegex(RuntimeError, 'occupied'):
            self.inject('disable')

    def test_detach_is_idempotent_when_both_ports_already_absent(self):
        self.inject()
        self.calls.clear()
        result = self.inject()
        self.assertTrue(result['idempotent'])
        self.assertEqual(self.calls, [])

    def test_actual_absent_datapath_edge_classifies_link_without_injection_flag(self):
        self.inject()
        observed = ls.edge_state(self.network, 's2', 's3', self.ports)
        evidence = apply_topology_payload({}, {'ok': True, 'links': {'s2-s3': observed}})
        self.assertEqual(classify_evidence(evidence)[0]['classification'], 'link_failure')

    def test_snapshot_maps_uuid_membership_and_optional_fields(self):
        responses = [
            dict(headings=['name', 'ports'], data=[['s2', ['set', [['uuid', 'p1']]]]]),
            dict(headings=['_uuid', 'name', 'interfaces'], data=[[['uuid', 'p1'], 's2-eth2', ['uuid', 'i1']]]),
            dict(headings=['_uuid', 'name', 'ofport', 'admin_state', 'link_state'],
                 data=[[['uuid', 'i1'], 's2-eth2', 2, ['set', ['up']], 'up']]),
        ]
        # OVS optional singleton string is encoded as the scalar in normal output;
        # this test focuses on UUID/set membership, so supply the normal scalar.
        responses[2]['data'][0][3] = 'up'
        run = mock.Mock(side_effect=[json.dumps(data) for data in responses])
        snapshot = ls.read_ports(run)
        self.assertEqual(snapshot['s2-eth2']['bridge'], 's2')
        self.assertTrue(ls.port_available(self.a, snapshot))
        self.assertEqual(run.call_count, 3)


if __name__ == '__main__':
    unittest.main(verbosity=2)
