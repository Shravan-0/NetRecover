"""Observed OVS attachment + interface state, and scoped real link fault injection.

A kernel-UP veth is NOT a usable datapath edge when detached from its OVS bridge.
No detector decision depends on the injection cache or the requested action.
"""
import json
from pathlib import Path
import re
import subprocess
import time
import uuid
from recovery_history import atomic_json


def run_command(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=8)
    if result.returncode:
        raise RuntimeError('%s failed: %s' % (argv[0], result.stderr.strip()))
    return result.stdout


def value(item):
    if isinstance(item, list) and len(item) == 2:
        if item[0] in ('uuid', 'named-uuid'):
            return item[1]
        if item[0] == 'set':
            return [value(v) for v in item[1]]
        if item[0] == 'map':
            return {value(k): value(v) for k, v in item[1]}
    return item


def sequence(item):
    return item if isinstance(item, list) else [item]


def read_ports(run=run_command):
    def rows(table, columns):
        data = json.loads(run(['ovs-vsctl', '--timeout=4', '--format=json',
                               '--columns=' + ','.join(columns), 'list', table]))
        return [dict(zip(data['headings'], map(value, row))) for row in data['data']]
    bridges = rows('Bridge', ['name', 'ports'])
    ports = {r['_uuid']: r for r in rows('Port', ['_uuid', 'name', 'interfaces', 'tag', 'trunks', 'vlan_mode', 'qos', 'other_config', 'external_ids'])}
    interfaces = {r['_uuid']: r for r in rows('Interface', ['_uuid', 'name', 'ofport', 'type', 'options', 'other_config', 'external_ids', 'admin_state', 'link_state'])}
    result = {}
    for bridge in bridges:
        for ref in sequence(bridge['ports']):
            port = ports.get(ref)
            if port is None:
                continue
            for iref in sequence(port['interfaces']):
                intf = interfaces.get(iref)
                if intf:
                    result[intf['name']] = dict(intf, bridge=bridge['name'], port_config=port)
    return result


def is_interface_up(intf):
    if type(getattr(intf, 'node', None)).__name__ == 'OVSSwitch':
        try:
            flags_path = Path('/sys/class/net') / intf.name / 'flags'
            if flags_path.is_file():
                flags = int(flags_path.read_text().strip(), 0)
                return bool(flags & 1)
        except (OSError, ValueError):
            pass
    return bool(intf.isUp())


def port_available(intf, snapshot):
    row = snapshot.get(intf.name)
    return bool(row and row['bridge'] == intf.node.name
                and isinstance(row.get('ofport'), int) and row['ofport'] > 0
                and row.get('admin_state') != 'down' and row.get('link_state') != 'down'
                and is_interface_up(intf))


def edge_interfaces(network, left, right):
    matches = []
    for link in network.links:
        if {link.intf1.node.name, link.intf2.node.name} == {left, right}:
            matches.append((link.intf1, link.intf2))
    if len(matches) != 1:
        raise RuntimeError('Expected one existing link between %s and %s' % (left, right))
    return matches[0]


def edge_state(network, left, right, snapshot=None):
    if snapshot is None:
        snapshot = read_ports()
    a, b = edge_interfaces(network, left, right)
    return 'up' if port_available(a, snapshot) and port_available(b, snapshot) else 'down'


def validate_plain_port(row):
    """The existing lab uses plain system-veth ports. Refuse custom configurations."""
    port = row['port_config']
    if (row.get('type') not in ('', 'system')
            or any(row.get(key) for key in ('options', 'other_config', 'external_ids'))
            or any(port.get(key) for key in ('tag', 'trunks', 'vlan_mode', 'qos', 'other_config', 'external_ids'))
            or len(sequence(port['interfaces'])) != 1):
        raise RuntimeError('Custom port configuration detected; refusing to detach without a dedicated restore plan')


def set_link_fault(network, action, base, saved, run=run_command, read=None,
                   sleep=time.sleep, clock=time.monotonic):
    if action not in ('enable', 'disable'):
        raise ValueError('Action must be enable or disable')
    if read is None:
        read = lambda: read_ports(run)
    endpoints = edge_interfaces(network, 's2', 's3')
    for intf in endpoints:
        if not re.fullmatch(r's[23]-eth[0-9]+', intf.name):
            raise RuntimeError('Unexpected link interface name')
    before = read()
    if action == 'enable':
        if all(intf.name not in before for intf in endpoints):
            return dict(ok=True, state='down', method='ovs_datapath_port_detach', idempotent=True)
        # Validate and save BOTH sides before changing either one.
        plan = []
        for intf in endpoints:
            row = before.get(intf.name)
            if not row or row['bridge'] != intf.node.name or not port_available(intf, before):
                raise RuntimeError('Link is not initially attached/usable; no new injection performed')
            validate_plain_port(row)
            plan.append(dict(interface=intf.name, bridge=intf.node.name, ofport=row['ofport'], original=row))
        backup = Path(base) / 'logs' / ('link_fault_ports_' + uuid.uuid4().hex + '.json')
        atomic_json(backup, {'method': 'ovs_datapath_port_detach', 'ports': plan})
        saved.update({p['interface']: p for p in plan})
        removed = []
        try:
            for entry in plan:
                removed.append(entry)
                run(['ovs-vsctl', '--timeout=4', '--if-exists', 'del-port', entry['bridge'], entry['interface']])
            after = read()
            if any(intf.name in after for intf in endpoints):
                raise RuntimeError('OVS still has a failed-link attachment; injection not confirmed')
            return dict(ok=True, state='down', method='ovs_datapath_port_detach',
                        endpoint_ports=plan, actual_attachments_present=False, port_backup=str(backup))
        except Exception as exc:
            errors = []
            for entry in removed:
                try:
                    run(['ovs-vsctl', '--timeout=4', '--may-exist', 'add-port', entry['bridge'], entry['interface'],
                         '--', 'set', 'Interface', entry['interface'], 'ofport_request=%s' % entry['ofport']])
                except Exception as restore:
                    errors.append(str(restore))
            raise RuntimeError('Injection failed: %s; rollback errors=%s; backup=%s' % (exc, errors, backup))
    # Explicit post-test restoration: retain veths, names and original OpenFlow ports.
    for intf in endpoints:
        current = before.get(intf.name)
        if current:
            if current['bridge'] != intf.node.name:
                raise RuntimeError('Interface attached to another bridge; refusing to move it')
        else:
            entry = saved.get(intf.name)
            number = entry['ofport'] if entry else intf.node.ports[intf]
            if any(r['bridge'] == intf.node.name and r.get('ofport') == number for r in before.values()):
                raise RuntimeError('Original OpenFlow port is occupied; refusing to steal it')
            run(['ovs-vsctl', '--timeout=4', '--may-exist', 'add-port', intf.node.name, intf.name,
                 '--', 'set', 'Interface', intf.name, 'ofport_request=%s' % number])
        run(['ip', 'link', 'set', 'dev', intf.name, 'up'])
    deadline = clock() + 5
    after = read()
    while edge_state(network, 's2', 's3', after) != 'up' and clock() < deadline:
        sleep(.1)
        after = read()
    if edge_state(network, 's2', 's3', after) != 'up':
        raise RuntimeError('Restoration applied but actual OVS/kernel availability did not verify')
    return dict(ok=True, state='up', method='ovs_datapath_port_restore',
                actual_ports={intf.name: after[intf.name] for intf in endpoints})
