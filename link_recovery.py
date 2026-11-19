"""Real alternate-path forwarding for the existing Mininet network.

Imported by topo_large, not a separate network/controller. No Mininet import needed.
All entry points are called under topo_large.NETWORK_LOCK.
"""
from collections import deque
import hashlib
import ipaddress
import re
import subprocess
from recovery_verification import connectivity
from link_state import read_ports, port_available

COOKIE_PREFIX = 0xAC4E000000000000
COOKIE_MASK = 0xFFFF000000000000
PRIORITY = 41000


def shortest_path(graph, source, target):
    queue = deque([(source, [source])])
    visited = {source}
    while queue:
        node, path = queue.popleft()
        if node == target:
            return path
        for peer in sorted(graph.get(node, {})):
            if peer not in visited:
                visited.add(peer)
                queue.append((peer, path + [peer]))
    return None


def command(argv, stdin=None, timeout=6):
    result = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('Command failed: %s: %s' % (argv[0], result.stderr.strip()))
    return result.stdout


def ping_pair(source, target):
    # popen avoids the shared interactive shell used by Mininet Node.cmd().
    proc = source.popen(['ping', '-n', '-c', '1', '-W', '1', '-w', '2', target.IP()],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = proc.communicate(timeout=3)
        return dict(source=source.name, target=target.name, target_ip=target.IP(),
                    passed=proc.returncode == 0, output=out.decode(errors='replace')[-1500:],
                    error=err.decode(errors='replace')[-500:])
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return dict(source=source.name, target=target.name, passed=False, error='Ping timed out')


def topology_graph(network):
    """Discover actual ofports/host attachment; never assume ethN numbering."""
    snapshot = read_ports()
    names = {node.name for node in network.switches}
    graph = {name: {} for name in names}
    hosts = {}
    all_edges = []
    for link in network.links:
        a, b = link.intf1, link.intf2
        an, bn = a.node.name, b.node.name
        if an in names and bn in names:
            up = port_available(a, snapshot) and port_available(b, snapshot)
            all_edges.append((an, bn, up))
            if up:
                graph[an][bn] = a
                graph[bn][an] = b
        elif (an in names) != (bn in names):
            switch_intf, host_intf = (a, b) if an in names else (b, a)
            host = host_intf.node
            ipaddress.IPv4Address(host.IP())
            hosts[host.name] = dict(host=host, switch=switch_intf.node.name,
                                    interface=switch_intf, up=bool(port_available(switch_intf, snapshot) and host_intf.isUp()))
    if names != {'s1', 's2', 's3', 's4', 's5'} or set(hosts) != {'h%s' % i for i in range(1, 9)}:
        raise RuntimeError('Unexpected topology; refusing forwarding changes')
    if not all(value['up'] for value in hosts.values()):
        raise RuntimeError('A host attachment is down; alternate-link recovery alone is insufficient')
    return graph, hosts, all_edges


def recover_link(network, incident_id, run=command, ping=ping_pair, verification_timeout=90):
    """Reroute while s2-s3 remains DOWN; return observed verification, never an ACK."""
    if not re.fullmatch(r'[a-f0-9]{32}', incident_id):
        raise ValueError('Invalid incident ID')
    graph, hosts, edges = topology_graph(network)
    failed = [up for a, b, up in edges if {a, b} == {'s2', 's3'}]
    if failed != [False]:
        raise RuntimeError('s2-s3 is not observed down; no failure to reroute')
    alternate = shortest_path(graph, 's2', 's3')
    if not alternate:
        raise RuntimeError('No available alternate path for s2-s3')

    original = {name: dict(peers) for name, peers in graph.items()}
    original['s2']['s3'] = None
    original['s3']['s2'] = None
    affected = []
    for src, a in sorted(hosts.items()):
        for dst, b in sorted(hosts.items()):
            if src == dst:
                continue
            path = shortest_path(original, a['switch'], b['switch'])
            if path and any({x, y} == {'s2', 's3'} for x, y in zip(path, path[1:])):
                affected.append([src, dst])

    cookie = COOKIE_PREFIX | (int(hashlib.sha256(incident_id.encode()).hexdigest()[:12], 16))
    evidence = dict(failed_link='s2-s3', link_state_basis='kernel_and_actual_ovs_attachment', affected_switches=['s2', 's3'],
                    affected_hosts=sorted({h for pair in affected for h in pair}),
                    affected_host_pairs=affected, alternate_path=alternate,
                    cookie=hex(cookie), priority=PRIORITY, checks=[], forwarding={})
    flows = {name: [] for name in graph}
    for dst_name, dst in sorted(hosts.items()):
        ip = str(ipaddress.IPv4Address(dst['host'].IP()))
        for switch in sorted(graph):
            path = shortest_path(graph, switch, dst['switch'])
            if path is None:
                raise RuntimeError('Remaining topology is disconnected')
            intf = dst['interface'] if len(path) == 1 else graph[switch][path[1]]
            name = intf.name
            if not re.fullmatch(r's[1-5]-eth[0-9]+', name):
                raise RuntimeError('Unexpected OVS interface name')
            port = int(run(['ovs-vsctl', '--timeout=4', 'get', 'Interface', name, 'ofport']).strip())
            if port <= 0:
                raise RuntimeError('OVS interface has no usable OpenFlow port')
            evidence['forwarding']['%s:%s' % (switch, dst_name)] = dict(path=path, ofport=port)
            prefix = 'cookie=%s,table=0,priority=%s,idle_timeout=0,hard_timeout=0,' % (hex(cookie), PRIORITY)
            flows[switch].append(prefix + 'ip,nw_dst=%s,actions=output:%s' % (ip, port))
            flows[switch].append(prefix + 'arp,arp_tpa=%s,actions=output:%s' % (ip, port))

    # Recheck physical observations immediately before changing forwarding.
    _, _, current_edges = topology_graph(network)
    if sorted(edges) != sorted(current_edges):
        raise RuntimeError('Topology changed during planning; refusing stale plan')
    installed = []
    try:
        for switch, rules in sorted(flows.items()):
            installed.append(switch)  # A failed bulk command may have applied a subset.
            run(['ovs-ofctl', '-O', 'OpenFlow13', '--timeout=4', 'add-flows', switch, '-'],
                stdin='\n'.join(rules) + '\n')
        probe_result = connectivity([entry['host'] for entry in hosts.values()], ping,
                                    timeout=verification_timeout)
        evidence['checks'] = probe_result['checks']
        evidence['convergence_sweeps'] = probe_result['sweeps']
        _, _, after = topology_graph(network)
        evidence['failed_link_still_down'] = any(
            {a, b} == {'s2', 's3'} and not up for a, b, up in after)
        evidence['topology_unchanged'] = sorted(after) == sorted(edges)
        evidence['flow_dumps'] = {
            switch: run(['ovs-ofctl', '-O', 'OpenFlow13', '--timeout=4', 'dump-flows',
                         switch, 'cookie=%s/-1' % hex(cookie)]) for switch in sorted(flows)
        }
        evidence['flow_rules_present'] = all(
            len(re.findall(r'cookie=%s\b' % re.escape(hex(cookie)), dump)) == 16
            for dump in evidence['flow_dumps'].values())
        evidence['alternate_path_counters_positive'] = all(
            any(int(value) > 0 for value in re.findall(r'n_packets=(\d+)', evidence['flow_dumps'][switch]))
            for switch in alternate)
        evidence['passed'] = sum(check['passed'] is True for check in evidence['checks'])
        evidence['total'] = len(evidence['checks'])
        verified = (evidence['passed'] == evidence['total'] == 56
                    and evidence['failed_link_still_down'] and evidence['topology_unchanged']
                    and evidence['flow_rules_present'] and evidence['alternate_path_counters_positive'])
        if not verified:
            raise RuntimeError('Alternate route did not pass 56/56 connectivity checks with failed link down')
        return dict(ok=True, verified=True, recovery_status='RECOVERED',
                    action='restore_link', verification=evidence)
    except Exception as exc:
        evidence['action_error'] = str(exc)
        rollback_errors = []
        for switch in installed:
            try:
                run(['ovs-ofctl', '-O', 'OpenFlow13', '--timeout=4', 'del-flows', switch,
                     'cookie=%s/-1' % hex(cookie)])
            except Exception as rollback:
                rollback_errors.append('%s: %s' % (switch, rollback))
        evidence['rollback_errors'] = rollback_errors
        return dict(ok=False, verified=False,
                    recovery_status='UNVERIFIED' if rollback_errors else 'FAILED',
                    failure_reason=str(exc), verification=evidence)


def remove_link_recovery_flows(network):
    """Explicit manual link restoration removes only this module's cookie namespace."""
    for switch in network.switches:
        command(['ovs-ofctl', '-O', 'OpenFlow13', '--timeout=4', 'del-flows', switch.name,
                 'cookie=%s/%s' % (hex(COOKIE_PREFIX), hex(COOKIE_MASK))])
