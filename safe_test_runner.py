"""Explicit isolated test suite. Denies live service ports and network-control commands."""
import ipaddress
from pathlib import Path
import sys
import unittest

TESTS = ['test_link_state', 'test_service_recovery', 'test_controller_recovery',
         'test_recovery_history', 'test_link_recovery', 'test_recovery_executor',
         'test_phase3_integration', 'test_auto_recovery_gate', 'test_classify_fault',
         'test_recovery_engine', 'test_service_namespace', 'test_dashboard_phase1',
         'test_power_control', 'test_system_health']


def safety_fence(event, args):
    if event == 'socket.connect':
        address = args[1]
        if isinstance(address, tuple):
            host, port = address[:2]
            try:
                local = ipaddress.ip_address(host).is_loopback
            except ValueError:
                local = host == 'localhost'
            if not local or port in {8765, 5000, 6633, 8080, 8090}:
                raise RuntimeError('ISOLATED TEST SAFETY FENCE: live/external connection refused')
    if event == 'subprocess.Popen':
        executable = Path(args[0]).name
        if not (executable.startswith('python') or executable in ('node', 'nodejs')):
            raise RuntimeError('ISOLATED TEST SAFETY FENCE: network/system subprocess refused: ' + executable)


if __name__ == '__main__':
    sys.addaudithook(safety_fence)
    suite = unittest.defaultTestLoader.loadTestsFromNames(TESTS)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
