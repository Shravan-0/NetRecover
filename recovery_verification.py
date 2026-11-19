"""Bounded real probes shared by recovery actions. No network activity at import."""
import subprocess
import time


def http_probe(host, url):
    proc = host.popen(['curl', '--silent', '--show-error', '--connect-timeout', '1',
                       '--max-time', '2', '--output', '/dev/null', '--write-out', '%{http_code}', url],
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        output, error = proc.communicate(timeout=3)
        code = output.decode(errors='replace').strip()
        return dict(source=host.name, url=url, http_status=code,
                    passed=proc.returncode == 0 and code == '200',
                    error=error.decode(errors='replace')[-500:])
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return dict(source=host.name, url=url, http_status='000', passed=False,
                    error='HTTP probe timed out')


def connectivity(hosts, ping, timeout=90, clock=time.monotonic, sleep=time.sleep):
    """Require one complete successful 56-pair sweep; tolerate bounded STP convergence.

    Never combine old successful pairs from different sweeps into a fake all-pass.
    timeout=0 requests exactly one sweep (used by isolated tests).
    """
    hosts = sorted(hosts, key=lambda node: node.name)
    if {node.name for node in hosts} != {'h%s' % n for n in range(1, 9)}:
        raise RuntimeError('Expected the existing eight Mininet hosts')
    deadline = clock() + timeout
    sweeps = []
    while True:
        checks = []
        for source in hosts:
            for target in hosts:
                if source is target:
                    continue
                if timeout > 0 and clock() >= deadline:
                    break
                checks.append(ping(source, target))
            if timeout > 0 and clock() >= deadline:
                break
        passed = sum(row.get('passed') is True for row in checks)
        sweeps.append(dict(passed=passed, total=len(checks)))
        verified = passed == len(checks) == 56
        if verified or timeout <= 0 or clock() >= deadline:
            return dict(verified=verified, passed=passed, total=len(checks), checks=checks,
                        sweeps=sweeps, convergence_timeout_seconds=timeout)
        sleep(min(1, max(0, deadline - clock())))
