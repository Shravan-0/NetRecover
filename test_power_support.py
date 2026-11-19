"""Test fixture: operate on real power files only inside TemporaryDirectory fixtures."""
from contextlib import contextmanager
from pathlib import Path
from unittest import mock
import power_control
import recovery_executor as executor


@contextmanager
def temporary_gate(enabled, status_file=None):
    path = Path(status_file) if status_file is not None else executor.STATUS_FILE
    if path.resolve().parent == (Path(executor.__file__).resolve().parent / 'logs'):
        raise AssertionError('A gate test must explicitly use a temporary status path')
    with mock.patch.object(executor, 'STATUS_FILE', path):
        gate = path.with_name('recovery_power.json')
        before = power_control.raw_state(gate)['enabled']
        power_control.set_enabled(enabled, path=gate, actor='isolated_test_fixture')
        try:
            yield
        finally:
            power_control.set_enabled(before, path=gate, actor='isolated_test_fixture')
