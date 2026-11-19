"""Shared fail-closed recovery power gate. No process restarts; no network activity.

OFF blocks new permits. An already accepted operation drains under its shared lock;
status remains STOPPING until it exits. OFF is displayed only after it has drained.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import uuid
from recovery_history import atomic_json

POWER_FILE = Path(__file__).resolve().parent / 'logs/recovery_power.json'


class PowerDisabled(RuntimeError):
    pass


class PowerConflict(RuntimeError):
    pass


def path_for(path=None):
    return Path(path) if path is not None else POWER_FILE


def raw_state(path=None):
    try:
        data = json.loads(path_for(path).read_text())
        if (not isinstance(data, dict) or type(data.get('enabled')) is not bool or type(data.get('revision')) is not int
                or data['revision'] < 1):
            raise ValueError('Invalid gate schema')
        return dict(data, valid=True)
    except (OSError, ValueError, TypeError):
        return dict(enabled=False, revision=0, valid=False,
                    error='Power state missing/unreadable/invalid; automatic recovery is blocked')


def dispatch_busy(path=None):
    lock = path_for(path).with_suffix('.dispatch.lock')
    try:
        with lock.open('r') as stream:
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        return False
    except OSError:
        return False


def status(path=None):
    data = raw_state(path)
    busy = dispatch_busy(path)
    return dict(data, requested_enabled=data['enabled'], accepting_new_recoveries=data['enabled'],
                in_flight=busy, state=('ON' if data['enabled'] else 'STOPPING' if busy else 'OFF'),
                source='shared_power_file', detail=(
                    'ON: supported classified faults may execute through the recovery engine' if data['enabled'] else
                    'STOPPING: new actions blocked; an accepted operation is finishing safely' if busy else
                    'OFF: detection/classification continue; no automatic actions are permitted'))


def is_enabled(path=None):
    # Environment variables cannot override a dashboard OFF or a damaged/missing file.
    return raw_state(path)['enabled']


def set_enabled(enabled, expected_revision=None, path=None, actor='dashboard'):
    if type(enabled) is not bool:
        raise ValueError('enabled must be a JSON boolean')
    if expected_revision is not None and (type(expected_revision) is not int or expected_revision < 0):
        raise ValueError('expected_revision must be a non-negative integer')
    path = path_for(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    state_lock = path.with_suffix('.state.lock')
    with state_lock.open('a') as stream:
        os.chmod(state_lock, 0o600)
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        current = raw_state(path)
        if expected_revision is not None and expected_revision != current['revision']:
            raise PowerConflict('Power state changed; refresh before retrying')
        if enabled and not current['enabled'] and dispatch_busy(path):
            raise PowerConflict('An operation is draining; wait until OFF before enabling again')
        dispatch = path.with_suffix('.dispatch.lock')
        with dispatch.open('a'):
            os.chmod(dispatch, 0o600)
        if current['valid'] and current['enabled'] == enabled:
            return status(path)
        stamp = datetime.now(timezone.utc).isoformat()
        record = dict(enabled=enabled, revision=current['revision'] + 1, changed_at=stamp,
                      actor=actor, actor_uid=os.getuid(), actor_pid=os.getpid())
        atomic_json(path, record)
        audit = dict(record, event_id=uuid.uuid4().hex)
        audit_path = path.with_suffix('.audit.jsonl')
        fd = os.open(str(audit_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, 'a') as log:
            os.fchmod(log.fileno(), 0o600)
            log.write(json.dumps(audit) + '\n')
            log.flush()
            os.fsync(log.fileno())
        return status(path)


@contextmanager
def execution_permit(path=None):
    path = path_for(path)
    try:
        stream = path.with_suffix('.dispatch.lock').open('r')
    except OSError as exc:
        raise PowerDisabled('Power lock unavailable; action blocked') from exc
    with stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
        state = raw_state(path)
        if not state['enabled']:
            raise PowerDisabled('MAIN POWER is OFF; automatic action blocked')
        yield state
