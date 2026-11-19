"""Transactional incident history. SQLite is authoritative; JSON is a compatibility view.

No live network operations occur here. All write transactions use BEGIN IMMEDIATE.
"""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from datetime import datetime, timezone
import uuid

STATUSES = {"DETECTED", "CLASSIFIED", "RECOVERING", "RECOVERED", "FAILED", "UNVERIFIED"}
LEGACY = {"RECOVERING": "running", "RECOVERED": "success", "FAILED": "failed",
          "UNVERIFIED": "unverified", "DETECTED": "detected", "CLASSIFIED": "classified"}


def now():
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def owner_identity(pid=None):
    pid = os.getpid() if pid is None else pid
    raw = Path('/proc/%s/stat' % pid).read_text()
    fields = raw.rsplit(') ', 1)[1].split()
    return {"pid": pid, "start": fields[19], "state": fields[0],
            "boot": Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


def owner_alive(owner):
    try:
        current = owner_identity(owner['pid'])
        return (current['start'] == owner['start'] and current['boot'] == owner['boot']
                and current['state'] not in ('Z', 'X'))
    except (FileNotFoundError, ProcessLookupError):
        return False
    except (OSError, KeyError, IndexError, ValueError):
        return True  # Insufficient evidence: never steal a possibly live attempt.


class History:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.transaction() as db:
            schema = '''
                CREATE TABLE IF NOT EXISTS incidents(
                    id TEXT PRIMARY KEY, incident_key TEXT NOT NULL,
                    active INTEGER NOT NULL, data TEXT NOT NULL);
                CREATE UNIQUE INDEX IF NOT EXISTS one_active_incident
                    ON incidents(incident_key) WHERE active=1;
                CREATE TABLE IF NOT EXISTS attempts(
                    id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(id),
                    data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS events(
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT NOT NULL REFERENCES incidents(id),
                    recorded_at TEXT NOT NULL, status TEXT NOT NULL, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            '''
            for statement in schema.split(';'):
                if statement.strip():
                    db.execute(statement)

    @contextlib.contextmanager
    def transaction(self):
        db = sqlite3.connect(str(self.path), timeout=15)
        try:
            db.execute('PRAGMA foreign_keys=ON')
            db.execute('PRAGMA synchronous=FULL')
            db.execute('PRAGMA busy_timeout=15000')
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _event(db, record, status, detail=None):
        if status not in STATUSES:
            raise ValueError('Invalid recovery status')
        db.execute('INSERT INTO events(incident_id,recorded_at,status,data) VALUES(?,?,?,?)',
                   (record['incident_id'], now(), status, json.dumps(detail or {})))

    @staticmethod
    def _save(db, record):
        db.execute('UPDATE incidents SET active=?,data=? WHERE id=?',
                   (int(record['active']), json.dumps(record), record['incident_id']))

    def import_legacy(self, path):
        """Preserve old records once, without presenting old claims as fresh verification."""
        with self.transaction() as db:
            if db.execute("SELECT 1 FROM metadata WHERE key='legacy_imported'").fetchone():
                return
            source = Path(path)
            if source.exists():
                data = json.loads(source.read_text())  # Invalid source: fail closed, don't overwrite.
                records = data.get('attempts', data.get('active_attempts', []))
                if not isinstance(records, list):
                    raise ValueError('Invalid legacy recovery history')
                for old in records:
                    if not isinstance(old, dict) or not old.get('incident_key'):
                        continue
                    key = old['incident_key']
                    if db.execute('SELECT 1 FROM incidents WHERE incident_key=? AND active=1', (key,)).fetchone():
                        continue
                    iid = uuid.uuid4().hex
                    # Historical successes are retained, with their original evidence/provenance.
                    status = {'success': 'RECOVERED', 'failed': 'FAILED'}.get(old.get('status'), 'UNVERIFIED')
                    rec = dict(old, incident_id=iid, incident_key=key, active=True,
                               status=status, recovery_status=status, legacy_imported=True,
                               verification=old.get('verification', {'legacy_record': old}),
                               verification_provenance='legacy_report_not_rechecked',
                               detected_at=old.get('detected_at', old.get('started_at', now())),
                               automatic_recovery_enabled=old.get('automatic_recovery_enabled'),
                               failure_reason=old.get('error'), completed_at=old.get('finished_at'))
                    db.execute('INSERT INTO incidents VALUES(?,?,1,?)', (iid, key, json.dumps(rec)))
                    self._event(db, rec, status, {'legacy_record': old})
                    attempt = self.compatible(dict(rec, attempt_id=uuid.uuid4().hex))
                    db.execute('INSERT INTO attempts VALUES(?,?,?)',
                               (attempt['attempt_id'], iid, json.dumps(attempt)))
                db.execute("INSERT OR REPLACE INTO metadata VALUES('legacy_source',?)", (json.dumps(data),))
            db.execute("INSERT INTO metadata VALUES('legacy_imported','true')")

    def observe(self, incidents, enabled, complete=True):
        ids = []
        with self.transaction() as db:
            seen = set()
            for item in incidents:
                if not isinstance(item, dict):
                    continue
                classification = item.get('classification', 'unclassified')
                key = item.get('incident_key') or '%s:%s' % (classification, item.get('target', 'unknown'))
                if key in seen:
                    continue
                seen.add(key)
                row = db.execute('SELECT data FROM incidents WHERE incident_key=? AND active=1', (key,)).fetchone()
                if row:
                    rec = json.loads(row[0])
                    rec.update(last_seen_at=now(), gate_last_observed=bool(enabled))
                    self._save(db, rec)
                else:
                    stamp = now()
                    iid = uuid.uuid4().hex
                    rec = dict(item, incident_id=iid, incident_key=key, active=True,
                               detected_at=item.get('detected_at') or stamp, last_seen_at=stamp,
                               affected_component=item.get('target', 'unknown'),
                               fault_type=item.get('fault_type') or classification,
                               classification=classification, automatic_recovery_enabled=bool(enabled),
                               gate_at_detection=bool(enabled), gate_last_observed=bool(enabled),
                               started_at=None, completed_at=None, recovery_action=None,
                               verification=None, verified=False, failure_reason=None,
                               blocked_reason=None if enabled else 'automatic_recovery_disabled',
                               status='DETECTED', recovery_status='DETECTED')
                    db.execute('INSERT INTO incidents VALUES(?,?,1,?)', (iid, key, json.dumps(rec)))
                    self._event(db, rec, 'DETECTED', {'gate_enabled': bool(enabled)})
                    if classification != 'unclassified':
                        rec.update(status='CLASSIFIED', recovery_status='CLASSIFIED')
                        self._event(db, rec, 'CLASSIFIED', {'classification': classification})
                        self._save(db, rec)
                ids.append((rec['incident_id'], item))
            if complete:
                for iid, key, raw in db.execute('SELECT id,incident_key,data FROM incidents WHERE active=1').fetchall():
                    rec = json.loads(raw)
                    if key not in seen and rec['status'] != 'RECOVERING':
                        rec.update(active=False, cleared_at=now())
                        self._save(db, rec)
        return ids

    def claim(self, iid, plan, enabled):
        if not enabled:
            return None
        with self.transaction() as db:
            row = db.execute('SELECT data FROM incidents WHERE id=?', (iid,)).fetchone()
            rec = json.loads(row[0])
            if not rec['active'] or rec['status'] != 'CLASSIFIED':
                return None
            attempt_id = uuid.uuid4().hex
            rec.update(status='RECOVERING', recovery_status='RECOVERING',
                       attempt_id=attempt_id, started_at=now(), owner=owner_identity(),
                       automatic_recovery_enabled=True, gate_at_execution=True,
                       power_revision=plan.get("power_revision"),
                       recovery_action=plan['action'], action=plan['action'],
                       blocked_reason=None)
            self._save(db, rec)
            self._event(db, rec, 'RECOVERING', {'plan': plan, 'attempt_id': attempt_id})
            db.execute('INSERT INTO attempts VALUES(?,?,?)',
                       (attempt_id, iid, json.dumps(self.compatible(rec))))
            return rec

    def finish(self, iid, status, result=None, reason=None):
        if status not in {'RECOVERED', 'FAILED', 'UNVERIFIED'}:
            raise ValueError('Invalid terminal state')
        with self.transaction() as db:
            rec = json.loads(db.execute('SELECT data FROM incidents WHERE id=?', (iid,)).fetchone()[0])
            if rec['status'] != 'RECOVERING':
                raise RuntimeError('Attempt is not running')
            stamp = now()
            rec.update(status=status, recovery_status=status, verified=status == 'RECOVERED',
                       completed_at=stamp, finished_at=stamp, failure_reason=reason,
                       error=reason, result=result, verification=(result or {}).get('verification', result))
            self._save(db, rec)
            self._event(db, rec, status, {'result': result, 'failure_reason': reason})
            output = self.compatible(rec)
            db.execute('UPDATE attempts SET data=? WHERE id=?', (json.dumps(output), rec['attempt_id']))
            return output

    def reconcile(self):
        with self.transaction() as db:
            rows = db.execute('SELECT data FROM incidents WHERE active=1').fetchall()
        for raw, in rows:
            rec = json.loads(raw)
            if rec['status'] == 'RECOVERING' and not owner_alive(rec.get('owner', {})):
                try:
                    self.finish(rec['incident_id'], 'UNVERIFIED', reason='Executor interrupted; action may have occurred. No automatic replay.')
                except RuntimeError:
                    pass  # Another reconciler already completed this transition.

    @staticmethod
    def compatible(record):
        result = dict(record)
        canonical = record.get('recovery_status', record.get('status'))
        result['recovery_status'] = canonical
        result['status'] = LEGACY.get(canonical, str(canonical).lower())
        return result

    def snapshot(self):
        with self.transaction() as db:
            incidents = [json.loads(row[0]) for row in db.execute('SELECT data FROM incidents ORDER BY rowid')]
            attempts = [json.loads(row[0]) for row in db.execute('SELECT data FROM attempts ORDER BY rowid')]
            events = [dict(seq=s, incident_id=i, recorded_at=t, status=k, detail=json.loads(d))
                      for s, i, t, k, d in db.execute('SELECT * FROM events ORDER BY seq')]
        active_ids = {r['incident_id'] for r in incidents if r['active']}
        return dict(updated_at=now(), attempts=attempts,
                    active_attempts=[r for r in attempts if r['incident_id'] in active_ids],
                    attempt_count=len(attempts), incidents=incidents, events=events,
                    history_database=str(self.path), schema_version=1)

    def export(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.with_name(path.name + '.export.lock').open('a') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                # Read inside the export lock: a late writer cannot publish an older snapshot.
                atomic_json(path, self.snapshot())
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
