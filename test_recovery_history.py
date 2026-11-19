from test_power_support import temporary_gate
import power_control
"""Storage and concurrency tests. Only temporary files/processes; no live ACN APIs."""
import concurrent.futures
import json
import multiprocessing
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

from recovery_history import History, atomic_json, owner_identity
import recovery_executor as executor
from classify_fault import classify_evidence


def incident(key='link_failure:s2-s3'):
    return dict(classification='link_failure', target='s2-s3',
                incident_key=key, classification_confidence=1.0, detection_status='detected')


PLAN = dict(action='restore_link', target='s2-s3')


def write_worker(path, index):
    store = History(path)
    for i in range(4):
        store.observe([incident('worker:%s:%s' % (index, i))], False, complete=False)
        store.export(Path(path).with_suffix('.json'))


def claim_worker(path, iid, queue):
    store = History(path)
    queue.put(store.claim(iid, PLAN, True) is not None)


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'recovery_history.sqlite3'
        self.store = History(self.path)

    def test_detected_classified_gate_off_are_durable(self):
        self.store.observe([incident()], False)
        data = History(self.path).snapshot()
        self.assertEqual([e['status'] for e in data['events']], ['DETECTED', 'CLASSIFIED'])
        self.assertEqual(data['attempts'], [])
        self.assertFalse(data['incidents'][0]['automatic_recovery_enabled'])
        self.assertEqual(data['incidents'][0]['blocked_reason'], 'automatic_recovery_disabled')

    def test_gate_off_claim_refused(self):
        iid = self.store.observe([incident()], False)[0][0]
        self.assertIsNone(self.store.claim(iid, PLAN, False))
        self.assertEqual(self.store.snapshot()['attempts'], [])

    def test_clear_retains_successful_incident_attempt_and_events(self):
        iid = self.store.observe([incident()], True)[0][0]
        self.store.claim(iid, PLAN, True)
        self.store.finish(iid, 'RECOVERED', {'verification': {'passed': 56, 'total': 56}})
        self.store.observe([], True)
        snapshot = History(self.path).snapshot()
        self.assertEqual(snapshot['active_attempts'], [])
        self.assertEqual(snapshot['attempt_count'], 1)
        self.assertEqual(snapshot['attempts'][0]['recovery_status'], 'RECOVERED')
        self.assertEqual(snapshot['attempts'][0]['status'], 'success')
        self.assertFalse(snapshot['incidents'][0]['active'])
        self.assertEqual([e['status'] for e in snapshot['events']],
                         ['DETECTED', 'CLASSIFIED', 'RECOVERING', 'RECOVERED'])

    def test_recurrence_uses_new_id(self):
        first = self.store.observe([incident()], False)[0][0]
        self.store.observe([], False)
        second = self.store.observe([incident()], False)[0][0]
        self.assertNotEqual(first, second)

    def test_partial_observation_does_not_clear(self):
        first = self.store.observe([incident()], False)[0][0]
        self.store.observe([], False, complete=False)
        self.assertEqual(self.store.observe([incident()], False)[0][0], first)

    def test_restart_deduplicates_terminal_attempt(self):
        iid = self.store.observe([incident()], True)[0][0]
        self.store.claim(iid, PLAN, True)
        self.store.finish(iid, 'FAILED', reason='Actual connectivity failed')
        self.assertIsNone(History(self.path).claim(iid, PLAN, True))

    def test_live_attempt_is_not_stolen(self):
        iid = self.store.observe([incident()], True)[0][0]
        self.store.claim(iid, PLAN, True)
        History(self.path).reconcile()
        self.assertEqual(self.store.snapshot()['incidents'][0]['status'], 'RECOVERING')

    def test_interrupted_attempt_unverified_and_not_replayed(self):
        iid = self.store.observe([incident()], True)[0][0]
        self.store.claim(iid, PLAN, True)
        with mock.patch('recovery_history.owner_alive', return_value=False):
            History(self.path).reconcile()
        self.assertEqual(self.store.snapshot()['incidents'][0]['status'], 'UNVERIFIED')
        self.assertIsNone(self.store.claim(iid, PLAN, True))

    def test_unclassified_is_still_recorded(self):
        self.store.observe([dict(classification='unclassified', target='h2:8080')], False)
        self.assertEqual(self.store.snapshot()['incidents'][0]['status'], 'DETECTED')

    def test_legacy_history_is_retained_once(self):
        path = Path(self.tmp.name) / 'status.json'
        old = dict(incident(), status='success', verified=True, action='restore_link')
        path.write_text(json.dumps({'active_attempts': [old]}))
        self.store.import_legacy(path)
        self.store.import_legacy(path)
        self.store.observe([], False)
        self.store.export(path)
        data = json.loads(path.read_text())
        self.assertEqual(data['attempt_count'], 1)
        self.assertTrue(data['attempts'][0]['legacy_imported'])
        self.assertEqual(data['attempts'][0]['verification_provenance'], 'legacy_report_not_rechecked')
        self.assertEqual(data['attempts'][0]['classification'], old['classification'])

    def test_invalid_legacy_file_not_overwritten(self):
        path = Path(self.tmp.name) / 'status.json'
        path.write_text('broken JSON')
        with self.assertRaises(ValueError):
            self.store.import_legacy(path)
        self.assertEqual(path.read_text(), 'broken JSON')

    def test_concurrent_processes_preserve_records_and_json(self):
        ctx = multiprocessing.get_context('spawn')
        processes = [ctx.Process(target=write_worker, args=(str(self.path), i)) for i in range(4)]
        for process in processes:
            process.start()
        for process in processes:
            process.join(30)
            if process.is_alive():
                process.terminate()
                process.join()
                self.fail('Writer process timed out')
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(len(self.store.snapshot()['incidents']), 16)
        output = json.loads(self.path.with_suffix('.json').read_text())
        self.assertEqual(len(output['incidents']), 16)
        with sqlite3.connect(str(self.path)) as db:
            self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')

    def test_concurrent_processes_claim_only_once(self):
        iid = self.store.observe([incident()], True)[0][0]
        ctx = multiprocessing.get_context('spawn')
        queue = ctx.Queue()
        processes = [ctx.Process(target=claim_worker, args=(str(self.path), iid, queue)) for _ in range(4)]
        for process in processes:
            process.start()
        results = [queue.get(timeout=20) for _ in processes]
        for process in processes:
            process.join(20)
            self.assertEqual(process.exitcode, 0)
        queue.close()
        queue.join_thread()
        self.assertEqual(sum(results), 1)
        self.assertEqual(self.store.snapshot()['attempt_count'], 1)

    def test_unique_temporary_files_under_concurrent_writes(self):
        path = Path(self.tmp.name) / 'atomic.json'
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda n: atomic_json(path, {'writer': n}), range(40)))
        self.assertIn(json.loads(path.read_text())['writer'], range(40))
        self.assertEqual(list(Path(self.tmp.name).glob('*.tmp')), [])

    def test_owner_identity_contains_restart_protection(self):
        identity = owner_identity()
        self.assertEqual(identity['pid'], os.getpid())
        self.assertTrue(identity['start'])
        self.assertTrue(identity['boot'])


class ExecutorHistoryIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.status = Path(self.tmp.name) / 'recovery_status.json'
        patcher = mock.patch.object(executor, 'STATUS_FILE', self.status)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_gate_off_detection_classification_and_persistence(self):
        results = classify_evidence({'links': {'s2-s3': 'down'}})
        with temporary_gate(False), \
             mock.patch.object(executor, 'execute_plan') as run:
            executor.execute_recoveries(results)
        run.assert_not_called()
        saved = json.loads(self.status.read_text())
        self.assertEqual(saved['incidents'][0]['classification'], 'link_failure')
        self.assertEqual(saved['incidents'][0]['status'], 'CLASSIFIED')
        self.assertEqual(saved['attempt_count'], 0)

    def test_ack_without_real_verification_is_not_recovered(self):
        with temporary_gate(True), \
             mock.patch.object(executor, 'execute_plan', return_value={'ok': True}):
            outcomes = executor.execute_recoveries([incident()])
        self.assertEqual(outcomes[0]['recovery_status'], 'UNVERIFIED')
        self.assertFalse(outcomes[0]['verified'])

    def test_enable_after_gate_off_claims_same_incident(self):
        with temporary_gate(False):
            executor.execute_recoveries([incident()])
        first_id = json.loads(self.status.read_text())['incidents'][0]['incident_id']
        with temporary_gate(True), \
             mock.patch.object(executor, 'execute_plan', return_value={'verified': True}):
            outcomes = executor.execute_recoveries([incident()])
        self.assertEqual(outcomes[0]['incident_id'], first_id)
        self.assertTrue(outcomes[0]['gate_at_execution'])
        self.assertFalse(outcomes[0]['gate_at_detection'])

    def test_success_survives_clear_and_executor_memory_reset(self):
        with temporary_gate(True), \
             mock.patch.object(executor, 'execute_plan', return_value={'verified': True}) as run:
            executor.execute_recoveries([incident()])
            executor.ACTIVE_ATTEMPTS = {}
            executor.execute_recoveries([incident()])
            executor.execute_recoveries([])
        run.assert_called_once()
        self.assertEqual(json.loads(self.status.read_text())['attempt_count'], 1)

    def test_missing_observations_do_not_create_new_episode(self):
        with temporary_gate(False):
            executor.execute_recoveries([incident()])
            executor.execute_recoveries([], observation_complete=False)
            executor.execute_recoveries([incident()])
        self.assertEqual(len(json.loads(self.status.read_text())['incidents']), 1)

    def test_corrupt_database_blocks_execution(self):
        self.status.with_name('recovery_history.sqlite3').write_text('not sqlite')
        with temporary_gate(True), \
             mock.patch.object(executor, 'execute_plan') as run:
            with self.assertRaises(sqlite3.DatabaseError):
                executor.execute_recoveries([incident()])
        run.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
