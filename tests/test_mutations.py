"""Infrastructure failures remain explicit and do not discard later experiments."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'scripts'))
import check_mutations as mutations


class MutationReporting(unittest.TestCase):
    def test_failed_experiments_are_saved_and_later_experiments_run(self):
        errors = [subprocess.CalledProcessError(1, ['cc']),
                  subprocess.TimeoutExpired(['harness'], 40),
                  FileNotFoundError('missing JSON'),
                  json.JSONDecodeError('invalid JSON', '', 0)]
        for error in errors:
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                (root / 'iip').mkdir()
                for name in ('iip/main.c', 'test_tcp_window.h'):
                    (root / name).write_text('fixture')
                out = root / 'results'
                with patch.object(mutations, 'ROOT', root), \
                     patch.object(mutations, 'FILES', ['iip/main.c', 'test_tcp_window.h']), \
                     patch.object(mutations, 'EXPERIMENTS', [('broken', 'A', 'FAIL', 'target-defect'),
                                                          ('later', 'B', 'FAIL', 'target-defect')]), \
                     patch.object(mutations, 'run', side_effect=[error, ('PASS', 0), ('FAIL', 1)]), \
                     patch.object(mutations, 'mutate'), \
                     patch.object(sys, 'argv', ['mutations', '--output', str(out)]), \
                     contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(mutations.main(), 1)
                rows = json.loads((out / 'summary.json').read_text())
                self.assertEqual([r['actual'] for r in rows], ['ERROR', 'FAIL'])
                self.assertFalse(rows[0]['ok'])
                self.assertTrue(rows[1]['ok'])
                self.assertEqual(rows[0]['stage'], 'baseline')

    def test_stale_json_cannot_supply_a_missing_report(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'case.json').write_text('{"cases":[{"id":"A","status":"PASS"}],"exit_code":0}')
            with patch.object(mutations, 'run_command', return_value=subprocess.CompletedProcess([], 0)):
                with self.assertRaises(FileNotFoundError):
                    mutations.run(root, root, 'case', 'A')

    def test_survivor_and_inconclusive_are_not_detected(self):
        for actual, rc, outcome in [('PASS', 0, 'survived'),
                                    ('INCONCLUSIVE', 1, 'unresolved'),
                                    ('ERROR', 1, 'unresolved')]:
            with self.subTest(actual=actual), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                (root / 'iip').mkdir()
                for name in ('iip/main.c', 'test_tcp_window.h'):
                    (root / name).write_text('fixture')
                out = root / 'results'
                with patch.object(mutations, 'ROOT', root), \
                     patch.object(mutations, 'FILES', ['iip/main.c', 'test_tcp_window.h']), \
                     patch.object(mutations, 'EXPERIMENTS', [('defect', 'A', 'FAIL', 'target-defect')]), \
                     patch.object(mutations, 'run', side_effect=[('PASS', 0), (actual, rc)]), \
                     patch.object(mutations, 'mutate'), \
                     patch.object(sys, 'argv', ['mutations', '--output', str(out)]), \
                     contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(mutations.main(), 1)
                row = json.loads((out / 'summary.json').read_text())[0]
                self.assertEqual(row['outcome'], outcome)
                self.assertFalse(row['ok'])

    def test_abnormal_exit_is_not_assertion_detection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def command(*args, **kwargs):
                (root / 'case.json').write_text(json.dumps({
                    'cases': [{'id': 'A', 'status': 'FAIL', 'execution': 'signal'}], 'exit_code': -11}))
                return subprocess.CompletedProcess([], -11)
            with patch.object(mutations, 'run_command', side_effect=command):
                with self.assertRaisesRegex(ValueError, 'normal assertion'):
                    mutations.run(root, root, 'case', 'A')

    def test_failing_baseline_never_reaches_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'iip').mkdir()
            (root / 'iip/main.c').write_text('fixture')
            out = root / 'results'
            with patch.object(mutations, 'ROOT', root), \
                 patch.object(mutations, 'FILES', ['iip/main.c']), \
                 patch.object(mutations, 'EXPERIMENTS', [('defect', 'A', 'FAIL', 'target-defect')]), \
                 patch.object(mutations, 'run', return_value=('FAIL', 1)), \
                 patch.object(mutations, 'mutate') as mutate, \
                 patch.object(sys, 'argv', ['mutations', '--output', str(out)]), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(mutations.main(), 1)
                mutate.assert_not_called()
            row = json.loads((out / 'summary.json').read_text())[0]
            self.assertEqual(row['outcome'], 'invalid-baseline')
            self.assertEqual(row['baseline'], 'FAIL')
            self.assertFalse(row['ok'])

    def test_phase9_ledger_links_match_experiments(self):
        ledger = json.loads((mutations.ROOT / 'requirements.json').read_text())
        linked = {(name, case['id']) for case in ledger['cases']
                  for name in case.get('mutation_experiments', [])}
        experiments = {(name, case) for name, case, _, _ in mutations.EXPERIMENTS
                       if name.startswith('p9_')}
        self.assertEqual(len(experiments), 10)
        self.assertEqual(linked, experiments)

    def test_phase9_oracle_dependencies(self):
        ledger = json.loads((mutations.ROOT / 'requirements.json').read_text())
        cases = {c['id']: c for c in ledger['cases']}
        self.assertIn('legacy-fixture', cases['MUTATION-SACK-INVALID']['oracle_dependencies'])
        self.assertIn('scripted-wire-peer', cases['MUTATION-EOF-CALLBACK']['oracle_dependencies'])

    def test_missing_execution_metadata_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def command(*args, **kwargs):
                (root / 'case.json').write_text(json.dumps({
                    'cases': [{'id': 'A', 'status': 'FAIL'}], 'exit_code': 1}))
                return subprocess.CompletedProcess([], 1)
            with patch.object(mutations, 'run_command', side_effect=command):
                with self.assertRaisesRegex(ValueError, 'execution=None'):
                    mutations.run_case(root / 'harness', root, 'case', 'A')
