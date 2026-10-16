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
