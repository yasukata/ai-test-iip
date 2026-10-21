"""Coverage must remain independent of test selection, outcomes and provenance."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'scripts'))
import report_coverage as coverage


class CoverageReporting(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = (ROOT / 'requirements.json').read_bytes()
        cls.ledger = json.loads(raw)
        cls.digest = hashlib.sha256(raw).hexdigest()

    def result(self, case, status='PASS', execution='normal'):
        return dict({k: case[k] for k in ('id', 'requirement_id', 'coverage', 'oracle_class',
                                          'profile', 'strength', 'source')},
                    status=status, execution=execution, reason='example')

    def report(self, rows, digest=None):
        return coverage.build_report(self.ledger, self.digest,
                                     dict(ledger_sha256=digest or self.digest, cases=rows))

    def test_static_inventory_has_no_execution_claim(self):
        report = coverage.build_report(self.ledger, self.digest)
        self.assertEqual(report['counts']['reported_cases'], 0)
        self.assertEqual(report['counts']['passed_cases'], 0)
        self.assertEqual(report['counts']['unreported_cases'], len(self.ledger['cases']))
        self.assertEqual(set(report['counts']['coverage_entries']),
                         coverage.COVERAGE)
        self.assertEqual(report['counts']['coverage_entries']['fully-tested'], 0)

    def test_pass_never_upgrades_coverage(self):
        case = self.ledger['cases'][0]
        report = self.report([self.result(case)])
        entry = report['requirements'][case['requirement_id']][0]
        self.assertEqual(entry['coverage'], 'partial')
        self.assertEqual(report['conformance'], 'NOT_ESTABLISHED')
        self.assertEqual(report['counts']['passed_cases'], 1)

    def test_skip_and_crash_are_distinct_from_pass_and_missing(self):
        cases = self.ledger['cases'][:3]
        report = self.report([self.result(cases[0]),
                              self.result(cases[1], 'NOT_APPLICABLE', 'not-run'),
                              self.result(cases[2], 'FAIL', 'signal')])
        self.assertEqual(report['counts']['reported_cases'], 3)
        self.assertEqual(report['counts']['executed_cases'], 2)
        self.assertEqual(report['counts']['passed_cases'], 1)
        self.assertEqual(report['counts']['unreported_cases'], len(self.ledger['cases'])-3)
        self.assertEqual(report['requirements'][cases[1]['requirement_id']][0]['coverage'], 'partial')

    def test_reject_stale_unknown_duplicate_or_inconsistent_results(self):
        row = self.result(self.ledger['cases'][0])
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            self.report([row], 'old')
        for rows in ([row, row], [dict(row, id='UNKNOWN')],
                     [dict(row, execution='signal')], [dict(row, coverage='fully-tested')],
                     [dict(row, requirement_id='other')], [dict(row, execution=None)]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                self.report(rows)

    def test_fully_tested_requires_explicit_scope_and_completeness(self):
        ledger = copy.deepcopy(self.ledger)
        ledger['cases'][0]['coverage'] = 'fully-tested'
        with self.assertRaisesRegex(ValueError, 'bounded_scope'):
            coverage.validate(ledger)
        ledger['cases'][0].update(bounded_scope='enumerated conditions only',
                                  completeness_basis='every enumerated condition asserted')
        self.assertTrue(coverage.validate(ledger))

    def test_missing_normative_text_or_section_is_rejected(self):
        for key, value in [('requirement', ''), ('rfc_references', []),
                           ('rfc_references', [dict(rfc=9293, section=None)])]:
            ledger = copy.deepcopy(self.ledger)
            ledger['cases'][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                coverage.validate(ledger)

    def test_multiple_cases_for_requirement_remain_separate(self):
        report = coverage.build_report(self.ledger, self.digest)
        rows = report['requirements']['RFC9293:MUST-39']
        self.assertGreater(len(rows), 1)
        self.assertIn('PROFILE-SWS-RX', [row['id'] for row in rows])
        self.assertEqual(len({row['id'] for row in rows}), len(rows))

    def test_capture_attaches_results_and_removes_old_evidence(self):
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            command = [sys.executable, str(ROOT / 'scripts/capture_run.py'), '--output', temp, '--']
            result = subprocess.run(command + [str(ROOT / 'ai-test-iip'), '--case', 'MUST-3'],
                                    cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((Path(temp) / 'coverage.json').read_text())
            self.assertEqual(report['counts']['reported_cases'], 1)
            self.assertEqual(report['counts']['passed_cases'], 1)
            self.assertEqual(report['ledger_sha256'], self.digest)
            result = subprocess.run(command + [sys.executable, '-c', 'pass'],
                                    cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            for filename in ('results.json', 'coverage.json', 'coverage.md', 'requirements-report.json'):
                self.assertFalse((Path(temp) / filename).exists(), filename)

    def test_markdown_cannot_inject_table_rows(self):
        report = coverage.build_report(self.ledger, self.digest)
        first = next(iter(report['requirements'].values()))[0]
        first['requirement'] = 'a|b\n<script>'
        text = coverage.markdown(report)
        self.assertIn('a&#124;b<br>&lt;script&gt;', text)


if __name__ == '__main__':
    unittest.main()
