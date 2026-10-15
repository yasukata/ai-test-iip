"""Exercise externally visible reporting contracts against the built harness."""
import json
import os
import shlex
import sys
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent

class HarnessRun:
    binary = ROOT / "ai-test-iip"

    def run_case(self, *args):
        with tempfile.TemporaryDirectory() as temp:
            dest = Path(temp)/'result.json'
            r = subprocess.run([str(self.binary), *args, '--json',str(dest)],capture_output=True,text=True)
            return r, json.loads(dest.read_text()) if dest.exists() else None

class Reporting(HarnessRun, unittest.TestCase):
    def test_independent_case_and_tap_plan(self):
        r,j = self.run_case('--case','MUST-7')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn('1..1\n',r.stdout)
        self.assertEqual([c['id'] for c in j['cases']],['MUST-7'])
        self.assertEqual(j['conformance'],'NOT_ESTABLISHED')

    def test_unknown_case_is_error(self):
        r,j = self.run_case('--case','DOES-NOT-EXIST')
        self.assertEqual(r.returncode,2)
        self.assertIsNone(j)

    def test_additional_profiles_run_by_default(self):
        r,j = self.run_case('--case','ROBUST-6','--case','ROBUST-10')
        self.assertIsNotNone(j, r.stderr)
        self.assertTrue(j['configuration']['strict_api'])
        self.assertTrue(j['configuration']['blake2'])
        self.assertEqual(len(j['cases']), 2)
        for case in j['cases']:
            self.assertNotEqual(case['status'], 'NOT_APPLICABLE', case)

    def test_disabled_profile_has_reason(self):
        r,j = self.run_case('--case','TFO-2A','--no-tfo')
        self.assertEqual(r.returncode,0)
        self.assertEqual(j['cases'][0]['status'],'NOT_APPLICABLE')
        self.assertTrue(j['cases'][0]['reason'])

    def test_partial_coverage_cannot_certify(self):
        r,j = self.run_case('--case','MUST-3','--conformance')
        self.assertEqual(j['cases'][0]['status'],'PASS')
        self.assertEqual(r.returncode,3)

    def test_json_write_error(self):
        r = subprocess.run([str(ROOT/'ai-test-iip'),'--case','MUST-3','--json','/dev/full'],capture_output=True)
        self.assertEqual(r.returncode,2)

class SyntheticReporting(HarnessRun, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory(prefix="iip-reporting-")
        cls.addClassCleanup(temp.cleanup)
        cls.binary = Path(temp.name) / "reporting-harness"
        command = shlex.split(os.environ.get("CC", "cc"))
        subprocess.run(command + ["-std=gnu11", "-O0", "-g", "-o", str(cls.binary),
                       str(ROOT / "tests/reporting_harness.c")], check=True,
                       capture_output=True, text=True)

    def test_stdout_write_failure_is_recorded_in_json(self):
        for identifier, status in [("PASS", "PASS"), ("FAIL", "FAIL"), ("ERROR", "ERROR")]:
            with self.subTest(case=identifier), tempfile.TemporaryDirectory() as temp:
                dest = Path(temp) / "result.json"
                with open("/dev/full", "w") as output:
                    result = subprocess.run(
                        [str(self.binary), "--case", identifier, "--json", str(dest)],
                        stdout=output, stderr=subprocess.PIPE, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn("Cannot write test output to stdout", result.stderr)
                report = json.loads(dest.read_text())
                self.assertEqual(report["exit_code"], 2)
                self.assertEqual(report["cases"][0]["status"], status)

    def test_list_reports_stdout_failure(self):
        with open("/dev/full", "w") as output:
            result = subprocess.run([str(self.binary), "--list"], stdout=output,
                                    stderr=subprocess.PIPE, text=True)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("Cannot write test output to stdout", result.stderr)

    def test_status_mapping_and_exit_codes(self):
        cases = [
            ("PASS", "PASS", 0, "ok"),
            ("FAIL", "FAIL", 1, "not ok"),
            ("SKIP", "NOT_APPLICABLE", 0, "ok"),
            ("EMPTY-SKIP", "ERROR", 2, "not ok"),
            ("TODO", "DEVIATION", 0, "not ok"),
            ("MANDATORY-TODO", "INCONCLUSIVE", 1, "not ok"),
            ("SHOULD-FAIL", "DEVIATION", 0, "not ok"),
            ("INCONCLUSIVE", "INCONCLUSIVE", 1, "not ok"),
            ("ERROR", "ERROR", 2, "not ok"),
            ("INVALID", "ERROR", 2, "not ok"),
            ("SIGNAL", "FAIL", 1, "not ok"),
        ]
        for identifier, status, code, tap in cases:
            with self.subTest(case=identifier):
                result, report = self.run_case("--case", identifier)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertEqual(report["exit_code"], code)
                self.assertEqual(report["cases"][0]["status"], status)
                self.assertEqual(report["summary"][status.lower()], 1)
                self.assertEqual(sum(report["summary"].values()), 1)
                self.assertIn(f"{tap} 1 - {identifier} ", result.stdout)
                self.assertIn("1..1\n", result.stdout)
                if status != "PASS":
                    self.assertTrue(report["cases"][0]["reason"])
                if status == "NOT_APPLICABLE":
                    self.assertIn(" # SKIP ", result.stdout)
                if status == "DEVIATION":
                    self.assertIn(" # TODO ", result.stdout)

    def test_error_takes_precedence_and_later_cases_run(self):
        result, report = self.run_case("--case", "FAIL", "--case", "ERROR",
                                       "--case", "SIGNAL", "--case", "REQUIRE")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(len(report["cases"]), 4)
        self.assertEqual(report["cases"][-1]["id"], "REQUIRE")
        self.assertEqual(report["summary"]["fail"], 3)
        self.assertEqual(report["summary"]["error"], 1)

    def test_condition_details_reach_reports_without_leaking(self):
        for identifier, detail in [("CONDITION", "expected=1, actual=2"),
                                   ("REQUIRE", "expected=3, actual=4")]:
            with self.subTest(case=identifier):
                result, report = self.run_case("--case", identifier)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(report["cases"][0]["reason"], detail)
                self.assertIn(detail, result.stdout)
                self.assertIn(detail, result.stderr)
        result, report = self.run_case("--case", "CONDITION", "--case", "EMPTY-SKIP")
        self.assertEqual([c["id"] for c in report["cases"]], ["CONDITION", "EMPTY-SKIP"])
        reasons = {c["id"]: c["reason"] for c in report["cases"]}
        self.assertEqual(reasons["EMPTY-SKIP"], "missing applicability reason")

    def test_json_escapes_reason(self):
        _, report = self.run_case("--case", "ESCAPED")
        self.assertEqual(report["cases"][0]["reason"], 'quoted "reason"\nnext\tfield\\end')

    def test_tap_free_text_cannot_add_records_or_directives(self):
        reason = 'first\nnot ok 999 - forged # SKIP ignored # TODO ignored\r\t\x1b[31m\x7f\\tail'
        cases = [("TAP-FAIL", "FAIL", 1, None),
                 ("TAP-SKIP", "NOT_APPLICABLE", 0, "SKIP"),
                 ("TAP-TODO", "DEVIATION", 0, "TODO")]
        for identifier, status, code, directive in cases:
            with self.subTest(case=identifier):
                result, report = self.run_case("--case", identifier)
                self.assertEqual(result.returncode, code)
                self.assertEqual(report["cases"][0]["status"], status)
                self.assertEqual(report["cases"][0]["reason"], reason)
                lines = result.stdout.splitlines()
                self.assertEqual(len(lines), 3, result.stdout)
                self.assertEqual(lines[:2], ["TAP version 13", "1..1"])
                self.assertFalse(any(ord(c) < 32 or ord(c) == 127 for c in lines[2]))
                self.assertIn(r'description\n \x23 TODO fake', lines[2])
                self.assertIn(r'first\nnot ok 999 - forged \x23 SKIP ignored \x23 TODO ignored', lines[2])
                self.assertIn(r'\r\t\x1b[31m\x7f\\tail', lines[2])
                self.assertEqual(lines[2].count(" # SKIP "), int(directive == "SKIP"))
                self.assertEqual(lines[2].count(" # TODO "), int(directive == "TODO"))

    def test_console_wrapper_preserves_status_with_special_text(self):
        cases = [("TAP-FAIL", 1, "1 FAIL", "0 NOT_APPLICABLE", "0 DEVIATION"),
                 ("TAP-SKIP", 0, "0 FAIL", "1 NOT_APPLICABLE", "0 DEVIATION"),
                 ("TAP-TODO", 0, "0 FAIL", "0 NOT_APPLICABLE", "1 DEVIATION")]
        for identifier, code, failures, skipped, deviations in cases:
            with self.subTest(case=identifier), tempfile.TemporaryDirectory() as temp:
                log = Path(temp) / "output.log"
                result = subprocess.run(
                    [sys.executable, str(ROOT / "run_tests.py"), "--log", str(log),
                     "--", str(self.binary), "--case", identifier],
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, code, result.stderr)
                summary = next(line for line in result.stdout.splitlines()
                               if line.startswith("TAP cases:"))
                self.assertIn(failures, summary)
                self.assertIn(skipped, summary)
                self.assertIn(deviations, summary)
                self.assertEqual(len(log.read_text().splitlines()), 4)

    def test_conformance_exit_requires_otherwise_successful_run(self):
        for identifier, code in [("PASS", 3), ("FAIL", 1), ("ERROR", 2)]:
            with self.subTest(case=identifier):
                result, report = self.run_case("--case", identifier, "--conformance")
                self.assertEqual(result.returncode, code)
                self.assertEqual(report["conformance"], "NOT_ESTABLISHED")


if __name__ == '__main__':
    unittest.main()
