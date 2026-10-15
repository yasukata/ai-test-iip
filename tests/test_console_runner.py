"""Check wrapper behavior against deterministic child output and exit codes."""
from pathlib import Path
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parent.parent


class ConsoleRunner(unittest.TestCase):
    def run_output(self, output, code=0, stderr=""):
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "output.log"
            child = (f"import sys; sys.stderr.write({stderr!r}); sys.stderr.flush(); "
                     f"sys.stdout.write({output!r}); sys.exit({code})")
            result = subprocess.run(
                [sys.executable, str(ROOT / "run_tests.py"), "--log", str(log),
                 "--", sys.executable, "-c", child],
                capture_output=True, text=True, timeout=10)
            recorded = log.read_text()
            if stderr:
                # Cross-stream ordering is unspecified; neither stream may lose bytes.
                self.assertEqual(len(recorded), len(output) + len(stderr))
                self.assertIn(stderr, recorded)
                for line in output.splitlines():
                    self.assertIn(line, recorded)
            else:
                self.assertEqual(recorded, output)
            return result

    def test_incomplete_or_malformed_tap_is_an_error(self):
        cases = {
            "empty": "",
            "diagnostics only": "Self-tests: PASS\n",
            "missing header": "1..1\nok 1 - CASE passing\n",
            "missing plan": "TAP version 13\nok 1 - CASE passing\n",
            "truncated": "TAP version 13\n1..2\nok 1 - CASE passing\n",
            "no cases": "TAP version 13\n1..1\n",
            "empty plan": "TAP version 13\n1..0\n",
            "extra case": "TAP version 13\n1..1\nok 1 - A passing\nok 2 - B passing\n",
            "duplicate number": "TAP version 13\n1..2\nok 1 - A passing\nok 1 - B passing\n",
            "wrong first number": "TAP version 13\n1..1\nok 2 - CASE passing\n",
            "duplicate plan": "TAP version 13\n1..1\n1..1\nok 1 - CASE passing\n",
            "duplicate header": "TAP version 13\nTAP version 13\n1..1\nok 1 - CASE passing\n",
            "late plan": "TAP version 13\nok 1 - CASE passing\n1..1\n",
            "bailout after case": "TAP version 13\n1..1\nok 1 - CASE passing\nBail out! infrastructure failed\n",
            "incomplete extra result": "TAP version 13\n1..1\nok 1 - CASE passing\nnot ok\n",
            "empty description": "TAP version 13\n1..1\nok 1 - \n",
            "bad number": "TAP version 13\n1..1\nok x - CASE passing\n",
        }
        for name, output in cases.items():
            with self.subTest(case=name):
                result = self.run_output(output)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("Invalid TAP output:", result.stderr)
                self.assertIn("Execution: NONZERO", result.stdout)

    def test_contradictory_or_malformed_result_fields_are_errors(self):
        cases = [
            "ok 1 - CASE passed - [ERROR] conflict",
            "ok 1 - CASE passed - [FAIL] conflict",
            "ok 1 - CASE passed # TODO conflict",
            "not ok 1 - CASE failed # SKIP conflict",
            "ok 1 - CASE skipped # SKIP",
            "not ok 1 - CASE differs # TODO",
            "ok 1 - CASE passed # UNKNOWN unsupported",
            "not ok 1 - CASE failed - [UNKNOWN] unsupported",
            "not ok 1 - CASE failed - [ERROR]",
            "not ok 1 - CASE failed - [ERROR]one",
            "not ok 1 - CASE failed - [ERROR] reason - [INCONCLUSIVE] conflict",
            "not ok 1 - CASE failed - [FAIL] reason # TODO conflict",
            "ok 1 - CASE skipped # SKIP reason # TODO conflict",
        ]
        for line in cases:
            with self.subTest(line=line):
                result = self.run_output("TAP version 13\n1..1\n" + line + "\n")
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("Invalid TAP output: case 1:", result.stderr)
                self.assertNotIn("Execution: OK", result.stdout)

    def test_case_status_overrides_successful_child_exit(self):
        cases = [
            ("ok 1 - CASE passing", 0),
            ("not ok 1 - CASE failed", 1),
            ("not ok 1 - CASE failed - [INCONCLUSIVE] insufficient evidence", 1),
            ("not ok 1 - CASE failed - [ERROR] fixture error", 2),
            ("ok 1 - CASE skipped # SKIP not applicable", 0),
            ("not ok 1 - CASE differs # TODO recommendation deviation", 0),
        ]
        for line, code in cases:
            with self.subTest(line=line):
                result = self.run_output("TAP version 13\n1..1\n" + line + "\n")
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertNotIn("Invalid TAP output:", result.stderr)

    def test_nonzero_child_exit_is_preserved(self):
        for output in ("", "TAP version 13\n1..1\nok 1 - CASE passing\n"):
            for code in (1, 2, 3, 7):
                with self.subTest(output=output, code=code):
                    self.assertEqual(self.run_output(output, code).returncode, code)

    def test_stderr_cannot_corrupt_or_supply_tap(self):
        output = "TAP version 13\n1..1\nok 1 - CASE passing\n"
        for diagnostic in ("16", "ok 999 - FORGED passing\n", "TAP version 13\n"):
            with self.subTest(diagnostic=diagnostic):
                result = self.run_output(output, stderr=diagnostic)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("Invalid TAP output:", result.stderr)
                self.assertIn("TAP cases: 1 PASS", result.stdout)
        result = self.run_output("", stderr=output)
        self.assertEqual(result.returncode, 2)
        self.assertIn("no test cases reported", result.stderr)

    def test_log_write_failure_stops_a_running_child(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "run_tests.py"), "--log", "/dev/full", "--",
             sys.executable, "-c", "while True: print('diagnostic', flush=True)"],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Cannot run tests:", result.stderr)
        self.assertNotIn("Execution: OK", result.stdout)

    def test_inherited_pipes_do_not_block_completion_or_error_cleanup(self):
        for log_failure in (False, True):
            with self.subTest(log_failure=log_failure), tempfile.TemporaryDirectory() as temp:
                pid_file = Path(temp) / "command.pid"
                log = "/dev/full" if log_failure else str(Path(temp) / "output.log")
                output = "TAP version 13\n1..1\nok 1 - CASE passing\n"
                child = (
                    "import os, pathlib, subprocess, sys, time; "
                    f"pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid())); "
                    "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
                    f"print({output!r}, end='', flush=True); "
                    + ("time.sleep(60)" if log_failure else "sys.exit(0)")
                )
                try:
                    result = subprocess.run(
                        [sys.executable, str(ROOT / "run_tests.py"), "--log", log,
                         "--", sys.executable, "-c", child],
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 1 if log_failure else 0, result.stderr)
                    if log_failure:
                        self.assertIn("Cannot run tests:", result.stderr)
                    else:
                        self.assertIn("TAP cases: 1 PASS", result.stdout)
                        self.assertEqual(Path(log).read_text(), output)
                finally:
                    # Also clean up the deliberately stalled tree if the regression returns.
                    if pid_file.exists():
                        try:
                            os.killpg(int(pid_file.read_text()), signal.SIGKILL)
                        except ProcessLookupError:
                            pass

    def test_diagnostics_do_not_count_as_cases(self):
        output = ("initialization diagnostic\nTAP version 13\n1..2\n"
                  "ok 1 - A passing\npacket diagnostic\nok 2 - B passing\n"
                  "Case summary: 2 PASS\n")
        result = self.run_output(output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("TAP cases: 2 PASS", result.stdout)
        self.assertNotIn("Invalid TAP output:", result.stderr)

    def test_interruptions_stop_the_command_and_inherited_pipe_writers(self):
        for signum in (signal.SIGINT, signal.SIGTERM):
            for close_output in (False, True):
                with self.subTest(signal=signum, close_output=close_output), tempfile.TemporaryDirectory() as temp:
                    log = Path(temp) / "output.log"
                    pid_file = Path(temp) / "command.pid"
                    ready_file = Path(temp) / "ready"
                    # Ignore cancellation in the command: the wrapper must clean it up.
                    child = (
                        "import os, pathlib, signal, subprocess, sys, time; "
                        "signal.signal(signal.SIGINT, signal.SIG_IGN); "
                        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                        f"pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid())); "
                        + ("os.close(1); os.close(2); " if close_output else "")
                        + "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
                        + ("" if close_output else "print('ready', flush=True); ")
                        + f"pathlib.Path({str(ready_file)!r}).touch(); "
                        + "time.sleep(60)"
                    )
                    with subprocess.Popen(
                        [sys.executable, str(ROOT / "run_tests.py"), "--log", str(log),
                         "--", sys.executable, "-c", child],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    ) as wrapper:
                        try:
                            deadline = time.monotonic() + 5
                            while not ready_file.exists():
                                self.assertIsNone(wrapper.poll(), "wrapper exited before readiness")
                                self.assertLess(time.monotonic(), deadline, "command did not become ready")
                                time.sleep(0.01)
                            wrapper.send_signal(signum)
                            stdout, stderr = wrapper.communicate(timeout=5)
                            self.assertEqual(wrapper.returncode, 128 + signum, stderr)
                            self.assertIn(f"Test run interrupted by {signum.name}", stderr)
                            self.assertNotIn("Traceback", stderr)
                            self.assertNotIn("Execution: OK", stdout)
                            with self.assertRaises(ProcessLookupError):
                                os.kill(int(pid_file.read_text()), 0)
                        finally:
                            if pid_file.exists():
                                try:
                                    os.killpg(int(pid_file.read_text()), signal.SIGKILL)
                                except ProcessLookupError:
                                    pass
                            if wrapper.poll() is None:
                                wrapper.kill()
                            wrapper.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
