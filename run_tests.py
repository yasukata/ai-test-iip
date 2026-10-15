#!/usr/bin/env python3
"""Display harness results while retaining the complete diagnostic output."""

import argparse
import os
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import re
import queue
import signal
import threading
import subprocess
import sys
import time


class RunInterrupted(Exception):
    def __init__(self, signum):
        self.signum = signum


@contextmanager
def interruption_handlers():
    """Unwind process cleanup on both terminal and supervisor cancellation."""
    def interrupt(signum, frame):
        raise RunInterrupted(signum)

    previous = {signum: signal.signal(signum, interrupt)
                for signum in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def stop_process_group(process):
    """Stop the command and descendants that inherited its output pipes."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


@contextmanager
def output_lines(process):
    """Drain both pipes concurrently, retaining each line's source for parsing."""
    pending = queue.Queue()

    def read(stream, is_stdout):
        try:
            for line in stream:
                pending.put((is_stdout, line))
        except (OSError, ValueError) as error:
            pending.put((is_stdout, error))
        finally:
            pending.put((is_stdout, None))

    readers = [threading.Thread(target=read, args=(stream, is_stdout), daemon=True)
               for stream, is_stdout in ((process.stdout, True), (process.stderr, False))]
    for reader in readers:
        reader.start()

    def lines():
        finished = 0
        while finished < len(readers):
            # EOF depends on every inherited writer, not just the command itself.
            if process.poll() is not None:
                stop_process_group(process)
            try:
                is_stdout, line = pending.get(timeout=0.1)
            except queue.Empty:
                continue
            if line is None:
                finished += 1
            elif isinstance(line, Exception):
                raise OSError("cannot read test output") from line
            else:
                yield is_stdout, line

    try:
        yield lines()
    finally:
        # A logging/printing failure must not leave the child blocked on a pipe.
        stop_process_group(process)
        for reader in readers:
            reader.join()


@dataclass(frozen=True)
class CaseResult:
    number: int
    identifier: str
    description: str
    status: str


def parse_case(match):
    """Parse reserved result fields; free text is escaped by test_report.h."""
    ok = match[1] == "ok"
    description = match[3]
    body, separator, directive = description.partition(" # ")
    marker = body.partition(" - [")
    if separator:
        name, space, reason = directive.partition(" ")
        if name not in ("SKIP", "TODO") or not space or not reason.strip():
            raise ValueError("invalid or unexplained TAP directive")
        if " # " in directive or marker[1]:
            raise ValueError("conflicting TAP result fields")
        if (name == "SKIP") != ok:
            raise ValueError("TAP directive contradicts ok/not ok")
        status = "NOT_APPLICABLE" if name == "SKIP" else "DEVIATION"
    elif marker[1]:
        status, closing, reason = marker[2].partition("]")
        if status not in ("FAIL", "INCONCLUSIVE", "ERROR") or not closing:
            raise ValueError("invalid TAP status marker")
        if ok or not reason.startswith(" ") or not reason.strip() or " - [" in reason:
            raise ValueError("contradictory or malformed TAP status")
    else:
        status = "PASS" if ok else "FAIL"
    return CaseResult(int(match[2]), description.split()[0], description, status)


def case_group(identifier):
    for prefixes, group in (
        (("MUST-",), "RFC 9293"),
        (("IP4-", "ICMP-", "UDP-"), "IPv4 host"),
        (("TCP-",), "TCP extensions and resets"),
        (("ROBUST-",), "Robustness"),
        (("TFO-",), "TCP Fast Open"),
    ):
        if identifier.startswith(prefixes):
            return group
    return "Tests"


class TapRun:
    """Validate the nonempty, header/plan-first TAP stream emitted by our harness."""

    def __init__(self):
        self.header = False
        self.plan = None
        self.observed = 0
        self.errors = []

    def observe(self, text):
        if text == "TAP version 13":
            if self.header or self.plan is not None or self.observed:
                self.errors.append("duplicate or misplaced TAP header")
            self.header = True
            return None
        plan = re.fullmatch(r"1\.\.([0-9]+)", text)
        if plan:
            if not self.header or self.plan is not None or self.observed:
                self.errors.append("duplicate or misplaced TAP plan")
            try:
                self.plan = int(plan[1])
            except ValueError:
                self.errors.append("TAP plan exceeds the integer conversion limit")
            return None
        match = re.fullmatch(r"(not ok|ok) ([0-9]+) - (\S.*)", text)
        if match:
            if not self.header or self.plan is None:
                self.errors.append("case appeared before the TAP header and plan")
            self.observed += 1
            try:
                case = parse_case(match)
            except ValueError as error:
                self.errors.append(f"case {match[2]}: {error}")
                return None
            if case.number != self.observed:
                self.errors.append(f"expected case number {self.observed}, got {case.number}")
            return case
        if text.startswith("Bail out!"):
            self.errors.append("TAP bailout: " + text)
        elif text in ("ok", "not ok") or text.startswith(("TAP version ", "1..", "ok ", "not ok ")):
            self.errors.append("malformed TAP record: " + text)
        return None

    def problems(self):
        errors = list(self.errors)
        if not self.header:
            errors.append("missing TAP version 13 header")
        if self.plan is None:
            errors.append("missing TAP plan")
        elif self.plan != self.observed:
            errors.append(f"planned {self.plan} cases, observed {self.observed}")
        if not self.observed:
            errors.append("no test cases reported")
        return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verbose", action="store_true", help="show diagnostic lines too")
    parser.add_argument("--log", default="test-results.log", help="complete output log path")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command or ["./ai-test-iip"]
    if command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("a test command is required after --")

    tap = TapRun()
    counts = Counter()
    failures = []
    suite = None
    started = time.monotonic()
    log_path = Path(args.log)
    print(f"Running: {' '.join(command)}", flush=True)
    try:
        with interruption_handlers(), log_path.open("w", encoding="utf-8") as log:
            with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, errors="replace", bufsize=1,
                                  start_new_session=True) as process:
                with output_lines(process) as lines:
                    for is_stdout, line in lines:
                        log.write(line)
                        log.flush()
                        text = line.rstrip()
                        case = tap.observe(text) if is_stdout else None
                        if case:
                            group = case_group(case.identifier)
                            if group != suite:
                                suite = group
                                print(f"\n{suite}", flush=True)
                            counts[case.status] += 1
                            print(f"  [{case.status:4}] {case.description}", flush=True)
                            if case.status in ("FAIL", "INCONCLUSIVE", "ERROR"):
                                failures.append(case.description)
                        elif "summary:" in text or text.endswith(": PASS") or text.startswith("Self-test failed:"):
                            print(f"  {text}", flush=True)
                        elif args.verbose and text != "TAP version 13" and not re.fullmatch(r"1\.\.[0-9]+", text):
                            print(f"    {text}", flush=True)
                    result = process.wait()
    except RunInterrupted as error:
        print(f"Test run interrupted by {signal.Signals(error.signum).name}", file=sys.stderr)
        return 128 + error.signum
    except OSError as error:
        print(f"Cannot run tests: {error}", file=sys.stderr)
        return 1

    problems = tap.problems()
    for problem in problems:
        print(f"Invalid TAP output: {problem}", file=sys.stderr)
    if result == 0:
        # A successful process exit cannot certify missing or failed observations.
        if problems or counts['ERROR']:
            result = 2
        elif counts['FAIL'] or counts['INCONCLUSIVE']:
            result = 1
    print(f"\nExecution: {'OK' if result == 0 else 'NONZERO'} (exit={result}, {time.monotonic() - started:.1f}s); case results do not prove complete conformance")
    if counts:
        print("TAP cases: " + ", ".join(f"{counts[key]} {key}" for key in ("PASS", "FAIL", "NOT_APPLICABLE", "DEVIATION", "INCONCLUSIVE", "ERROR")))
    if failures:
        print("\nFailed cases:")
        for description in failures:
            print(f"  - {description}")
    print(f"Full diagnostics: {log_path}")
    return result if result >= 0 else 128 - result


if __name__ == "__main__":
    sys.exit(main())
