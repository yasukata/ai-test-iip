#!/usr/bin/env python3
"""Display harness results while retaining the complete diagnostic output."""

import argparse
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
import re
import queue
import threading
import subprocess
import sys
import time


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
            is_stdout, line = pending.get()
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
        if any(reader.is_alive() for reader in readers) and process.poll() is None:
            process.kill()
        for reader in readers:
            reader.join()


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
        plan = re.fullmatch(r"1\.\.(\d+)", text)
        if plan:
            if not self.header or self.plan is not None or self.observed:
                self.errors.append("duplicate or misplaced TAP plan")
            self.plan = int(plan[1])
            return None
        match = re.fullmatch(r"(not ok|ok) (\d+) - (\S.*)", text)
        if match:
            if not self.header or self.plan is None:
                self.errors.append("case appeared before the TAP header and plan")
            self.observed += 1
            if int(match[2]) != self.observed:
                self.errors.append(f"expected case number {self.observed}, got {match[2]}")
            return match
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
        with log_path.open("w", encoding="utf-8") as log:
            with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, errors="replace", bufsize=1) as process:
                with output_lines(process) as lines:
                    for is_stdout, line in lines:
                        log.write(line)
                        log.flush()
                        text = line.rstrip()
                        match = tap.observe(text) if is_stdout else None
                        if match:
                            description = match[3]
                            identifier = description.split()[0]
                            group = ("RFC 9293" if identifier.startswith("MUST-") else
                                     "IPv4 host" if identifier.startswith(("IP4-", "ICMP-", "UDP-")) else
                                     "TCP extensions and resets" if identifier.startswith("TCP-") else
                                     "Robustness" if identifier.startswith("ROBUST-") else
                                     "TCP Fast Open" if identifier.startswith("TFO-") else "Tests")
                            if group != suite:
                                suite = group
                                print(f"\n{suite}", flush=True)
                            status = ("DEVIATION" if " # TODO " in description else
                                      "NOT_APPLICABLE" if " # SKIP " in description else
                                      "INCONCLUSIVE" if " - [INCONCLUSIVE] " in description else
                                      "ERROR" if " - [ERROR] " in description else
                                      "PASS" if match[1] == "ok" else "FAIL")
                            counts[status] += 1
                            print(f"  [{status:4}] {description}", flush=True)
                            if status in ("FAIL", "INCONCLUSIVE", "ERROR"):
                                failures.append(description)
                        elif "summary:" in text or text.endswith(": PASS") or text.startswith("Self-test failed:"):
                            print(f"  {text}", flush=True)
                        elif args.verbose and text != "TAP version 13" and not re.fullmatch(r"1\.\.\d+", text):
                            print(f"    {text}", flush=True)
                    result = process.wait()
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
