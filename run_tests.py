#!/usr/bin/env python3
"""Display harness results while retaining the complete diagnostic output."""

import argparse
from collections import Counter
from pathlib import Path
import re
import subprocess
import sys
import time


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

    counts = Counter()
    failures = []
    suite = None
    started = time.monotonic()
    log_path = Path(args.log)
    print(f"Running: {' '.join(command)}", flush=True)
    try:
        with log_path.open("w", encoding="utf-8") as log:
            with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  text=True, errors="replace", bufsize=1) as process:
                for line in process.stdout:
                    log.write(line)
                    log.flush()
                    text = line.rstrip()
                    match = re.match(r"(not ok|ok) \d+ - (.*)", text)
                    if match:
                        description = match[2]
                        identifier = description.split()[0]
                        group = ("RFC 9293" if identifier.startswith("MUST-") else
                                 "IPv4 host" if identifier.startswith(("IP4-", "ICMP-", "UDP-")) else
                                 "TCP extensions and resets" if identifier.startswith("TCP-") else
                                 "Robustness" if identifier.startswith("ROBUST-") else
                                 "TCP Fast Open" if identifier.startswith("TFO-") else "Tests")
                        if group != suite:
                            suite = group
                            print(f"\n{suite}", flush=True)
                        status = ("TODO" if " # TODO " in description else
                                  "SKIP" if " # SKIP " in description else
                                  "PASS" if match[1] == "ok" else "FAIL")
                        counts[status] += 1
                        print(f"  [{status:4}] {description}", flush=True)
                        if status == "FAIL":
                            failures.append(description)
                    elif "summary:" in text or text.endswith(": PASS") or text.startswith("Self-test failed:"):
                        print(f"  {text}", flush=True)
                    elif args.verbose and text != "TAP version 13" and not re.fullmatch(r"1\.\.\d+", text):
                        print(f"    {text}", flush=True)
                result = process.wait()
    except OSError as error:
        print(f"Cannot run tests: {error}", file=sys.stderr)
        return 1

    print(f"\nResult: {'PASS' if result == 0 else 'FAIL'} ({time.monotonic() - started:.1f}s)")
    if counts:
        print("TAP cases: " + ", ".join(f"{counts[key]} {key}" for key in ("PASS", "FAIL", "SKIP", "TODO")))
    if failures:
        print("\nFailed cases:")
        for description in failures:
            print(f"  - {description}")
    print(f"Full diagnostics: {log_path}")
    return result if result >= 0 else 128 - result


if __name__ == "__main__":
    sys.exit(main())
