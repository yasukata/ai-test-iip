#!/usr/bin/env python3
"""Select a ledger phase and retain the normal capture_run evidence bundle."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', type=int, required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('binary')
    args = parser.parse_args()
    cases = json.loads((ROOT / 'requirements.json').read_text())['cases']
    selected = [c['id'] for c in cases if c.get('phase') == args.phase]
    if not selected:
        parser.error(f'no cases registered for phase {args.phase}')
    command = [sys.executable, str(ROOT / 'scripts/capture_run.py'),
               '--output', args.output, '--', args.binary]
    for case_id in selected:
        command.extend(['--case', case_id])
    env = os.environ.copy()
    env.setdefault('IIP_FUZZ_FAILURE_PREFIX', str(Path(args.output) / 'fuzz'))
    return subprocess.call(command, cwd=ROOT, env=env)


if __name__ == '__main__':
    sys.exit(main())
