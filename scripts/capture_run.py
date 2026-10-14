#!/usr/bin/env python3
"""Capture a reproducible run; preserve the harness exit status."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parent.parent

def output(*cmd):
    p = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
    return p.stdout.strip() if p.returncode == 0 else p.stderr.strip()

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--output', required=True)
    p.add_argument('command', nargs=argparse.REMAINDER)
    a = p.parse_args()
    cmd = a.command
    if cmd[:1] == ['--']: cmd = cmd[1:]
    if not cmd: p.error('test command required')
    dest = Path(a.output).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    cmd += ['--json', str(dest / 'results.json')]
    files = (list(ROOT.glob('*.c')) + list(ROOT.glob('*.h')) + list(ROOT.glob('*.md'))
        + list((ROOT/'scripts').glob('*.py')) + list((ROOT/'tests').glob('*.*'))
        + [ROOT/'iip/main.c', ROOT/'requirements.json', ROOT/'Makefile', ROOT/'run_tests.py'])
    metadata = dict(command=cmd, platform=platform.platform(), compiler=output('cc','--version'),
        root_commit=output('git','rev-parse','HEAD'), iip_commit=output('git','-C','iip','rev-parse','HEAD'),
        blake2_commit=output('git','-C','blake2-upstream','rev-parse','HEAD'),
        environment={k:v for k,v in os.environ.items() if k.startswith(('IIP_', 'ASAN_', 'UBSAN_'))},
        sha256={str(f.relative_to(ROOT)):hashlib.sha256(f.read_bytes()).hexdigest() for f in files if f.exists()})
    with tarfile.open(dest/'sources.tar.gz', 'w:gz') as archive:
        for f in files:
            if f.is_file(): archive.add(f, arcname=str(f.relative_to(ROOT)))
    (dest/'environment.json').write_text(json.dumps(metadata,indent=2)+'\n')
    (dest/'workspace.patch').write_text(output('git','diff','HEAD'))
    (dest/'iip.patch').write_text(output('git','-C','iip','diff','HEAD'))
    with (dest/'results.tap').open('w') as tap, (dest/'diagnostics.log').open('w') as log:
        r = subprocess.run(cmd,cwd=ROOT,stdout=tap,stderr=log)
    (dest/'exit-code.txt').write_text(str(r.returncode)+'\n')
    if (dest/'results.json').exists():
        result = json.loads((dest/'results.json').read_text())
        ledger = {c['id']:c for c in json.loads((ROOT/'requirements.json').read_text())['cases']}
        groups = {}
        for c in result['cases']:
            entry = dict(ledger[c['id']]); entry.update(c)
            groups.setdefault(c['requirement_id'], []).append(entry)
        (dest/'requirements-report.json').write_text(json.dumps(dict(conformance='NOT_ESTABLISHED', requirements=groups),indent=2)+'\n')
    print(f'{dest}: exit={r.returncode}')
    return r.returncode if r.returncode >= 0 else 128-r.returncode

if __name__ == '__main__': sys.exit(main())
