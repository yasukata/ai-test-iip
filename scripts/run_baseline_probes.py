#!/usr/bin/env python3
"""Build and capture native-handshake diagnostic probes outside the case registry.

A failing target probe remains a nonzero exit. These are reproducers, not a
known-failure allowlist or replacements for the registered white-box tests.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--sanitizer', choices=('none', 'asan', 'ubsan'), default='none')
    args = parser.parse_args()
    dest = Path(args.output).resolve()
    dest.mkdir(parents=True, exist_ok=False)
    compiler = shlex.split(os.environ.get('CC', 'cc'))
    command = compiler + shlex.split(os.environ.get('CPPFLAGS', '')) + [
        '-std=gnu11', '-O1', '-g', '-fno-omit-frame-pointer', '-Wall', '-Wextra', '-Wpedantic']
    if args.sanitizer != 'none':
        command += ['-fsanitize=' + {'asan': 'address', 'ubsan': 'undefined'}[args.sanitizer]]
    command += ['-o', str(dest / 'baseline-probes'), 'tests/baseline_probes.c']
    env = dict(os.environ)
    if args.sanitizer == 'asan':
        env['ASAN_OPTIONS'] = 'detect_leaks=0:halt_on_error=1'
    if args.sanitizer == 'ubsan':
        env['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
    metadata = dict(build_command=command, sanitizer=args.sanitizer,
                    sanitizer_environment={k: env[k] for k in ('ASAN_OPTIONS', 'UBSAN_OPTIONS') if k in env})
    for key, cmd in [('compiler', compiler + ['--version']),
                     ('harness_commit', ['git', 'rev-parse', 'HEAD']),
                     ('iip_commit', ['git', '-C', 'iip', 'rev-parse', 'HEAD'])]:
        metadata[key] = subprocess.check_output(cmd, cwd=ROOT, text=True).strip()
    with (dest / 'build.log').open('w') as log:
        build = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    metadata['build_exit'] = build.returncode
    if build.returncode:
        (dest / 'manifest.json').write_text(json.dumps(metadata, indent=2) + '\n')
        return 2
    binary = dest / 'baseline-probes'
    metadata['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
    names = subprocess.check_output([str(binary), '--list'], cwd=ROOT, env=env, text=True).splitlines()
    results = []
    for name in names:
        with (dest / (name + '.stdout')).open('w') as out, (dest / (name + '.stderr')).open('w') as err:
            run = subprocess.run([str(binary), name], cwd=ROOT, env=env, stdout=out, stderr=err)
        record = dict(probe=name, command=[str(binary), name], process_exit=run.returncode)
        try:
            result = json.loads((dest / (name + '.stdout')).read_text())
            if result.get('probe') != name or 'status' not in result or 'execution' not in result:
                raise ValueError('invalid probe result')
            record.update(result)
        except (ValueError, TypeError) as error:
            record.update(status='ERROR', execution='missing-report', reason=str(error))
        results.append(record)
        print(name, record['status'], record['execution'], 'exit=' + str(run.returncode), flush=True)
    sources = sorted(set(ROOT.glob('*.c')) | set(ROOT.glob('*.h')) |
                     {ROOT / 'iip/main.c', ROOT / 'tests/baseline_probes.c', Path(__file__).resolve()})
    metadata['source_sha256'] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in sources}
    (dest / 'manifest.json').write_text(json.dumps(metadata, indent=2) + '\n')
    (dest / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    return int(any(r['status'] != 'PASS' or r['execution'] != 'normal' or r['process_exit'] != 0
                   for r in results))


if __name__ == '__main__':
    sys.exit(main())
