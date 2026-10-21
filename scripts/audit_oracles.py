#!/usr/bin/env python3
"""Inventory oracle provenance. This is a conservative source audit, not a C proof.

Preprocessing expands the model/sequence wrappers before following direct calls.
Native code and documented packet/API bindings are traversal boundaries. Paths
are not feasibility-checked; a reachable helper can cover unused branches.
"""
import argparse
from collections import Counter
import json
import hashlib
import os
from pathlib import Path
import re
import shlex
import subprocess

ROOT = Path(__file__).resolve().parent.parent
CLASSES = {'external', 'white-box', 'adapter', 'harness', 'unavailable'}
# These functions implement the harness/stack ABI, not scenario expectations.
BOUNDARIES = {
    'build_tcp_packet', 'build_udp_packet', 'build_icmp_packet',
    'test_workspace_init', 'test_api_run', 'test_api_connect', 'test_api_close',
    'test_api_send', 'test_api_consumed', 'test_api_fast_open',
    'test_api_set_time', 'test_api_set_local_address', 'free_output',
    'test_event_append', 'test_event_count', 'test_event_nth',
    'test_event_log_clear', 'test_condition_failed', 'fixture_setup_failed',
    'test_pkt_ip4', 'test_pkt_l4', 'test_pb_ip4', 'test_pb_l4',
    'malformed_exact_packet', 'test_pkt_alloc_capacity',
}


def validate(ledger):
    catalog = ledger['oracle_dependencies']
    for case in ledger['cases']:
        assert case['oracle_class'] in CLASSES, case['id']
        deps = case['oracle_dependencies']
        assert isinstance(deps, list) and len(deps) == len(set(deps)), case['id']
        assert all(dep in catalog for dep in deps), case['id']
        assert case['oracle_review'].strip(), case['id']
    return True


def mask_literals(text):
    # Preserve offsets and newlines for brace matching and source references.
    return re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                  lambda m: re.sub(r'[^\n]', ' ', m[0]), text, flags=re.S)


def functions_from_preprocessor(text):
    allowed = {p.name for p in ROOT.glob('test_*.h')} | {'main.c', 'conformance_tests.h', 'test_api.c', 'test_backend.c'}
    # Preserve only test-side code. Never inspect iip to derive expectations.
    lines, locations = [], []
    filename, number = '', 0
    for line in text.splitlines(True):
        marker = re.match(r'# (\d+) "([^"]+)"', line)
        if marker:
            number, filename = int(marker[1]), marker[2]
            continue
        if filename in allowed:
            lines.append(line); locations.append((filename, number))
        number += 1
    source = ''.join(lines)
    masked = mask_literals(source)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    import bisect
    pattern = re.compile(r'(?m)^static\s+[^;{}=]*?\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{')
    functions = {}
    for match in pattern.finditer(masked):
        start, end, depth = match.end(), match.end(), 1
        while depth and end < len(masked):
            depth += (masked[end] == '{') - (masked[end] == '}')
            end += 1
        if depth:
            raise ValueError(f'unbalanced function {match[1]}')
        row = bisect.bisect_right(offsets, match.start()) - 1
        functions[match[1]] = dict(body=masked[start:end-1],
                                  source=f'{locations[row][0]}:{locations[row][1]}')
    return functions


def reachable(functions, name):
    pending, found = [name], set()
    while pending:
        current = pending.pop()
        if current in found or current not in functions:
            continue
        found.add(current)
        if current in BOUNDARIES or current.startswith(('iip_ops_', 'test_backend_')):
            continue
        pending.extend(re.findall(r'\b([A-Za-z_]\w*)\s*\(', functions[current]['body']))
    return sorted(found)


def inventory(ledger, functions):
    rows = []
    for case in ledger['cases']:
        name = case['function']
        if name not in functions:
            raise ValueError(f"unresolved case entry: {case['id']} {name}")
        names = reachable(functions, name)
        # Evidence of direct internal access; absence is NOT a black-box proof.
        internals = [n for n in names if n not in BOUNDARIES and
                     not n.startswith(('iip_ops_', 'test_backend_')) and
                     re.search(r'\bstruct ii_(?:tcp_conn|pb)\b|(?:->|\.)\s*(?:conn|tcp_conns|pbs|seq_next_expected|acked_seq|sent_seq|rto_ms|cc)\b',
                               functions[n]['body'])]
        rows.append(dict(id=case['id'], function=name, source=functions[name]['source'],
                         oracle_class=case['oracle_class'], dependencies=case['oracle_dependencies'],
                         review=case['oracle_review'], internal_access_candidates=internals,
                         reachable_helpers={n: functions[n]['source'] for n in names}))
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', default='artifacts/phase8/oracle-audit.json')
    args = p.parse_args()
    raw = (ROOT / 'requirements.json').read_bytes()
    ledger = json.loads(raw)
    validate(ledger)
    command = shlex.split(os.environ.get('CC', 'cc')) + shlex.split(os.environ.get('CPPFLAGS', ''))
    text = subprocess.check_output(command + ['-E', 'main.c'], cwd=ROOT, text=True)
    rows = inventory(ledger, functions_from_preprocessor(text))
    report = dict(conformance='NOT_ESTABLISHED', ledger_sha256=hashlib.sha256(raw).hexdigest(),
                  method='reviewed classes + conservative direct-call source inventory',
                  limitations='No path feasibility, indirect-call or complete C semantic analysis. Internal candidates include setup and observations. ABI bindings are explicit traversal boundaries.',
                  boundaries=sorted(BOUNDARIES), dependencies=ledger['oracle_dependencies'],
                  summary=dict(Counter(r['oracle_class'] for r in rows)), cases=rows)
    dest = Path(args.output); dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(report, indent=2) + '\n')
    print(f'{len(rows)} cases: {report["summary"]}; {dest}')


if __name__ == '__main__':
    main()
