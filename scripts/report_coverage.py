#!/usr/bin/env python3
"""Validate and report the bounded coverage inventory, independently of outcomes."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
COVERAGE = {'fully-tested', 'partial', 'not-tested', 'not-applicable', 'not-supported'}
KINDS = {'normative', 'protocol-processing', 'implementation-profile', 'harness-contract'}
STATUSES = {'PASS', 'FAIL', 'DEVIATION', 'NOT_APPLICABLE', 'INCONCLUSIVE', 'ERROR'}
EXECUTIONS = {'normal', 'timeout', 'signal', 'exit-error', 'missing-report',
              'infrastructure-error', 'not-run'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(ledger):
    require(ledger.get('schema_version') == 2, 'coverage requires ledger schema 2')
    require(set(ledger['coverage_policy']['statuses']) == COVERAGE, 'coverage vocabulary')
    seen = set()
    for entry in ledger['cases'] + ledger['coverage_gaps']:
        identifier = entry['id']
        require(identifier not in seen, f'duplicate inventory ID: {identifier}')
        seen.add(identifier)
        require(entry['coverage'] in COVERAGE, f'{identifier}: invalid coverage')
        require(entry['requirement_kind'] in KINDS, f'{identifier}: invalid requirement kind')
        for key in ('requirement_id', 'requirement', 'applicability', 'gaps'):
            require(isinstance(entry.get(key), str) and entry[key].strip(), f'{identifier}: missing {key}')
        refs = entry['rfc_references']
        require(isinstance(refs, list), f'{identifier}: invalid RFC references')
        require(refs or entry['requirement_kind'] in ('implementation-profile', 'harness-contract'),
                f'{identifier}: missing RFC reference')
        for ref in refs:
            require(type(ref['rfc']) is int and ref['rfc'] > 0 and
                    isinstance(ref['section'], str) and ref['section'].strip(),
                    f'{identifier}: missing RFC number/section')
        if 'function' in entry:
            require(entry['coverage'] in ('partial', 'fully-tested'), f'{identifier}: implemented case coverage')
            for key in ('oracle', 'requirement_basis'):
                require(isinstance(entry.get(key), str) and entry[key].strip(), f'{identifier}: missing {key}')
        else:
            require(entry['coverage'] in ('not-tested', 'not-applicable', 'not-supported'),
                    f'{identifier}: gap cannot claim tested coverage')
            require(entry['test_case_ids'] == [] and bool(entry['methodology'].strip()),
                    f'{identifier}: gap must explicitly have no detecting tests')
        if entry['coverage'] == 'fully-tested':
            require(bool(entry.get('bounded_scope')) and bool(entry.get('completeness_basis')),
                    f'{identifier}: fully-tested requires bounded_scope and completeness_basis')
    return True


def build_report(ledger, digest, results=None):
    validate(ledger)
    observed = {}
    if results is not None:
        require(results.get('ledger_sha256') == digest, 'results ledger hash mismatch; recapture using current registry')
        known = {c['id']: c for c in ledger['cases']}
        for result in results['cases']:
            identifier = result['id']
            require(identifier in known and identifier not in observed, f'unknown/duplicate result: {identifier}')
            require(result.get('status') in STATUSES and result.get('execution') in EXECUTIONS,
                    f'{identifier}: invalid/missing status or execution')
            for key in ('requirement_id', 'coverage', 'oracle_class', 'profile', 'strength', 'source'):
                require(result.get(key) == known[identifier][key], f'{identifier}: inconsistent {key}')
            require(result['status'] != 'PASS' or result['execution'] == 'normal',
                    f'{identifier}: PASS without normal execution')
            observed[identifier] = result
    groups = {}
    for case in ledger['cases']:
        group = groups.setdefault(case['requirement_id'], [])
        row = {k: case[k] for k in ('id', 'requirement', 'requirement_basis', 'requirement_kind',
               'rfc_references', 'strength', 'profile', 'applicability', 'coverage', 'gaps',
               'oracle_class', 'oracle_dependencies', 'oracle_review', 'responsibility')}
        for key in ('bounded_scope', 'completeness_basis', 'mutation_experiments', 'strength_basis', 'source'):
            if key in case:
                row[key] = case[key]
        row['test_case_ids'] = [case['id']]
        row['methodology'] = case['oracle']
        row['function'] = case['function']
        result = observed.get(case['id'])
        row['observation'] = ({k: result[k] for k in ('status', 'execution', 'reason')}
                              if result else None)
        group.append(row)
    for gap in ledger['coverage_gaps']:
        groups.setdefault(gap['requirement_id'], []).append(dict(gap, observation=None))
    executed = [r for r in observed.values() if r['execution'] != 'not-run']
    return dict(schema_version=1, ledger_sha256=digest, conformance='NOT_ESTABLISHED',
                policy=ledger['coverage_policy'],
                counts=dict(implemented_cases=len(ledger['cases']),
                            requirement_groups=len(groups),
                            coverage_entries={status: sum(e['coverage'] == status for es in groups.values() for e in es)
                                              for status in sorted(COVERAGE)},
                            reported_cases=len(observed), executed_cases=len(executed),
                            passed_cases=sum(r['status'] == 'PASS' for r in executed),
                            unreported_cases=len(ledger['cases'])-len(observed),
                            outcomes=dict(sorted(Counter(r['status'] for r in observed.values()).items())),
                            executions=dict(sorted(Counter(r['execution'] for r in observed.values()).items()))),
                run_configuration=results.get('configuration') if results else None,
                run_exit_code=results.get('exit_code') if results else None,
                requirements=groups)


def markdown(report):
    def cell(value):
        return str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('|', '&#124;').replace('\n', '<br>')
    counts = report['counts']
    lines = ['# RFC coverage inventory', '', '<!-- Generated by scripts/report_coverage.py; edit requirements.json. -->', '',
             f"Ledger SHA256: `{report['ledger_sha256']}`", '',
             'Coverage describes implemented assertions. PASS does not upgrade coverage or prove compliance.',
             'Selected requirements only; not an exhaustive RFC inventory. Conformance: NOT_ESTABLISHED.', '',
             f"Implemented cases: {counts['implemented_cases']}; reported: {counts['reported_cases']}; "
             f"executed: {counts['executed_cases']}; passed: {counts['passed_cases']}; unreported: {counts['unreported_cases']}.", '',
             'No run is attached to the checked-in inventory. Missing observations mean unreported, not PASS.', '',
             '| Requirement / case | RFC / section | Kind / strength | Requirement summary | Applicable conditions | Methodology | Coverage / observation | Known limitations |',
             '| --- | --- | --- | --- | --- | --- | --- | --- |']
    if counts['reported_cases']:
        lines.remove('No run is attached to the checked-in inventory. Missing observations mean unreported, not PASS.')
    for requirement, entries in report['requirements'].items():
        for e in entries:
            refs = ', '.join(f"RFC {r['rfc']} §{r['section']}" for r in e['rfc_references']) or 'Local contract; no normative RFC'
            observation = e['observation']
            outcome = (f"{observation['status']} / {observation['execution']}: {observation['reason']}" if observation else 'unreported')
            method = e['methodology']
            if 'oracle_class' in e:
                method += f" Oracle: {e['oracle_class']}; {e['oracle_review']}"
            lines.append('| ' + ' | '.join(map(cell, [requirement + ' / ' + e['id'], refs,
                         e['requirement_kind'] + ' / ' + e.get('strength', 'scope analysis'),
                         e['requirement'] + (' [' + e['requirement_basis'] + ']' if 'requirement_basis' in e else ''),
                         e['applicability'], method, e['coverage'] + ' / ' + outcome,
                         e['gaps'] + (' Bounded scope: ' + e['bounded_scope'] + '; completeness: ' + e['completeness_basis']
                                      if e['coverage'] == 'fully-tested' else '')])) + ' |')
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results', type=Path, help='Current-ledger harness JSON; optional')
    parser.add_argument('--output', type=Path, default=ROOT / 'artifacts/coverage')
    parser.add_argument('--check', action='store_true', help='Check generated static Markdown is current')
    args = parser.parse_args()
    raw = (ROOT / 'requirements.json').read_bytes()
    try:
        report = build_report(json.loads(raw), hashlib.sha256(raw).hexdigest(),
                              json.loads(args.results.read_text()) if args.results else None)
        rendered = markdown(report)
        if args.check:
            require(args.results is None, '--check only accepts the static inventory')
            require((ROOT / 'RFC-COVERAGE.md').read_text() == rendered, 'stale RFC-COVERAGE.md; run make coverage-doc')
        else:
            args.output.mkdir(parents=True, exist_ok=True)
            (args.output / 'coverage.json').write_text(json.dumps(report, indent=2) + '\n')
            (args.output / 'coverage.md').write_text(rendered)
        print(json.dumps(report['counts'], sort_keys=True))
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print(f'coverage: {exc}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
