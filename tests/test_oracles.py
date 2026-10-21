"""Provenance must not disappear or label supplied behavior as native."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'scripts'))
import audit_oracles as audit


class OracleProvenance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ledger = json.loads((ROOT / 'requirements.json').read_text())

    def test_every_case_has_valid_provenance(self):
        self.assertTrue(audit.validate(self.ledger))
        for mutation in ('missing-class', 'unknown-dependency', 'empty-review'):
            changed = copy.deepcopy(self.ledger)
            case = changed['cases'][0]
            if mutation == 'missing-class':
                del case['oracle_class']
            elif mutation == 'unknown-dependency':
                case['oracle_dependencies'].append('invented')
            else:
                case['oracle_review'] = ''
            with self.subTest(mutation=mutation), self.assertRaises((AssertionError, KeyError)):
                audit.validate(changed)

    def test_adapter_and_synthetic_cases_stay_separate(self):
        cases = {c['id']: c for c in self.ledger['cases']}
        for identifier, dependency in [('IP4-OPT-2', 'ip4-option-error'),
                                       ('UDP-PORT-1', 'udp-port-error'),
                                       ('MUST-57', 'input-filter'),
                                       ('MUST-52', 'source-route'),
                                       ('MUST-44', 'source-selector')]:
            with self.subTest(case=identifier):
                self.assertEqual(cases[identifier]['oracle_class'], 'adapter')
                self.assertIn(dependency, cases[identifier]['oracle_dependencies'])
        self.assertEqual(cases['HARNESS-SELF']['oracle_class'], 'harness')
        self.assertEqual(cases['TCP-LIFE-APPLICATION-ABORT']['oracle_class'], 'unavailable')

    def test_source_inventory_stops_at_native_and_abi_boundaries(self):
        source = '''# 1 "iip/main.c"
static int target(void) { return private_state(); }
# 10 "test_oracle.h"
static int helper(void) { const char *text = "} invented()"; return target(); }
static int scenario(void) { return helper() + test_api_run(); }
# 20 "test_api.c"
static int test_api_run(void) { return private_state(); }
static int private_state(void) { return 1; }
'''
        functions = audit.functions_from_preprocessor(source)
        self.assertNotIn('target', functions)
        self.assertEqual(audit.reachable(functions, 'scenario'),
                         ['helper', 'scenario', 'test_api_run'])
        self.assertEqual(functions['scenario']['source'], 'test_oracle.h:11')
        broken = dict(cases=[dict(id='MISSING', function='missing')])
        with self.assertRaisesRegex(ValueError, 'unresolved case entry'):
            audit.inventory(broken, functions)
