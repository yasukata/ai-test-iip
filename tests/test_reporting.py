"""Exercise externally visible reporting contracts against the built harness."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent

class Reporting(unittest.TestCase):
    def run_case(self, *args):
        with tempfile.TemporaryDirectory() as temp:
            dest = Path(temp)/'result.json'
            r = subprocess.run([str(ROOT/'ai-test-iip'), *args, '--json',str(dest)],capture_output=True,text=True)
            return r, json.loads(dest.read_text()) if dest.exists() else None

    def test_independent_case_and_tap_plan(self):
        r,j = self.run_case('--case','MUST-7')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn('1..1\n',r.stdout)
        self.assertEqual([c['id'] for c in j['cases']],['MUST-7'])
        self.assertEqual(j['conformance'],'NOT_ESTABLISHED')

    def test_unknown_case_is_error(self):
        r,j = self.run_case('--case','DOES-NOT-EXIST')
        self.assertEqual(r.returncode,2)
        self.assertIsNone(j)

    def test_unbound_api_is_not_pass(self):
        r,j = self.run_case('--case','MUST-51')
        self.assertEqual(r.returncode,1)
        self.assertEqual(j['cases'][0]['status'],'INCONCLUSIVE')

    def test_disabled_profile_has_reason(self):
        r,j = self.run_case('--case','TFO-2A','--no-tfo')
        self.assertEqual(r.returncode,0)
        self.assertEqual(j['cases'][0]['status'],'NOT_APPLICABLE')
        self.assertTrue(j['cases'][0]['reason'])

    def test_partial_coverage_cannot_certify(self):
        r,j = self.run_case('--case','MUST-3','--conformance')
        self.assertEqual(j['cases'][0]['status'],'PASS')
        self.assertEqual(r.returncode,3)

    def test_json_write_error(self):
        r = subprocess.run([str(ROOT/'ai-test-iip'),'--case','MUST-3','--json','/dev/full'],capture_output=True)
        self.assertEqual(r.returncode,2)

if __name__ == '__main__': unittest.main()
