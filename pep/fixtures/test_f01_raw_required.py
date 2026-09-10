"""F01 regression: production must never downgrade missing raw to summary-only.

Tests use synthetic inputs and controlled raw files. Passing is a verifier
regression result, not an acquisition or containment certification.
"""
from pathlib import Path
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
PEP = HERE.parent
sys.path[:0] = [str(PEP), str(HERE)]
import make_fixtures as fixtures
from test_e9_raw_mutations import build
from verify_b7_evidence import REQUIRED_RAW, derive


class RawRequiredTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.raw = self.root / 'b7_raw'
        self.raw.mkdir()
        self.artifacts = copy.deepcopy(fixtures.honest_artifacts())
        build(str(self.raw), self.artifacts['b7'], 'honest')
        for name in ('acceptance', 'layerb', 'v4', 'b7'):
            (self.root / (name + '.json')).write_text(
                json.dumps(self.artifacts[name]), encoding='utf-8')
        # The existing fixture writer supplies the intact audit hash chain.
        self.audit = HERE / 'f00_honest' / 'audit.jsonl'

    def invoke(self, script, *args):
        return subprocess.run([sys.executable, str(PEP / script), *map(str, args)],
                              capture_output=True, text=True, encoding='utf-8',
                              env=dict(os.environ, PYTHONUTF8='1', PYTHONDONTWRITEBYTECODE='1'),
                              timeout=15)

    def auditor(self, *extra):
        return self.invoke('audit_gate_evidence.py', '--acceptance', self.root/'acceptance.json',
                           '--layerb', self.root/'layerb.json', '--audit', self.audit,
                           '--run-id', fixtures.RID, '--v4', self.root/'v4.json',
                           '--b7-evidence', self.root/'b7.json', *extra)

    def verifier(self, *extra):
        return self.invoke('verify_b7_evidence.py', '--evidence', self.root/'b7.json',
                           '--layerb', self.root/'layerb.json', '--run-id', fixtures.RID, *extra)

    def test_production_library_requires_raw_argument(self):
        ok, failures = derive(self.artifacts['b7'], self.artifacts['layerb'], fixtures.RID)
        self.assertFalse(ok)
        self.assertIn('RAW_DIRECTORY_ABSENT_OR_UNSAFE', failures)

    def test_raw_positive_control_passes(self):
        self.assertEqual(derive(self.artifacts['b7'], self.artifacts['layerb'],
                                fixtures.RID, str(self.raw)), (True, []))
        result = self.verifier('--raw-dir', self.raw)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'], 'PROVEN')

    def test_auditor_positive_raw_control_passes(self):
        result = self.auditor()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('RESULT: CERTIFIED', result.stdout)

    def test_each_required_file_removal_fails_both_entrypoints(self):
        for name in REQUIRED_RAW:
            with self.subTest(name=name):
                path = self.raw / name
                blob = path.read_bytes()
                path.unlink()
                try:
                    ok, failures = derive(self.artifacts['b7'], self.artifacts['layerb'],
                                          fixtures.RID, str(self.raw))
                    self.assertFalse(ok)
                    self.assertIn('RAW_ARTIFACTS_ABSENT_OR_UNSAFE', failures)
                    result = self.auditor()
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn('RAW_ARTIFACTS_ABSENT_OR_UNSAFE', result.stdout)
                    self.assertNotIn('RESULT: CERTIFIED', result.stdout)
                finally:
                    path.write_bytes(blob)

    def test_auditor_missing_directory_is_not_certified(self):
        self.raw.rename(self.root / 'removed_raw')
        result = self.auditor()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('RAW_DIRECTORY_ABSENT_OR_UNSAFE', result.stdout)
        self.assertNotIn('RESULT: CERTIFIED', result.stdout)

    def test_standalone_missing_and_empty_raw_fail(self):
        empty = self.root / 'empty'
        empty.mkdir()
        for args in ((), ('--raw-dir', empty), ('--raw-dir', self.root/'absent')):
            with self.subTest(args=args):
                result = self.verifier(*args)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(json.loads(result.stdout)['status'], 'NOT_PROVEN')

    def test_summary_fixture_never_emits_release_success(self):
        self.raw.rename(self.root / 'removed_raw')
        result = self.auditor('--fixture-mode')
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn('RESULT: FIXTURE_VALIDATED', result.stdout)
        self.assertNotIn('RESULT: CERTIFIED', result.stdout)

    def test_forged_summary_still_fails_in_fixture_mode(self):
        self.artifacts['b7']['receiver']['measurement_seen'] = True
        (self.root/'b7.json').write_text(json.dumps(self.artifacts['b7']), encoding='utf-8')
        result = self.auditor('--fixture-mode')
        self.assertEqual(result.returncode, 1)
        self.assertIn('RESULT: FIXTURE_REJECTED', result.stdout)

    def test_raw_contradiction_cannot_be_hidden_by_summary(self):
        # Update the claimed hash too: the semantic check must detect delivery.
        import hashlib
        path = self.raw / 'receiver.jsonl'
        with path.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps({'nonce': self.artifacts['b7']['probe']['nonce']})+'\n')
        self.artifacts['b7']['receiver']['raw_log_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        (self.root/'b7.json').write_text(json.dumps(self.artifacts['b7']), encoding='utf-8')
        result = self.auditor()
        self.assertEqual(result.returncode, 1)
        self.assertIn('RAW_MEASUREMENT_REACHED_RECEIVER', result.stdout)

    def test_raw_file_replaced_by_directory_fails(self):
        path = self.raw / 'attempt.pcap'
        path.unlink()
        path.mkdir()
        ok, failures = derive(self.artifacts['b7'], self.artifacts['layerb'], fixtures.RID, str(self.raw))
        self.assertFalse(ok)
        self.assertIn('RAW_ARTIFACTS_ABSENT_OR_UNSAFE', failures)


if __name__ == '__main__':
    unittest.main(verbosity=2)
