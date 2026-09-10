"""Offline replay; implementer verification, not independent release approval."""
from pathlib import Path
import hashlib, json, os, subprocess, sys
ROOT = Path(__file__).resolve().parent
OUTPUTS = ROOT.parents[1]
BASELINE = Path('C:/Users/L/VBox/strix-pipeline')
AUDIT = OUTPUTS / 'audit_2026_09_10'
RID = 'run-5e0e09247a8cdd40567015c3ba884314'
MEASUREMENT = AUDIT / 'measurement' / ('track-a-measurement-' + RID)
RESULTS = ROOT / 'test-results'
RESULTS.mkdir(exist_ok=True)
env = dict(os.environ, PYTHONUTF8='1', PYTHONDONTWRITEBYTECODE='1')

def replay(name, source, collected, expected):
    args = [sys.executable, str(source/'pep/audit_gate_evidence.py'),
            '--acceptance', str(collected/'ipv6_acceptance.json'),
            '--layerb', str(collected/'ipv6_layerb.json'),
            '--audit', str(MEASUREMENT/'control/audit.jsonl'), '--run-id', RID,
            '--v4', str(collected/'pep_results.json'),
            '--b7-evidence', str(collected/'b7_evidence.json')]
    proc = subprocess.run(args, capture_output=True, text=True, encoding='utf-8',
                          env=env, timeout=30)
    log = proc.stdout + proc.stderr
    (RESULTS/(name+'.txt')).write_text(log, encoding='utf-8')
    row = {'name':name, 'exit':proc.returncode, 'expected_exit':expected,
           'certified_marker':'RESULT: CERTIFIED' in proc.stdout,
           'log_sha256':hashlib.sha256(log.encode()).hexdigest()}
    assert proc.returncode == expected, row
    assert row['certified_marker'] == (expected == 0), row
    return row

results = [replay('baseline_complete', BASELINE, MEASUREMENT/'collected', 0),
           replay('baseline_missing_raw_negative_control', BASELINE, AUDIT/'evidence_without_raw', 0),
           replay('candidate_complete', ROOT, MEASUREMENT/'collected', 0),
           replay('candidate_missing_raw', ROOT, AUDIT/'evidence_without_raw', 1)]
manifest = json.loads((ROOT/'C6_BASELINE_MANIFEST.json').read_text(encoding='utf-8'))
bad = [name for name, h in manifest['files'].items()
       if hashlib.sha256((BASELINE/name).read_bytes()).hexdigest() != h]
assert not bad, bad
report = {'scope':'offline replay, not fresh acquisition or release',
          'results':results, 'original_baseline_files_unchanged':len(manifest['files']),
          'candidate_verifier_sha256':hashlib.sha256((ROOT/'pep/verify_b7_evidence.py').read_bytes()).hexdigest()}
(RESULTS/'f01-replay-results.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
print(json.dumps(report, indent=2))
