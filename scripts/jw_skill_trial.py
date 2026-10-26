"""Offline paired skill evaluation. Supplied run refs are UNATTESTED.
Never calls models, verifies remote links, changes budgets or authorizes release.
"""
from __future__ import annotations
import json
import re
from typing import Any

SHA = re.compile(r'^[a-f0-9]{40}$')

def _runs(raw: Any) -> dict[int, dict] | None:
    if type(raw) is not list or not 3 <= len(raw) <= 100:
        return None
    parsed = {}
    for r in raw:
        if type(r) is not dict or set(r) != {'seed','cases','passed','failed','skipped','tokens','run_ref'}:
            return None
        for key in ('seed','cases','passed','failed','skipped','tokens'):
            if type(r[key]) is not int or r[key] < (10 if key == 'cases' else 0):
                return None
        if r['cases'] != r['passed'] + r['failed'] + r['skipped']:
            return None
        if not isinstance(r['run_ref'], str) or not r['run_ref'].strip() or len(r['run_ref']) > 2048:
            return None
        if r['seed'] in parsed:
            return None
        parsed[r['seed']] = r
    return parsed

def evaluate(payload: Any) -> dict:
    """Compare self-reported metrics, never certify actual independent execution."""
    base = {'status':'BLOCKED','evidence':'UNATTESTED_INPUT',
            'independent_result_verified':False,'models_executed_by_evaluator':False,
            'production_release':'BLOCKED','auto_adopt':False}
    if type(payload) is not dict or payload.get('schema') != 'jw-paired-skill-trial-v1':
        return {**base,'reason':'INVALID_SCHEMA'}
    code = payload.get('code_sha')
    suite = payload.get('suite_sha256')
    if not isinstance(code,str) or not SHA.fullmatch(code) or not isinstance(suite,str) or not re.fullmatch(r'[0-9a-f]{64}',suite):
        return {**base,'reason':'EXACT_SOURCE_AND_SUITE_DIGEST_REQUIRED'}
    if payload.get('safety') != {'baseline':'PASS','candidate':'PASS'}:
        return {**base,'reason':'SAFETY_NOT_PROVEN'}
    sides = []
    for name in ('baseline','candidate'):
        side = payload.get(name)
        if type(side) is not dict or set(side) != {'model','environment','skill_sha','runs'}:
            return {**base,'reason':'INCOMPLETE_'+name.upper()}
        if not isinstance(side['skill_sha'],str) or not SHA.fullmatch(side['skill_sha']):
            return {**base,'reason':'INVALID_SKILL_REVISION'}
        if not isinstance(side['model'],str) or not side['model'].strip() or not isinstance(side['environment'],str) or not side['environment'].strip():
            return {**base,'reason':'ENVIRONMENT_OR_MODEL_MISSING'}
        runs = _runs(side['runs'])
        if runs is None or any(r['skipped'] for r in runs.values()):
            return {**base,'reason':'MALFORMED_OR_SKIPPED_EVALUATION'}
        sides.append((side,runs))
    b, c = sides
    if b[0]['model'] != c[0]['model'] or b[0]['environment'] != c[0]['environment'] or set(b[1]) != set(c[1]):
        return {**base,'reason':'UNPAIRED_RUNS_OR_ENVIRONMENT'}
    if any(b[1][seed]['cases'] != c[1][seed]['cases'] for seed in b[1]):
        return {**base,'reason':'TEST_CASE_COUNT_MISMATCH'}
    bs, cs = sum(x['passed'] for x in b[1].values()),sum(x['passed'] for x in c[1].values())
    bt, ct = sum(x['tokens'] for x in b[1].values()),sum(x['tokens'] for x in c[1].values())
    regressed = any(c[1][seed]['passed'] < b[1][seed]['passed'] for seed in b[1])
    if regressed: status='REGRESSION_REVIEW'
    elif cs <= bs: status='NO_MEASURED_GAIN'
    elif bt == 0 or ct > bt * 1.15: status='COST_REGRESSION_REVIEW'
    else: status='CANDIDATE_FOR_INDEPENDENT_VERIFICATION'
    return {**base,'status':status,'reason':'RECEIPT_COMPARISON_ONLY',
            'paired_runs':len(b[1]),'baseline_passed':bs,'candidate_passed':cs,
            'baseline_tokens':bt,'candidate_tokens':ct,
            'pass_gain_percentage_points':round(100*(cs-bs)/sum(x['cases'] for x in b[1].values()),2)}

def main() -> int:
    import argparse
    from pathlib import Path
    p=argparse.ArgumentParser()
    p.add_argument('--receipt',type=Path,required=True)
    args=p.parse_args()
    try: result=evaluate(json.loads(args.receipt.read_text('utf-8')))
    except (OSError,UnicodeError,ValueError): result=evaluate(None)
    print(json.dumps(result,sort_keys=True,ensure_ascii=False))
    return 0 if result['status']=='CANDIDATE_FOR_INDEPENDENT_VERIFICATION' else 3

if __name__=='__main__':
    raise SystemExit(main())
