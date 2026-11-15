"""NO-GO independent evidence gate for JARVIS WORKS V22.3.
It never authorizes a production release. It rejects synthetic, incomplete, stale,
unsigned, differently-SHA or mixed-origin claims. Network attestation must follow.
"""
from __future__ import annotations
import json, re, sys
from pathlib import Path

SHA='cdcdc857e173f572fb1815f657cbc5d9b117bbd4'
OWNER_UI_SHA='953c1b00cead79173c0c7a9c40319344e510bec9f6a1f646f30e0a147356076d'
REQUIRED=('P1','P2','P3','P4')
REAL_REQUIREMENTS={
 'P1':('offsite_recovery_key_custody','gcm_authenticated','restored_into_independent_pg17','source_restore_signatures_match'),
 'P2':('server_authenticated','csrf_verified','tenant_ab_isolation','real_business_write_readback','all_17_business_routes_real','safari_device'),
 'P3':('actual_external_https','same_sha_deployed','real_authenticated_business_e2e','nonproduction_staging'),
 'P4':('gate1','gate2','gate3','gate4','gate5','zero_fail_error_skip','independent_qa')
}
def evaluate(doc):
    findings=[]
    if not isinstance(doc,dict): return {'status':'BLOCKED','findings':['invalid evidence root'],'can_release':False}
    if doc.get('schema')!='JW_V223_RELEASE_EVIDENCE_V1':findings.append('unrecognized evidence schema')
    if doc.get('candidate_sha')!=SHA:findings.append('candidate SHA differs from isolated reviewed deployment')
    if doc.get('ui_sha256')!=OWNER_UI_SHA:findings.append('owner UI differs from approved immutable original')
    phases=doc.get('phases')
    if not isinstance(phases,dict):phases={}
    for phase in REQUIRED:
        d=phases.get(phase)
        if not isinstance(d,dict):findings.append(phase+': missing evidence');continue
        if d.get('status')!='PASS':findings.append(phase+': not PASS')
        if d.get('candidate_sha')!=SHA:findings.append(phase+': provenance SHA mismatch')
        if d.get('synthetic') is not False:findings.append(phase+': synthetic/unknown cannot prove production equivalent')
        if d.get('real_environment') is not True:findings.append(phase+': missing real-run proof')
        for key in ('evidence_url','independent_run_id','evidence_sha256','environment_id'):
            val=d.get(key)
            if not isinstance(val,str) or not val.strip() or val.lower() in ('unknown','todo','pass','not run','not_run'):
                findings.append(phase+': missing '+key)
        if not isinstance(d.get('evidence_sha256'),str) or not re.fullmatch(r'[0-9a-f]{64}',d['evidence_sha256']):
            findings.append(phase+': malformed evidence SHA-256')
        if not str(d.get('evidence_url','')).startswith('https://'):
            findings.append(phase+': evidence must be HTTPS')
        for key in REAL_REQUIREMENTS[phase]:
            if d.get(key) is not True:findings.append(phase+': unverified '+key)
    independent=doc.get('independent_audit') or {}
    if independent.get('different_operator') is not True or independent.get('reviewed_same_sha')!=SHA:
        findings.append('independent operator same-SHA attestation missing')
    # Even perfect user-controlled JSON cannot prove external action. NEVER issue FINAL_PASS.
    return {'status':'BLOCKED' if findings else 'STRUCTURALLY_ELIGIBLE_EXTERNAL_QA_REQUIRED',
            'findings':sorted(set(findings)),'can_release':False}

def main(argv):
    if len(argv)!=1:print('usage: jw_v223_release_no_go_gate.py evidence.json',file=sys.stderr);return 2
    try:doc=json.loads(Path(argv[0]).read_text('utf8'))
    except (OSError,ValueError):doc=None
    result=evaluate(doc)
    print(json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True))
    return 1 if result['status']=='BLOCKED' else 0

if __name__=='__main__':raise SystemExit(main(sys.argv[1:]))
