"""Fail-closed review of launch evidence. No deployment or authorization.
Historical lab successes never substitute for externally scoped conditions.
Each evidence pin is independently provided, not taken from its own receipt.
"""
import hashlib,json
from datetime import datetime,timedelta,timezone
from review_gates import need,digest,utc
REQUIRED={'hosted_auth_load':'HOSTED_QA','payroll_expert_review':'INDEPENDENT_REVIEW','payroll_provider_mapping':'EXTERNAL_TEST_CHANNEL','offline_key_access':'OWNER_OFFLINE','recovery_acl_baseline':'INDEPENDENT_RECOVERY','historical_provenance':'HISTORICAL_REVIEW','official_scanner':'HOSTED_QA','ocr_corpus_accuracy':'INDEPENDENT_CORPUS','desktop_flow':'HOSTED_QA'}
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def sha(x):return hashlib.sha256(canonical(x)).hexdigest()

def check(*,candidate_sha,environment,expected_pins,receipts,now):
    need(digest(candidate_sha,40) and type(environment) is str and 1<=len(environment)<=128 and utc(now),'RELEASE_SCOPE')
    need(type(expected_pins) is dict and set(expected_pins)<=set(REQUIRED) and all(digest(x) for x in expected_pins.values()),'RELEASE_PINS')
    need(type(receipts) is dict and set(receipts)<=set(REQUIRED),'RELEASE_RECEIPTS')
    findings={}
    for k,scope in REQUIRED.items():
        r=receipts.get(k)
        if k not in expected_pins or r is None:findings[k]='BLOCKED_MISSING_INDEPENDENT_EVIDENCE';continue
        if type(r) is not dict or set(r)!={'kind','scope','candidate_sha','environment','observed_at','artifact_sha256','result'} or r['kind']!=k or r['scope']!=scope or r['candidate_sha']!=candidate_sha or r['environment']!=environment or not digest(r['artifact_sha256']) or r['result']!='PASS':findings[k]='BLOCKED_SCOPE_OR_RESULT';continue
        if sha(r)!=expected_pins[k]:findings[k]='BLOCKED_PIN';continue
        try:t=datetime.fromisoformat(r['observed_at'])
        except (ValueError,TypeError):findings[k]='BLOCKED_TIME';continue
        # Conservative review policy; owner has not authorized actual release thresholds.
        if not utc(t) or not timedelta(0)<=now-t<=timedelta(days=7):findings[k]='BLOCKED_TIME';continue
        findings[k]='PINNED_CLAIM_PRESENT_NOT_INDEPENDENTLY_ATTESTED'
    return dict(status='BLOCKED' if any(v.startswith('BLOCKED') for v in findings.values()) else 'REVIEW_REQUIRED',findings=findings,release_authorized=False,production_authorized=False,physical_custody_verified=False,statutory_validated=False)
