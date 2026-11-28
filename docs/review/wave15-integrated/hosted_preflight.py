"""No network or credentials. Fail closed before a future isolated QA load run."""
from datetime import timedelta
from urllib.parse import urlsplit
import json,hashlib,re
from review_gates import need,digest,utc

def pin(x):return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()).hexdigest()
def assess(*,plan,expected_pin,observed,now):
    need(type(plan) is dict and set(plan)=={'sha','service','deployment','origin','fixture_sha256','requests','concurrency','scope'} and digest(expected_pin) and pin(plan)==expected_pin,'QA_PLAN_PIN')
    need(digest(plan['sha'],40) and digest(plan['fixture_sha256']) and all(type(plan[k]) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,128}',plan[k]) for k in ('service','deployment')) and plan['scope']=='ISOLATED_SYNTHETIC_QA','QA_SCOPE')
    need(type(plan['origin']) is str,'QA_ORIGIN');u=urlsplit(plan['origin']);need(u.scheme=='https' and u.hostname and re.fullmatch(r'[a-z0-9.-]+\.onrender\.com',u.hostname) and u.netloc==u.hostname and not (u.path or u.query or u.fragment),'QA_ORIGIN')
    need(type(plan['requests']) is int and 1<=plan['requests']<=24 and type(plan['concurrency']) is int and 1<=plan['concurrency']<=min(4,plan['requests']),'QA_LIMIT')
    need(type(observed) is dict and set(observed)=={'sha','service','deployment','origin','fixture_sha256','live','isolated_qa','auth_fixture_verified','observed_at'} and utc(now) and utc(observed['observed_at']) and all(type(observed[k]) is bool for k in ('live','isolated_qa','auth_fixture_verified')),'QA_OBSERVATION')
    reasons=[]
    for k in ('sha','service','deployment','origin','fixture_sha256'):
        if plan[k]!=observed[k]:reasons.append('QA_MISMATCH_'+k.upper())
    if not timedelta(0)<=now-observed['observed_at']<=timedelta(minutes=5):reasons.append('QA_STALE')
    for k in ('live','isolated_qa','auth_fixture_verified'):
        if not observed[k]:reasons.append('QA_NOT_VERIFIED_'+k.upper())
    return dict(status='BLOCKED' if reasons else 'PINNED_QA_PREFLIGHT_ASSERTIONS_ONLY',reasons=reasons,network_executed=False,load_authorized=False,production_authorized=False)
