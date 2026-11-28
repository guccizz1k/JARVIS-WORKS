"""Review-only hosted workload acceptance; no network or load generation.
Only independently pinned request-level evidence and deployment snapshots.
Thresholds must be supplied by owner; no production SLA or authorization claim.
"""
import hashlib,json,math,re
from datetime import datetime,timedelta
from review_gates import need,digest,utc

def pin(x):return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()).hexdigest()
def timestamp(s):
    try:return datetime.fromisoformat(s)
    except (TypeError,ValueError):return None

def assess(*,plan,expected_plan_pin,record,expected_record_pin,now):
    need(type(plan) is dict and set(plan)=={'service','deployment','sha','run_id','ids','max_p95_ms','max_concurrency'} and digest(expected_plan_pin) and pin(plan)==expected_plan_pin,'HOST_PLAN_PIN')
    need(all(type(plan[k]) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,128}',plan[k]) for k in ('service','deployment','run_id')) and digest(plan['sha'],40),'HOST_PLAN_SCOPE')
    ids=plan['ids'];need(type(ids) is list and 1<=len(ids)<=1000 and all(type(x) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,128}',x) for x in ids) and len(set(ids))==len(ids),'HOST_IDS')
    threshold=plan['max_p95_ms'];limit=plan['max_concurrency'];need(type(threshold) is int and 1<=threshold<=60000 and type(limit) is int and 1<=limit<=min(16,len(ids)),'HOST_LIMIT')
    need(type(record) is dict and set(record)=={'plan_pin','before','after','start','end','samples','max_concurrency'} and record['plan_pin']==expected_plan_pin and digest(expected_record_pin) and pin(record)==expected_record_pin,'HOST_RECORD_PIN')
    start,end=timestamp(record['start']),timestamp(record['end']);need(all(utc(x) for x in (start,end,now)) and timedelta(0)<end-start<=timedelta(minutes=10) and timedelta(0)<=now-end<=timedelta(minutes=5),'HOST_WINDOW')
    reasons=[]
    for name in ('before','after'):
        x=record[name];need(type(x) is dict and set(x)=={'service','deployment','sha','live','observed_at'},'HOST_DEPLOY_SHAPE')
        t=timestamp(x['observed_at']);need(utc(t),'HOST_DEPLOY_TIME')
        if (x['service'],x['deployment'],x['sha'],x['live'])!=(plan['service'],plan['deployment'],plan['sha'],True) or type(x['live']) is not bool:reasons.append('DEPLOYMENT_CHANGED')
        if name=='before' and not (start-t>=timedelta(0) and start-t<=timedelta(minutes=1)):reasons.append('DEPLOYMENT_BRACKET')
        if name=='after' and not (end<=t<=now and t-end<=timedelta(minutes=1)):reasons.append('DEPLOYMENT_BRACKET')
    need(type(record['max_concurrency']) is int and 1<=record['max_concurrency']<=limit,'HOST_CONCURRENCY')
    rows=record['samples'];need(type(rows) is list and len(rows)<=len(ids),'HOST_SAMPLE_SHAPE');seen=set();ms=[]
    for x in rows:
        need(type(x) is dict and set(x)=={'id','status','ms','tenant_scope_ok','tls_ok','business_ok'} and type(x['id']) is str and x['id'] in ids and x['id'] not in seen,'HOST_SAMPLE_BINDING');seen.add(x['id'])
        v=x['ms'];need(type(v) in (int,float) and math.isfinite(v) and 0<=v<=(end-start).total_seconds()*1000+1 and type(x['status']) is int and all(type(x[k]) is bool for k in ('tenant_scope_ok','tls_ok','business_ok')),'HOST_SAMPLE_VALUE')
        if x['status']==200 and all(x[k] for k in ('tenant_scope_ok','tls_ok','business_ok')):ms.append(v)
        else:reasons.append('REQUEST_FAILED')
    if seen!=set(ids):reasons.append('REQUEST_MISSING')
    ms.sort();p95=ms[math.ceil(.95*len(ms))-1] if ms else None
    if p95 is None or p95>threshold:reasons.append('LATENCY_THRESHOLD')
    return dict(status='BLOCKED' if reasons else 'PINNED_HOSTED_ASSERTIONS_MATCH_ONLY',reasons=sorted(set(reasons)),completed=len(seen),successful=len(ms),p95_ms=p95,production_sla_verified=False,provider_authenticated=False,production_authorized=False)
