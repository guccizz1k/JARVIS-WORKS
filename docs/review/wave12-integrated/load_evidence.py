"""Bounded request-level measurement; no extrapolation to production or SLA.
Caller must authenticate provenance and supply independent run plan.
"""
import math,re
from review_gates import need,digest,utc
from datetime import timedelta

def summarize(*,plan,samples,started,ended,now):
    need(type(plan) is dict and set(plan)=={'run_id','sha','environment','request_ids','concurrency'} and digest(plan['sha'],40) and type(plan['run_id']) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,64}',plan['run_id']) and plan['environment']=='DISPOSABLE_LOCAL','LOAD_SCOPE')
    ids=plan['request_ids'];c=plan['concurrency']
    need(type(ids) is list and 1<=len(ids)<=1000 and all(type(x) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,64}',x) for x in ids) and len(set(ids))==len(ids) and type(c) is int and 1<=c<=min(16,len(ids)),'LOAD_PLAN')
    need(all(utc(x) for x in (started,ended,now)) and timedelta(0)<ended-started<=timedelta(minutes=5) and timedelta(0)<=now-ended<=timedelta(minutes=5),'LOAD_TIME')
    need(type(samples) is list and len(samples)<=len(ids),'LOAD_SAMPLE_SHAPE')
    seen=set();success=[];errors=0
    for row in samples:
        need(type(row) is dict and set(row)=={'id','run_id','sha','ms','status','scope_ok'} and type(row['id']) is str and row['id'] in ids and row['id'] not in seen and row['run_id']==plan['run_id'] and row['sha']==plan['sha'],'LOAD_SAMPLE_BINDING')
        seen.add(row['id']);v=row['ms'];s=row['status']
        need(type(v) in (float,int) and 0<=v<=(ended-started).total_seconds()*1000+1 and math.isfinite(v) and type(s) is int and (s==0 or 100<=s<=599) and type(row['scope_ok']) is bool,'LOAD_SAMPLE_VALUE')
        if s==200 and row['scope_ok']:success.append(v)
        else:errors+=1
    success.sort();missing=len(ids)-len(seen)
    return dict(status='LOCAL_MEASUREMENT_ONLY' if errors==missing==0 else 'BLOCKED_INCOMPLETE_OR_FAILED',planned=len(ids),completed=len(seen),successful=len(success),failed=errors,missing=missing,success_p95_ms=round(success[math.ceil(.95*len(success))-1],3) if success else None,hosted_sla_verified=False,production_authorized=False)
