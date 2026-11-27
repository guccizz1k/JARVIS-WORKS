"""Offline incident assessment only. No monitoring connection, rollback or deployment.
Thresholds and observed metrics must be independently supplied and authenticated.
"""
from datetime import datetime,timezone,timedelta
import re

def assess(*,expected_source,observed_source,observed_at,now,window_seconds,
           request_count,error_count,p95_ms,health_ok,policy):
    def need(ok,code):
        if not ok:raise ValueError(code)
    def integer(x,lo,hi):return type(x) is int and lo<=x<=hi
    need(type(expected_source) is str and re.fullmatch("[a-f0-9]{40}",expected_source)
        and type(observed_source) is str and re.fullmatch("[a-f0-9]{40}",observed_source),"INCIDENT_SOURCE")
    need(all(type(x) is datetime and x.utcoffset()==timedelta(0) for x in (observed_at,now)),"INCIDENT_TIME")
    need(type(policy) is dict and set(policy)=={"max_age_seconds","minimum_requests","max_error_bps","max_p95_ms","window_seconds"},"INCIDENT_POLICY")
    need(integer(policy["max_age_seconds"],1,86400) and integer(policy["minimum_requests"],1,10**9)
        and integer(policy["max_error_bps"],0,10000) and integer(policy["max_p95_ms"],1,10**7)
        and integer(policy["window_seconds"],1,86400),"INCIDENT_POLICY")
    need(integer(window_seconds,1,86400) and integer(request_count,0,10**9)
        and integer(error_count,0,request_count) and (p95_ms is None or integer(p95_ms,0,10**7))
        and type(health_ok) is bool,"INCIDENT_METRICS")
    reasons=[]
    if observed_source!=expected_source:reasons.append("SOURCE_MISMATCH")
    if not timedelta(0)<=now-observed_at<=timedelta(seconds=policy["max_age_seconds"]):reasons.append("STALE_OR_FUTURE")
    if window_seconds!=policy["window_seconds"]:reasons.append("WINDOW_MISMATCH")
    if request_count<policy["minimum_requests"] or p95_ms is None:reasons.append("INSUFFICIENT_METRICS")
    if reasons:status="BLOCKED_EVIDENCE"
    else:
        if not health_ok:reasons.append("HEALTH_FAILURE")
        if error_count*10000>request_count*policy["max_error_bps"]:reasons.append("ERROR_RATE_EXCEEDED")
        if p95_ms>policy["max_p95_ms"]:reasons.append("LATENCY_EXCEEDED")
        status="INCIDENT_REVIEW_REQUIRED" if reasons else "OBSERVATION_WITHIN_SUPPLIED_LIMITS"
    return dict(status=status,reasons=reasons,provider_verified=False,
        automatic_rollback=False,rollback_authorized=False,production_authorized=False)
