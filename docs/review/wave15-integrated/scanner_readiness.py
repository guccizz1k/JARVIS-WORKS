"""Independent readiness classification: keep all blockers, no stale DB scanning."""
from datetime import datetime,timezone,timedelta
from review_gates import need,utc,digest
from cvd_diagnostics import PAIR_NAMES,NAMES

def assess(*,header,available,cert_count,modern_checks,now):
    need(type(header) is dict and type(header.get('version')) is int and header['version']>0 and utc(now),'SCANNER_HEADER')
    try:build=datetime.fromisoformat(header['build_at']);observed=datetime.fromisoformat(header['observed_at'])
    except (KeyError,ValueError,TypeError):raise ValueError('SCANNER_HEADER_TIME') from None
    need(utc(build) and utc(observed) and type(available) is list and all(type(x) is str for x in available) and len(set(available))==len(available) and set(available)<=set(PAIR_NAMES),'SCANNER_INPUT')
    need(type(cert_count) is int and 0<=cert_count<=32 and type(modern_checks) is dict and set(modern_checks)<=set(NAMES) and all(type(v) is bool for v in modern_checks.values()),'SCANNER_CHECKS')
    reasons=[]
    if not timedelta(0)<=now-observed<=timedelta(hours=24):reasons.append('OBSERVATION_TIME_INVALID')
    if build>now or build>observed:reasons.append('BUILD_IN_FUTURE')
    elif now-build>timedelta(hours=48):reasons.append('DAILY_BUILD_OLDER_THAN_48H')
    absent=sorted(set(PAIR_NAMES)-set(available))
    if absent:reasons.append('DETACHED_OR_DATABASE_FILES_MISSING')
    if not cert_count:reasons.append('TRUST_CERT_MISSING')
    if set(modern_checks)!=set(NAMES):reasons.append('DETACHED_SIGNATURE_CHECK_NOT_COMPLETE')
    if any(v is False for v in modern_checks.values()):reasons.append('DETACHED_SIGNATURE_REJECTED')
    return dict(status='BLOCKED' if reasons else 'REVIEW_ASSERTIONS_ONLY',reasons=reasons,missing=absent,age_seconds=int((now-build).total_seconds()),scan_authorized=False,production_authorized=False,independent_trust_verified=False)
