"""Freshness diagnostics for exact vendor CVD header; no freshness bypass.
Header values are unauthenticated until vendor verification succeeds.
"""
from datetime import datetime,timezone,timedelta
from review_gates import need,Blocked,utc
import re,hashlib,json

NAMES=('main.cvd','daily.cvd','bytecode.cvd')
PAIR_NAMES=tuple(x for n in NAMES for x in (n,n+'.sign'))

def parse_header(raw):
    need(type(raw) is bytes and len(raw)==512,'CVD_HEADER_LENGTH')
    try: text=raw.decode('ascii').rstrip(' \x00\r\n')
    except UnicodeError: raise Blocked('CVD_HEADER_ENCODING') from None
    # Canonical ClamAV header: magic + 8 fields. Build date string may contain colons.
    fields=text.rsplit(':',7)
    need(len(fields)==8 and fields[0].startswith('ClamAV-VDB:') and len(fields[0])>11 and all(fields[i] for i in range(1,8)),'CVD_HEADER_SHAPE')
    need(all(re.fullmatch(r'[0-9]{1,10}',fields[i]) for i in (1,2,3,7)),'CVD_HEADER_NUMBER')
    version,sigs,level,epoch=(int(fields[i]) for i in (1,2,3,7))
    need(0<version<=2**32-1 and 0<sigs<=2**32-1 and 0<level<=2**32-1 and 0<epoch<=2**32-1,'CVD_HEADER_NUMBER')
    return dict(version=version,signatures=sigs,functionality_level=level,build_at=datetime.fromtimestamp(epoch,timezone.utc))

def diagnose(*,header,now,observed_at,advertised_version=None,previous_verified_version=None,engine_level=None):
    need(utc(now) and utc(observed_at),'CVD_TIME')
    x=parse_header(header);build=x['build_at'];reasons=[]
    if not timedelta(0)<=now-observed_at<=timedelta(hours=24):reasons.append('OBSERVATION_TIME_INVALID')
    if build>observed_at or build>now:reasons.append('BUILD_IN_FUTURE')
    elif now-build>timedelta(hours=48) or observed_at-build>timedelta(hours=48):reasons.append('DAILY_BUILD_OLDER_THAN_48H')
    for n in (advertised_version,previous_verified_version,engine_level):need(n is None or type(n) is int and 0<n<=2**32-1,'CVD_REFERENCE_VALUE')
    if advertised_version is not None and x['version']!=advertised_version:reasons.append('ADVERTISED_VERSION_MISMATCH')
    if previous_verified_version is not None and x['version']<previous_verified_version:reasons.append('VERSION_ROLLBACK')
    if engine_level is not None and x['functionality_level']>engine_level:reasons.append('ENGINE_LEVEL_INSUFFICIENT')
    return dict(status='BLOCKED' if reasons else 'HEADER_MATCH_ONLY',reasons=reasons,version=x['version'],build_at=build.isoformat(),observed_at=observed_at.isoformat(),age_seconds=int((now-build).total_seconds()),advertised_version=advertised_version,previous_verified_version=previous_verified_version,detached_signature_verified=False,scan_authorized=False,production_authorized=False)

# Only modern detached signature sets may enter this review candidate.
def check_pairs(entries):
    need(type(entries) is dict and set(entries)==set(PAIR_NAMES),'CVD_DETACHED_SET')
    from review_gates import digest
    for name,row in entries.items():
        limit=65536 if name.endswith('.sign') else 512*1024*1024
        minimum=1 if name.endswith('.sign') else 512
        need(type(row) is dict and set(row)=={'sha256','bytes'} and digest(row['sha256']) and type(row['bytes']) is int and minimum<=row['bytes']<=limit,'CVD_PAIR_ENTRY')
    return hashlib.sha256(json.dumps(entries,sort_keys=True,separators=(',',':')).encode()).hexdigest()
