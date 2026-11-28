"""Read-only provider metrics classification; empty != zero requests.
Do not infer successful authenticated workload or served SHA from provider aggregates.
"""
from datetime import datetime,timedelta
from review_gates import need,utc

def classify(record,*,service,expected_start,expected_end):
    need(type(record) is dict and set(record)=={'resourceId','timeRange','metrics'} and record['resourceId']==service,'PROVIDER_METRIC_SCOPE')
    need(utc(expected_start) and utc(expected_end) and timedelta(0)<expected_end-expected_start<=timedelta(hours=24),'PROVIDER_METRIC_WINDOW')
    window=record['timeRange'];need(type(window) is dict and set(window)=={'start','end'},'PROVIDER_METRIC_WINDOW')
    need(datetime.fromisoformat(window['start'])==expected_start and datetime.fromisoformat(window['end'])==expected_end,'PROVIDER_METRIC_WINDOW')
    rows=record['metrics'];need(type(rows) is list and len(rows)==2,'PROVIDER_METRIC_SHAPE');counts={}
    for x in rows:
        need(type(x) is dict and set(x)=={'type','data'} and x['type'] in ('http_request_count','http_latency') and x['type'] not in counts and type(x['data']) is list and len(x['data'])<=10000,'PROVIDER_METRIC_SHAPE')
        counts[x['type']]=len(x['data'])
    # Counts are series counts, not request counts. Aggregates require another parser.
    return dict(status='BLOCKED_EMPTY_METRIC_SERIES' if not all(counts.values()) else 'AGGREGATES_PRESENT_NOT_BUSINESS_PROOF',series_counts=counts,authenticated_workload_verified=False,provider_sla_verified=False,production_authorized=False)
