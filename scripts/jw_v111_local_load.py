"""Bounded loopback-only GET /healthz load probe; not a production load test."""
from __future__ import annotations
import json
import math
import os
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPHandler, HTTPRedirectHandler

class DenyRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None

def validate_target(value: str) -> str:
    if type(value) is not str:
        raise ValueError('loopback-only address required')
    try:
        p=urlsplit(value)
        if (p.scheme!='http' or p.hostname!='127.0.0.1'
            or p.username is not None or p.password is not None
            or p.path!='/healthz' or p.query or p.fragment
            or p.port is None or not 1024<=p.port<=65535
            or p.netloc!='127.0.0.1:'+str(p.port)
            or value!='http://127.0.0.1:'+str(p.port)+'/healthz'):
            raise ValueError('refuse non-loopback destination')
    except (ValueError,TypeError) as exc:
        raise ValueError('refuse non-loopback destination') from exc
    return value

def probe(url: str, *, requests: int = 100, concurrency: int = 4) -> dict:
    validate_target(url)
    if (os.getenv('JW_ENV','').lower() in ('production','prod')
        or os.getenv('JW_SCALE_ALLOW_LOCAL_PROBE')!='YES_LOOPBACK_ONLY'):
        raise RuntimeError('local-only approval missing')
    if (type(requests) is not int or type(concurrency) is not int
        or not 1<=requests<=500 or not 1<=concurrency<=16 or requests<concurrency):
        raise ValueError('bounded probe limits exceeded')
    opener=build_opener(HTTPHandler(),DenyRedirect())
    def one(_:int) -> tuple[int,float]:
        before=time.monotonic()
        try:
            response=opener.open(
                Request(url,method='GET',headers={'Accept':'application/json'}),timeout=3)
            with response:
                code=response.status
                response.read(4096)
        except HTTPError as err:
            code=err.code
        except (URLError,OSError,TimeoutError):
            code=0
        return code,(time.monotonic()-before)*1000
    started=time.monotonic()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        results=list(pool.map(one,range(requests)))
    elapsed=time.monotonic()-started
    times=sorted(ms for _,ms in results)
    def percentile(p:float)->float:
        return round(times[max(0,math.ceil(len(times)*p)-1)],2)
    failed=sum(code!=200 for code,_ in results)
    return {
        'evidence':'LOCALHOST_HEALTH_ENDPOINT_ONLY',
        'requests':requests,'concurrency':concurrency,
        'http_successes':requests-failed,'error_fraction':round(failed/requests,5),
        'p50_ms':percentile(.5),'p95_ms':percentile(.95),
        'p99_ms':percentile(.99),'rps':round(requests/elapsed,2),
        'business_write_load_measured':False,'multi_tenant_rls_load_measured':False,
        'websocket_broadcast_load_measured':False,'100k_capacity_verified':False}

def main()->int:
    import argparse
    parser=argparse.ArgumentParser(description='Only 127.0.0.1 /healthz; never public')
    parser.add_argument('--url',required=True)
    parser.add_argument('--requests',type=int,default=100)
    parser.add_argument('--concurrency',type=int,default=4)
    args=parser.parse_args()
    try:
        print(json.dumps(probe(args.url,requests=args.requests,
                               concurrency=args.concurrency),indent=2))
        return 0
    except (RuntimeError,ValueError):
        print(json.dumps({'status':'BLOCKED','reason':'LOCAL_PROBE_GUARD'}))
        return 3

if __name__=='__main__':
    raise SystemExit(main())
