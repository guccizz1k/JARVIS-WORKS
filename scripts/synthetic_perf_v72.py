"""Local synthetic API concurrency benchmark; not a production SLA claim."""
from __future__ import annotations
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import statistics
import tempfile
import time
from fastapi.testclient import TestClient


def run(*,workers=4,repeats=6):
    if os.environ.get('JW_ENV','').lower() in ('prod','production'):
        raise RuntimeError('Local synthetic benchmark cannot run against production')
    if workers<1 or workers>16 or repeats<1 or repeats>50:raise ValueError('limits exceeded')
    from app import main
    with tempfile.TemporaryDirectory(prefix='jw-v72-load-') as td:
        previous=main.DB_PATH
        previous_seed=os.environ.get('DEMO_SEED')
        main.DB_PATH=Path(td)/'synthetic.db';os.environ['DEMO_SEED']='1'
        try:
            with TestClient(main.app,base_url='https://testserver') as client:
                login=client.post('/api/login',json={'email':'demo@hanbit.example','password':'Demo!2026secure'})
                assert login.status_code==200
                token=login.cookies.get(main.SESSION_COOKIE)
                headers={'Cookie':main.SESSION_COOKIE+'='+token}
                def visit(i):
                    ts=time.monotonic()
                    path='/api/operations/integrity' if i%2 else '/api/dashboard'
                    resp=client.get(path,headers=headers)
                    return {'ms':(time.monotonic()-ts)*1000,'status':resp.status_code}
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    output=list(pool.map(visit,range(workers*repeats)))
                if any(item['status']!=200 for item in output):
                    raise RuntimeError('Synthetic concurrent request failed')
                times=sorted(x['ms'] for x in output)
                p95=times[max(0,(len(times)*95+99)//100-1)]
                return {'dataset':'demo synthetic only','requests':len(output),'workers':workers,
                        'successes':len(output),'p50_ms':round(statistics.median(times),2),
                        'p95_ms':round(p95,2),'max_ms':round(max(times),2),
                        'local_result':'PASS','production_sla_measured':False}
        finally:
            main.DB_PATH=previous
            if previous_seed is None:os.environ.pop('DEMO_SEED',None)
            else:os.environ['DEMO_SEED']=previous_seed

if __name__=='__main__':print(json.dumps(run(),ensure_ascii=False,indent=2))
