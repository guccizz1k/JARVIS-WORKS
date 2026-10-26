"""Staging-only socket poll benchmark (synthetic gateway; no real PostgreSQL)."""
from __future__ import annotations
import importlib.util
import json
import sys
import time
from contextlib import ExitStack
from pathlib import Path
from threading import Lock
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.pg_messenger_bridge_v90 import SQL, VerifiedSession
from app import pg_messenger_realtime_v90 as improved

BASELINE=Path(__file__).resolve().with_name('pg_messenger_realtime_before_v90.py')
class Gateway:
    def __init__(self): self.lock=Lock();self.calls=0
    def query(self, session, sql, args):
        if sql not in (SQL['messages'],SQL['edits']):raise AssertionError(sql)
        with self.lock:self.calls+=1
        return []

def measure(provider, seconds=1.2, sessions=1):
    gw=Gateway();app=FastAPI()
    app.include_router(provider.create_realtime_router(gw,lambda _: VerifiedSession('s'*64,True),
        allowed_origins=frozenset({'https://testserver'}),poll_seconds=0.02,heartbeat_every=1000))
    with TestClient(app) as client:
        with ExitStack() as stack:
            for i in range(sessions):
                ws = stack.enter_context(client.websocket_connect(
                    f'/api/pg-stage/v90/chats/bench-{i}/stream',
                    headers={'Origin':'https://testserver'}))
                assert ws.receive_json()['type']=='ready'
            t0=time.monotonic();time.sleep(seconds);elapsed=time.monotonic()-t0
            with gw.lock:calls=gw.calls
    return {'sessions':sessions,'elapsed_s':round(elapsed,3),
            'db_mock_queries':calls,'queries_per_s':round(calls/elapsed,1)}

def main():
    spec=importlib.util.spec_from_file_location('app._baseline_ws_v90',BASELINE)
    old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
    a=[measure(old) for _ in range(3)]
    b=[measure(improved) for _ in range(3)]
    avga=sum(x['queries_per_s'] for x in a)/len(a)
    avgb=sum(x['queries_per_s'] for x in b)/len(b)
    multi_old = [measure(old, seconds=1.0, sessions=10) for _ in range(2)]
    multi_new = [measure(improved, seconds=1.0, sessions=10) for _ in range(2)]
    old10 = sum(x['queries_per_s'] for x in multi_old)/len(multi_old)
    new10 = sum(x['queries_per_s'] for x in multi_new)/len(multi_new)
    out={'kind':'Synthetic localhost TestClient+WS; no PostgreSQL',
        'single_connection':{'baseline':a,'candidate':b,
          'mean_original_qps':round(avga,1),'mean_adaptive_qps':round(avgb,1),
          'poll_reduction_percent':round(100*(1-avgb/avga),1)},
        'ten_connections':{'baseline':multi_old,'candidate':multi_new,
          'mean_original_qps':round(old10,1),'mean_adaptive_qps':round(new10,1),
          'poll_reduction_percent':round(100*(1-new10/old10),1)}}
    print(json.dumps(out,indent=2));return 0 if avgb < avga*.7 and new10 < old10*.7 else 1
if __name__=='__main__':sys.exit(main())
