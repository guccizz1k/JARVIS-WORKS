"""Synthetic SQLite messenger write integrity/performance smoke (NOT a PG benchmark).

Only uses a TemporaryDirectory for DB contents; blocks production mode and
never reads a customer's configured JARVIS_DB_PATH. No public HTTP server.
"""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json
import os
import statistics
import tempfile
import time
import uuid


def run(writers: int = 8, total: int = 160):
    if os.environ.get('JW_ENV', '').lower() == 'production':
        raise RuntimeError('Refusing benchmark in production environment')
    if writers < 1 or writers > 16 or total < writers or total > 2000:
        raise ValueError('Benchmark workload exceeds bounded local smoke scope')

    # Import after production guard, but never initialize the configured DB.
    from app import main
    from fastapi.testclient import TestClient
    prior_path = main.DB_PATH
    prior_seed = os.environ.get('DEMO_SEED')
    with tempfile.TemporaryDirectory(prefix='jw-v28-synth-') as tmp:
        try:
            os.environ['DEMO_SEED'] = '1'
            main.DB_PATH = Path(tmp) / 'synthetic.db'
            with TestClient(main.app, base_url='https://testserver') as client:
                def authenticate(email):
                    r=client.post('/api/login',json={
                        'email':email,'password':'Demo!2026secure'})
                    assert r.status_code==200, r.status_code
                    return r.json()['user']['org_id'], {
                        'Cookie':main.SESSION_COOKIE+'='+r.cookies.get(main.SESSION_COOKIE),
                        'X-CSRF-Token':r.json()['csrf_token']}
                org_a, ah=authenticate('demo@hanbit.example')
                org_b, _=authenticate('demo@bada.example')
                r=client.post('/api/messenger/threads',headers=ah,
                              json={'recipient_org_id':org_b})
                assert r.status_code in (200,201),r.status_code
                tid=r.json()['id']
                with main.conn() as c:
                    user=c.execute('SELECT id FROM users WHERE org_id=?',(org_a,)).fetchone()['id']
                def writer(n):
                    started=time.perf_counter()
                    uid=uuid.uuid4().hex
                    with main.transaction() as c:
                        c.execute('''INSERT INTO messenger_messages
                        (id,connection_id,sender_org,sender_user,kind,body,request_id,created_at)
                        VALUES(?,?,?,?,'text',?,?,?)''',
                        (uid,tid,org_a,user,f'Synthetic concurrency {n}',
                         uuid.uuid4().hex,main.now()))
                        seq=c.execute('SELECT message_seq FROM messenger_messages WHERE id=?',
                                      (uid,)).fetchone()[0]
                    return uid,seq,(time.perf_counter()-started)*1000
                start=time.perf_counter()
                with ThreadPoolExecutor(max_workers=writers) as pool:
                    results=list(pool.map(writer,range(total)))
                elapsed=time.perf_counter()-start
                with main.conn() as c:
                    records=c.execute('SELECT id,message_seq FROM messenger_messages '
                         'WHERE connection_id=? ORDER BY message_seq',(tid,)).fetchall()
                    integrity=c.execute('PRAGMA integrity_check').fetchone()[0]
                assert integrity=='ok'
                assert len(records)==total
                assert {r[0] for r in records}=={r[0] for r in results}
                assert [r[1] for r in records]==list(range(1,total+1))
                samples=sorted(r[2] for r in results)
                p95=samples[max(0,int(0.95*(len(samples)-1)))]
                return {
                    'mode':'synthetic local SQLite file-backed temporary database',
                    'postgresql_live':False,'network_server':False,
                    'workers':writers,'messages':total,'duration_s':round(elapsed,3),
                    'throughput_messages_per_s':round(total/elapsed,1),
                    'write_p95_ms':round(p95,2),'write_max_ms':round(max(samples),2),
                    'sqlite_integrity_check':integrity,'sequence_1_to_n':True,
                    'message_loss':0
                }
        finally:
            main.DB_PATH = prior_path
            if prior_seed is None:
                os.environ.pop('DEMO_SEED',None)
            else:
                os.environ['DEMO_SEED']=prior_seed


if __name__=='__main__':
    print(json.dumps(run(),ensure_ascii=False,indent=2))
