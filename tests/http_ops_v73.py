"""Actual local loopback FastAPI HTTP integration (not production or Safari)."""
from __future__ import annotations
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import requests


def run():
    with tempfile.TemporaryDirectory(prefix='jw-v73-http-') as temp:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        env=os.environ.copy()
        env.update({'JARVIS_DB_PATH':str(Path(temp)/'dev.db'), 'DEMO_SEED':'1',
                    'JW_ENV':'development','JW_INSECURE_LOCAL_DEV':'1'})
        proc=subprocess.Popen([sys.executable,'-m','uvicorn','app.main:app',
            '--host','127.0.0.1','--port',str(port)],cwd=str(Path(__file__).parents[1]),
            env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            base=f'http://127.0.0.1:{port}'
            for attempt in range(60):
                try:
                    ready=requests.get(base+'/api/health',timeout=1)
                    if ready.status_code==200:break
                except requests.RequestException:pass
                if proc.poll() is not None:raise AssertionError('Local server terminated')
                time.sleep(.2)
            else:raise AssertionError('Local server timeout')
            with requests.Session() as s:
                assert s.get(base+'/api/operations/integrity',timeout=3).status_code==401
                login=s.post(base+'/api/login',json={'email':'demo@hanbit.example','password':'Demo!2026secure'},timeout=5)
                assert login.status_code==200,login.text
                resp=s.get(base+'/api/operations/integrity',timeout=5)
                assert resp.status_code==200,resp.text
                summary=resp.json()
                assert summary['status']=='pass' and summary['operational_pg_rls_verified'] is False
                assert 'cross-origin' not in str(summary)
                # Untrusted Origin blocked on mutations, even with valid session+CSRF.
                denied=s.post(base+'/api/logout',headers={
                    'Origin':'https://evil.example',
                    'X-CSRF-Token':login.json()['csrf_token']},timeout=5)
                assert denied.status_code==403,denied.text
                # The rejected cross-origin request must not revoke this login.
                assert s.get(base+'/api/operations/integrity',timeout=5).status_code==200
            return {'local_http':'PASS','unauthenticated':'401',
                    'admin_integrity':'PASS','origin_guard':'PASS',
                    'real_postgres_verified':False,'safari_verified':False}
        finally:
            proc.terminate()
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)

if __name__=='__main__':
    import json
    print(json.dumps(run(),ensure_ascii=False))
