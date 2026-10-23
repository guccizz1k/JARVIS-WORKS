"""Disposable loopback HTTP smoke test. No remote deployment or customer data."""
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path
import requests
ROOT=Path(__file__).resolve().parents[1]

def run():
    with tempfile.TemporaryDirectory() as temp, socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        env=os.environ.copy();env.update({'DEMO_SEED':'1','JW_INSECURE_LOCAL_DEV':'1','JW_ENV':'review','JARVIS_DB_PATH':str(Path(temp)/'works.db')})
        proc=subprocess.Popen(['python','-m','uvicorn','app.main:app','--host','127.0.0.1','--port',str(port),'--log-level','error'],cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        sock.close()
        try:
            host=f'http://127.0.0.1:{port}'
            deadline=time.monotonic()+15
            while time.monotonic()<deadline:
                try:
                    if requests.get(host+'/api/config',timeout=1).status_code==200:break
                except requests.RequestException:time.sleep(.1)
            else:raise AssertionError('Uvicorn did not start on loopback')
            with requests.Session() as client:
                assert client.get(host+'/',timeout=5).status_code==200
                script=client.get(host+'/static/automation_v61.js',timeout=5)
                assert script.status_code==200 and 'automationPageV61' in script.text
                login=client.post(host+'/api/login',json={'email':'demo@hanbit.example','password':'Demo!2026secure'},timeout=5)
                assert login.status_code==200,login.text
                assert client.get(host+'/api/me',timeout=5).status_code==200
                metrics=client.get(host+'/api/automation/time-savings',timeout=5)
                assert metrics.status_code==200 and metrics.json()['status']=='NOT_MEASURED'
                active=client.get(host+'/api/automation/timing/active',timeout=5)
                assert active.status_code==200 and active.json() is None
                csrf=login.json()['csrf_token']
                created=client.post(host+'/api/automation/timing/start',headers={'X-CSRF-Token':csrf},json={'workflow':'trade_statement','mode':'manual'},timeout=5)
                assert created.status_code==201,created.text
                run_id=created.json()['id']
                assert client.get(host+'/api/automation/timing/active',timeout=5).json()['id']==run_id
                cancelled=client.post(host+'/api/automation/timing/'+run_id+'/cancel',headers={'X-CSRF-Token':csrf},json={},timeout=5)
                assert cancelled.status_code==200,cancelled.text
            print('V6.1 HTTP LOOPBACK: PASS startup, static JS, auth, metrics, active/cancel, CSRF')
        finally:
            proc.terminate()
            try:proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:proc.kill();proc.communicate()

if __name__=='__main__':run()
