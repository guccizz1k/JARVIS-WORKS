"""Disposable HTTP API smoke via loopback. Does not imply browser or production approval."""
from __future__ import annotations
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path
import requests
from tests.test_smart_import import make_xlsx
from tests.test_quote_import import qxlsx
ROOT=Path(__file__).resolve().parents[1]

def run():
    with tempfile.TemporaryDirectory() as td, socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        port=sock.getsockname()[1]
        sock.close()
        env={**os.environ,'DEMO_SEED':'1','JW_INSECURE_LOCAL_DEV':'1','JW_ENV':'review',
             'JARVIS_DB_PATH':str(Path(td)/'works.db')}
        server=subprocess.Popen(['python','-m','uvicorn','app.main:app','--host',
            '127.0.0.1','--port',str(port),'--log-level','error'],cwd=ROOT,
            env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        host=f'http://127.0.0.1:{port}'
        try:
            for i in range(100):
                try:
                    if requests.get(host+'/api/config',timeout=1).status_code==200:break
                except requests.RequestException:pass
                time.sleep(.1)
            else:raise AssertionError('loopback server did not start')
            with requests.Session() as s:
                login=s.post(host+'/api/login',json={'email':'demo@hanbit.example','password':'Demo!2026secure'},timeout=7)
                assert login.status_code==200,login.text
                csrf={'X-CSRF-Token':login.json()['csrf_token']}
                upload=s.post(host+'/api/imports/batch/preview',headers=csrf,files=[
                    ('files',('one.xlsx',make_xlsx())),('files',('two.xlsx',qxlsx()))],timeout=45)
                assert upload.status_code==201,upload.text
                result=upload.json()
                assert result['staged_count']==2 and result['transaction_records_created']==0
                assert s.get(host+'/api/imports/queue',timeout=6).json()['pending_count']==2
                assert s.get(host+'/api/dashboard',timeout=6).json()['orders']==0
                rejected=s.post(host+'/api/imports/batch/preview',headers=csrf,files=[
                    ('files',('doc.xlsx',make_xlsx())),('files',('image.png',b'\x89PNG'))],timeout=15)
                assert rejected.status_code==422 and '사진 OCR' in rejected.text
                assert s.get(host+'/api/imports/queue',timeout=6).json()['pending_count']==2
                assert s.get(host+'/static/app.js',timeout=6).status_code==200
            print('V6.3 HTTP loopback PASS: auth, multipart, atomic staging, no auto-posting, invalid image rejection')
        finally:
            server.terminate()
            try:server.communicate(timeout=10)
            except subprocess.TimeoutExpired:server.kill();server.communicate(timeout=5)

if __name__=='__main__':run()
