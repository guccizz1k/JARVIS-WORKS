"""Actual loopback TLS/cookies and bridge race/financial workflow; synthetic only."""
import os
import socket
import ssl
import sqlite3
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]


def test_bridge_real_https_cookie_epoch_and_full_business_flow(tmp_path):
    cert, key = tmp_path/'server.crt', tmp_path/'server.key'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-sha256','-days','1','-nodes',
                    '-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1',
                    '-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
    key.chmod(0o600)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
    env={**os.environ,'JW_ENV':'review','DEMO_SEED':'1','JARVIS_DB_PATH':str(tmp_path/'synthetic.db'),
         'JW_ROOT_UI':'owner-visual-review','JW_APPROVED_UI_REVIEW':'ISOLATED_REVIEW_ONLY'}
    for name in ('BOOTSTRAP_EMAIL','BOOTSTRAP_PASSWORD','JW_INSECURE_LOCAL_DEV'):
        env.pop(name,None)
    with (tmp_path/'server.log').open('w') as log:
        proc=subprocess.Popen([sys.executable,'-m','uvicorn','app.main:app','--host','127.0.0.1',
                               '--port',str(port),'--ssl-certfile',str(cert),'--ssl-keyfile',str(key)],
                              cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT)
        try:
            origin=f'https://127.0.0.1:{port}'
            context=ssl.create_default_context(cafile=str(cert))
            with httpx.Client(verify=context,trust_env=False) as client:
                for _ in range(120):
                    assert proc.poll() is None, 'Synthetic HTTPS server exited'
                    try:
                        if client.get(origin+'/api/health').status_code==200: break
                    except httpx.TransportError: pass
                    time.sleep(.1)
                else: raise AssertionError('Synthetic HTTPS readiness timeout')
            from app.main import hash_password, now
            with sqlite3.connect(tmp_path/'synthetic.db') as db:
                org=db.execute("SELECT org_id FROM users WHERE email='demo@hanbit.example'").fetchone()[0]
                db.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',
                           (uuid.uuid4().hex,org,'sameorg@example.invalid',hash_password('Demo!2026secure'),'Synthetic member','member',now()))
            from tests.test_evidence_v64 import xlsx
            evidence=tmp_path/'synthetic.xlsx'
            evidence.write_bytes(xlsx(company='SYNTHETIC ONLY',gross=1000,reference='TLS-EVIDENCE-01'))
            runenv={**env,'JW_TEST_EVIDENCE_FILE':str(evidence),'NODE_EXTRA_CA_CERTS':str(cert),'JW_TEST_ORIGIN':origin,'JW_TEST_PASSWORD':'Demo!2026secure'}
            result=subprocess.run(['node','tests/fixtures/v223_auth_https.mjs'],cwd=ROOT,env=runenv,
                                  capture_output=True,text=True,timeout=90)
            assert result.returncode==0, result.stdout+'\n'+result.stderr
            assert 'PASS_REAL_HTTPS_BRIDGE_COOKIE_CSRF_EPOCH_AND_BUSINESS' in result.stdout
        finally:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill();proc.wait()
