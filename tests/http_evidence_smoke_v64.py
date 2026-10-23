"""Synthetic isolated loopback HTTP smoke (real Uvicorn process; not an external deployment)."""
from __future__ import annotations
import os,socket,subprocess,sys,tempfile,time
from pathlib import Path
import requests
from tests.test_evidence_v64 import xlsx
ROOT=Path(__file__).resolve().parents[1]

def run():
 with tempfile.TemporaryDirectory() as tmp:
  with socket.socket() as sock:
   sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
  env={**os.environ,'JARVIS_DB_PATH':str(Path(tmp)/'db.sqlite3'),
       'JW_INSECURE_LOCAL_DEV':'1','DEMO_SEED':'1','JW_ENV':'test','JW_UPLOAD_SCAN':'off'}
  p=subprocess.Popen([sys.executable,'-m','uvicorn','app.main:app','--host','127.0.0.1','--port',str(port)],
       cwd=str(ROOT),env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
  try:
   url=f'http://127.0.0.1:{port}'
   for i in range(100):
    try:
     if requests.get(url+'/api/config',timeout=.5).status_code==200:break
    except requests.RequestException:time.sleep(.2)
   else:raise RuntimeError('HTTP server failed to boot: '+str(p.poll()))
   sess=requests.Session()
   assert sess.get(url+'/api/evidence/dashboard',timeout=4).status_code==401
   login=sess.post(url+'/api/login',json={'email':'demo@hanbit.example','password':'Demo!2026secure'},timeout=10)
   assert login.status_code==200,login.text
   csrf=login.json()['csrf_token']
   raw=xlsx()
   assert sess.post(url+'/api/evidence/preview',files={'file':('receipt.xlsx',raw)},timeout=20).status_code==403
   headers={'X-CSRF-Token':csrf}
   uploaded=sess.post(url+'/api/evidence/preview',files={'file':('receipt.xlsx',raw)},headers=headers,timeout=20)
   assert uploaded.status_code==201,uploaded.text
   pdoc=uploaded.json()
   payload={'preview_digest':pdoc['digest'],'record_type':'expense','document_kind':'receipt',
      'counterparty':'한국상사','document_date':'2026-10-21','gross_amount':11000,
      'reference_number':'R20260001','original_checked':True}
   result=sess.post(url+'/api/evidence/preview/'+pdoc['id']+'/confirm',json=payload,headers=headers,timeout=20)
   assert result.status_code==201,result.text
   dash=sess.get(url+'/api/dashboard',timeout=10).json()
   assert dash['evidence']['by_type']['expense']['amount']==11000
   assert dash['invoices']==0 and dash['outstanding']==0
   print('V6.4 HTTP loopback PASS: auth, CSRF, XLSX upload, review, evidence summary; no official invoice')
  finally:
   p.terminate()
   try:p.communicate(timeout=10)
   except subprocess.TimeoutExpired:p.kill();p.communicate()

if __name__=='__main__':run()
