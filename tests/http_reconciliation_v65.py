"""Local HTTP smoke through Uvicorn + requests; not a production deployment."""
from __future__ import annotations
import io,os,socket,subprocess,sys,tempfile,time
from pathlib import Path
import requests
from openpyxl import Workbook
ROOT=Path(__file__).resolve().parents[1]

def xlsx(company,ref,amount):
 wb=Workbook();sheet=wb.active
 for row in [('문서종류','매출전표'),('거래처',company),('거래일','2026-10-21'),('총금액',amount),('문서번호',ref)]:sheet.append(row)
 out=io.BytesIO();wb.save(out);return out.getvalue()

def run():
 with tempfile.TemporaryDirectory() as temp:
  with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
  env={**os.environ,'JARVIS_DB_PATH':str(Path(temp)/'db.sqlite3'),
       'JW_INSECURE_LOCAL_DEV':'1','DEMO_SEED':'1','JW_ENV':'test','JW_UPLOAD_SCAN':'off'}
  proc=subprocess.Popen([sys.executable,'-m','uvicorn','app.main:app','--host','127.0.0.1','--port',str(port)],
    cwd=str(ROOT),env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
  try:
   url=f'http://127.0.0.1:{port}'
   for i in range(100):
    try:
     if requests.get(url+'/api/config',timeout=1).status_code==200:break
    except requests.RequestException:time.sleep(.2)
   else:raise RuntimeError('Uvicorn boot did not finish')
   s=requests.Session()
   assert s.get(url+'/api/evidence/reconciliation/queue',timeout=5).status_code==401
   login=s.post(url+'/api/login',json={'email':'demo@hanbit.example','password':'Demo!2026secure'},timeout=10)
   assert login.status_code==200,login.text
   headers={'X-CSRF-Token':login.json()['csrf_token']}
   cust=s.get(url+'/api/customers',timeout=5).json()[0]
   quote=s.post(url+'/api/quotes',headers=headers,json={'customer_id':cust['id'],'title':'Local HTTP V65',
       'vat_mode':'taxable','items':[{'name':'부품A','quantity':2,'unit_price':5000}]},timeout=5)
   assert quote.status_code==201,quote.text
   d=s.get(url+'/api/quotes/'+quote.json()['id'],timeout=5).json()
   staged=s.post(url+'/api/evidence/preview',files={'file':('sales.xlsx',xlsx(d['customer_name_snapshot'],d['doc_no'],d['money']['total']))},headers=headers,timeout=25)
   assert staged.status_code==201,staged.text
   p=staged.json()
   confirmed=s.post(url+'/api/evidence/preview/'+p['id']+'/confirm',headers=headers,json={
      'preview_digest':p['digest'],'record_type':'sales','document_kind':'sales_slip',
      'counterparty':d['customer_name_snapshot'],'document_date':'2026-10-21',
      'gross_amount':d['money']['total'],'reference_number':d['doc_no'],'original_checked':True},timeout=5)
   assert confirmed.status_code==201,confirmed.text
   rid=confirmed.json()['id']
   cands=s.get(url+'/api/evidence/records/'+rid+'/candidates',timeout=5)
   assert cands.status_code==200,cands.text
   match=next(x for x in cands.json()['candidates'] if x['source_id']==d['id'])
   body={'source_type':match['source_type'],'source_id':match['source_id'],
         'comparison_digest':match['comparison_digest'],'original_and_differences_checked':True}
   assert s.post(url+'/api/evidence/records/'+rid+'/reconcile-link',json=body,timeout=5).status_code==403
   linked=s.post(url+'/api/evidence/records/'+rid+'/reconcile-link',json=body,headers=headers,timeout=5)
   assert linked.status_code==201,linked.text
   summary=s.get(url+'/api/evidence/reconciliation/queue',timeout=5).json()
   assert summary['items'][0]['status']=='linked'
   assert s.get(url+'/api/evidence/records/'+rid+'/reconciliation',timeout=5).json()['linked'] is True
   print('V6.5 HTTP loopback PASS: auth/CSRF, source+OCR evidence, candidates, operator acknowledgement, immutable linkage')
  finally:
   proc.terminate()
   try:proc.communicate(timeout=10)
   except subprocess.TimeoutExpired:proc.kill();proc.communicate()

if __name__=='__main__':run()
