"""Loopback HTTP V6.8 end-to-end — no production resources used."""
from __future__ import annotations
import io,os,socket,subprocess,sys,tempfile,time
from pathlib import Path
import requests
from openpyxl import Workbook
ROOT=Path(__file__).resolve().parents[1]

def file_bytes(company,ref,total):
 w=Workbook();s=w.active
 for row in [('문서종류','매출전표'),('거래처',company),('거래일','2026-10-21'),('총금액',total),('문서번호',ref)]:s.append(row)
 s.append(['품목명','수량','단가','금액']);s.append(['A',2,100,200]);s.append(['B',1,300,300])
 b=io.BytesIO();w.save(b);return b.getvalue()

def run():
 with tempfile.TemporaryDirectory() as tmp:
  with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
  env={**os.environ,'JARVIS_DB_PATH':str(Path(tmp)/'db.sqlite3'),
       'JW_INSECURE_LOCAL_DEV':'1','DEMO_SEED':'1','JW_ENV':'test','JW_UPLOAD_SCAN':'off'}
  proc=subprocess.Popen([sys.executable,'-m','uvicorn','app.main:app','--host','127.0.0.1',
        '--port',str(port)],cwd=str(ROOT),env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
  try:
   base=f'http://127.0.0.1:{port}';s=requests.Session()
   for _ in range(90):
    try:
     if s.get(base+'/api/config',timeout=1).status_code==200:break
    except requests.RequestException:time.sleep(.25)
   else:raise RuntimeError('Uvicorn did not start')
   assert s.get(base+'/api/evidence/reconciliation/exceptions').status_code==401
   auth=s.post(base+'/api/login',json={'email':'demo@hanbit.example','password':'Demo!2026secure'},timeout=10)
   assert auth.status_code==200,auth.text
   csrf={'X-CSRF-Token':auth.json()['csrf_token']}
   customer=s.get(base+'/api/customers').json()[0]
   q=s.post(base+'/api/quotes',headers=csrf,json={'customer_id':customer['id'],
        'title':'HTTP 다중 품목','vat_mode':'taxable','items':[
         {'name':'A','quantity':2,'unit_price':100},{'name':'B','quantity':1,'unit_price':300}]})
   assert q.status_code==201,q.text
   d=s.get(base+'/api/quotes/'+q.json()['id']).json()
   p=s.post(base+'/api/evidence/preview',headers=csrf,files={
        'file':('sales.xlsx',file_bytes(d['customer_name_snapshot'],d['doc_no'],d['money']['total']))},timeout=30)
   assert p.status_code==201,p.text
   assert len(p.json()['document']['suggested_lines'])==2
   document=p.json();c=s.post(base+'/api/evidence/preview/'+document['id']+'/confirm',headers=csrf,json={
     'preview_digest':document['digest'],'record_type':'sales','document_kind':'sales_slip',
     'counterparty':d['customer_name_snapshot'],'document_date':'2026-10-21',
     'gross_amount':d['money']['total'],'reference_number':d['doc_no'],'original_checked':True})
   assert c.status_code==201,c.text
   rid=c.json()['id'];hints=s.get(base+'/api/evidence/records/'+rid+'/line-suggestions')
   assert hints.status_code==200 and len(hints.json()['lines'])==2
   url=base+'/api/evidence/records/'+rid+'/line-items'
   payload={'original_checked':True,'lines':hints.json()['lines']}
   assert s.post(url,json=payload).status_code==403
   saved=s.post(url,headers=csrf,json=payload);assert saved.status_code==201,saved.text
   cand=s.get(base+'/api/evidence/records/'+rid+'/candidates')
   match=next(x for x in cand.json()['candidates'] if x['source_id']==d['id'])
   assert match['issues']==[] and match['line_comparison']['full_source_coverage']
   review_url=base+'/api/evidence/records/'+rid+'/review-event'
   queue=s.get(base+'/api/evidence/reconciliation/exceptions').json()
   row=next(x for x in queue['items'] if x['record_id']==rid)
   event=s.post(review_url,headers=csrf,json={'expected_digest':row['expected_digest'],
        'status':'document_checked','original_checked':True,'note':'실제 원본문서에서 품목과 금액 모두 확인'})
   assert event.status_code==201,event.text
   assert s.get(base+'/api/evidence/records/'+rid+'/review-history').json()['chain_integrity_valid']
   assert s.get(base+'/api/evidence/reconciliation/exceptions').json()['needs_attention']==1
   link=s.post(base+'/api/evidence/records/'+rid+'/reconcile-link',headers=csrf,json={
        'source_type':match['source_type'],'source_id':match['source_id'],
        'comparison_digest':match['comparison_digest'],'original_and_differences_checked':True})
   assert link.status_code==201,link.text
   assert s.get(base+'/api/evidence/reconciliation/exceptions').json()['needs_attention']==0
   assert s.get(base+'/api/evidence/records/'+rid+'/line-items').json()['confirmed']
   print('V6.8 HTTP loopback PASS: authentication, CSRF, suggested lines, manual confirmation, review history, link')
  finally:
   proc.terminate()
   try:proc.communicate(timeout=10)
   except subprocess.TimeoutExpired:proc.kill();proc.communicate()
if __name__=='__main__':run()
