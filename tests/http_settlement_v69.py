"""Loopback Uvicorn + HTTP session + CSRF check for V6.9, without production data."""
import os,socket,subprocess,sys,tempfile,time
from pathlib import Path
import requests
ROOT=Path(__file__).resolve().parents[1]

def run():
 with tempfile.TemporaryDirectory() as tmp:
  with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
  env={**os.environ,'JARVIS_DB_PATH':str(Path(tmp)/'db.sqlite'),
       'JW_INSECURE_LOCAL_DEV':'1','DEMO_SEED':'1','JW_ENV':'test','JW_UPLOAD_SCAN':'off'}
  proc=subprocess.Popen([sys.executable,'-m','uvicorn','app.main:app','--host','127.0.0.1','--port',str(port)],
      cwd=str(ROOT),env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
  try:
   base=f'http://127.0.0.1:{port}';s=requests.Session()
   for _ in range(80):
    try:
     if s.get(base+'/api/config',timeout=1).status_code==200:break
    except requests.RequestException:time.sleep(.2)
   else:raise RuntimeError('loopback not ready')
   assert s.get(base+'/api/invoices/notreal/adjustments').status_code==401
   login=s.post(base+'/api/login',json={'email':'demo@hanbit.example','password':'Demo!2026secure'})
   assert login.status_code==200,login.text
   csrf={'X-CSRF-Token':login.json()['csrf_token']}
   def post(path,body):
    resp=s.post(base+path,headers=csrf,json=body,timeout=15)
    assert resp.status_code in (200,201),resp.text
    return resp.json()
   cust=s.get(base+'/api/customers').json()[0]
   q=post('/api/quotes',dict(customer_id=cust['id'],title='V69 HTTP',vat_mode='taxable',
                              items=[dict(name='부품',quantity=4,unit_price=100)]))
   post('/api/quotes/'+q['id']+'/status',dict(status='sent'))
   post('/api/quotes/'+q['id']+'/status',dict(status='accepted'))
   order=post('/api/orders/from-quote',dict(quote_id=q['id'],due_date='2099-12-30'))
   post('/api/orders/'+order['id']+'/status',dict(status='processing'))
   post('/api/orders/'+order['id']+'/status',dict(status='fulfilled'))
   inv=post('/api/invoices/from-order',dict(order_id=order['id'],due_date='2099-12-31'))
   path='/api/invoices/'+inv['id']+'/adjustments'
   proposal=dict(request_key='http_v69_adjustment_01',kind='discount',amount=25,
                 reason='원본에 기재된 공급가액 할인을 확인했습니다',original_checked=True)
   assert s.post(base+path,json=proposal).status_code==403 # missing CSRF
   created=post(path,proposal)
   assert s.post(base+path,headers=csrf,json=proposal).json()['reused']
   listing=s.get(base+path).json()
   assert listing['settlement']['adjusted_total']==440
   updated=post(path+'/'+created['id']+'/decision',
                dict(approve=True,expected_digest=listing['expected_digest'],
                     original_checked=True,note='원본문서의 할인 사유와 금액을 확인했습니다'))
   assert updated['settlement']['adjusted_total']==413
   assert s.get(base+'/api/invoices/'+inv['id']).json()['balance']==413
   assert s.get(base+'/api/dashboard').json()['outstanding']>=413
   print('V6.9 REAL LOOPBACK HTTP PASS: auth, CSRF, approval, adjusted totals, dashboard')
  finally:
   proc.terminate()
   try:proc.communicate(timeout=8)
   except subprocess.TimeoutExpired:proc.kill();proc.communicate()

if __name__=='__main__':run()
