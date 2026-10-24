"""Real Chromium → real FastAPI HTTP document lifecycle and A/B authorization.

Independent additive J1-J5 gate. This exercises browser-origin HTTP requests and
rendered quote/invoice UI; it is NOT a UI form-entry test or live PostgreSQL E2E.
Only isolated loopback demo credentials and ephemeral SQLite are permitted.
"""
from __future__ import annotations
import os
import sys
from scripts.ci_playwright_cli_smoke import BASE, PROOF, assertion, cli, login, wait_http

FINANCIAL_FLOW = r"""async () => {
  const meResponse = await fetch('/api/me', {credentials:'same-origin'});
  if (!meResponse.ok) throw new Error('A session unavailable');
  const me = await meResponse.json();
  const req = async (path, method='GET', body) => {
    const headers={'Accept':'application/json'};
    if (method !== 'GET') headers['X-CSRF-Token']=me.csrf_token;
    if (body !== undefined) headers['Content-Type']='application/json';
    const response=await fetch('/api'+path,{method,headers,
      credentials:'same-origin',body:body===undefined?undefined:JSON.stringify(body)});
    return {status:response.status,body:await response.json()};
  };
  const ok = (result,status,label) => {
    if (result.status !== status) throw new Error(label+' HTTP '+result.status+' expected '+status);
    return result.body;
  };
  const customers=ok(await req('/customers'),200,'customers');
  if (!customers.length) throw new Error('No disposable customer fixture');
  const payload={customer_id:customers[0].id,title:'JW-CI-브라우저-문서흐름',
    vat_mode:'taxable',items:[
      {name:'검증부품 A',quantity:3,unit_price:101},
      {name:'검증부품 B',quantity:2,unit_price:503}
    ]};
  const q=ok(await req('/quotes','POST',payload),201,'create quote');
  if (q.money.subtotal!==1309 || q.money.vat!==131 || q.money.total!==1440)
    throw new Error('Financial total differs from integer-KRW expected value');
  ok(await req('/orders/from-quote','POST',{quote_id:q.id,due_date:'2099-12-30'}),
    409,'unapproved quote must be rejected');
  ok(await req('/quotes/'+q.id+'/status','POST',{status:'sent'}),200,'quote sent');
  ok(await req('/quotes/'+q.id+'/status','POST',{status:'accepted'}),200,'quote accepted');
  const o=ok(await req('/orders/from-quote','POST',{quote_id:q.id,due_date:'2099-12-30'}),
    201,'quote-to-order');
  ok(await req('/orders/from-quote','POST',{quote_id:q.id,due_date:'2099-12-30'}),
    409,'duplicate order must fail');
  if (o.money.total !== q.money.total) throw new Error('Order money mismatch');
  ok(await req('/orders/'+o.id+'/status','POST',{status:'processing'}),200,'order processing');
  ok(await req('/orders/'+o.id+'/status','POST',{status:'fulfilled'}),200,'order fulfilled');
  const invoice=ok(await req('/invoices/from-order','POST',
    {order_id:o.id,due_date:'2099-12-31'}),201,'order-to-invoice');
  if(invoice.money.total!==1440 || invoice.balance!==1440)
    throw new Error('Invoice money differs from source quote');
  const paidAt=new Intl.DateTimeFormat('sv-SE',{timeZone:'Asia/Seoul',year:'numeric',
    month:'2-digit',day:'2-digit'}).format(new Date());
  const payment={amount:400,paid_at:paidAt,reference:'jw-ci-pay-0001',note:'test-only'};
  const p=ok(await req('/invoices/'+invoice.id+'/payments','POST',payment),
    201,'partial payment');
  if(p.balance!==1040) throw new Error('Partial payment balance mismatch');
  const replay=ok(await req('/invoices/'+invoice.id+'/payments','POST',payment),
    201,'idempotent replay');
  if(replay.balance!==1040) throw new Error('Replay double charged');
  ok(await req('/invoices/'+invoice.id+'/payments','POST',{...payment,amount:401}),
    409,'conflicting replay');
  const done=ok(await req('/invoices/'+invoice.id+'/payments','POST',
    {amount:1040,paid_at:paidAt,reference:'jw-ci-pay-0002',note:'settlement'}),201,
    'final payment');
  if(done.balance!==0) throw new Error('Settlement balance not zero');
  const inv=ok(await req('/invoices/'+invoice.id),200,'invoice re-read');
  if(inv.payment_status!=='paid' || inv.balance!==0)
    throw new Error('Invoice did not reach paid state');
  window.__jwCiFinancial={org_id:me.org_id,quote:q.id,order:o.id,invoice:invoice.id,
    customer:customers[0].id,total:1440};
  return 'JW_FINANCE_A_PASS';
}"""

CHECK_QUOTES = r"""async () => {
  document.querySelector('nav [data-page="quotes"]').click();
  for(let i=0;i<70;i++){
    const rendered=document.querySelector('#main-content')?.innerText||'';
    if(rendered.includes('JW-CI-브라우저-문서흐름') && rendered.includes('1,440'))
      return 'JW_QUOTE_UI_PASS';
    await new Promise(r=>setTimeout(r,100));
  }
  throw new Error('Quote not visible in real rendered UI');
}"""

CHECK_INVOICES = r"""async () => {
  document.querySelector('nav [data-page="invoices"]').click();
  for(let i=0;i<70;i++){
    const rendered=document.querySelector('#main-content')?.innerText||'';
    if(rendered.includes('청구·입금 관리') && rendered.includes('1,440'))
      return 'JW_INVOICE_UI_PASS';
    await new Promise(r=>setTimeout(r,100));
  }
  throw new Error('Invoice missing from rendered screen');
}"""

LOGOUT = r"""async () => {
  document.querySelector('#logout').click();
  for(let i=0;i<70;i++){
    if(!document.querySelector('#login-view')?.classList.contains('hidden')){
      const r=await fetch('/api/me',{credentials:'same-origin'});
      if(r.status!==401) throw new Error('Logout did not revoke session');
      return 'JW_LOGOUT_PASS';
    }
    await new Promise(r=>setTimeout(r,100));
  }
  throw new Error('Logout did not complete');
}"""

CROSS_TENANT = r"""async () => {
  const p=window.__jwCiFinancial;
  if(!p) throw new Error('Missing company A proof IDs');
  const userResponse=await fetch('/api/me',{credentials:'same-origin'});
  if(!userResponse.ok) throw new Error('Company B not logged in');
  const me=await userResponse.json();
  if(me.org_id===p.org_id) throw new Error('Tenant B equals tenant A');
  const probe=async(path,method='GET',payload)=>{
    const headers={'Accept':'application/json'};
    if(method!=='GET') headers['X-CSRF-Token']=me.csrf_token;
    if(payload!==undefined) headers['Content-Type']='application/json';
    const r=await fetch('/api'+path,{method,headers,credentials:'same-origin',
      body:payload===undefined?undefined:JSON.stringify(payload)});
    return r.status;
  };
  const paidAt=new Intl.DateTimeFormat('sv-SE',{timeZone:'Asia/Seoul',year:'numeric',month:'2-digit',day:'2-digit'}).format(new Date());
  const checks=[
    ['quote',await probe('/quotes/'+p.quote)],
    ['order',await probe('/orders/'+p.order)],
    ['invoice',await probe('/invoices/'+p.invoice)],
    ['reconciliation',await probe('/reconciliation/'+p.order)],
    ['foreign-customer',await probe('/quotes','POST',{
      customer_id:p.customer,title:'illegal',vat_mode:'taxable',
      items:[{name:'x',quantity:1,unit_price:1}]})],
    ['foreign-order',await probe('/orders/from-quote','POST',
      {quote_id:p.quote,due_date:'2099-12-30'})],
    ['foreign-payment',await probe('/invoices/'+p.invoice+'/payments','POST',
      {amount:1,paid_at:paidAt,reference:'jw-ci-forbidden'})],
  ];
  for(const [name,code] of checks)
    if(code!==404) throw new Error('Cross-tenant '+name+' returned '+code+', expected 404');
  const quotes=await fetch('/api/quotes',{credentials:'same-origin'});
  if(!quotes.ok || (await quotes.json()).some(q=>q.id===p.quote))
    throw new Error('Foreign quote appeared in B list');
  return 'JW_CROSS_TENANT_7_DENIED_PASS';
}"""

RESTORE_A = r"""async () => {
  const p=window.__jwCiFinancial;
  const r=await fetch('/api/invoices/'+p.invoice,{credentials:'same-origin'});
  if(!r.ok) throw new Error('Cannot re-read original invoice');
  const inv=await r.json();
  if(inv.balance!==0 || inv.payment_status!=='paid' || inv.money.total!==1440)
    throw new Error('Cross-tenant write changed original invoice');
  return 'JW_A_RELOGIN_INTEGRITY_PASS';
}"""

def main() -> int:
    if (os.getenv('JW_BROWSER_CI_ONLY')!='ISOLATED_LOOPBACK_DEMO'
        or os.getenv('JW_INSECURE_LOCAL_DEV')!='1'
        or os.getenv('DEMO_SEED')!='1'
        or os.getenv('JW_ENV','').lower() in ('prod','production')):
        raise RuntimeError('Explicit isolated loopback demo environment required')
    wait_http()
    PROOF.mkdir(parents=True,exist_ok=True)
    opened=False
    try:
        cli('open',BASE)
        opened=True
        assertion("() => {if(location.origin!=='http://127.0.0.1:8765') throw new Error('Nonlocal origin');return 'JW_LOOPBACK_ONLY_PASS'}",
                  'JW_LOOPBACK_ONLY_PASS')
        tenant_a=login('demo@hanbit.example','JW_TENANT_A')
        assertion(FINANCIAL_FLOW,'JW_FINANCE_A_PASS',timeout=150)
        assertion(CHECK_QUOTES,'JW_QUOTE_UI_PASS')
        cli('screenshot',f"--filename={PROOF/'document_a_quote.png'}")
        assertion(CHECK_INVOICES,'JW_INVOICE_UI_PASS')
        cli('screenshot',f"--filename={PROOF/'document_a_paid_invoice.png'}")
        assertion(LOGOUT,'JW_LOGOUT_PASS')
        tenant_b=login('demo@bada.example','JW_TENANT_B')
        if tenant_a==tenant_b:
            raise AssertionError('Two logins returned same tenant ID')
        assertion(CROSS_TENANT,'JW_CROSS_TENANT_7_DENIED_PASS',timeout=80)
        assertion(LOGOUT,'JW_LOGOUT_PASS')
        if login('demo@hanbit.example','JW_TENANT_A_RELOGIN')!=tenant_a:
            raise AssertionError('Company A did not recover its own organization')
        assertion(RESTORE_A,'JW_A_RELOGIN_INTEGRITY_PASS')
        print('PASS: real Chromium HTTP quote→accepted→order→fulfilled→invoice→partial+final payments; '
              'integer KRW, duplicate/idempotency, visible UI, 7 forbidden cross-tenant probes, '
              'logout revocation and original integrity',flush=True)
        return 0
    finally:
        if opened:
            try:cli('close',timeout=15)
            except Exception:pass

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as exc:
        print('FAIL: '+type(exc).__name__+': '+str(exc)[-550:],file=sys.stderr)
        raise SystemExit(1)
