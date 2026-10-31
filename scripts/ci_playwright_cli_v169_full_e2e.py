"""V16.9 actual Chromium browser-origin upload->finance->messenger contract.

Synthetic loopback-only existing application; NOT a hosted production/Safari E2E.
Uses the real browser Fetch/FormData API and FastAPI network backend, not a
TestClient fetch shim. Existing dedicated form/UI tests remain independent.
"""
from __future__ import annotations

import base64
import os
import sys

from scripts.ci_playwright_cli_smoke import BASE, PROOF, assertion, cli, login, wait_http
from tests.test_quote_import import qxlsx

BROWSER_FLOW = r"""async () => {
  if(location.origin!=='http://127.0.0.1:8765')
    throw Error('V169 forbidden non-loopback origin');
  const response=await fetch('/api/me',{credentials:'same-origin'});
  if(!response.ok)throw Error('V169 missing browser authentication');
  const me=await response.json();
  const request=async(path,method='GET',body,form=false)=>{
    const headers={};
    if(method!=='GET')headers['X-CSRF-Token']=me.csrf_token;
    if(body!==undefined&&!form)headers['Content-Type']='application/json';
    const r=await fetch('/api'+path,{method,headers,body:form?body:
      (body===undefined?undefined:JSON.stringify(body)),credentials:'same-origin'});
    return [r.status,await r.json()];
  };
  const check=(r,status,label)=>{if(r[0]!==status)throw Error(label+' returned '+r[0]+' not '+status);
    return r[1];};
  const listBefore=check(await request('/quotes'),200,'quotes-before').length;
  const bytes=Uint8Array.from(atob('__WORKBOOK_B64__'),c=>c.charCodeAt(0));
  const file=new File([bytes],'v169_synthetic_quote.xlsx',{
    type:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'});
  const upload=new FormData();upload.append('file',file);
  const preview=check(await request('/imports/preview','POST',upload,true),201,'xlsx-browser-upload');
  if(preview.document.record_type!=='quote' || preview.document.money.total!==176000 ||
     !preview.ready_to_confirm)throw Error('Unverified xlsx extraction');
  if(check(await request('/quotes'),200,'quotes-unapproved').length!==listBefore)
    throw Error('Import created a quote before human confirmation');
  const unauthorized=await fetch('/api/imports/'+preview.id+'/confirm',{
    method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({preview_digest:preview.digest,approve:true})});
  if(unauthorized.status!==403)throw Error('CSRF bypass on import confirmation');
  const verified=check(await request('/imports/'+preview.id+'/confirm','POST',{
    preview_digest:preview.digest,confirmed_customer:preview.document.company,
    confirmed_quote_date:preview.document.quote_date,
    confirmed_total:preview.document.money.total,approve:true}),201,'approved-import');
  const quote=verified.quote;
  if(quote.status!=='draft' || quote.source_import_id!==preview.id)
    throw Error('Quote source immutability lost');
  check(await request('/quotes/'+quote.id+'/status','POST',{status:'sent'}),200,'quote-sent');
  check(await request('/quotes/'+quote.id+'/status','POST',{status:'accepted'}),200,'quote-accepted');
  const order=check(await request('/orders/from-quote','POST',{
    quote_id:quote.id,due_date:'2099-12-30'}),201,'order-from-quote');
  check(await request('/orders/'+order.id+'/status','POST',{status:'processing'}),200,'processing');
  check(await request('/orders/'+order.id+'/status','POST',{status:'fulfilled'}),200,'fulfilled');
  const invoice=check(await request('/invoices/from-order','POST',{
    order_id:order.id,due_date:'2099-12-31'}),201,'invoice');
  if(invoice.money.total!==176000)throw Error('Invoice integrity drift');
  const at=new Intl.DateTimeFormat('sv-SE',{timeZone:'Asia/Seoul',
    year:'numeric',month:'2-digit',day:'2-digit'}).format(new Date());
  check(await request('/invoices/'+invoice.id+'/payments','POST',{
    amount:76000,paid_at:at,reference:'v169-part-a',note:'synthetic-only'}),201,'partial-pay');
  const close=check(await request('/invoices/'+invoice.id+'/payments','POST',{
    amount:100000,paid_at:at,reference:'v169-part-b',note:'synthetic-only'}),201,'remaining-pay');
  if(close.balance!==0)throw Error('Unpaid remainder after recorded payments');
  if(check(await request('/invoices/'+invoice.id),200,'invoice-recheck').payment_status!=='paid')
    throw Error('Invoice ledger not marked internally paid');
  const other=check(await request('/messenger/directory'),200,'messenger-directory')
    .find(row=>row.org_id!==me.org_id);
  if(!other)throw Error('No verified synthetic messenger partner');
  const thread=check(await request('/messenger/threads','POST',{
    recipient_org_id:other.org_id}),201,'new-messenger-thread');
  const safeText='V169 synthetic document reviewed: '+invoice.id;
  const sent=check(await request('/messenger/threads/'+thread.id+'/messages','POST',{
    content:safeText,request_id:'v169-synth-'+invoice.id}),201,'send-messenger-message');
  if(!sent.id)throw Error('Messenger persisted no message ID');
  if(check(await request('/invoices/'+invoice.id),200,'invoice-post-message').balance!==0)
    throw Error('Messenger mutated invoice balance');
  window.__jwV169={source:preview.id,quote:quote.id,order:order.id,
    invoice:invoice.id,org:me.org_id,thread:thread.id,message:sent.id,text:safeText};
  return 'JW_V169_BROWSER_UPLOAD_FINANCE_MESSENGER_A_PASS';
}""".replace("__WORKBOOK_B64__", "__PYTHON_B64__")

VIEW_A = r"""async () => {
  const target=document.querySelector('nav [data-page="invoices"]');
  if(!target)throw Error('No invoice navigation');
  target.click();
  for(let i=0;i<80;i++){
    const view=document.querySelector('#main-content')?.innerText||'';
    if(view.includes('청구·입금 관리') && view.includes('176,000'))
      return 'JW_V169_RENDERED_INVOICE_PASS';
    await new Promise(resolve=>setTimeout(resolve,100));
  }
  throw Error('Invoice not visible through actual browser UI');
}"""

LOGOUT = r"""async () => {
  document.querySelector('#logout').click();
  for(let i=0;i<80;i++){
    if(!document.querySelector('#login-view')?.classList.contains('hidden')){
      if((await fetch('/api/me',{credentials:'same-origin'})).status!==401)
        throw Error('Session survived logout');
      return 'JW_V169_BROWSER_LOGOUT_REVOKED_PASS';
    }
    await new Promise(resolve=>setTimeout(resolve,100));
  }
  throw Error('Logout UI failed');
}"""

CHECK_B = r"""async () => {
  const p=window.__jwV169;
  if(!p)throw Error('Lost browser challenge state');
  const me=(await (await fetch('/api/me')).json());
  if(!me.org_id || me.org_id===p.org)throw Error('Tenant B equals A');
  const req=async(path)=>{
    const res=await fetch('/api'+path,{credentials:'same-origin'});
    return res.status;
  };
  const forbidden=[
    '/imports/'+p.source,'/quotes/'+p.quote,'/orders/'+p.order,
    '/invoices/'+p.invoice,'/reconciliation/'+p.order,
    '/invoices/'+p.invoice+'/payments'
  ];
  for(const path of forbidden){
    const status=await req(path);
    if(status!==404)throw Error('Foreign tenant data '+path+' leaked HTTP '+status);
  }
  const messages=await fetch('/api/messenger/threads/'+p.thread+'/messages');
  if(messages.status!==200)throw Error('B cannot view its legitimate conversation');
  const contents=await messages.json();
  const m=contents.find(x=>x.id===p.message);
  if(!m || m.body!==p.text || m.mine!==false)
    throw Error('Incoming business messenger integrity');
  if((await fetch('/api/dashboard')).status!==200)throw Error('B dashboard unavailable');
  return 'JW_V169_BROWSER_CROSS_TENANT_SIX_DENIED_AND_MESSENGER_B_PASS';
}"""

CHECK_A = r"""async () => {
  const p=window.__jwV169;
  if(!p)throw Error('Lost original A receipt');
  const inv=await fetch('/api/invoices/'+p.invoice,{credentials:'same-origin'});
  if(inv.status!==200)throw Error('A invoice not restored');
  const data=await inv.json();
  if(data.balance!==0 || data.money.total!==176000 || data.payment_status!=='paid')
    throw Error('A invoice state changed after B read');
  return 'JW_V169_BROWSER_RELOGIN_A_INTEGRITY_PASS';
}"""

RESPONSIVE = r"""() => {
  const width=window.innerWidth;
  const viewport=document.documentElement;
  if(!document.querySelector('#app-shell') || width<310)
    throw Error('UI missing at requested viewport');
  if(viewport.scrollWidth>width+2)
    throw Error('Horizontal overflow: '+width+' vs '+viewport.scrollWidth);
  return 'JW_V169_RESPONSIVE_WIDTH_'+width+'_PASS';
}"""


def main():
    if (os.getenv("JW_ENV","").lower() not in ("review","test")
        or os.getenv("JW_BROWSER_CI_ONLY")!="ISOLATED_LOOPBACK_DEMO"
        or os.getenv("JW_INSECURE_LOCAL_DEV")!="1"
        or os.getenv("DEMO_SEED")!="1"):
        raise RuntimeError("V169 real Chromium acceptance is loopback synthetic only")
    wait_http()
    PROOF.mkdir(parents=True,exist_ok=True)
    opened=False
    try:
        cli("open",BASE)
        opened=True
        login("demo@hanbit.example","V169_A")
        assertion(BROWSER_FLOW.replace("__PYTHON_B64__",base64.b64encode(qxlsx()).decode()),
                  "JW_V169_BROWSER_UPLOAD_FINANCE_MESSENGER_A_PASS",timeout=180)
        assertion(VIEW_A,"JW_V169_RENDERED_INVOICE_PASS")
        cli("screenshot",f"--filename={PROOF/'v169_a_browser_invoice.png'}")
        for width,height in ((320,780),(390,844),(768,980),(1440,900)):
            cli("resize",str(width),str(height))
            assertion(RESPONSIVE,"JW_V169_RESPONSIVE_WIDTH_"+str(width)+"_PASS")
            if width in (390,1440):
                cli("screenshot",f"--filename={PROOF/f'v169_a_{width}.png'}")
        assertion(LOGOUT,"JW_V169_BROWSER_LOGOUT_REVOKED_PASS")
        login("demo@bada.example","V169_B")
        assertion(CHECK_B,"JW_V169_BROWSER_CROSS_TENANT_SIX_DENIED_AND_MESSENGER_B_PASS")
        assertion(LOGOUT,"JW_V169_BROWSER_LOGOUT_REVOKED_PASS")
        login("demo@hanbit.example","V169_A_AGAIN")
        assertion(CHECK_A,"JW_V169_BROWSER_RELOGIN_A_INTEGRITY_PASS")
        print("PASS_V169_CHROMIUM_NETWORK_XLSX_UPLOAD_CONFIRM_QUOTE_ORDER_INVOICE_PAYMENTS",flush=True)
        print("PASS_V169_CHROMIUM_CROSS_TENANT_SIX_DENIED_REAL_MESSENGER_AND_LOGOUT",flush=True)
        print("PASS_V169_CHROMIUM_320_390_768_1440_NO_OVERFLOW",flush=True)
        print("LIMIT: synthetic loopback, no bank settlement / external issuer / hosted positive browser",flush=True)
    finally:
        if opened:
            try:cli("close",timeout=15)
            except Exception:pass


if __name__=="__main__":
    try:main()
    except Exception as exc:
        print("FAIL_V169: "+type(exc).__name__+": "+str(exc)[-700:],file=sys.stderr)
        raise SystemExit(1)
