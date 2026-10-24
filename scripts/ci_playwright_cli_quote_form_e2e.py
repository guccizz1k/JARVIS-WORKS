"""J1–J6 full *real DOM* quote-form gate, deliberately isolated to loopback demo.

Unlike the HTTP document lifecycle checker, this script uses the live UI:
add/remove line controls, form validation, VAT preview, actual DOM submission,
persisted invoice-source quote and tenant boundary. Not PostgreSQL financial E2E.
"""
from __future__ import annotations

import os
import re

from scripts.ci_playwright_cli_smoke import BASE, PROOF, assertion, cli, login, wait_http

TITLE = "JW-J1-J6-DOM-QUOTE-1309"
FORM_PROOF = r"""async () => {
  if(location.origin !== 'http://127.0.0.1:8765') throw Error('Outside isolated loopback');
  const r = await fetch('/api/me',{credentials:'same-origin'});
  if(!r.ok) throw Error('No real logged-in session');
  const me=await r.json();
  const before=await fetch('/api/quotes',{credentials:'same-origin'});
  if(!before.ok) throw Error('Quotes list unavailable');
  if((await before.json()).some(x=>x.title==='JW-J1-J6-DOM-QUOTE-1309'))
    throw Error('Non-ephemeral duplicate quote');
  window.__jwJ1J6Org = me.org_id;
  const wait=async(fn,label) => {
    for(let i=0;i<90;i++) {
      const x=fn();
      if(x)return x;
      await new Promise(resolve=>setTimeout(resolve,100));
    }
    throw Error('DOM deadline '+label);
  };
  const nav=document.querySelector('nav [data-page="quotes"]');
  if(!nav)throw Error('Quotes nav missing');
  nav.click();
  const addQuote=await wait(()=>document.querySelector('[data-action="new-quote"]'),'new-quote');
  addQuote.click();
  const form=await wait(()=>document.querySelector('#entity-form[data-submit="quote"]'),'quote-form');
  const lines=form.querySelector('#line-container');
  const field=(parent,name,value) => {
    const n=parent.querySelector('[name="'+name+'"]');
    if(!n)throw Error('Missing '+name);
    n.value=value;
    n.dispatchEvent(new Event('input',{bubbles:true}));
    n.dispatchEvent(new Event('change',{bubbles:true}));
    return n;
  };
  field(form,'title','JW-J1-J6-DOM-QUOTE-1309');
  field(form,'vat_mode','taxable');
  let one=lines.querySelector('[data-line]');
  if(!one)throw Error('Initial item missing');
  field(one,'item_name','J1-protected-line');
  field(one,'quantity','0');
  if(form.checkValidity())throw Error('Invalid zero quantity passed native validation');
  field(one,'quantity','3');
  field(one,'unit_price','101');
  const addLine=form.querySelector('[data-action="add-line"]');
  if(!addLine)throw Error('Add item button missing');
  addLine.click();
  if(lines.querySelectorAll('[data-line]').length!==2)throw Error('Second row failed');
  const two=lines.querySelectorAll('[data-line]')[1];
  field(two,'item_name','J6-evidence-line');
  field(two,'quantity','2');
  field(two,'unit_price','503');
  const preview=await wait(()=> {
    const t=form.querySelector('#money-preview')?.innerText||'';
    return t.includes('1,309')&&t.includes('131')&&t.includes('1,440')?t:null;
  },'exact VAT preview');
  if(!form.checkValidity())throw Error('Valid form rejected');
  form.requestSubmit();
  await wait(()=>!document.querySelector('#entity-form[data-submit="quote"]'),'submitted form closed');
  await wait(()=>document.querySelector('#main-content')?.innerText.includes('JW-J1-J6-DOM-QUOTE-1309'),'UI listing');
  const qs=await fetch('/api/quotes',{credentials:'same-origin'});
  if(!qs.ok)throw Error('Cannot reread persisted quote');
  const matches=(await qs.json()).filter(x=>x.title==='JW-J1-J6-DOM-QUOTE-1309');
  if(matches.length!==1)throw Error('Not exactly one persisted UI-submitted quote: '+matches.length);
  const q=matches[0];
  if(q.money?.subtotal!==1309||q.money?.vat!==131||q.money?.total!==1440)
    throw Error('Server integer KRW/VAT does not match independent fixture: '+JSON.stringify(q.money));
  const detail=await fetch('/api/quotes/'+encodeURIComponent(q.id),{credentials:'same-origin'});
  if(!detail.ok)throw Error('Quote detail inaccessible');
  const doc=await detail.json();
  if(doc.items.length!==2 || doc.items[0].quantity!==3 || doc.items[1].unit_price!==503)
    throw Error('Persisted line items changed');
  const main=document.querySelector('#main-content')?.innerText||'';
  if(!main.includes('1,440'))throw Error('Rendered quote total mismatch');
  window.__jwJ1J6Quote={id:q.id,org:me.org_id,title:q.title};
  return 'JW_J1_J6_REAL_FORM_PASS:'+q.id;
}"""

A_LOGOUT = r"""async () => {
 const btn=document.querySelector('#logout');
 if(!btn)throw Error('Logout control missing');
 btn.click();
 for(let i=0;i<80;i++) {
   const login=document.querySelector('#login-view');
   if(login && !login.classList.contains('hidden')) {
     const me=await fetch('/api/me',{credentials:'same-origin'});
     if(me.status!==401)throw Error('Auth not revoked on browser logout');
     return 'JW_J1_J6_LOGOUT_PASS';
   }
   await new Promise(r=>setTimeout(r,100));
 }
 throw Error('Logout UI timeout');
}"""

B_DENIAL = r"""async () => {
 const q=window.__jwJ1J6Quote;
 if(!q)throw Error('Lost source ID');
 const r=await fetch('/api/me',{credentials:'same-origin'});
 if(!r.ok)throw Error('B not logged in');
 const me=await r.json();
 if(!me.org_id||q.org===me.org_id)throw Error('Tenant collision');
 const denied=await fetch('/api/quotes/'+encodeURIComponent(q.id),{credentials:'same-origin'});
 if(denied.status!==404)throw Error('Foreign quote exposed: '+denied.status);
 const list=await fetch('/api/quotes',{credentials:'same-origin'});
 if(!list.ok||(await list.json()).some(x=>x.id===q.id))
   throw Error('Foreign quote listed in B');
 document.querySelector('nav [data-page="quotes"]').click();
 for(let i=0;i<80;i++) {
   const main=document.querySelector('#main-content')?.innerText||'';
   if(main.includes('견적 관리')) {
     if(main.includes(q.title))throw Error('Foreign quote visible in B DOM');
     return 'JW_J1_J6_B_ISOLATION_PASS';
   }
   await new Promise(r=>setTimeout(r,100));
 }
 throw Error('B quote screen not ready');
}"""

A_RECOVERY = r"""async () => {
 const q=window.__jwJ1J6Quote;
 const resp=await fetch('/api/quotes/'+encodeURIComponent(q.id),{credentials:'same-origin'});
 if(!resp.ok)throw Error('A quote missing after B test');
 const doc=await resp.json();
 if(doc.money.total!==1440 || doc.items.length!==2)
   throw Error('Cross-tenant test damaged original');
 return 'JW_J1_J6_A_RECOVERY_PASS';
}"""


def main() -> int:
    if (
        os.environ.get("JW_BROWSER_CI_ONLY") != "ISOLATED_LOOPBACK_DEMO"
        or os.environ.get("JW_INSECURE_LOCAL_DEV") != "1"
        or os.environ.get("DEMO_SEED") != "1"
        or os.environ.get("JW_ENV", "").lower() in ("production", "prod")
        or BASE != "http://127.0.0.1:8765"
    ):
        raise RuntimeError("BLOCKED: only local disposable demo browser allowed")
    wait_http()
    PROOF.mkdir(parents=True, exist_ok=True)
    opened=False
    try:
        cli("open",BASE)
        opened=True
        login("demo@hanbit.example","JW_FORM_TENANT_A")
        proof=assertion(FORM_PROOF,"JW_J1_J6_REAL_FORM_PASS:",timeout=140)
        if not re.search(r"JW_J1_J6_REAL_FORM_PASS:[0-9a-zA-Z-]{8,}",proof):
            raise AssertionError("Cannot verify generated form quote ID")
        cli("screenshot",f"--filename={PROOF/'jw_j1_j6_real_quote_form.png'}")
        assertion(A_LOGOUT,"JW_J1_J6_LOGOUT_PASS")
        login("demo@bada.example","JW_FORM_TENANT_B")
        assertion(B_DENIAL,"JW_J1_J6_B_ISOLATION_PASS")
        assertion(A_LOGOUT,"JW_J1_J6_LOGOUT_PASS")
        login("demo@hanbit.example","JW_FORM_TENANT_A_RESTORED")
        assertion(A_RECOVERY,"JW_J1_J6_A_RECOVERY_PASS")
        print("PASS: J1–J6 Chromium real DOM form invalid->valid, 2-line input, UI VAT, POST, DB re-read, A/B tenant denial, relogin integrity; SQLite demo only",flush=True)
        return 0
    finally:
        if opened:
            try:cli("close",timeout=12)
            except Exception:pass


if __name__ == "__main__":
    raise SystemExit(main())
