"""Actual Chromium over loopback HTTPS -> real FastAPI V9.2/3 -> PG17.

Only synthetic company sessions from a disposable database. The QA-only HTML
and cookie issuer exist *only in this script*, never in the product. HTTPS
certificate is explicitly trusted by the CI runner; never disable TLS verify.
"""
from __future__ import annotations

import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.request
import uvicorn
import psycopg
from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import HTMLResponse

from app import pg_quote_api_v92 as write
from app import pg_quote_read_v93 as read
from app import pg_v90_integrated_entry as v90
from scripts import ci_v90_postgres_browser as fixture
from scripts.ci_playwright_cli_smoke import cli, assertion, PROOF

BASE = "https://127.0.0.1:8769"

QA_HTML = """<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>JARVIS WORKS PG stage test</title></head><body>
<main><h1>JARVIS WORKS 견적서 PostgreSQL 스테이징</h1>
<label>견적명 <input id="title" value="J1-J6 HTTPS PG 견적"></label>
<button id="create" type="button">견적 생성</button>
<p id="result" role="status"></p><ul id="list"></ul>
</main><script>
const root='/api/pg-stage/v92/quotes';
async function load() {
 const response=await fetch(root,{credentials:'same-origin'});
 if(!response.ok)throw Error('List HTTP '+response.status);
 const items=await response.json();
 document.querySelector('#list').replaceChildren(
  ...items.map(x=>{const li=document.createElement('li');li.textContent=x.title;return li}));
}
document.querySelector('#create').addEventListener('click',async()=>{
 try {
  const info=await(await fetch('/qa/info',{credentials:'same-origin'})).json();
  const data={request_id:'qa-'+crypto.randomUUID().replaceAll('-',''),
    customer_id:'ci-customer-a',title:document.querySelector('#title').value,
    vat_mode:'taxable',items:[{name:'Line A',quantity:3,unit_price:101},
                             {name:'Line B',quantity:2,unit_price:503}]};
  const result=await fetch(root,{method:'POST',credentials:'same-origin',
    headers:{'content-type':'application/json','X-CSRF-Token':info.csrf},
    body:JSON.stringify(data)});
  if(!result.ok)throw Error('POST '+result.status);
  const created=await result.json();
  const detail=await fetch(root+'/'+created.quote_id,{credentials:'same-origin'});
  if(!detail.ok)throw Error('Detail '+detail.status);
  const quote=await detail.json();
  if(quote.money.total!==1440||quote.items.length!==2)throw Error('Wrong persisted total');
  document.querySelector('#result').textContent='PG HTTPS 통합 저장 완료: '+created.quote_id;
  await load();
 } catch(err) {document.querySelector('#result').textContent='FAIL '+err.message;}
});
load();
</script></body></html>"""


def _ssl_files(path: Path) -> tuple[Path, Path]:
    key=path/"stage.key"
    crt=path/"stage.crt"
    subprocess.run(
        ["openssl","req","-x509","-newkey","rsa:2048","-nodes",
         "-keyout",str(key),"-out",str(crt),"-days","1",
         "-subj","/CN=localhost",
         "-addext","subjectAltName=DNS:localhost,IP:127.0.0.1",
         "-addext","basicConstraints=critical,CA:TRUE"],
        check=True,capture_output=True,timeout=12)
    key.chmod(0o600)
    if os.environ.get("JW_V93_TRUST_LOCAL_CA")!="EPHEMERAL_RUNNER_ONLY":
        raise RuntimeError("Cannot add synthetic CA outside an ephemeral CI runner")
    # Trust only this freshly generated localhost certificate on this isolated
    # GitHub runner. Browser SSL checking stays ON; never ignore HTTPS errors.
    subprocess.run(["sudo","cp",str(crt),"/usr/local/share/ca-certificates/jw-v93-ci.crt"],
                   check=True,capture_output=True,timeout=8)
    subprocess.run(["sudo","update-ca-certificates"],check=True,capture_output=True,timeout=15)
    home=Path.home()/".pki"/"nssdb"
    home.mkdir(parents=True,exist_ok=True)
    if not (home/"cert9.db").exists():
        subprocess.run(["certutil","-N","--empty-password","-d","sql:"+str(home)],
                       check=True,capture_output=True,timeout=8)
    subprocess.run(["certutil","-A","-d","sql:"+str(home),
                    "-n","JARVIS V93 local CI only","-t","C,,","-i",str(crt)],
                   check=True,capture_output=True,timeout=8)
    return key,crt


def main() -> int:
    if (os.environ.get("JW_PG_CI_ALLOW")!="ONLY_EPHEMERAL_LOCAL_DATABASE"
        or os.environ.get("JW_ENV")!="review"):
        raise RuntimeError("BLOCKED: isolated review-only PG17")
    fixture.bootstrap()
    with psycopg.connect(fixture.root_dsn,autocommit=True) as pg:
        pg.execute((fixture.ROOT/"db/review/ci_v92_quote_ephemeral.sql").read_text())
    os.environ.update({
       "JW_ENV":"dev","JW_PG_STAGE_V84":"ISOLATED_DEV_READ_ONLY",
       "JW_PG_AUTH_V85":"ISOLATED_DEV_AUTH_ONLY",
       "JW_PG_MESSENGER_V90":"ISOLATED_DEV_MESSENGER_ONLY",
       "JW_PG_QUOTE_V92":"ISOLATED_DEV_QUOTE_V92",
       "JW_V90_ALLOWED_ORIGINS":BASE,
       "JW_PG_INTERNAL_LEDGER_V180":"ISOLATED_DEV_UNRECONCILED_LEDGER_ONLY",
    })
    os.environ.pop("JW_INSECURE_LOCAL_DEV",None)
    v90.stage._connect=lambda: psycopg.connect(fixture.TRADE_DSN,connect_timeout=5)
    app=FastAPI()
    # Mount the real review-only PostgreSQL messenger HTTP + WebSocket on the SAME TLS server.
    assert v90.register_v90_messenger(app)
    from app import pg_auth_v85 as auth
    assert auth.register_v85_auth(app)
    assert write.register_v92_quote_api(app)
    assert read.register_v93_quote_reader(app)
    # V13.2: genuine PostgreSQL payment RPC behind a CI-only HTTPS review path.
    # Neither the production FastAPI app nor the stand-alone preview imports it.
    from scripts.ci_v132_finance_https_router import register as register_finance_ci
    assert register_finance_ci(app)
    # Review-only V18.0 INTERNAL ledger, isolated PG17 HTTPS ONLY.
    from scripts.review import pg_manual_ledger_v180
    assert pg_manual_ledger_v180.register_v180_ledger(app)

    @app.get("/qa/")
    def page(): return HTMLResponse(QA_HTML,headers={"Cache-Control":"no-store"})

    @app.get("/qa/set/{company}")
    def set_qa_session(company: str, response: Response):
        if company not in ("A","B","C"):
            raise HTTPException(404,"Test tenant unavailable")
        response.set_cookie("__Host-jw_session",fixture.TOKENS[company],
                            httponly=True,secure=True,samesite="strict",path="/")
        response.headers["Cache-Control"]="no-store"
        return {"ok":True}

    @app.get("/qa/info")
    def csrf_probe():
        # Test-only fixture. In product, JWT/auth route uses DB-backed auth.
        from fastapi import Request
        # Does not authorize writes; the PG endpoint independently checks token.
        return {"csrf":fixture.CSRF["A"]}

    with tempfile.TemporaryDirectory(prefix="jw-v93-https-") as tmp:
        key,crt=_ssl_files(Path(tmp))
        config=uvicorn.Config(app,host="127.0.0.1",port=8769,log_level="error",
                              ws="websockets-sansio",
                              ssl_keyfile=str(key),ssl_certfile=str(crt),access_log=False)
        server=uvicorn.Server(config)
        thread=threading.Thread(target=server.run,daemon=True)
        thread.start()
        trusted=ssl.create_default_context(cafile=str(crt))
        for _ in range(90):
            try:
                with urllib.request.urlopen(BASE+"/qa/",context=trusted,timeout=1) as r:
                    if r.status==200:break
            except Exception:time.sleep(.12)
        else:
            server.should_exit=True
            raise RuntimeError("Verified local TLS server not ready")
        print("PASS: Python client verified local HTTPS CA + SAN hostname",flush=True)
        PROOF.mkdir(parents=True,exist_ok=True)
        browser=False
        try:
            cli("open",BASE+"/qa/")
            browser=True
            assertion("""async () => {
                if (location.protocol!=='https:' || location.hostname!=='127.0.0.1')
                  throw Error('Real browser not using stage HTTPS');
                await fetch('/qa/set/A',{credentials:'same-origin'});
                const r=await fetch('/api/pg-stage/v92/quotes',{credentials:'same-origin'});
                if(!r.ok)throw Error('PG session lost: '+r.status);
                document.querySelector('#create').click();
                for(let i=0;i<80;i++){
                  const t=document.querySelector('#result').textContent;
                  if(t.includes('PG HTTPS 통합 저장 완료:')) {
                    // The UI sets the success message before awaiting
                    // the async GET/list refresh. Check the real DOM only
                    // after that request completes, not in a race window.
                    for(let k=0;k<50;k++) {
                      const body=document.querySelector('#list').innerText;
                      if(body.includes('J1-J6 HTTPS PG 견적'))
                        return 'JW_V93_REAL_HTTPS_PG_CREATE_PASS';
                      await new Promise(resolve=>setTimeout(resolve,100));
                    }
                    throw Error('PG list render missing after refresh deadline');
                  }
                  if(t.includes('FAIL'))throw Error(t);
                  await new Promise(resolve=>setTimeout(resolve,100));
                }
                throw Error('HTTPS quote not persisted');
            }""","JW_V93_REAL_HTTPS_PG_CREATE_PASS",timeout=100)
            cli("screenshot",f"--filename={PROOF/'jw_v93_https_pg_quote.png'}")
            assertion("""async () => {
                const records=await(await fetch('/api/pg-stage/v92/quotes',{credentials:'same-origin'})).json();
                const mine=records.find(q=>q.title==='J1-J6 HTTPS PG 견적');
                if(!mine)throw Error('Missing A quote');
                await fetch('/qa/set/B',{credentials:'same-origin'});
                const list=await fetch('/api/pg-stage/v92/quotes',{credentials:'same-origin'});
                if(!list.ok || (await list.json()).some(q=>q.id===mine.id))
                  throw Error('Foreign quote visible in company B');
                const denied=await fetch('/api/pg-stage/v92/quotes/'+mine.id,{credentials:'same-origin'});
                if(denied.status!==404)throw Error('Foreign quote detail not denied '+denied.status);
                await fetch('/qa/set/A',{credentials:'same-origin'});
                const restored=await fetch('/api/pg-stage/v92/quotes/'+mine.id,{credentials:'same-origin'});
                if(!restored.ok || (await restored.json()).money.total!==1440)
                  throw Error('Company A quote lost after switch');
                return 'JW_V93_HTTPS_TENANT_B_DENIAL_AND_RECOVERY_PASS';
            }""","JW_V93_HTTPS_TENANT_B_DENIAL_AND_RECOVERY_PASS")
            # V10.4 extension: quote + B2B messenger share one verified HTTPS origin.
            assertion(r"""async () => {
              if(location.origin!=='https://127.0.0.1:8769')
                throw Error('Untrusted stage origin');
              const request=async (url,method='GET',value,csrf)=>{
                const headers={'Accept':'application/json'};
                if(value!==undefined) headers['Content-Type']='application/json';
                if(csrf)headers['X-CSRF-Token']=csrf;
                const r=await fetch(url,{method,credentials:'same-origin',headers,
                  body:value===undefined?undefined:JSON.stringify(value)});
                return {code:r.status,data:await r.json()};
              };
              await fetch('/qa/set/A',{credentials:'same-origin'});
              const csrf=(await(await fetch('/qa/info')).json()).csrf;
              const noCsrf=await request('/api/pg-stage/v90/chats','POST',{other_org_id:'ci-b'});
              if(noCsrf.code!==403) throw Error('Missing messenger CSRF was allowed');
              const opened=await request('/api/pg-stage/v90/chats','POST',{other_org_id:'ci-b'},csrf);
              if(opened.code!==200||!opened.data.connection_id)
                throw Error('PG messenger start failed '+opened.code);
              const id=opened.data.connection_id;
              const path='/api/pg-stage/v90/chats/'+encodeURIComponent(id)+'/messages';
              const body={request_id:'v104-https-wss-msg-001',body:'JW_PG_HTTPS_WSS_A_TO_B'};
              const sent=await request(path,'POST',body,csrf);
              if(sent.code!==200||!sent.data.message_id) throw Error('PG send failed '+sent.code);
              const replay=await request(path,'POST',body,csrf);
              if(replay.code!==200||replay.data.message_id!==sent.data.message_id)
                throw Error('Replay duplicated messenger message');
              await fetch('/qa/set/B',{credentials:'same-origin'});
              const b=await request(path);
              if(b.code!==200||JSON.stringify(b.data).indexOf('JW_PG_HTTPS_WSS_A_TO_B')<0)
                throw Error('Authorized B lost PG messenger message');
              const events=await new Promise((resolve,reject)=>{
                const socket=new WebSocket('wss://127.0.0.1:8769'+
                  '/api/pg-stage/v90/chats/'+encodeURIComponent(id)+'/stream?after=0');
                let checkpoint=false,done=false;
                const timeout=setTimeout(()=>{
                  if(!done){done=true;socket.close();reject(Error('WSS replay timeout'));}
                },8000);
                socket.onmessage=e=>{
                  const item=JSON.parse(e.data);
                  if(item.type==='ready')checkpoint=true;
                  if(item.type==='message'&&JSON.stringify(item.data).includes('JW_PG_HTTPS_WSS_A_TO_B')){
                    done=true;clearTimeout(timeout);socket.close();
                    if(!checkpoint)reject(Error('Missing WSS checkpoint'));else resolve(true);
                  }
                };
                socket.onerror=()=>{if(!done){done=true;clearTimeout(timeout);reject(Error('WSS TLS/handshake failed'));}};
                socket.onclose=()=>{if(!done){done=true;clearTimeout(timeout);reject(Error('WSS closed without replay'));}};
              });
              if(!events)throw Error('WSS events absent');
              await fetch('/qa/set/C',{credentials:'same-origin'});
              const forbidden=await request(path);
              if(forbidden.code!==403)throw Error('Nonmember C read A/B chat '+forbidden.code);
              await fetch('/qa/set/A',{credentials:'same-origin'});
              const quotes=await request('/api/pg-stage/v92/quotes');
              if(quotes.code!==200||!quotes.data.some(q=>q.title==='J1-J6 HTTPS PG 견적'))
                throw Error('Finance quote changed after websocket session switch');
              return 'JW_V104_ONE_HTTPS_ORIGIN_PG17_QUOTE_WSS_CHAT_A_B_C_PASS';
            }""","JW_V104_ONE_HTTPS_ORIGIN_PG17_QUOTE_WSS_CHAT_A_B_C_PASS",timeout=90)
            cli("screenshot",f"--filename={PROOF/'jw_v104_https_pg_quote_chat.png'}")
            print("PASS: verified localhost HTTPS PG17 quote + messenger + WSS replay, tenant A/B/C, CSRF and dedupe",flush=True)
            from scripts.ci_v93_finance_restore import restore_proof
            restore_proof()
            # V10.6: do this AFTER the unchanged 13-table restore, so its
            # fingerprint remains meaningful and the auth fixture adds no
            # tables to the independently verified restore baseline.
            from scripts.ci_v106_real_pg_auth import prepare_real_auth, PASSWORD
            with psycopg.connect(fixture.root_dsn,autocommit=True) as pg:
                pg.execute((fixture.ROOT/'scripts/ci_v127_ephemeral_order.sql').read_text(encoding='utf-8'))
            prepare_real_auth(fixture)
            assertion(r"""async () => {
              const req=async(path,method='GET',body,csrf)=>{
                const h={'Accept':'application/json'};
                if(body!==undefined)h['Content-Type']='application/json';
                if(csrf)h['X-CSRF-Token']=csrf;
                const r=await fetch(path,{method,headers:h,credentials:'same-origin',
                  body:body===undefined?undefined:JSON.stringify(body)});
                return {code:r.status,data:await r.json()};
              };
              const auth='/api/pg-stage/v85/';
              const root='/api/pg-stage/v92/quotes';
              const bad=await req(auth+'login','POST',
                {email:'a@invalid.test',password:'wrong-ci-password'});
              if(bad.code!==401)throw Error('Real PG failed-password login not denied: '+bad.code);
              const a=await req(auth+'login','POST',
                {email:'a@invalid.test',password:'CI-v106-disposable-auth-password-only'});
              if(a.code!==200||!a.data.csrf_token||a.data.backend!=='postgresql_auth_stage')
                throw Error('Real PG A credential login failed '+a.code);
              const csrfA=a.data.csrf_token;
              const me=await req('/api/pg-stage/v90/me');
              if(me.code!==200||me.data.org_id!=='ci-a'||me.data.csrf_token!==csrfA)
                throw Error('Newly issued PG session not accepted by business role');
              const quote={request_id:'v106-real-auth-quote-0001',customer_id:'ci-customer-a',
                title:'REAL PG AUTH QUOTE',vat_mode:'taxable',
                items:[{name:'A',quantity:3,unit_price:101},{name:'B',quantity:2,unit_price:503}]};
              const created=await req(root,'POST',quote,csrfA);
              if(created.code!==201||created.data.money.total!==1440)
                throw Error('PG auth-to-finance write failed '+created.code);
              const replay=await req(root,'POST',quote,csrfA);
              if(replay.code!==200||replay.data.quote_id!==created.data.quote_id)
                throw Error('Authorized PG quote retry not idempotent');
              const orderPath='/api/pg-stage/v92/order-drafts';
              const previewPath='/api/pg-stage/v92/quote-review-previews/'+created.data.quote_id;
              const preview=await req(previewPath);
              if(preview.code!==200||preview.data.money.total!==1440||
                 preview.data.source_document_verified!==false||
                 !/^[a-f0-9]{64}$/.test(preview.data.preview_sha256))
                throw Error('Server-grounded quote preview unavailable');
              const reviewPath='/api/pg-stage/v92/quote-reviews';
              const reviewBody={quote_id:created.data.quote_id,
                preview_sha256:preview.data.preview_sha256,preview_checked:true};
              const premature=await req(orderPath,'POST',{
                request_id:'v128-no-receipt-0001',quote_id:created.data.quote_id,
                original_checked:true},csrfA);
              if(premature.code!==422)
                throw Error('Bare client original_checked was enough to create an order');
              const forged=await req(orderPath,'POST',{
                request_id:'v128-fake-receipt-0001',quote_id:created.data.quote_id,
                original_checked:true,review_receipt_id:'f'.repeat(32)},csrfA);
              if(forged.code!==409)
                throw Error('Forged approval receipt accepted');
              const badDigest=await req(reviewPath,'POST',{
                ...reviewBody,preview_sha256:'0'.repeat(64)},csrfA);
              if(badDigest.code!==409)
                throw Error('Stale quote preview digest was accepted');
              const noReviewCsrf=await req(reviewPath,'POST',reviewBody);
              if(noReviewCsrf.code!==403)
                throw Error('Preview acknowledgement bypassed CSRF');
              const acknowledged=await req(reviewPath,'POST',reviewBody,csrfA);
              if(acknowledged.code!==201||!acknowledged.data.review_receipt_id||
                 acknowledged.data.source_document_verified!==false)
                throw Error('Verified preview acknowledgement not saved');
              const renewed=await req(reviewPath,'POST',reviewBody,csrfA);
              if(renewed.code!==201||renewed.data.review_receipt_id===
                 acknowledged.data.review_receipt_id)
                throw Error('Fresh review must not return old eventually-expiring receipt');
              const fromQuote={request_id:'v127-order-request-0001',
                quote_id:created.data.quote_id,original_checked:true,
                review_receipt_id:renewed.data.review_receipt_id};
              const rejectUnchecked=await req(orderPath,'POST',{
                ...fromQuote,original_checked:false},csrfA);
              if(rejectUnchecked.code!==422)
                throw Error('Order draft accepted unchecked source');
              const noOrderCSRF=await req(orderPath,'POST',fromQuote);
              if(noOrderCSRF.code!==403)
                throw Error('Order draft created without CSRF');
              const order=await req(orderPath,'POST',fromQuote,csrfA);
              if(order.code!==201||!order.data.draft_only||
                 order.data.approval_posted!==false||order.data.money.total!==1440)
                throw Error('Source-grounded draft order not created');
              const orderId=order.data.order_id;
              const orderRetry=await req(orderPath,'POST',fromQuote,csrfA);
              if(orderRetry.code!==200||orderRetry.data.order_id!==orderId)
                throw Error('Order duplicate replay not idempotent');
              const conflict=await req(orderPath,'POST',{
                ...fromQuote,request_id:'v127-different-request-0002'},csrfA);
              if(conflict.code!==409)
                throw Error('Second request silently duplicated order');
              const ownOrder=await req(orderPath+'/'+orderId);
              if(ownOrder.code!==200||ownOrder.data.money.total!==1440||
                 ownOrder.data.items.length!==2||
                 ownOrder.data.source_quote_id!==created.data.quote_id)
                throw Error('Order draft not linked to source quote');
              const chat=await req('/api/pg-stage/v90/chats','POST',
                  {other_org_id:'ci-b'},csrfA);
              if(chat.code!==200||!chat.data.connection_id)
                throw Error('PG auth-to-messenger start failed');
              const msgs='/api/pg-stage/v90/chats/'+chat.data.connection_id+'/messages';
              const sent=await req(msgs,'POST',
                {request_id:'v106-real-auth-message-0001',body:'V106_REAL_AUTH_PG_A_TO_B'},csrfA);
              if(sent.code!==200||!sent.data.message_id)
                throw Error('PG auth-to-messenger send failed');
              const noCSRF=await req(msgs,'POST',
                {request_id:'v106-no-csrf-attempt',body:'DENIED'});
              if(noCSRF.code!==403)throw Error('New PG auth bypassed business CSRF');
              const badLogout=await req(auth+'logout','POST',undefined,'wrong');
              if(badLogout.code!==403)throw Error('Bad PG logout CSRF accepted');
              const validLogout=await req(auth+'logout','POST',undefined,csrfA);
              if(validLogout.code!==200||validLogout.data.ok!==true)
                throw Error('PG A logout failed');
              const revoked=await req('/api/pg-stage/v90/me');
              if(revoked.code!==401)throw Error('Logged-out A retained business access');
              const b=await req(auth+'login','POST',
                {email:'b@invalid.test',password:'CI-v106-disposable-auth-password-only'});
              if(b.code!==200||!b.data.csrf_token)throw Error('Real PG B login failed');
              const foreignOrder=await req(orderPath+'/'+orderId);
              if(foreignOrder.code!==404)throw Error('B read A draft order');
              const foreign=await req(root+'/'+created.data.quote_id);
              if(foreign.code!==404)throw Error('PG B accessed PG A financial document');
              const recv=await req(msgs);
              if(recv.code!==200||!JSON.stringify(recv.data).includes('V106_REAL_AUTH_PG_A_TO_B'))
                throw Error('PG B cannot receive authorized A message');
              const blogout=await req(auth+'logout','POST',undefined,b.data.csrf_token);
              if(blogout.code!==200)throw Error('B logout failed');
              const bRevoked=await req(msgs);
              if(bRevoked.code!==401)throw Error('Logged-out B retained chat');
              const c=await req(auth+'login','POST',
                {email:'c@invalid.test',password:'CI-v106-disposable-auth-password-only'});
              if(c.code!==200||!c.data.csrf_token)
                throw Error('Real PG C login failed');
              const cMe=await req('/api/pg-stage/v90/me');
              if(cMe.code!==200||cMe.data.org_id!=='ci-c')
                throw Error('Real PG C session has wrong tenant');
              const cOrder=await req(orderPath+'/'+orderId);
              if(cOrder.code!==404)throw Error('C read A draft order');
              const cForeign=await req(root+'/'+created.data.quote_id);
              if(cForeign.code!==404)throw Error('PG C accessed A financial document');
              const cCreate=await req(root,'POST',{
                request_id:'v126-c-forged-cross-tenant-0001',
                customer_id:'ci-customer-a',title:'FORBIDDEN',vat_mode:'taxable',
                items:[{name:'test',quantity:1,unit_price:1}]
              },c.data.csrf_token);
              if(cCreate.code!==404)throw Error('PG C created foreign-customer quote');
              const cChat=await req(msgs);
              if(cChat.code!==403)throw Error('PG C read nonmember A/B messages');
              const cLogout=await req(auth+'logout','POST',undefined,c.data.csrf_token);
              if(cLogout.code!==200)throw Error('Real PG C logout failed');
              const cRevoked=await req('/api/pg-stage/v90/me');
              if(cRevoked.code!==401)throw Error('Logged-out C retained PG session');
              const again=await req(auth+'login','POST',
                {email:'a@invalid.test',password:'CI-v106-disposable-auth-password-only'});
              if(again.code!==200)throw Error('Real PG A relogin failed');
              const aQuote=await req(root+'/'+created.data.quote_id);
              if(aQuote.code!==200||aQuote.data.money.total!==1440)
                throw Error('PG A finance recovery after logout failed');
              return 'JW_V127_PG17_QUOTE_ORDER_DRAFT_A_B_C_PASS';
            }""","JW_V127_PG17_QUOTE_ORDER_DRAFT_A_B_C_PASS",timeout=110)
            with psycopg.connect(fixture.root_dsn) as root:
                events=root.execute("""
                    SELECT event_type,count(*) FROM jw_dev.security_events
                    GROUP BY event_type ORDER BY event_type
                """).fetchall()
                if dict(events)!={"login_success":4,"logout":3}:
                    raise AssertionError("Actual PostgreSQL auth events inconsistent")
            # V13.2: strictly disposable PostgreSQL17 supports the ORIGINAL
            # reviewed V8.3 SECURITY DEFINER payment RPC under independent
            # auth and trade logins, without changing real DEV schemas.
            with psycopg.connect(fixture.root_dsn,autocommit=True) as pg:
                pg.execute((fixture.ROOT/'scripts/ci_v132_finance_ephemeral.sql').read_text(encoding='utf-8'))
                # This CI-only schema addition matches the actual jw_dev.orders
                # V18.0 provenance column. Never touches Supabase or production.
                pg.execute("ALTER TABLE jw_dev.orders ADD COLUMN review_state text NOT NULL DEFAULT 'acknowledged'")
                pg.execute((fixture.ROOT/'security/jw_dev_v83_payment_rpc.sql').read_text(encoding='utf-8'))
                rows=pg.execute("""SELECT id,org_id,customer_id,quote_id
                                   FROM jw_dev.order_drafts_v127 WHERE org_id='ci-a'""").fetchall()
                if len(rows)!=1:
                    raise AssertionError("Authenticated A quote→reviewed order draft missing")
                order_id,org_id,customer_id,quote_id=rows[0]
                if org_id!='ci-a' or not quote_id or not customer_id:
                    raise AssertionError("Original quote link lost")
                pg.execute("""INSERT INTO jw_dev.orders(id,org_id,customer_id,quote_id,status)
                              VALUES('ci-v132-order-a',%s,%s,%s,'fulfilled')""",
                           (org_id,customer_id,quote_id))
                pg.execute("""INSERT INTO jw_dev.invoices
                           (id,org_id,order_id,customer_id,vat_mode,status)
                           VALUES('ci-v132-invoice-a','ci-a','ci-v132-order-a',%s,'taxable','issued')""",
                           (customer_id,))
                lines=pg.execute("""SELECT name,quantity,unit_price
                           FROM jw_dev.order_draft_items_v127 WHERE order_id=%s
                           ORDER BY position""",(order_id,)).fetchall()
                if len(lines)!=2 or sum(q*p for _,q,p in lines)!=1309:
                    raise AssertionError("Review source lineitems changed")
                for i,(name,qty,price) in enumerate(lines):
                    pg.execute("""INSERT INTO jw_dev.invoice_items
                                 (id,invoice_id,name,quantity,unit_price)
                                 VALUES(%s,'ci-v132-invoice-a',%s,%s,%s)""",
                               (f'ci-v132-a-item-{i}',name,qty,price))
                # Second independently logged-in company must never see A.
                pg.execute("""INSERT INTO jw_dev.quotes
                         (id,org_id,customer_id,customer_name_snapshot,doc_no,title,
                          status,vat_mode,created_at,updated_at)
                         VALUES('ci-v132-quote-b','ci-b','ci-customer-b','CI Customer B',
                                'ci-v132-quote-no-b','B reference','accepted','taxable',
                                now()::text,now()::text)""")
                pg.execute("""INSERT INTO jw_dev.orders(id,org_id,customer_id,quote_id,status)
                              VALUES('ci-v132-order-b','ci-b','ci-customer-b',
                                     'ci-v132-quote-b','fulfilled')""")
                pg.execute("""INSERT INTO jw_dev.invoices(id,org_id,order_id,customer_id,vat_mode,status)
                              VALUES('ci-v132-invoice-b','ci-b','ci-v132-order-b',
                                     'ci-customer-b','taxable','issued')""")
                pg.execute("""INSERT INTO jw_dev.invoice_items
                        (id,invoice_id,name,quantity,unit_price)
                        VALUES('ci-v132-item-b','ci-v132-invoice-b','B',1,9000)""")
                can=pg.execute("""SELECT pg_catalog.has_function_privilege(
                  'jw_app_dev','jw_dev.record_payment_v83(text,bigint,date,text,text)','EXECUTE'),
                  pg_catalog.has_function_privilege(
                  'jw_app_dev','jw_dev.financial_state_v83(text)','EXECUTE')""").fetchone()
                if can!=(True,False):
                    raise AssertionError("Finance RPC privileges not minimized")
                pay_grant=pg.execute("""SELECT pg_catalog.has_table_privilege(
                  'jw_app_dev','jw_dev.payments','INSERT')""").fetchone()
                if pay_grant!=(False,):
                    raise AssertionError("Direct payment INSERT not forbidden")
                # V18.0: extra independently tenant-scoped synthetic invoice,
                # never a real bank settlement or externally issued invoice.
                pg.execute("""INSERT INTO jw_dev.quotes
                     (id,org_id,customer_id,customer_name_snapshot,doc_no,title,
                      status,vat_mode,created_at,updated_at)
                     VALUES('ci-v180-quote-a','ci-a','ci-customer-a',
                            'CI Customer A','ci-v180-quote-no','V180 Review',
                            'draft','taxable',now()::text,now()::text)""")
                pg.execute("""INSERT INTO jw_dev.orders
                     (id,org_id,customer_id,quote_id,status,review_state)
                     VALUES('ci-v180-order-a','ci-a','ci-customer-a',
                            'ci-v180-quote-a','fulfilled','acknowledged')""")
                pg.execute("""INSERT INTO jw_dev.invoices
                     (id,org_id,order_id,customer_id,vat_mode,status)
                     VALUES('ci-v180-invoice-a','ci-a','ci-v180-order-a',
                            'ci-customer-a','taxable','issued')""")
                pg.execute("""INSERT INTO jw_dev.invoice_items
                     (id,invoice_id,name,quantity,unit_price)
                     VALUES('ci-v180-item-a','ci-v180-invoice-a','Synthetic A',2,3500)""")

            assertion(r"""async () => {
              const req=async(path,method='GET',body,csrf)=>{
                const h={'Accept':'application/json'};
                if(body!==undefined)h['Content-Type']='application/json';
                if(csrf)h['X-CSRF-Token']=csrf;
                const r=await fetch(path,{method,credentials:'same-origin',headers:h,
                    body:body===undefined?undefined:JSON.stringify(body)});
                return {code:r.status,data:await r.json()};
              };
              if(location.protocol!=='https:' || location.hostname!=='127.0.0.1')
                throw Error('Financial API not accessed through HTTPS');
              const root='/api/pg-stage/v132/ci-finance/';
              const auth='/api/pg-stage/v85/';
              const me=await req('/api/pg-stage/v90/me');
              if(me.code!==200||me.data.org_id!=='ci-a'||!me.data.csrf_token)
                throw Error('Real authenticated A session lost');
              const csrf=me.data.csrf_token;
              const aInvoice=await req(root+'invoices/ci-v132-invoice-a');
              if(aInvoice.code!==200||aInvoice.data.paid_amount!==0)
                throw Error('A invoice not linked or unpaid');
              const foreign=await req(root+'invoices/ci-v132-invoice-b');
              if(foreign.code!==404)throw Error('A read B invoice');
              const today=new Date().toISOString().slice(0,10);
              const first={invoice_id:'ci-v132-invoice-a',amount:1000,
                 reference:'v132-first-payment-001',paid_at:today,note:'synthetic'};
              const noCsrf=await req(root+'payments','POST',first);
              if(noCsrf.code!==403)throw Error('Financial CSRF bypass, status '+noCsrf.code+': '+JSON.stringify(noCsrf.data).slice(0,200));
              const [paid,replayed]=await Promise.all([
                  req(root+'payments','POST',first,csrf),
                  req(root+'payments','POST',first,csrf)]);
              if(paid.code!==200||replayed.code!==200||!paid.data.payment_id||
                 paid.data.payment_id!==replayed.data.payment_id)
                throw Error('Concurrent payment replay not idempotent');
              const partly=await req(root+'invoices/ci-v132-invoice-a');
              if(partly.code!==200||partly.data.paid_amount!==1000)
                throw Error('Payment committed incorrectly');
              const excessive=await req(root+'payments','POST',{
                ...first,amount:1000,reference:'v132-overpay-0002'},csrf);
              if(excessive.code!==409)throw Error('Overpayment was accepted');
              const forged=await req(root+'payments','POST',{
                ...first,invoice_id:'ci-v132-invoice-b',reference:'v132-foreign-0003'},csrf);
              if(forged.code!==403)throw Error('A paid foreign B invoice');
              const reversed=await req(root+'payments/reverse','POST',{
                  invoice_id:'ci-v132-invoice-a',payment_id:paid.data.payment_id},csrf);
              if(reversed.code!==200||reversed.data.reversed!==true)
                throw Error('Admin payment reversal failed');
              const after=await req(root+'invoices/ci-v132-invoice-a');
              if(after.code!==200||after.data.paid_amount!==0)
                throw Error('Reversed amount still active');
              const forbiddenReplay=await req(root+'payments','POST',first,csrf);
              if(forbiddenReplay.code!==409)
                throw Error('Reversed idempotency key accepted');
              const aFinal=await req(root+'payments','POST',{
                ...first,amount:1440,reference:'v132-a-final-0004'},csrf);
              if(aFinal.code!==200)throw Error('A final invoice settlement failed');
              const b=await req(auth+'login','POST',{
                email:'b@invalid.test',
                password:'CI-v106-disposable-auth-password-only'});
              if(b.code!==200||!b.data.csrf_token)
                throw Error('Independent company B login failed');
              const bForeign=await req(root+'invoices/ci-v132-invoice-a');
              if(bForeign.code!==404)throw Error('B can read A settled invoice');
              const bPay=await req(root+'payments','POST',{
                  ...first,invoice_id:'ci-v132-invoice-b',amount:9900,
                  reference:'v132-b-final-0005'},b.data.csrf_token);
              if(bPay.code!==200)throw Error('B legitimate payment blocked');
              const bFinal=await req(root+'invoices/ci-v132-invoice-b');
              if(bFinal.code!==200||bFinal.data.paid_amount!==9900)
                throw Error('B invoice total differs from proof');
              const bDenied=await req(root+'payments','POST',{
                  ...first,invoice_id:'ci-v132-invoice-a',
                  reference:'v132-b-cross-0006'},b.data.csrf_token);
              if(bDenied.code!==403)throw Error('B paid A invoice');
              const c=await req(auth+'login','POST',{
                email:'c@invalid.test',
                password:'CI-v106-disposable-auth-password-only'});
              if(c.code!==200||!c.data.csrf_token)throw Error('Company C login failed');
              if((await req(root+'invoices/ci-v132-invoice-a')).code!==404)
                throw Error('C can read A invoice');
              if((await req(root+'invoices/ci-v132-invoice-b')).code!==404)
                throw Error('C can read B invoice');
              const cDenied=await req(root+'payments','POST',{
                 ...first,reference:'v132-c-cross-0007'},c.data.csrf_token);
              if(cDenied.code!==403)throw Error('Company C cross-tenant payment');
              const unknown=await req(auth+'logout','POST',undefined,c.data.csrf_token);
              if(unknown.code!==200)throw Error('C session logout failed');
              const revoked=await req(root+'invoices/ci-v132-invoice-a');
              if(revoked.code!==401)throw Error('Revoked C session accesses payments');
              return 'JW_V132_REAL_HTTPS_PG17_AUTHENTICATED_FINANCE_A_B_C_PASS';
            }""","JW_V132_REAL_HTTPS_PG17_AUTHENTICATED_FINANCE_A_B_C_PASS",timeout=115)
            with psycopg.connect(fixture.root_dsn) as root:
                row=root.execute("""SELECT
                (SELECT count(*) FROM jw_dev.payments WHERE org_id='ci-a' AND reversed_at IS NULL),
                (SELECT coalesce(sum(amount),0) FROM jw_dev.payments WHERE org_id='ci-a' AND reversed_at IS NULL),
                (SELECT count(*) FROM jw_dev.payments WHERE org_id='ci-a' AND reversed_at IS NOT NULL),
                (SELECT count(*) FROM jw_dev.payments WHERE org_id='ci-b' AND reversed_at IS NULL),
                (SELECT coalesce(sum(amount),0) FROM jw_dev.payments WHERE org_id='ci-b' AND reversed_at IS NULL)
                """).fetchone()
                if row!=(1,1440,1,1,9900):
                    raise AssertionError(f"Real finance settlement summary incorrect: {row!r}")
            # V18.0: true Chromium HTTPS + verified DB-backed A/B login,
            # isolated V83 RPC, admin-reviewed unreconciled-only ledger.
            assertion(r"""async () => {
              const root='/api/pg-stage/v180/';
              const req=async(path,method='GET',body,csrf)=>{
                const h={'Accept':'application/json'};
                if(body!==undefined)h['Content-Type']='application/json';
                if(csrf)h['X-CSRF-Token']=csrf;
                const r=await fetch(path,{method,credentials:'same-origin',
                  headers:h,body:body===undefined?undefined:JSON.stringify(body)});
                return {code:r.status,data:await r.json()};
              };
              if(location.protocol!=='https:')throw Error('V180 not HTTPS');
              const before=await req(root+'invoices/ci-v180-invoice-a/ledger-preview');
              if(before.code!==401)throw Error('Revoked C session accessed V180 ledger');
              const login=await req('/api/pg-stage/v85/login','POST',{
                email:'a@invalid.test',
                password:'CI-v106-disposable-auth-password-only'
              });
              if(login.code!==200||!login.data.csrf_token)
                throw Error('V180 independent A login failed');
              const csrf=login.data.csrf_token;
              const first=await req(root+'invoices/ci-v180-invoice-a/ledger-preview');
              if(first.code!==200||first.data.recorded_active_krw!==0||
                 first.data.bank_reconciliation_verified!==false||
                 first.data.financial_settlement_verified!==false)
                throw Error('V180 ledger preview falsely claims reconciliation');
              if((await req(root+'invoices/ci-v132-invoice-b/ledger-preview')).code!==404)
                throw Error('V180 foreign B invoice visible');
              const day=new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Seoul',
                 year:'numeric',month:'2-digit',day:'2-digit'}).format(new Date());
              const body={invoice_id:'ci-v180-invoice-a',amount_krw:1000,
                 paid_at:day,reference:'ci-v180-payment-001',
                 note:'INTERNAL_NOT_BANK_CONFIRMED',
                 invoice_source_checked:true,internal_manual_entry_only:true,
                 bank_reconciliation_verified:false,
                 physical_delivery_independently_verified:false};
              const noCsrf=await req(root+'manual-payments','POST',body);
              if(noCsrf.code!==403)throw Error('V180 CSRF bypass');
              const forgery=await req(root+'manual-payments','POST',{
                   ...body,bank_reconciliation_verified:true},csrf);
              if(forgery.code!==422)throw Error('V180 fake bank confirmation accepted');
              const [paid,replayed]=await Promise.all([
                req(root+'manual-payments','POST',body,csrf),
                req(root+'manual-payments','POST',body,csrf)
              ]);
              if(paid.code!==200||replayed.code!==200||
                 !paid.data.payment_id||
                 paid.data.payment_id!==replayed.data.payment_id||
                 paid.data.financial_settlement_verified!==false)
                throw Error('V180 real PG concurrent payment replay failed');
              const partial=await req(root+'invoices/ci-v180-invoice-a/ledger-preview');
              if(partial.code!==200||partial.data.recorded_active_krw!==1000||
                 partial.data.active_payment_count!==1)
                throw Error('V180 partial recorded amount mismatch');
              const denied=await req(root+'manual-payments','POST',{
                ...body,invoice_id:'ci-v132-invoice-b',
                reference:'ci-v180-foreign-002'},csrf);
              if(denied.code!==404)throw Error('V180 cross-tenant write not 404');
              const reversed=await req(root+'manual-payments/reverse','POST',{
                invoice_id:body.invoice_id,payment_id:paid.data.payment_id,
                reversal_approved:true,internal_manual_entry_only:true
              },csrf);
              if(reversed.code!==200||reversed.data.reversed!==true)
                throw Error('V180 reversal not confirmed');
              if((await req(root+'manual-payments','POST',body,csrf)).code!==409)
                throw Error('V180 reversed idempotency key reused');
              const full=await req(root+'manual-payments','POST',{
                 ...body,amount_krw:7700,reference:'ci-v180-final-003'},csrf);
              if(full.code!==200)throw Error('V180 full internal ledger entry denied');
              const overpay=await req(root+'manual-payments','POST',{
                 ...body,amount_krw:1,reference:'ci-v180-overpay-004'},csrf);
              if(overpay.code!==409)throw Error('V180 overpayment accepted');
              const final=await req(root+'invoices/ci-v180-invoice-a/ledger-preview');
              if(final.code!==200||final.data.recorded_active_krw!==7700||
                 final.data.reversed_payment_count!==1||
                 final.data.bank_reconciliation_verified!==false)
                 throw Error('V180 final ledger changed or falsely reconciled');
              const b=await req('/api/pg-stage/v85/login','POST',{
                email:'b@invalid.test',
                password:'CI-v106-disposable-auth-password-only'});
              if(b.code!==200)throw Error('V180 B login failed');
              if((await req(root+'invoices/ci-v180-invoice-a/ledger-preview')).code!==404)
                throw Error('V180 B sees A internal ledger');
              return 'JW_V180_REAL_HTTPS_PG17_INTERNAL_UNRECONCILED_LEDGER_PASS';
            }""","JW_V180_REAL_HTTPS_PG17_INTERNAL_UNRECONCILED_LEDGER_PASS",timeout=100)
            with psycopg.connect(fixture.root_dsn) as root:
                finance=root.execute("""SELECT
                  (SELECT count(*) FROM jw_dev.payments
                   WHERE invoice_id='ci-v180-invoice-a'),
                  (SELECT count(*) FROM jw_dev.payments
                   WHERE invoice_id='ci-v180-invoice-a'
                     AND reversed_at IS NOT NULL),
                  (SELECT coalesce(sum(amount),0) FROM jw_dev.payments
                   WHERE invoice_id='ci-v180-invoice-a'
                     AND reversed_at IS NULL),
                  (SELECT count(*) FROM jw_dev.audit_logs a
                   JOIN jw_dev.payments p ON p.id=a.entity_id
                   WHERE p.invoice_id='ci-v180-invoice-a' AND a.action='create'),
                  (SELECT count(*) FROM jw_dev.audit_logs a
                   JOIN jw_dev.payments p ON p.id=a.entity_id
                   WHERE p.invoice_id='ci-v180-invoice-a' AND a.action='reverse')
                """).fetchone()
                if finance!=(2,1,7700,2,1):
                    raise AssertionError(f"V180 synthetic audit or finance corruption: {finance}")
            print("PASS_V180_REAL_CHROMIUM_HTTPS_RESTRICTED_PG17_CSRF_TENANT_REPLAY_REVERSAL",flush=True)
            print("LIMIT_V180_UNRECONCILED_INTERNAL_LEDGER_NOT_BANK_PROOF_OR_LEGAL_INVOICE",flush=True)
            print("PASS: browser HTTPS -> real V85 auth -> verified V90 trade role -> "
                  "original V83 PostgreSQL ledger RPC; A/B/C, CSRF, "
                  "concurrent idempotency, tenant denial, reversal and KRW 1440/9900",flush=True)
            print("PASS: real PG17 independent credential login, hashed DB sessions, "
                  "login failure, CSRF, A->quote+chat->B, logout revocation, "
                  "A/B/C tenant denial, C auth revocation, and relogin recovery",flush=True)
            print("LIMIT: synthetic A/B fixture on disposable PG17; MFA not enabled; "
                  "Render isolated Postgres not yet provisioned/connected",flush=True)
            print("PASS: real Chromium browser -> HTTPS -> V9.3 API -> PG17 nonprivileged session; quote form/GET/tenant denial",flush=True)
            print("LIMIT: localhost self-signed synthetic CA; QA-only cookie issuer; not hosted production HTTPS or real Supabase auth",flush=True)
            return 0
        finally:
            if browser:
                try:cli("close",timeout=12)
                except Exception:pass
            server.should_exit=True
            thread.join(timeout=4)

if __name__=="__main__":
    raise SystemExit(main())
