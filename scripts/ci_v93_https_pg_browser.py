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
              const fromQuote={request_id:'v127-order-request-0001',
                quote_id:created.data.quote_id,original_checked:true};
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
