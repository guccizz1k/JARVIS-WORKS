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
            from scripts.ci_v93_finance_restore import restore_proof
            restore_proof()
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
