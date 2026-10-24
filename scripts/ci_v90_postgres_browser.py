"""CI-only PostgreSQL 17 + real FastAPI V9 RPC + Chromium and rollback validation.

This is NOT production auth, TLS acceptance, or the full financial UI.
The server runs on loopback and the DB must be a freshly initialized PG17 service.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import psycopg
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg import sql

from app.pg_messenger_bridge_v90 import VerifiedSession, create_router
from scripts.ci_playwright_cli_smoke import assertion, cli

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:8766"
TOKENS: dict[str, str] = {}
CSRF: dict[str, str] = {}
TRADE_DSN = ""
root_dsn = os.environ.get("JW_PG_CI_ROOT_DSN", "")

def require_disposable() -> None:
    if os.environ.get("JW_PG_CI_ALLOW") != "ONLY_EPHEMERAL_LOCAL_DATABASE":
        raise RuntimeError("Refusing non-CI PostgreSQL")
    o = conninfo_to_dict(root_dsn)
    if o.get("host") != "127.0.0.1" or o.get("dbname") != "postgres" or o.get("user") != "postgres":
        raise RuntimeError("Refusing nonlocal or shared database DSN")
    with psycopg.connect(root_dsn) as db:
        with db.cursor() as cur:
            cur.execute("SELECT current_setting('server_version_num')::integer / 10000")
            if cur.fetchone()[0] != 17:
                raise RuntimeError("Postgres 17 is mandatory")
            cur.execute("SELECT count(*) FROM pg_roles WHERE rolname <> 'postgres' AND rolname !~ '^pg_'")
            if cur.fetchone()[0] != 0:
                raise RuntimeError("Expected fresh disposable DB roles only")
            cur.execute("SELECT count(*) FROM pg_database WHERE NOT datistemplate AND datname<>'postgres'")
            if cur.fetchone()[0] != 0:
                raise RuntimeError("Expected fresh disposable DB")

def bootstrap() -> None:
    global TRADE_DSN
    require_disposable()
    trade_pwd = secrets.token_urlsafe(36)
    auth_pwd = secrets.token_urlsafe(36)
    with psycopg.connect(root_dsn, autocommit=True) as db:
        with db.cursor() as cur:
            for target in ("jw_app_dev", "jw_auth_stage_v85", "anon", "authenticated", "service_role"):
                cur.execute(sql.SQL("CREATE ROLE {} NOLOGIN NOINHERIT NOBYPASSRLS").format(sql.Identifier(target)))
            for login, password in (("jw_ci_trade", trade_pwd), ("jw_ci_auth", auth_pwd)):
                cur.execute(sql.SQL(
                    "CREATE ROLE {} LOGIN NOINHERIT NOBYPASSRLS NOSUPERUSER NOCREATEROLE NOCREATEDB PASSWORD {}"
                ).format(sql.Identifier(login), sql.Literal(password)))
            cur.execute("GRANT jw_app_dev TO jw_ci_trade WITH INHERIT FALSE, SET TRUE")
            cur.execute("GRANT jw_auth_stage_v85 TO jw_ci_auth WITH INHERIT FALSE, SET TRUE")
            cur.execute((ROOT / "db/review/ci_v90_ephemeral_pg_schema.sql").read_text())
            for file in ("ci_qa_001_jw_dev_secure_messenger_directory.sql",
                         "ci_qa_002_jw_dev_messenger_rpc.sql",
                         "ci_qa_006_commit_order_cursor_guard_candidate.sql"):
                cur.execute((ROOT / "db/review" / file).read_text())
            for who, org in (("A", "ci-ua"), ("B", "ci-ub"), ("C", "ci-uc")):
                token = secrets.token_urlsafe(48)
                TOKENS[who] = token
                CSRF[who] = secrets.token_urlsafe(24)
                cur.execute("""INSERT INTO jw_dev.sessions
                    (id,token_hash,user_id,expires_at,csrf_token,created_at)
                    VALUES (%s,%s,%s,(now()+interval '2 hours')::text,%s,now()::text)""",
                    (who, hashlib.sha256(token.encode()).hexdigest(), org, CSRF[who]))
    TRADE_DSN = make_conninfo(root_dsn, user="jw_ci_trade", password=trade_pwd)
    auth_dsn = make_conninfo(root_dsn, user="jw_ci_auth", password=auth_pwd)
    with psycopg.connect(TRADE_DSN) as t, psycopg.connect(auth_dsn) as a:
        with t.cursor() as tc, a.cursor() as ac:
            tc.execute("SELECT session_user,pg_backend_pid(),pg_has_role(session_user,'jw_auth_stage_v85','MEMBER')")
            ac.execute("SELECT session_user,pg_backend_pid(),pg_has_role(session_user,'jw_app_dev','MEMBER')")
            tr, au = tc.fetchone(), ac.fetchone()
            if tr[0]!="jw_ci_trade" or au[0]!="jw_ci_auth" or tr[1]==au[1] or tr[2] or au[2]:
                raise AssertionError("Independent role credentials failed")

class PgGateway:
    def query(self, session_hash: str, statement: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        with psycopg.connect(TRADE_DSN) as db:
            with db.transaction():
                with db.cursor() as cur:
                    cur.execute("SET LOCAL ROLE jw_app_dev")
                    cur.execute("SELECT set_config('jw.session_hash',%s,true)", (session_hash,))
                    cur.execute(statement, params)
                    columns = [x.name for x in cur.description] if cur.description else []
                    return [dict(zip(columns, row)) for row in cur.fetchall()] if columns else []

def authorize(request: Request) -> VerifiedSession:
    token = request.cookies.get("jw_ci_session", "")
    h = hashlib.sha256(token.encode()).hexdigest()
    if len(token)<30:
        raise HTTPException(401, "Synthetic session required")
    with psycopg.connect(TRADE_DSN) as db:
        with db.cursor() as cur:
            cur.execute("SET LOCAL ROLE jw_app_dev")
            cur.execute("SELECT set_config('jw.session_hash',%s,true)", (h,))
            cur.execute("SELECT jw_dev.current_org_from_session()")
            if not cur.fetchone()[0]:
                raise HTTPException(401, "DB session revoked")
    identity = next((n for n,t in TOKENS.items() if secrets.compare_digest(t,token)),None)
    if identity is None:
        raise HTTPException(401, "Unrecognized synthetic token")
    valid = request.method=="GET" or secrets.compare_digest(request.headers.get("X-CSRF-Token", ""), CSRF[identity])
    return VerifiedSession(session_hash=h,csrf_verified=valid)

app = FastAPI()
app.include_router(create_router(PgGateway(), authorize))
@app.get("/qa/health")
def health(): return {"ok": True,"backend":"postgresql"}
@app.post("/qa/login/{company}")
def login(company: str, response: Response):
    if company not in TOKENS:
        raise HTTPException(404)
    response.set_cookie("jw_ci_session", TOKENS[company], secure=False, httponly=True, samesite="strict")
    return {"company": company, "csrf": CSRF[company]}
@app.post("/qa/logout")
def logout(response: Response):
    response.delete_cookie("jw_ci_session")
    return {"ok":True}
@app.get("/")
def index():
    return HTMLResponse("""<!doctype html><html lang="ko"><meta charset="utf-8">
    <title>V9 PG Chromium CI</title><body><h1>Real PostgreSQL messenger CI</h1>
    <button id="login-a" onclick="login('A')">Login A</button>
    <button id="login-b" onclick="login('B')">Login B</button>
    <button id="login-c" onclick="login('C')">Login C</button>
    <input id="recipient" value="ci-b" aria-label="recipient">
    <button id="start" onclick="start()">Start chat</button>
    <textarea id="body" aria-label="message"></textarea>
    <button id="send" onclick="send()">Send</button>
    <button id="refresh" onclick="refresh()">Refresh</button>
    <pre id="result"></pre>
    <script>
      let csrf='',chat='';
      async function call(p,method='GET',body){
        const h={'Content-Type':'application/json'};
        if(method!=='GET')h['X-CSRF-Token']=csrf;
        const r=await fetch(p,{method,headers:h,credentials:'same-origin',
          body:body===undefined?undefined:JSON.stringify(body)});
        return {status:r.status,data:await r.json()};
      }
      async function login(c){const v=await call('/qa/login/'+c,'POST');
        if(v.status!==200)throw Error('login');csrf=v.data.csrf;
        document.querySelector('#result').textContent='TENANT_'+c;return v;}
      async function start(){const v=await call('/api/pg-stage/v90/chats','POST',
          {other_org_id:document.querySelector('#recipient').value});
        if(v.status!==200)throw Error('start '+v.status);
        chat=v.data.connection_id;document.querySelector('#result').textContent='CHAT_'+chat;return v;}
      async function send(){const v=await call('/api/pg-stage/v90/chats/'+chat+'/messages','POST',
          {request_id:'ci-'+crypto.randomUUID(),body:document.querySelector('#body').value});
        if(v.status!==200)throw Error('send '+v.status);
        document.querySelector('#result').textContent='SENT_'+v.data.message_cursor;return v;}
      async function refresh(){const v=await call('/api/pg-stage/v90/chats/'+chat+'/messages');
        if(v.status!==200)throw Error('list '+v.status);
        document.querySelector('#result').textContent=JSON.stringify(v.data);return v;}
    </script></body></html>""")

def browser_proof() -> str:
    script = r"""async () => {
       const click = id => document.getElementById(id).click();
       const wait = async (prefix) => {for(let i=0;i<60;i++){
         if(document.getElementById('result').textContent.startsWith(prefix))return;
         await new Promise(r=>setTimeout(r,100));
       }throw Error('DOM '+prefix)};
       click('login-a');await wait('TENANT_A');
       const noCsrf=await fetch('/api/pg-stage/v90/chats',{method:'POST',
         credentials:'same-origin',headers:{'Content-Type':'application/json'},
         body:JSON.stringify({other_org_id:'ci-b'})});
       if(noCsrf.status!==403)throw Error('CSRF bypass '+noCsrf.status);
       click('start');await wait('CHAT_');
       const chat=document.getElementById('result').textContent.slice(5);
       window.__chat=chat;
       document.getElementById('body').value='PG_REAL_BROWSER_V90';
       click('send');await wait('SENT_');
       click('refresh');await wait('[');
       if(!document.getElementById('result').textContent.includes('PG_REAL_BROWSER_V90'))
         throw Error('PG message absent');
       click('login-b');await wait('TENANT_B');
       const b=await refresh();
       if(b.status!==200||!JSON.stringify(b.data).includes('PG_REAL_BROWSER_V90'))
         throw Error('B recipient cannot see PG message');
       click('login-c');await wait('TENANT_C');
       const bad=await fetch('/api/pg-stage/v90/chats/'+chat+'/messages',
         {credentials:'same-origin'});
       if(bad.status!==403)throw Error('C read not denied '+bad.status);
       return 'JW_REAL_PG_BROWSER_RLS_PASS:'+chat;
    }"""
    return assertion(script,"JW_REAL_PG_BROWSER_RLS_PASS:",timeout=120)

def rollback_proof(chat: str) -> None:
    token = hashlib.sha256(TOKENS["A"].encode()).hexdigest()
    with psycopg.connect(TRADE_DSN) as db:
        with db.cursor() as cur:
            cur.execute("SET LOCAL ROLE jw_app_dev")
            cur.execute("SELECT set_config('jw.session_hash',%s,true)",(token,))
            cur.execute("SELECT * FROM jw_dev.v90_send_text(%s,%s,%s)",
                        (chat,"ci-rollback-probe","ROLLBACK_MUST_NOT_PERSIST"))
            db.rollback()  # uncommitted API write simulates crashed worker.
    rows = PgGateway().query(token,
        "SELECT * FROM jw_dev.v90_sync_messages(%s,%s,%s)",(chat,0,100))
    if any("ROLLBACK_MUST_NOT_PERSIST"==x["body"] for x in rows):
        raise AssertionError("Uncommitted message became visible")
    with psycopg.connect(TRADE_DSN) as db:
        with db.cursor() as cur:
            cur.execute("SET LOCAL ROLE jw_app_dev")
            cur.execute("SELECT set_config('jw.session_hash',%s,true)",(token,))
            cur.execute("SELECT * FROM jw_dev.v90_send_text(%s,%s,%s)",
                        (chat,"ci-recovery-committed","RECOVERED_AFTER_ROLLBACK"))
            db.commit()
    rows=PgGateway().query(token,"SELECT * FROM jw_dev.v90_sync_messages(%s,%s,%s)",(chat,0,100))
    if sum(x["body"]=="RECOVERED_AFTER_ROLLBACK" for x in rows)!=1:
        raise AssertionError("Committed recovery row absent/duplicated")

def concurrency_proof(chat: str) -> None:
    from threading import Event
    a_ready=Event()
    release=Event()
    starts={}
    def writer(actor, key, text, hold=False):
        token=hashlib.sha256(TOKENS[actor].encode()).hexdigest()
        with psycopg.connect(TRADE_DSN) as db:
            with db.cursor() as cur:
                cur.execute("SET LOCAL ROLE jw_app_dev")
                cur.execute("SELECT set_config('jw.session_hash',%s,true)",(token,))
                if hold:
                    cur.execute("SELECT message_cursor FROM jw_dev.v90_send_text(%s,%s,%s)",(chat,key,text))
                    num=cur.fetchone()[0]
                    a_ready.set()
                    if not release.wait(7):raise AssertionError("release event timeout")
                else:
                    starts["B"]=time.monotonic()
                    cur.execute("SELECT message_cursor FROM jw_dev.v90_send_text(%s,%s,%s)",(chat,key,text))
                    num=cur.fetchone()[0]
                db.commit()
                return num
    with ThreadPoolExecutor(max_workers=2) as pool:
        a=pool.submit(writer,"A","ci-concurrent-A","COMMIT_A",True)
        if not a_ready.wait(5):raise AssertionError("A transaction missing")
        b=pool.submit(writer,"B","ci-concurrent-B","COMMIT_B")
        time.sleep(.45)
        if b.done(): raise AssertionError("B inserted before A committed")
        release.set()
        ac=a.result(timeout=10)
        bc=b.result(timeout=10)
    if ac>=bc:raise AssertionError("Message cursor inverted")
    h=hashlib.sha256(TOKENS["A"].encode()).hexdigest()
    rows=PgGateway().query(h,"SELECT * FROM jw_dev.v90_sync_messages(%s,%s,%s)",(chat,0,100))
    proof=[x["body"] for x in rows if x["body"] in ("COMMIT_A","COMMIT_B")]
    if proof!=["COMMIT_A","COMMIT_B"]:
        raise AssertionError("Commit order not visible in full RPC")

def main() -> int:
    bootstrap()
    server=uvicorn.Server(uvicorn.Config(app,host="127.0.0.1",port=8766,log_level="error",access_log=False))
    thread=threading.Thread(target=server.run,daemon=True)
    thread.start()
    for _ in range(100):
        try:
            with urllib.request.urlopen(BASE+"/qa/health",timeout=1) as r:
                if r.status==200:break
        except Exception:time.sleep(.1)
    else:raise AssertionError("FastAPI server not ready")
    browser_open=False
    try:
        cli("open",BASE)
        browser_open=True
        proof=browser_proof()
        import re
        m=re.search(r"JW_REAL_PG_BROWSER_RLS_PASS:([0-9a-zA-Z-]+)",proof)
        if not m:raise AssertionError("Browser proof missing chat ID")
        chat=m.group(1)
        rollback_proof(chat)
        concurrency_proof(chat)
        print("PASS: Chromium real HTTP -> V9 FastAPI router -> PG17 SQL RPC; A/B visibility, C denial, CSRF",flush=True)
        print("PASS: 2 independent business SQL sessions send same chat; commit cursor monotonic; crash rollback & retry",flush=True)
        print("LIMIT: isolated schema/auth and local HTTP; not deployed full V8.9 user UI, not verified-full TLS",flush=True)
        return 0
    finally:
        if browser_open:
            try:cli("close",timeout=12)
            except Exception:pass
        server.should_exit=True
        thread.join(timeout=4)

if __name__=="__main__":
    raise SystemExit(main())
