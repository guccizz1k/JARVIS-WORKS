"""V19.8 real Chromium Fetch/FormData -> real PG17 V19.5 approval-to-order.

Actual browser networking, raw XLSX upload, server HMAC approval evidence,
restricted PostgreSQL, V160 quote, V92 review, V174 internal order and
V145 invoice-preflight fail-closed. Uses ORIGINAL product API handlers.
Synthetic test-only browser automation on localhost; NOT real UI, hosted
Render, physical delivery, legal invoice issuance or payment settlement.
Requires clean disposable postgres:17 and makes NO shared DB changes.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from threading import Thread
import time

import httpx
import psycopg
import uvicorn
from playwright.sync_api import sync_playwright

from scripts import ci_v195_atomic_approval_receipt_https as base
from scripts import ci_v157_real_pg_delivery_http as fixture
from app import pg_invoice_preview_v145 as invoice
from scripts.review import pg_import_preview_v195 as upload

HOST="https://localhost:8773"

BROWSER_FLOW=r"""async ({b64,csrf}) => {
 if(location.origin!=='https://localhost:8773')
   throw Error('BLOCKED_V198_NOT_HTTPS_LOOPBACK_BROWSER');
 const call=async(path,method='GET',value,mode='json',overrideCsrf)=>{
   const headers={};
   if(method!=='GET')headers['X-CSRF-Token']=(overrideCsrf??csrf);
   if(value!==undefined&&mode==='json')headers['Content-Type']='application/json';
   const r=await fetch(path,{method,headers,credentials:'same-origin',
      body:value===undefined?undefined:(mode==='form'?value:JSON.stringify(value))});
   let data;
   try{data=await r.json();}catch{data=null}
   return {status:r.status,data};
 };
 const ok=(r,code,label)=>{
   if(r.status!==code)throw Error(label+': HTTP '+r.status+' expected '+code+
      ' '+JSON.stringify(r.data).slice(0,350));
   return r.data;
 };
 const bytes=Uint8Array.from(atob(b64),ch=>ch.charCodeAt(0));
 const file=new File([bytes],"v198-original-bytes.xlsx",{
   type:"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"});
 const form=new FormData();form.append("file",file);
 const entry=ok(await call('/api/pg-stage/v193/imports/preview','POST',
                           form,'form'),201,'browser-upload');
 if(entry.document.company!=='Customer A'
    ||entry.document.money.total!==176000
    ||entry.document.items.length!==2
    ||entry.reviewed!==false
    ||entry.source_bytes_persisted!==false)
   throw Error('BROWSER_SOURCE_DOCUMENT_CHANGED');
 const pid=entry.preview_id,digest=entry.preview_digest;
 const confirmPath='/api/pg-stage/v193/imports/'+pid+'/confirm';
 const consent={preview_digest:digest,confirmed_customer:'Customer A',
     confirmed_quote_date:'2026-10-31',confirmed_total_krw:176000,approve:true};
 ok(await call(confirmPath,'POST',consent,'json',''),403,'missing-csrf');
 ok(await call(confirmPath,'POST',{...consent,
     confirmed_customer:'Forged counterparty'}),409,'changed-counterparty');
 ok(await call(confirmPath,'POST',{...consent,
     confirmed_total_krw:1}),409,'changed-total');
 for(let i=1;i<=20;i++){
   const forged=i.toString(16).padStart(32,'0');
   ok(await call('/api/pg-stage/v193/imports/'+forged+'/confirm',
     'POST',consent),404,'missing-source-'+i);
 }
 // User-facing browser explicitly opts in. This is synthetic actor action
 // and is NOT independently signed by a real external person.
 const approved=ok(await call(confirmPath,'POST',consent),
                    200,'signed-human-check');
 if(!approved.confirmed||!approved.approval_receipt_id)
   throw Error('MISSING_SIGNED_APPROVAL');
 const repeat=await call(confirmPath,'POST',consent);
 if(![404,409].includes(repeat.status))
   throw Error('DUPLICATED_IMPORT_APPROVAL');
 const conversion='/api/pg-stage/v160/imports/'+pid+'/quote-draft';
 const cv={preview_digest:digest,customer_id:'0'.repeat(32),reviewed:true,
   confirmed_customer:'Customer A',confirmed_quote_date:'2026-10-31',
   confirmed_total_krw:176000};
 ok(await call(conversion,'POST',{...cv,reviewed:false}),422,'no-review');
 const draft=ok(await call(conversion,'POST',cv),201,'source-linked-quote');
 const qid=draft.quote_id;
 if(!qid||draft.money.total!==176000||draft.approval_posted!==false)
   throw Error('QUOTE_LINEAGE_OR_MONEY_DRIFT');
 const repeats=await Promise.all(Array.from({length:12},()=>call(conversion,'POST',cv)));
 if(repeats.some(r=>r.status!==200||r.data.quote_id!==qid))
   throw Error('BROWSER_CONCURRENT_DUPLICATE_QUOTE');
 const qp=ok(await call('/api/pg-stage/v92/quote-review-previews/'+qid),
              200,'quote-preview');
 if(qp.source_document_verified!==false||qp.money.total!==176000)
   throw Error('FALSE_ORIGINAL_DOCUMENT_VERIFICATION');
 const reviewed=ok(await call('/api/pg-stage/v92/quote-reviews','POST',{
    quote_id:qid,preview_sha256:qp.preview_sha256,preview_checked:true
 }),201,'explicit-second-quote-review');
 const receipt=reviewed.review_receipt_id;
 const od=ok(await call('/api/pg-stage/v92/order-drafts','POST',{
    request_id:'v198-browser-order-draft',quote_id:qid,
    review_receipt_id:receipt,original_checked:true
 }),201,'reviewed-order-draft');
 if(!od.draft_only)throw Error('ORDER_NOT_DRAFT');
 const confirm=ok(await call(
   '/api/pg-stage/v174/order-drafts/'+od.order_id+'/register-preview'
 ),200,'internal-order-preview');
 if(confirm.money.total!==176000)throw Error('ORDER_AMOUNT_CHANGED');
 const order=ok(await call('/api/pg-stage/v174/orders/from-reviewed-draft',
    'POST',{
       draft_id:od.order_id,review_receipt_id:receipt,
       preview_sha256:confirm.preview_sha256,
       request_id:'v198-browser-internal-order',
       original_checked:true,register_internal_only:true
    }),201,'verified-internal-order');
 if(!order.internal_order_only||order.invoice_issued||order.payment_recorded)
   throw Error('UNVERIFIED_DELIVERY_OR_INVOICE_POSTED');
 const preflight=await call('/api/pg-stage/v145/orders/'+
                           order.order_id+'/invoice-preview');
 if(preflight.status!==409)
   throw Error('BROWSER_INVOICE_UNVERIFIED_ORDER_NOT_BLOCKED '+preflight.status);
 return {pid,digest,approval_receipt_id:approved.approval_receipt_id,
         receipt_sha256:approved.receipt_statement_sha256,
         quote_id:qid,order_id:order.order_id,review_receipt_id:receipt,
         forged_count:20,replay_count:12,invoice_blocked:true};
}"""

CROSS_TENANT=r"""async ({pid,qid,order_id,digest}) => {
 const get=async(p)=> (await fetch(p,{credentials:'same-origin'})).status;
 const paths=[
 '/api/pg-stage/v92/quote-review-previews/'+qid,
 '/api/pg-stage/v174/order-drafts/'+order_id+'/register-preview',
 '/api/pg-stage/v145/orders/'+order_id+'/invoice-preview'
 ];
 for(const p of paths){
   if((await get(p))!==404)throw Error('V198_CROSS_TENANT_ACCESS '+p);
 }
 const r=await fetch('/api/pg-stage/v160/imports/'+pid+'/quote-draft',{
  method:'POST',credentials:'same-origin',
  headers:{'Content-Type':'application/json','X-CSRF-Token':window.__ci_csrf},
  body:JSON.stringify({preview_digest:digest,customer_id:'0'.repeat(32),
    reviewed:true,confirmed_customer:'Customer A',
    confirmed_quote_date:'2026-10-31',confirmed_total_krw:176000})
 });
 if(r.status!==404)throw Error('V198_TENANT_B_QUOTE_LEAK '+r.status);
 return true;
}"""


def run_browser():
    if (os.getenv("JW_ENV")!="review" or
        os.getenv("JW_PG_CI_ALLOW")!="ONLY_EPHEMERAL_LOCAL_DATABASE" or
        "@127.0.0.1:5432/postgres" not in os.getenv("JW_PG_CI_ROOT_DSN","")):
        raise RuntimeError("BLOCKED_V198_REQUIRES_DISPOSABLE_PG17")
    fixture.disposable_root_check()
    app=base.prepare()
    os.environ["JW_V90_ALLOWED_ORIGINS"]=HOST
    assert invoice.register_v145_invoice_preview(app)
    with TemporaryDirectory(prefix="jw-v198-chromium-") as d:
        tls=Path(d)
        key,cert=tls/"key.pem",tls/"cert.pem"
        subprocess.run(["openssl","req","-x509","-nodes","-newkey",
          "rsa:2048","-keyout",str(key),"-out",str(cert),"-days","1",
          "-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost"],
          check=True,capture_output=True,timeout=20)
        server=uvicorn.Server(uvicorn.Config(app,host="127.0.0.1",port=8773,
          ssl_keyfile=str(key),ssl_certfile=str(cert),
          log_level="error",access_log=False))
        worker=Thread(target=server.run,daemon=True)
        worker.start()
        try:
            for _ in range(100):
                if server.started:break
                time.sleep(.1)
            assert server.started,"V198_REAL_SERVER_NOT_STARTED"
            # Independent pinned-CA HTTPS check, even though headless browser
            # uses ignore_https_errors for the synthetic localhost test cert.
            with httpx.Client(verify=str(cert),trust_env=False,
                timeout=15) as trusted:
                res=trusted.get(HOST+"/docs")
                assert res.status_code==200,"V198_PINNED_CERT_FAILED"
            with sync_playwright() as p:
                browser=p.chromium.launch(headless=True,
                                          args=["--no-sandbox"])
                try:
                    def context(actor):
                        ctx=browser.new_context(ignore_https_errors=True,
                            viewport={"width":1280,"height":880},
                            accept_downloads=False)
                        ctx.add_cookies([{
                          "name":"__Host-jw_session",
                          "value":fixture.TOKENS[actor],
                          "url":HOST,"secure":True,"httpOnly":True,
                          "sameSite":"Strict"
                        }])
                        page=ctx.new_page()
                        page.goto(HOST+"/docs",wait_until="domcontentloaded",
                                  timeout=25000)
                        assert page.evaluate("location.origin")==HOST
                        return ctx,page
                    a,pa=context("A")
                    try:
                        result=pa.evaluate(BROWSER_FLOW,{
                           "b64":base64.b64encode(base.xlsx()).decode("ascii"),
                           "csrf":fixture.CSRF["A"]})
                        assert result["forged_count"]==20 and result["replay_count"]==12
                        b,pb=context("B")
                        try:
                            pb.evaluate("(csrf)=>{window.__ci_csrf=csrf;}",
                                        fixture.CSRF["B"])
                            assert pb.evaluate(CROSS_TENANT,result) is True
                        finally:
                            b.close()
                        # Genuine DB SQL post-condition independent of Browser JS.
                        with psycopg.connect(fixture.DSN) as root:
                            row=root.execute("""SELECT status,preview_digest,
                                file_sha256,quote_id
                                FROM jw_dev.import_previews WHERE id=%s""",
                                (result["pid"],)).fetchone()
                            assert row[0]=="confirmed" and row[1]==result["digest"]
                            assert len(row[2])==64
                            assert row[3] is None,"V198_PREVIEW_LINK_FIELD_IMMUTABLE_BY_DESIGN"
                            receipt=root.execute("""SELECT signature,statement
                                FROM jw_dev.v195_approval_receipts
                                WHERE id=%s AND preview_id=%s""",
                                (result["approval_receipt_id"],result["pid"])).fetchone()
                            assert receipt is not None
                            assert hmac.compare_digest(receipt[0],hmac.new(
                              upload._approval_key,receipt[1].encode("utf-8"),
                              hashlib.sha256).hexdigest())
                            assert hashlib.sha256(receipt[1].encode()).hexdigest()==(
                              result["receipt_sha256"])
                            assert root.execute("""SELECT count(*) FROM jw_dev.quotes
                                WHERE id=%s AND source_import_id=%s""",
                                (result["quote_id"],"v160:"+fixture.ORG_A+":"+result["pid"])).fetchone()==(1,)
                            assert root.execute("""SELECT count(*) FROM jw_dev.orders
                                WHERE id=%s AND quote_id=%s""",
                                (result["order_id"],result["quote_id"])).fetchone()==(1,)
                            assert root.execute("""SELECT count(*) FROM jw_dev.order_items
                                WHERE order_id=%s""",(result["order_id"],)).fetchone()==(2,)
                            assert root.execute("""SELECT count(*) FROM jw_dev.invoices""").fetchone()==(0,)
                            assert root.execute("""SELECT to_regclass(
                                'jw_dev.payments')""").fetchone()==(None,)
                            assert root.execute("""SELECT count(*) FROM jw_dev.audit_logs
                                WHERE entity_id=%s AND action='approved_import_to_draft'""",
                                (result["quote_id"],)).fetchone()==(1,)
                        print("PASS_V198_CHROMIUM_REAL_FORMDATA_PG17_SIGNED_IMPORT_QUOTE_ORDER",
                              flush=True)
                        print("PASS_V198_CHROMIUM_20_FORGED_IMPORT_IDS_AND_12_CONCURRENT_REPLAY",
                              flush=True)
                        print("PASS_V198_CHROMIUM_TENANT_B_CROSS_ORG_4_ROUTE_DENIAL",
                              flush=True)
                        print("PASS_V198_INVOICE_PREFLIGHT_DENIES_UNVERIFIED_INTERNAL_ORDER",
                              flush=True)
                        print("PASS_V198_INDEPENDENT_SQL_HMAC_QUOTE_ORDER_AUDIT_FINGERPRINT",
                              flush=True)
                        print("LIMIT_V198_BROWSER_API_ONLY_LOCAL_TLS_NOT_HOSTED_UI_OR_DELIVERY",
                              flush=True)
                    finally:
                        a.close()
                finally:
                    browser.close()
        finally:
            server.should_exit=True
            worker.join(timeout=15)
            assert not worker.is_alive(),"V198_SERVER_FAILED_TO_SHUTDOWN"


if __name__=="__main__":
    run_browser()
