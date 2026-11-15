"""Independent REAL HTTPS synthetic quote-to-cash E2E against isolated Render staging.

This script deliberately writes ONLY synthetic records into the private, disposable
SQLite storage of jw-v223-qa-isolated-20261115. Never targets operational Supabase,
main or other Render services. Logs/checkpoint contain only check names and status.
"""
from __future__ import annotations
from datetime import datetime,timezone,timedelta
from http.cookiejar import CookieJar
from urllib.request import HTTPCookieProcessor, HTTPSHandler, Request, build_opener
from urllib.error import HTTPError, URLError
import json, ssl, time, uuid
from pathlib import Path

HOST="jw-v223-qa-isolated-20261115.onrender.com"
BASE="https://"+HOST
TARGET_SHA="cdcdc857e173f572fb1815f657cbc5d9b117bbd4"
TODAY=datetime.now(timezone(timedelta(hours=9))).date()
DUE=(TODAY+timedelta(days=45)).isoformat()
STAMP="SYNTHETIC_QA_"+uuid.uuid4().hex[:12]
class QA:
    def __init__(self):self.checked=[]
    def verify(self,name,predicate):
        if not bool(predicate):raise AssertionError("FAIL_"+name)
        self.checked.append(name)
class Client:
    def __init__(self):
        self.cookies=CookieJar()
        self.opener=build_opener(HTTPSHandler(context=ssl.create_default_context()),HTTPCookieProcessor(self.cookies))
        self.csrf=None
    def call(self,path,method="GET",body=None,csrf=True):
        assert path.startswith("/api/") and "?" not in path and not path.startswith("//")
        headers={"Accept":"application/json","User-Agent":"JW-REVIEW-SYNTHETIC-TRADE-E2E"}
        if body is not None:headers["Content-Type"]="application/json"
        if method!="GET" and csrf and self.csrf:headers["X-CSRF-Token"]=self.csrf
        req=Request(BASE+path,headers=headers,method=method,
                    data=json.dumps(body).encode("utf8") if body is not None else None)
        try:r=self.opener.open(req,timeout=35)
        except HTTPError as e:r=e
        with r:
            data=r.read(1024*1024+1)
            if len(data)>1024*1024:raise AssertionError("RESPONSE_TOO_LARGE")
            status=r.status
        try:value=json.loads(data)
        except ValueError:raise AssertionError("NON_JSON_API_RESPONSE")
        return status,value
    def login(self,email):
        status,body=self.call("/api/login","POST",{"email":email,"password":"Demo!2026secure"},csrf=False)
        if status!=200 or not isinstance(body.get("user"),dict):raise AssertionError("FAIL_SYNTHETIC_LOGIN")
        status,who=self.call("/api/me")
        if status!=200 or who.get("org_id")!=body["user"].get("org_id"):raise AssertionError("FAIL_SESSION_BINDING")
        self.csrf=who["csrf_token"]
        return who

def main():
    q=QA()
    a,b=Client(),Client()
    # Free tier may wake slowly; never treat sleeping as product defect.
    healthy=False
    for _ in range(9):
        try:
            status,d=Client().call("/api/health")
            if status==200 and d.get("status")=="ok":healthy=True;break
        except (URLError,TimeoutError):pass
        time.sleep(10)
    q.verify("real_https_health",healthy)
    alice=a.login("demo@hanbit.example")
    bob=b.login("demo@bada.example")
    q.verify("two_distinct_real_server_sessions",alice["id"]!=bob["id"] and alice["org_id"]!=bob["org_id"])
    status,who=a.call("/api/me");q.verify("A_identity_verified",status==200 and who["org_id"]==alice["org_id"])
    status,who=b.call("/api/me");q.verify("B_identity_verified",status==200 and who["org_id"]==bob["org_id"])
    status,bcustomers=b.call("/api/customers")
    q.verify("B_customer_available",status==200 and bcustomers and bcustomers[0]["org_id"]==bob["org_id"])
    # Test missing CSRF does not silently create a customer.
    payload={"name":STAMP+"_vendor","business_number":"","contact_name":"QA Only","email":"","phone":""}
    status,_=a.call("/api/customers","POST",payload,csrf=False)
    q.verify("customer_post_requires_csrf",status==403)
    status,customer=a.call("/api/customers","POST",payload)
    q.verify("customer_created_real_db",status==201 and customer.get("org_id")==alice["org_id"])
    custid=customer["id"]
    status,view=a.call("/api/customers")
    q.verify("customer_readback_real_db",status==200 and any(r["id"]==custid for r in view))
    status,_=b.call("/api/quotes","POST",{"customer_id":custid,"title":"attack","items":[{"name":"Item","quantity":1,"unit_price":1000}]})
    q.verify("cross_tenant_customer_lookup_denied",status==404)
    lines=[{"name":"SYNTHETIC_Industrial_Part","quantity":2,"unit_price":125000}]
    status,_=a.call("/api/quotes","POST",{"customer_id":custid,"title":"Bad Quantity","items":[{"name":"X","quantity":"2","unit_price":1}]})
    q.verify("strict_integer_quantity",status==422)
    status,quote=a.call("/api/quotes","POST",{"customer_id":custid,"title":STAMP,"vat_mode":"taxable","items":lines})
    q.verify("quote_create_real_db",status==201 and quote["org_id"]==alice["org_id"])
    qid=quote["id"]
    q.verify("subtotal_vat_exact",quote.get("money")=={"subtotal":250000,"vat":25000,"total":275000})
    status,read=a.call("/api/quotes/"+qid)
    q.verify("quote_readback_real_db",status==200 and read["id"]==qid)
    status,_=b.call("/api/quotes/"+qid)
    q.verify("cross_tenant_quote_denied",status==404)
    status,_=a.call("/api/quotes/"+qid+"/status","POST",{"status":"accepted"})
    q.verify("illegal_draft_to_accepted_blocked",status==409)
    status,sent=a.call("/api/quotes/"+qid+"/status","POST",{"status":"sent"})
    q.verify("quote_sent",status==200 and sent["status"]=="sent")
    status,accepted=a.call("/api/quotes/"+qid+"/status","POST",{"status":"accepted"})
    q.verify("quote_accepted",status==200 and accepted["status"]=="accepted")
    status,order=a.call("/api/orders/from-quote","POST",{"quote_id":qid,"due_date":DUE})
    q.verify("order_created_from_accepted_quote",status==201 and order["org_id"]==alice["org_id"])
    oid=order["id"]
    status,_=a.call("/api/orders/from-quote","POST",{"quote_id":qid,"due_date":DUE})
    q.verify("duplicate_order_blocked",status==409)
    status,_=b.call("/api/orders/"+oid)
    q.verify("cross_tenant_order_denied",status==404)
    status,processed=a.call("/api/orders/"+oid+"/status","POST",{"status":"processing"})
    q.verify("order_processing",status==200 and processed["status"]=="processing")
    status,fulfilled=a.call("/api/orders/"+oid+"/status","POST",{"status":"fulfilled"})
    q.verify("order_fulfilled",status==200 and fulfilled["status"]=="fulfilled")
    status,invoice=a.call("/api/invoices/from-order","POST",{"order_id":oid,"due_date":DUE})
    q.verify("invoice_created_real_db",status==201 and invoice["org_id"]==alice["org_id"])
    iid=invoice["id"]
    q.verify("invoice_balance_exact",invoice["balance"]==275000)
    status,_=a.call("/api/invoices/from-order","POST",{"order_id":oid,"due_date":DUE})
    q.verify("duplicate_invoice_blocked",status==409)
    status,_=b.call("/api/invoices/"+iid)
    q.verify("cross_tenant_invoice_denied",status==404)
    ref=STAMP+"_payment_ref"
    payment={"reference":ref,"amount":100000,"paid_at":TODAY.isoformat(),"note":"SYNTHETIC ONLY"}
    status,_=a.call("/api/invoices/"+iid+"/payments","POST",payment,csrf=False)
    q.verify("payment_requires_csrf",status==403)
    status,_=a.call("/api/invoices/"+iid+"/payments","POST",{**payment,"amount":999999999})
    q.verify("overpayment_denied",status==409)
    status,paid=a.call("/api/invoices/"+iid+"/payments","POST",payment)
    q.verify("partial_payment_posted",status==201 and paid["balance"]==175000)
    status,replayed=a.call("/api/invoices/"+iid+"/payments","POST",payment)
    q.verify("payment_idempotent_replay",status==201 and replayed["balance"]==175000)
    status,_=a.call("/api/invoices/"+iid+"/payments","POST",{**payment,"amount":200000})
    q.verify("idempotency_reference_conflict",status==409)
    status,payments=a.call("/api/invoices/"+iid+"/payments")
    q.verify("payment_list_actual_one",status==200 and len([p for p in payments if p["amount"]==100000])==1)
    payid=next(x["id"] for x in payments if x["amount"]==100000)
    status,_=b.call("/api/invoices/"+iid+"/payments/"+payid+"/reverse","POST")
    q.verify("cross_tenant_payment_reversal_denied",status==404)
    status,reversed_=a.call("/api/invoices/"+iid+"/payments/"+payid+"/reverse","POST")
    q.verify("payment_reversal_restores_balance",status==200 and reversed_["balance"]==275000)
    status,_=a.call("/api/invoices/"+iid+"/payments/"+payid+"/reverse","POST")
    q.verify("duplicate_reversal_denied",status==409)
    status,ledger=a.call("/api/reconciliation/"+oid)
    q.verify("reconciliation_real_api",status==200 and isinstance(ledger,dict))
    for client,name in [(a,"A"),(b,"B")]:
        status,_=client.call("/api/logout","POST",csrf=False)
        q.verify(name+"_logout_requires_csrf",status==403)
        status,_=client.call("/api/logout","POST")
        q.verify(name+"_logout_success",status==200)
        status,_=client.call("/api/me")
        q.verify(name+"_session_revoked",status==401)
    summary={"scope":"REAL_RENDER_HTTPS_SYNTHETIC_SQLITE_REVIEW_ONLY",
             "target":BASE,"deployed_control_plane_sha":TARGET_SHA,
             "checked":q.checked,"passed":len(q.checked),"failed":0,"skipped":0,
             "limitations":["not_supabase","not_real_pg17_restore","not_full_17_menu_business_write","not_safari_device","not_release"]}
    Path("jw-v223-real-trade-qa.json").write_text(json.dumps(summary,ensure_ascii=False,indent=2))
    print("PASS_REAL_SYNTHETIC_HTTPS_QUOTE_TO_CASH "+str(len(q.checked))+"_CHECKS_ZERO_FAIL")
    print("NOT_P2_P3_P4_PRODUCTION_RELEASE_PASS")
if __name__=="__main__":main()
