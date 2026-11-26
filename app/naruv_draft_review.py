"""Synthetic document registration and draft review. No auto posting or payment."""
import os
from fastapi import APIRouter,HTTPException,Request,Response
from starlette.concurrency import run_in_threadpool
from . import naruv_valuation_review as valuation
from . import naruv_native_write_review as write
from . import naruv_native_file_preview as preview
from . import pg_v90_integrated_entry as v90
from .naruv_document_review import review_document,ReviewBlocked,digest
from .naruv_payroll_draft import draft_gross,PayrollBlocked

PREFIX=preview.PREFIX+"/drafts"
FLAG="NARUV_DRAFT_REVIEW"
KR_FLAG="NARUV_KR_PAYROLL_CI_REVIEW"

def kr_enabled():
    return (enabled() and os.getenv(KR_FLAG)=="DISPOSABLE_FIXTURE_ONLY"
            and os.getenv("GITHUB_ACTIONS")=="true" and os.getenv("JW_PG_CI_ALLOW")=="ONLY_EPHEMERAL_LOCAL_DATABASE"
            and os.getenv("JW_ENV","").lower() in ("dev","development","test"))
def enabled():
    return valuation.enabled() and os.getenv(FLAG)=="ISOLATED_SYNTHETIC_ONLY"

def _read(token,csrf,prior,kind,key,period=None):
    import psycopg
    if not enabled():raise HTTPException(404,"DRAFT_DISABLED")
    try:
        with v90._pg_validated_cursor(token) as (cur,identity):
            actor,org=preview._verify_identity(identity,csrf)
            if (actor,org)!=prior:raise HTTPException(409,"SESSION_SCOPE_CHANGED")
            cur.execute("SET LOCAL statement_timeout='8s'")
            cur.execute("SET LOCAL lock_timeout='4s'")
            if kind=="document":
                cur.execute("SELECT * FROM naruv_draft.document_source(%s,%s)",(key,csrf))
                row=cur.fetchone()
                if row is None:raise HTTPException(404,"DRAFT_SOURCE_NOT_FOUND")
                revision,raw,sha,observations=row
                result=review_document(tenant=org,source_bytes=bytes(raw),registered_sha256=sha,observations=observations)
                result["source_binding_sha256"]=digest({"tenant":org,"document":key,"revision":revision,"review":result["review_sha256"]})
                result["revision"]=revision
            elif kind=="pay":
                cur.execute("SELECT * FROM naruv_draft.pay_source(%s,%s,%s)",(key,period,csrf))
                row=cur.fetchone()
                if row is None:raise HTTPException(404,"DRAFT_SOURCE_NOT_FOUND")
                revision,rate,bps,days=row
                result=draft_gross(tenant=org,worker=key,period=period,policy_revision=revision,
                                   hourly_krw=rate,minutes_by_day=days,multiplier_bps={"regular":10000,"additional":bps})
            else:raise RuntimeError("DRAFT_KIND")
            # guard() holds the actor fence through transaction end.
            result["persisted"]=False;result["production_authorized"]=False
            return result
    except (ReviewBlocked,PayrollBlocked):
        raise HTTPException(409,"DRAFT_SOURCE_INVALID") from None
    except psycopg.Error as exc:
        if getattr(getattr(exc,"diag",None),"message_primary","") in ("HR_CONFLICT","DOC_CONFLICT"):
            raise HTTPException(409,"DRAFT_SOURCE_CHANGED") from None
        raise write._db_error(exc) from None

KR_BODY_LIMIT=32768

def _decode_kr_body(raw):
    import json
    from . import naruv_inventory_review as inventory
    from .naruv_kr_payroll_review import DEDUCTIONS,KINDS,HEX
    try:
        if type(raw) is not bytes or len(raw)>KR_BODY_LIMIT:raise ValueError("size")
        d=json.loads(raw.decode("utf-8"),object_pairs_hook=inventory._pairs,
            parse_constant=inventory._reject_constant)
        required={"expected_draft_sha256","ordinary_hourly","classification_sha256",
                "classified_days","deductions","pension_assessed_base_krw"}
        if type(d) is not dict or not required<=set(d) or not set(d)<=required|{"insurance_assessed_bases","settlement_components","paid_holiday_review","unused_leave_review","shift_review","part_time_leave_review","monthly_tax_review"}:raise ValueError("shape")
        if "monthly_tax_review" in d:
            tax=d["monthly_tax_review"]
            if type(tax) is not dict or set(tax)!={"withholding_date","taxable_monthly_krw","eligible_family_count","eligible_children_8_20","selection_percent","assessment_sha256"}:
                raise ValueError("monthly tax shape")
        if "part_time_leave_review" in d:
            pt=d["part_time_leave_review"]
            if type(pt) is not dict or set(pt)!={"comparator_grant_days","contracted_week_minutes","contract_sha256","grant_assessment_sha256"}:
                raise ValueError("part-time leave shape")
        if "shift_review" in d:
            shift=d["shift_review"]
            if type(shift) is not dict or set(shift)!={"segments","shift_sha256"}:raise ValueError("shift shape")
        if "unused_leave_review" in d:
            leave=d["unused_leave_review"]
            if type(leave) is not dict or set(leave)!={"grant_ledger_sha256","expected_grant_ids","entries"}:
                raise ValueError("leave shape")
        if "settlement_components" in d and type(d["settlement_components"]) is not dict:raise ValueError("settlement shape")
        if "paid_holiday_review" in d:
            h=d["paid_holiday_review"]
            if type(h) is not dict or set(h)!={"calendar_sha256","days"}:raise ValueError("holiday shape")
        if "insurance_assessed_bases" in d:
            bases=d["insurance_assessed_bases"]
            if type(bases) is not dict or set(bases)!={"health_base_krw","employment_base_krw","assessment_sha256"}:
                raise ValueError("insurance shape")
            if any(type(bases[k]) is not int for k in ("health_base_krw","employment_base_krw")) or type(bases["assessment_sha256"]) is not str or not HEX.fullmatch(bases["assessment_sha256"]):
                raise ValueError("insurance shape")
        if any(type(d[k]) is not str or not HEX.fullmatch(d[k]) for k in ("expected_draft_sha256","classification_sha256")):
            raise ValueError("digest")
        if any(type(d[k]) is not int for k in ("ordinary_hourly","pension_assessed_base_krw")):raise ValueError("number")
        days=d["classified_days"]; deductions=d["deductions"]
        if type(days) is not list or len(days)>31 or type(deductions) is not dict or set(deductions)!=set(DEDUCTIONS):
            raise ValueError("shape")
        for row in days:
            if type(row) is not dict or set(row)!={"date",*KINDS} or type(row["date"]) is not str or any(type(row[k]) is not int for k in KINDS):
                raise ValueError("day")
        for row in deductions.values():
            if type(row) is not dict or set(row)!={"amount_krw","evidence_sha256","assessment"} or type(row["amount_krw"]) is not int or any(type(row[k]) is not str for k in ("evidence_sha256","assessment")):
                raise ValueError("deduction")
        return d
    except (ValueError,UnicodeError,RecursionError):
        raise HTTPException(422,"KR_REVIEW_INPUT") from None

async def _kr_body(request):
    import asyncio,re
    from starlette.requests import ClientDisconnect
    length=preview._one_header(request,"content-length")
    if length is not None:
        if not re.fullmatch(r"[0-9]{1,10}",length):raise HTTPException(400,"KR_REVIEW_LENGTH")
        if int(length)>KR_BODY_LIMIT:raise HTTPException(413,"KR_REVIEW_BODY_LIMIT")
    if preview._one_header(request,"content-encoding","identity")!="identity":
        raise HTTPException(415,"KR_REVIEW_ENCODING")
    buf=bytearray()
    try:
        async with asyncio.timeout(5):
            async for chunk in request.stream():
                if len(chunk)>KR_BODY_LIMIT-len(buf):raise HTTPException(413,"KR_REVIEW_BODY_LIMIT")
                buf.extend(chunk)
    except TimeoutError:raise HTTPException(408,"KR_REVIEW_TIMEOUT") from None
    except ClientDisconnect:raise HTTPException(400,"KR_REVIEW_INCOMPLETE") from None
    if length is not None and len(buf)!=int(length):raise HTTPException(400,"KR_REVIEW_LENGTH")
    return _decode_kr_body(bytes(buf))

def _kr_review(token,csrf,prior,worker,period,data):
    """Read only confirmed attendance in the authenticated PG transaction.
    Classification and assessments are manual submissions, not agency truth.
    """
    import psycopg
    from .naruv_kr_payroll_review import (source_bound_review,pension_collection_reference_2026,insurance_collection_review_2026,
        assessed_settlement_components_2026,approved_paid_holiday_review_2026,unused_leave_compensation_review_2026,
        shift_night_source_review_2026,fixed_part_time_annual_leave_reference_2026,assessed_monthly_tax_comparison_2026)
    if not kr_enabled():raise HTTPException(404,"KR_REVIEW_DISABLED")
    try:
        with v90._pg_validated_cursor(token) as (cur,identity):
            actor,org=preview._verify_identity(identity,csrf)
            if (actor,org)!=prior:raise HTTPException(409,"SESSION_SCOPE_CHANGED")
            cur.execute("SET LOCAL statement_timeout='8s'")
            cur.execute("SET LOCAL lock_timeout='4s'")
            cur.execute("SELECT * FROM naruv_draft.pay_source(%s,%s,%s)",(worker,period,csrf))
            row=cur.fetchone()
            if row is None:raise HTTPException(404,"DRAFT_SOURCE_NOT_FOUND")
            revision,rate,bps,days=row
            review=source_bound_review(tenant=org,worker=worker,period=period,policy_revision=revision,
                hourly_krw=rate,minutes_by_day=days,additional_bps=bps,
                expected_draft_sha256=data["expected_draft_sha256"],ordinary_hourly=data["ordinary_hourly"],
                classification_sha256=data["classification_sha256"],classified_days=data["classified_days"],
                deductions=data["deductions"])
            pension=data["pension_assessed_base_krw"]
            item=data["deductions"]["pension"]
            if item["assessment"]!="ASSESSED":raise PayrollBlocked("KR_NPS_ASSESSMENT_REQUIRED")
            pension_ref=pension_collection_reference_2026(tenant=org,worker=worker,period=period,
                assessed_base_krw=pension,assessment_sha256=item["evidence_sha256"],
                assessed_employee_krw=item["amount_krw"],scope="ORDINARY_SINGLE_WORKPLACE_NO_RELIEF")
            proof={"v":"KR_CI_MANUAL_API_V1","source":review["review_binding_sha256"],
                "pension":pension_ref["review_sha256"]}
            details={}
            if "insurance_assessed_bases" in data:
                keys=("health","long_term_care","employment_insurance")
                if any(data["deductions"][k]["assessment"]!="ASSESSED" for k in keys):
                    raise PayrollBlocked("KR_INSURANCE_ASSESSMENT_REQUIRED")
                insurance=insurance_collection_review_2026(tenant=org,worker=worker,period=period,
                    **data["insurance_assessed_bases"],
                    assessed_employee_krw={k:data["deductions"][k]["amount_krw"] for k in keys},
                    scope="ORDINARY_FULL_MONTH_NO_RELIEF_ASSESSED_BASES")
                proof.update(v="KR_CI_MANUAL_API_V2",insurance=insurance["review_sha256"])
                details={"insurance_reference":insurance}
            if "settlement_components" in data:
                settlement=assessed_settlement_components_2026(tenant=org,worker=worker,period=period,
                    components=data["settlement_components"])
                proof.update(v="KR_CI_MANUAL_API_V3",settlement=settlement["review_sha256"])
                details["settlement_reference"]=settlement
            if "paid_holiday_review" in data:
                holiday=approved_paid_holiday_review_2026(tenant=org,worker=worker,period=period,
                    ordinary_hourly=data["ordinary_hourly"],**data["paid_holiday_review"])
                actual={r["date"]:r["regular"]+r["additional"] for r in days}
                if any(actual.get(r["date"],0)!=r["actual_minutes"] for r in data["paid_holiday_review"]["days"]):
                    raise PayrollBlocked("KR_HOLIDAY_SOURCE_MISMATCH")
                proof.update(v="KR_CI_MANUAL_API_V3",holiday=holiday["review_sha256"])
                details["paid_holiday_reference"]=holiday
            if "unused_leave_review" in data:
                leave=unused_leave_compensation_review_2026(tenant=org,worker=worker,period=period,
                    ordinary_hourly=data["ordinary_hourly"],**data["unused_leave_review"])
                proof.update(v="KR_CI_MANUAL_API_V3",leave=leave["review_sha256"])
                details["unused_leave_reference"]=leave
            if "part_time_leave_review" in data:
                part_time=fixed_part_time_annual_leave_reference_2026(tenant=org,worker=worker,period=period,
                    ordinary_hourly=data["ordinary_hourly"],**data["part_time_leave_review"])
                proof.update(v="KR_CI_MANUAL_API_V4",part_time_leave=part_time["review_sha256"])
                details["part_time_leave_reference"]=part_time
            if "shift_review" in data:
                shift=shift_night_source_review_2026(tenant=org,worker=worker,period=period,
                    classified_days=data["classified_days"],**data["shift_review"])
                proof.update(v="KR_CI_MANUAL_API_V4" if "part_time_leave_review" in data else "KR_CI_MANUAL_API_V3",shift=shift["review_sha256"])
                details["shift_reference"]=shift
            if "monthly_tax_review" in data:
                tax=assessed_monthly_tax_comparison_2026(tenant=org,worker=worker,period=period,
                    gross_krw=review["wage"]["gross_estimate_krw"],deductions=data["deductions"],**data["monthly_tax_review"])
                proof.update(v="KR_CI_MANUAL_API_V5",monthly_tax=tax["review_sha256"])
                details["monthly_tax_reference"]=tax
            return {"status":"MANUAL_SUBMISSION_REFERENCE_ONLY","review":review,"pension_reference":pension_ref,**details,
                "evidence_authenticity_verified":False,"persisted":False,"statutory_validated":False,
                "payment_authorized":False,"production_authorized":False,"review_sha256":digest(proof)}
    except PayrollBlocked:
        raise HTTPException(409,"KR_REVIEW_INPUT_OR_SOURCE_CHANGED") from None
    except psycopg.Error as exc:
        if getattr(getattr(exc,"diag",None),"message_primary","")=="HR_CONFLICT":
            raise HTTPException(409,"DRAFT_SOURCE_CHANGED") from None
        raise write._db_error(exc) from None

def _admit_document(token,csrf,prior,key,rid,fmt,raw,observations):
    import hashlib,json,psycopg
    if not enabled():raise HTTPException(404,"DRAFT_DISABLED")
    try:
        with v90._pg_validated_cursor(token) as (cur,identity):
            actor,org=preview._verify_identity(identity,csrf)
            if (actor,org)!=prior:raise HTTPException(409,"SESSION_SCOPE_CHANGED")
            sha=hashlib.sha256(raw).hexdigest()
            review=review_document(tenant=org,source_bytes=raw,registered_sha256=sha,observations=observations)
            if any(x.startswith("INVALID_") for x in review["issues"]):raise HTTPException(422,"DOC_INPUT")
            cur.execute("SET LOCAL statement_timeout='8s'")
            cur.execute("SET LOCAL lock_timeout='4s'")
            cur.execute("SELECT naruv_draft.admit_document(%s,%s,%s,%s,%s::jsonb,true,%s)",
                        (key,rid,fmt,raw,json.dumps(observations,ensure_ascii=True,separators=(",",":")),csrf))
            row=cur.fetchone()
            if not row or type(row[0]) is not dict or row[0].get("source_sha256")!=sha or row[0].get("posting_authorized") is not False or row[0].get("production_authorized") is not False:
                raise HTTPException(503,"DOC_UNAVAILABLE")
            return row[0]
    except ReviewBlocked:raise HTTPException(422,"DOC_INPUT") from None
    except psycopg.Error as exc:
        reason=getattr(getattr(exc,"diag",None),"message_primary","")
        if reason=="DOC_INPUT":raise HTTPException(422,reason) from None
        if reason in ("DOC_CONFLICT","DOC_CAPACITY"):raise HTTPException(409,reason) from None
        raise write._db_error(exc) from None

def _revise_document(token,csrf,prior,key,rid,data):
    import json,psycopg
    if not enabled():raise HTTPException(404,"DRAFT_DISABLED")
    try:
        with v90._pg_validated_cursor(token) as (cur,identity):
            actor,org=preview._verify_identity(identity,csrf)
            if (actor,org)!=prior:raise HTTPException(409,"SESSION_SCOPE_CHANGED")
            cur.execute("SET LOCAL statement_timeout='8s'")
            cur.execute("SET LOCAL lock_timeout='4s'")
            cur.execute("SELECT * FROM naruv_draft.document_source(%s,%s)",(key,csrf))
            row=cur.fetchone()
            if row is None:raise HTTPException(404,"DRAFT_SOURCE_NOT_FOUND")
            _,raw,sha,_=row
            if sha!=data["source_sha256"]:raise HTTPException(409,"DOC_CONFLICT")
            review=review_document(tenant=org,source_bytes=bytes(raw),registered_sha256=sha,observations=data["observations"])
            if any(x.startswith("INVALID_") for x in review["issues"]):raise HTTPException(422,"DOC_INPUT")
            cur.execute("SELECT naruv_draft.revise_document(%s,%s,%s,%s,%s::jsonb,true,%s)",
                        (key,rid,data["previous_revision"],sha,json.dumps(data["observations"],ensure_ascii=True,separators=(",",":")),csrf))
            row=cur.fetchone()
            if not row or type(row[0]) is not dict or row[0].get("source_sha256")!=sha or row[0].get("posting_authorized") is not False or row[0].get("production_authorized") is not False:
                raise HTTPException(503,"DOC_UNAVAILABLE")
            return row[0]
    except ReviewBlocked:raise HTTPException(422,"DOC_INPUT") from None
    except psycopg.Error as exc:
        reason=getattr(getattr(exc,"diag",None),"message_primary","")
        if reason=="DOC_NOT_FOUND":raise HTTPException(404,reason) from None
        if reason=="DOC_INPUT":raise HTTPException(422,reason) from None
        if reason in ("DOC_CONFLICT","DOC_CAPACITY"):raise HTTPException(409,reason) from None
        raise write._db_error(exc) from None

def create_router():
    router=APIRouter(prefix=PREFIX,tags=["NARUV isolated document and payroll drafts"])
    async def read(kind,key,period,request,response):
        if not enabled():raise HTTPException(404,"DRAFT_DISABLED")
        token,csrf,_=write._request(request,key,period,needs_digest=False)
        prior=await run_in_threadpool(write._auth,token,csrf)
        await write._empty_body(request)
        result=await run_in_threadpool(_read,token,csrf,prior,kind,key,period)
        response.headers["Cache-Control"]="no-store"
        return result
    @router.post("/documents/{key}")
    async def document(key:str,request:Request,response:Response):
        return await read("document",key,None,request,response)
    @router.post("/payroll/{worker}/{period}")
    async def payroll(worker:str,period:str,request:Request,response:Response):
        import re
        if not re.fullmatch(r"[0-9]{4}-(0[1-9]|1[0-2])",period):raise HTTPException(422,"DRAFT_INPUT")
        return await read("pay",worker,period,request,response)
    if kr_enabled():
        @router.post("/payroll/{worker}/{period}/kr-review")
        async def kr_review(worker:str,period:str,request:Request,response:Response):
            import re
            if not kr_enabled():raise HTTPException(404,"KR_REVIEW_DISABLED")
            if not re.fullmatch(r"2026-(0[1-9]|1[0-2])",period):raise HTTPException(422,"KR_REVIEW_INPUT")
            token,csrf,_=write._request(request,worker,period,needs_digest=False)
            if preview._one_header(request,"content-type","")!="application/json":
                raise HTTPException(415,"KR_REVIEW_CONTENT_TYPE")
            prior=await run_in_threadpool(write._auth,token,csrf)
            data=await _kr_body(request)
            result=await run_in_threadpool(_kr_review,token,csrf,prior,worker,period,data)
            if preview._one_header(request,"accept","")=="text/html":
                from fastapi.responses import HTMLResponse
                from .naruv_kr_payroll_review import isolated_payroll_review_html
                return HTMLResponse(isolated_payroll_review_html(result),headers={
                    "Cache-Control":"no-store","X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY",
                    "Referrer-Policy":"no-referrer","Content-Security-Policy":"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"})
            response.headers["Cache-Control"]="no-store"
            return result
    @router.post("/documents/{key}/register/{rid}")
    async def register_document(key:str,rid:str,request:Request,response:Response):
        import base64,binascii,json
        from . import naruv_inventory_review as inventory
        if not enabled():raise HTTPException(404,"DRAFT_DISABLED")
        token,csrf,_=write._request(request,key,rid,needs_digest=False)
        if preview._one_header(request,"x-naruv-confirm","")!="yes":raise HTTPException(422,"DOC_CONFIRM_REQUIRED")
        if preview._one_header(request,"content-type","")!="application/json":raise HTTPException(415,"DOC_CONTENT_TYPE")
        prior=await run_in_threadpool(write._auth,token,csrf)
        body=await preview._bounded_body(request)
        try:
            d=json.loads(body.decode("utf-8"),object_pairs_hook=inventory._pairs,parse_constant=inventory._reject_constant)
            if type(d) is not dict or set(d)!={"format","original_base64","observations"}:raise ValueError("shape")
            fmt=d["format"];encoded=d["original_base64"];obs=d["observations"]
            if type(fmt) is not str or fmt not in ("pdf","xlsx") or type(encoded) is not str or len(encoded)>699052 or type(obs) is not list:raise ValueError("shape")
            raw=base64.b64decode(encoded,validate=True)
            if not 5<=len(raw)<=524288 or base64.b64encode(raw).decode("ascii")!=encoded:raise ValueError("bytes")
            if not raw.startswith(bytes.fromhex("255044462d" if fmt=="pdf" else "504b0304")):raise ValueError("signature")
            if len(json.dumps(obs,ensure_ascii=True,separators=(",",":")))>30000:raise ValueError("observations")
        except (ValueError,UnicodeError,RecursionError,binascii.Error):
            raise HTTPException(422,"DOC_INPUT") from None
        result=await run_in_threadpool(_admit_document,token,csrf,prior,key,rid,fmt,raw,obs)
        response.headers["Cache-Control"]="no-store"
        return result
    @router.post("/documents/{key}/revise/{rid}")
    async def revise_document(key:str,rid:str,request:Request,response:Response):
        import json,re
        from . import naruv_inventory_review as inventory
        if not enabled():raise HTTPException(404,"DRAFT_DISABLED")
        token,csrf,_=write._request(request,key,rid,needs_digest=False)
        if preview._one_header(request,"x-naruv-confirm","")!="yes":raise HTTPException(422,"DOC_CONFIRM_REQUIRED")
        if preview._one_header(request,"content-type","")!="application/json":raise HTTPException(415,"DOC_CONTENT_TYPE")
        prior=await run_in_threadpool(write._auth,token,csrf)
        raw=await preview._bounded_body(request)
        if len(raw)>32768:raise HTTPException(413,"DOC_INPUT")
        try:
            data=json.loads(raw.decode("utf-8"),object_pairs_hook=inventory._pairs,parse_constant=inventory._reject_constant)
            if (type(data) is not dict or set(data)!={"previous_revision","source_sha256","observations"}
                or type(data["previous_revision"]) is not str or not preview.IDENT.fullmatch(data["previous_revision"])
                or type(data["source_sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}",data["source_sha256"])
                or type(data["observations"]) is not list or len(json.dumps(data["observations"],ensure_ascii=True,separators=(",",":")))>30000):
                raise ValueError("shape")
        except (ValueError,UnicodeError,RecursionError):raise HTTPException(422,"DOC_INPUT") from None
        result=await run_in_threadpool(_revise_document,token,csrf,prior,key,rid,data)
        response.headers["Cache-Control"]="no-store"
        return result
    return router

def register_drafts(app):
    if not enabled():return False
    v90._origins();app.include_router(create_router());return True
