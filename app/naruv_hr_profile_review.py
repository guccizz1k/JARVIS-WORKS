"""CI-only authenticated synthetic profile storage; no real PII admitted.

Revision-checked demo; no production retention or key custody claims.
Existing ERP guards are required and SQL never receives plaintext.
"""
import os
import asyncio
import json
import re
import psycopg
from fastapi import APIRouter,HTTPException,Request,Response
from starlette.concurrency import run_in_threadpool
from . import naruv_pg_auth_review as auth, naruv_native_write_review as write
from . import naruv_native_file_preview as preview,pg_v90_integrated_entry as v90
from starlette.requests import ClientDisconnect
from . import naruv_inventory_review as inventory
from .naruv_hr_profile_envelope import seal_profile,open_profile,rotate_profile,ProfileBlocked

FLAG="NARUV_HR_PROFILE_CI"
KEY="NARUV_HR_PROFILE_CI_KEY"
NEXT_KEY="NARUV_HR_PROFILE_CI_NEXT_KEY"
KEY_IDS={"ci-profile-key":KEY,"ci-profile-key-2":NEXT_KEY}
PREFIX="/api/naruv-profile-ci/v1"
def enabled():
    return auth.enabled() and os.getenv(FLAG)=="DISPOSABLE_FIXTURE_ONLY"
def key(kid="ci-profile-key"):
    if kid not in KEY_IDS:raise HTTPException(503,"PROFILE_KEY_UNAVAILABLE")
    raw=os.getenv(KEY_IDS[kid],"")
    if not re.fullmatch(r"[a-f0-9]{64}",raw):raise HTTPException(503,"PROFILE_KEY_UNAVAILABLE")
    return bytes.fromhex(raw)
async def profile_body(request,*,replace=False,control=None):
    # The finance decoder is deliberately flat; profiles have a nested object.
    limit=8192
    length=preview._one_header(request,"content-length")
    if length is not None:
        if not re.fullmatch(r"[0-9]{1,5}",length):raise HTTPException(400,"PROFILE_LENGTH")
        if int(length)>limit:raise HTTPException(413,"PROFILE_BODY_LIMIT")
    buf=bytearray()
    try:
        async with asyncio.timeout(5):
            async for chunk in request.stream():
                if len(chunk)>limit-len(buf):raise HTTPException(413,"PROFILE_BODY_LIMIT")
                buf.extend(chunk)
    except TimeoutError:raise HTTPException(408,"PROFILE_TIMEOUT") from None
    except ClientDisconnect:raise HTTPException(400,"PROFILE_INCOMPLETE") from None
    if length is not None and len(buf)!=int(length):raise HTTPException(400,"PROFILE_LENGTH")
    try:
        data=json.loads(buf.decode("utf-8"),object_pairs_hook=inventory._pairs,parse_constant=inventory._reject_constant)
        if control:
            fields={"revision","expected_revision"} if control=="rotate" else {"expected_revision","approval_sha256"}
            if type(data) is not dict or set(data)!=fields:raise ValueError("shape")
            if any(type(v) is not str for v in data.values()):raise ValueError("type")
            if not preview.IDENT.fullmatch(data["expected_revision"]):raise ValueError("revision")
            if control=="rotate" and (not preview.IDENT.fullmatch(data["revision"]) or data["revision"]==data["expected_revision"]):raise ValueError("revision")
            if control=="purge" and not re.fullmatch(r"[a-f0-9]{64}",data["approval_sha256"]):raise ValueError("approval")
            return data
        fields={"revision","profile","expected_revision"} if replace else {"revision","profile"}
        if (type(data) is not dict or set(data)!=fields or type(data["revision"]) is not str
            or not preview.IDENT.fullmatch(data["revision"]) or type(data["profile"]) is not dict
            or set(data["profile"])!={"display_name","work_email","employment_start"}
            or any(type(v) is not str for v in data["profile"].values())):raise ValueError("shape")
        if replace and (type(data["expected_revision"]) is not str or not preview.IDENT.fullmatch(data["expected_revision"]) or data["expected_revision"]==data["revision"]):raise ValueError("revision")
        return data
    except (ValueError,UnicodeError,RecursionError):raise HTTPException(422,"PROFILE_INPUT") from None

def operate(token,csrf,prior,worker,body,control=None):
    if not enabled():raise HTTPException(404,"PROFILE_DISABLED")
    try:
        with v90._pg_validated_cursor(token) as (cur,identity):
            actor,org=preview._verify_identity(identity,csrf)
            if (actor,org)!=prior or org not in ("ci-a","ci-b"):raise HTTPException(403,"PROFILE_SCOPE")
            cur.execute("SET LOCAL statement_timeout='8s'")
            cur.execute("SET LOCAL lock_timeout='4s'")
            if control=="purge":
                cur.execute("SELECT naruv_draft.purge_profile(%s,%s,%s,%s)",(worker,body["expected_revision"],body["approval_sha256"],csrf))
                if cur.fetchone()!=({"status":"PURGED"},):raise HTTPException(503,"PROFILE_UNAVAILABLE")
                return {"status":"PURGED","production_authorized":False}
            def current():
                cur.execute("SELECT naruv_draft.profile_envelope(%s,NULL,NULL,NULL,%s)",(worker,csrf))
                row=cur.fetchone()
                if not row or type(row[0]) is not dict or set(row[0])!={"revision","envelope"}:raise HTTPException(503,"PROFILE_UNAVAILABLE")
                return row[0]
            if control=="rotate":
                old=current()
                if old["revision"]!=body["expected_revision"] or old["envelope"]["key_id"]!="ci-profile-key":
                    raise HTTPException(409,"PROFILE_STALE")
                try:
                    envelope=rotate_profile(tenant=org,worker=worker,old_revision=old["revision"],new_revision=body["revision"],
                        old_key_id="ci-profile-key",new_key_id="ci-profile-key-2",old_key=key(),new_key=key("ci-profile-key-2"),envelope=old["envelope"])
                except ProfileBlocked:raise HTTPException(409,"PROFILE_ROTATION_INVALID") from None
                cur.execute("SELECT naruv_draft.profile_envelope(%s,%s,%s::jsonb,%s,%s)",(worker,body["revision"],json.dumps(envelope),body["expected_revision"],csrf))
                if cur.fetchone()!=({"status":"SEALED","revision":body["revision"]},):raise HTTPException(503,"PROFILE_UNAVAILABLE")
                return {"status":"ROTATED","revision":body["revision"],"production_authorized":False}
            if body is not None:
                if set(body) not in ({"revision","profile"},{"revision","profile","expected_revision"}) or type(body["revision"]) is not str or not preview.IDENT.fullmatch(body["revision"]):
                    raise HTTPException(422,"PROFILE_INPUT")
                p=body["profile"]
                if type(p) is not dict or type(p.get("display_name")) is not str or not p["display_name"].startswith("Synthetic ") or type(p.get("work_email")) is not str or not p["work_email"].endswith("@example.invalid"):
                    raise HTTPException(422,"PROFILE_SYNTHETIC_ONLY")
                kid="ci-profile-key"
                if "expected_revision" in body:
                    old=current()
                    if old["revision"]!=body["expected_revision"]:raise HTTPException(409,"PROFILE_STALE")
                    kid=old["envelope"]["key_id"]
                    open_profile(tenant=org,worker=worker,revision=old["revision"],key_id=kid,key=key(kid),envelope=old["envelope"])
                envelope=seal_profile(tenant=org,worker=worker,revision=body["revision"],key_id=kid,key=key(kid),profile=p)
                cur.execute("SELECT naruv_draft.profile_envelope(%s,%s,%s::jsonb,%s,%s)",(worker,body["revision"],json.dumps(envelope),body.get("expected_revision"),csrf))
                row=cur.fetchone()
                if not row or row[0]!={"status":"SEALED","revision":body["revision"]}:raise HTTPException(503,"PROFILE_UNAVAILABLE")
                return dict(row[0],production_authorized=False)
            cur.execute("SELECT naruv_draft.profile_envelope(%s,NULL,NULL,NULL,%s)",(worker,csrf))
            row=cur.fetchone()
            if not row or type(row[0]) is not dict or set(row[0])!={"revision","envelope"}:raise HTTPException(503,"PROFILE_UNAVAILABLE")
            kid=row[0]["envelope"]["key_id"]
            result=open_profile(tenant=org,worker=worker,revision=row[0]["revision"],key_id=kid,key=key(kid),envelope=row[0]["envelope"])
            return {"revision":row[0]["revision"],"profile":result,"production_authorized":False}
    except ProfileBlocked:raise HTTPException(422 if body is not None else 409,"PROFILE_INVALID") from None
    except psycopg.Error as exc:
        reason=getattr(getattr(exc,"diag",None),"message_primary","")
        if reason=="PROFILE_NOT_FOUND":raise HTTPException(404,reason) from None
        if reason in ("PROFILE_EXISTS","PROFILE_STALE","PROFILE_REVISION_REUSED","PROFILE_RETAINED","PROFILE_PURGE_BLOCKED","PROFILE_PURGED"):raise HTTPException(409,reason) from None
        if reason=="PROFILE_INPUT":raise HTTPException(422,reason) from None
        raise write._db_error(exc) from None

def register(app):
    if not enabled():return False
    router=APIRouter(prefix=PREFIX)
    async def handle(worker,request,response,create,replace=False,control=None):
        auth.check(request)
        if not enabled():raise HTTPException(404,"PROFILE_DISABLED")
        if worker!="worker-1":raise HTTPException(422,"PROFILE_SYNTHETIC_ONLY")
        token,csrf,_=write._request(request,worker,needs_digest=False)
        prior=await run_in_threadpool(write._auth,token,csrf)
        if create:
            if request.headers.getlist("x-naruv-confirm")!=["yes"]:raise HTTPException(422,"PROFILE_CONFIRM_REQUIRED")
            if request.headers.getlist("content-type")!=["application/json"]:raise HTTPException(415,"PROFILE_CONTENT_TYPE")
            body=await profile_body(request,replace=replace,control=control)
        else:
            await write._empty_body(request)
            body=None
        result=await run_in_threadpool(operate,token,csrf,prior,worker,body,control)
        response.headers["Cache-Control"]="no-store"
        return result
    @router.post("/workers/{worker}/create")
    async def create(worker:str,request:Request,response:Response):return await handle(worker,request,response,True)
    @router.post("/workers/{worker}/replace")
    async def replace(worker:str,request:Request,response:Response):return await handle(worker,request,response,True,True)
    @router.post("/workers/{worker}/read")
    async def read(worker:str,request:Request,response:Response):return await handle(worker,request,response,False)
    @router.post("/workers/{worker}/rotate")
    async def rotate(worker:str,request:Request,response:Response):return await handle(worker,request,response,True,control="rotate")
    @router.post("/workers/{worker}/purge")
    async def purge(worker:str,request:Request,response:Response):return await handle(worker,request,response,True,control="purge")
    app.include_router(router)
    return True
