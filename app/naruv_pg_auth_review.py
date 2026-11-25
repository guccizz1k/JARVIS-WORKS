"""Separate default-off PG-only authentication perimeter, disposable CI only.

Uses existing V85 password/MFA/session implementation and the existing ERP
authorization. Never registers with legacy WORKS or issues SQLite sessions.
No production or hosted authorization.
"""
import asyncio
import json
import os
import re
from fastapi import APIRouter,HTTPException,Request,Response
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect
from . import pg_auth_v85 as auth,pg_v90_integrated_entry as v90
from . import naruv_native_write_review as write

FLAG="NARUV_PG_AUTH_CI"
ACK="DISPOSABLE_FIXTURE_ONLY"
PREFIX="/api/naruv-auth-review/v1"

def enabled():
    return (os.getenv(FLAG)==ACK and os.getenv("GITHUB_ACTIONS")=="true"
        and os.getenv("JW_PG_CI_ALLOW")=="ONLY_EPHEMERAL_LOCAL_DATABASE"
        and os.getenv("JW_ENV")=="dev" and auth.auth_stage_enabled() and v90.v90_enabled())

def check(request):
    if not enabled():raise HTTPException(404,"AUTH_REVIEW_DISABLED")
    if request.url.scheme!="https" or request.headers.getlist("origin")!=[str(request.base_url).rstrip("/")] or request.headers["origin"] not in v90._origins():
        raise HTTPException(403,"ORIGIN_DENIED")
    if request.query_params:raise HTTPException(422,"AUTH_SCOPE")
    # Reject old dual-session cookies and duplicate session cookies, including
    # cookies in separate header lines. Never accept an identity from payload.
    names=[p.partition("=")[0].strip() for line in request.headers.getlist("cookie") for p in line.split(";")]
    if names.count(auth.COOKIE)>1 or any(n in names for n in ("__Host-jw_legacy_v223","__Host-jw_pg_v223")):
        raise HTTPException(401,"AUTH_COOKIE_SCOPE")

def pairs(items):
    result={}
    for k,v in items:
        if k in result:raise ValueError("duplicate")
        result[k]=v
    return result

async def payload(request):
    if request.headers.getlist("content-type")!=["application/json"]:raise HTTPException(415,"AUTH_CONTENT_TYPE")
    if request.headers.getlist("content-encoding") not in ([],["identity"]):raise HTTPException(415,"AUTH_ENCODING")
    lengths=request.headers.getlist("content-length")
    if lengths and (len(lengths)!=1 or not re.fullmatch(r"[0-9]{1,5}",lengths[0]) or int(lengths[0])>8192):
        raise HTTPException(413,"AUTH_BODY_LIMIT")
    try:
        body=bytearray()
        async with asyncio.timeout(5):
            async for chunk in request.stream():
                if len(chunk)>8192-len(body):raise HTTPException(413,"AUTH_BODY_LIMIT")
                body.extend(chunk)
        value=json.loads(body.decode("utf-8"),object_pairs_hook=pairs)
        if type(value) is not dict or any(type(v) is not str and v is not None for v in value.values()):raise ValueError("shape")
        return auth.LoginPayload.model_validate(value)
    except (ValueError,UnicodeError,ValidationError,RecursionError):raise HTTPException(422,"AUTH_INPUT") from None
    except TimeoutError:raise HTTPException(408,"AUTH_TIMEOUT") from None
    except ClientDisconnect:raise HTTPException(400,"AUTH_INCOMPLETE") from None

def login_checked(value):
    if not enabled():raise HTTPException(404,"AUTH_REVIEW_DISABLED")
    return auth.login_session(value)

def revoke_checked(token,csrf):
    import hashlib
    if not enabled():raise HTTPException(404,"AUTH_REVIEW_DISABLED")
    with auth._auth_cursor() as cur:
        hashed=hashlib.sha256(token.encode("ascii")).hexdigest()
        cur.execute("SELECT jw_dev.v85_auth_check_csrf(%s,%s)",(hashed,csrf))
        if cur.fetchone()!=(True,):raise HTTPException(403,"AUTH_CSRF")
        cur.execute("SELECT jw_dev.v85_auth_revoke_session(%s)",(hashed,))
        if cur.fetchone()!=(True,):raise HTTPException(401,"AUTH_SESSION")

def register(app):
    if not enabled():return False
    v90._origins()
    router=APIRouter(prefix=PREFIX)
    @router.post("/login")
    async def login(request:Request,response:Response):
        check(request)
        # Explicitly require sign-out before replacing an existing cookie.
        if auth.COOKIE in request.cookies:raise HTTPException(409,"AUTH_LOGOUT_REQUIRED")
        value=await payload(request)
        raw,csrf,expiry=await run_in_threadpool(login_checked,value)
        response.set_cookie(auth.COOKIE,raw,secure=True,httponly=True,samesite="strict",path="/")
        response.headers["Cache-Control"]="no-store"
        return {"csrf_token":csrf,"expires_at":expiry,"backend":"isolated_pg_auth"}
    @router.post("/logout")
    async def logout(request:Request,response:Response):
        check(request)
        token=request.cookies.get(auth.COOKIE,"")
        if not re.fullmatch(r"[A-Za-z0-9_-]{30,512}",token):raise HTTPException(401,"AUTH_SESSION")
        csrf=request.headers.getlist("x-csrf-token")
        if len(csrf)!=1 or not 16<=len(csrf[0])<=512 or not csrf[0].isascii():raise HTTPException(403,"AUTH_CSRF")
        await write._empty_body(request)
        await run_in_threadpool(revoke_checked,token,csrf[0])
        response.delete_cookie(auth.COOKIE,path="/",secure=True,httponly=True,samesite="strict")
        response.headers["Cache-Control"]="no-store"
        return {"ok":True}
    app.include_router(router)
    return True
