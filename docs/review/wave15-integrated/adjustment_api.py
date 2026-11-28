"""Opt-in read-only adjustment API, lab factory only. No production registration.
Pin resolver is trusted server-side evidence; request never supplies a pin or draft.
Existing authenticated scope, CSRF, and restricted DB cursor callbacks are required.
"""
import re,os
from fastapi import APIRouter,HTTPException,Request,Response
from fastapi.responses import HTMLResponse
from starlette.concurrency import run_in_threadpool
from review_gates import Blocked,digest
from postconfirm_adjustment import read_proposal
from adjustment_view import render
HEADERS={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'"}
ID=r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}'
def enabled():return os.getenv('NARUV_ADJUSTMENT_API_CI')=='DISPOSABLE_FIXTURE_ONLY' and os.getenv('GITHUB_ACTIONS')=='true' and os.getenv('JW_PG_CI_ALLOW')=='ONLY_EPHEMERAL_LOCAL_DATABASE' and os.getenv('JW_ENV','').lower() in ('dev','development','test')
def reject(code,detail):raise HTTPException(code,detail,headers=HEADERS)
def create_router(*,prefix,original_enabled,request_scope,auth,validated_cursor,verify_identity,resolve_pin,db_error_type,db_error):
    router=APIRouter(prefix=prefix)
    def read(token,csrf,prior,worker,period,rid):
        if not enabled() or not original_enabled():reject(404,'ADJUSTMENT_DISABLED')
        try:
            with validated_cursor(token) as (cur,identity):
                actor,org=verify_identity(identity,csrf)
                if (actor,org)!=prior:reject(409,'SESSION_SCOPE_CHANGED')
                cur.execute("SET LOCAL statement_timeout='8s'");cur.execute("SET LOCAL lock_timeout='4s'")
                pin=resolve_pin(tenant=org,worker=worker,period=period,request_id=rid)
                if not digest(pin):reject(404,'ADJUSTMENT_UNAVAILABLE')
                return render(read_proposal(cur,tenant=org,worker=worker,period=period,request_id=rid,proposal_pin=pin,csrf=csrf))
        except db_error_type as e:
            reason=getattr(getattr(e,'diag',None),'message_primary','')
            if reason in ('ADJUSTMENT_NOT_FOUND','HR_NOT_FOUND'):reject(404,'ADJUSTMENT_UNAVAILABLE')
            if reason in ('ADJUSTMENT_SOURCE','HR_EVIDENCE_NOT_FOUND_OR_CHANGED','HR_CONFLICT'):reject(409,'ADJUSTMENT_EVIDENCE_MISMATCH')
            status=getattr(db_error(e),'status_code',503)
            reject(status if status in (401,403,404,409,422,503) else 503,'ADJUSTMENT_UNAVAILABLE')
        except (Blocked,ValueError):reject(409,'ADJUSTMENT_EVIDENCE_MISMATCH')
    @router.post('/payroll/{worker}/{period}/adjustment/{request_id}/review',response_class=HTMLResponse)
    async def review(worker:str,period:str,request_id:str,request:Request):
        try:
            if not enabled() or not original_enabled():reject(404,'ADJUSTMENT_DISABLED')
            if not all(re.fullmatch(ID,x) for x in (worker,request_id)) or not re.fullmatch(r'2026-(0[1-9]|1[0-2])',period) or request.url.query:reject(422,'ADJUSTMENT_INPUT')
            token,csrf,_=request_scope(request,worker,period,needs_digest=False)
            prior=await run_in_threadpool(auth,token,csrf)
            # Empty body only. Reject the first nonempty chunk, bound idle streaming time.
            import asyncio
            from starlette.requests import ClientDisconnect
            try:
                async with asyncio.timeout(5):
                    async for chunk in request.stream():
                        if chunk:reject(422,'ADJUSTMENT_BODY_NOT_ALLOWED')
            except TimeoutError:reject(408,'ADJUSTMENT_BODY_TIMEOUT')
            except ClientDisconnect:reject(400,'ADJUSTMENT_BODY_INCOMPLETE')
            html=await run_in_threadpool(read,token,csrf,prior,worker,period,request_id)
            return HTMLResponse(html,headers=HEADERS)
        except HTTPException as e:raise HTTPException(e.status_code,e.detail,headers={**(e.headers or {}),**HEADERS}) from None
    return router
