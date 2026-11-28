"""Review-only route factory for the existing authenticated draft API.
The receipt pin is a selector checked against the independently persisted DB record.
No write/publisher operation, no production registration, no legal or payment approval.
"""
import asyncio,json,re,os
from fastapi import APIRouter, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect
from pg_receipt_adapter import read_review
from review_gates import Blocked,digest

MAX_BODY=32768
HEADERS={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}

def enabled():
    return (os.getenv('NARUV_RECEIPT_API_CI')=='DISPOSABLE_FIXTURE_ONLY'
        and os.getenv('GITHUB_ACTIONS')=='true' and os.getenv('JW_PG_CI_ALLOW')=='ONLY_EPHEMERAL_LOCAL_DATABASE'
        and os.getenv('JW_ENV','').lower() in ('dev','development','test'))

def reject(code,detail):
    raise HTTPException(code,detail,headers=HEADERS)

def pairs(items):
    result={}
    for k,v in items:
        if k in result:raise ValueError('duplicate')
        result[k]=v
    return result

def constant(_):raise ValueError('constant')

async def body(request):
    data=bytearray()
    try:
        async with asyncio.timeout(5):
            async for chunk in request.stream():
                if len(data)+len(chunk)>MAX_BODY:reject(413,'RECEIPT_BODY_LIMIT')
                data.extend(chunk)
    except TimeoutError:reject(408,'RECEIPT_BODY_TIMEOUT')
    except ClientDisconnect:reject(400,'RECEIPT_BODY_INCOMPLETE')
    try:
        x=json.loads(data.decode('utf-8'),object_pairs_hook=pairs,parse_constant=constant)
        if type(x) is not dict or set(x)!={'confirmation_pin','receipt_pin','draft'} or not all(digest(x[k]) for k in ('confirmation_pin','receipt_pin')) or type(x['draft']) is not dict:raise ValueError('shape')
        return x
    except (ValueError,UnicodeError,RecursionError):reject(422,'RECEIPT_INPUT')

def create_router(*,prefix,original_enabled,request_scope,auth,header,validated_cursor,verify_identity,verifier,db_error_type,db_error):
    router=APIRouter(prefix=prefix)
    def review(token,csrf,prior,worker,period,data):
        if not enabled() or not original_enabled():reject(404,'RECEIPT_DISABLED')
        try:
            with validated_cursor(token) as (cur,identity):
                actor,org=verify_identity(identity,csrf)
                if (actor,org)!=prior:reject(409,'SESSION_SCOPE_CHANGED')
                cur.execute("SET LOCAL statement_timeout='8s'")
                cur.execute("SET LOCAL lock_timeout='4s'")
                return read_review(cur,tenant=org,worker=worker,period=period,confirmation_pin=data['confirmation_pin'],receipt_pin=data['receipt_pin'],csrf=csrf,draft=data['draft'],verifier=verifier)
        except db_error_type as exc:
            reason=getattr(getattr(exc,'diag',None),'message_primary','')
            # New RPC codes do not exist in the predecessor's error map.
            if reason=='HR_NOT_FOUND':reject(404,'RECEIPT_REVIEW_UNAVAILABLE')
            if reason in ('HR_EVIDENCE_NOT_FOUND_OR_CHANGED','HR_EVIDENCE_CONFIRMATION','HR_CONFLICT'):reject(409,'RECEIPT_EVIDENCE_MISMATCH')
            if reason=='HR_EVIDENCE_INPUT':reject(422,'RECEIPT_INPUT')
            mapped=db_error(exc)
            # Do not leak DB messages or tenant existence. Preserve only safe status classes.
            status=getattr(mapped,'status_code',503)
            reject(status if status in (401,403,404,409,422,503) else 503,'RECEIPT_REVIEW_UNAVAILABLE')
        except (Blocked,ValueError):reject(409,'RECEIPT_EVIDENCE_MISMATCH')
    @router.post('/payroll/{worker}/{period}/receipt-review')
    async def receipt_review(worker:str,period:str,request:Request,response:Response):
        try:
            if not enabled() or not original_enabled():reject(404,'RECEIPT_DISABLED')
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',worker) or not re.fullmatch(r'2026-(0[1-9]|1[0-2])',period):reject(422,'RECEIPT_INPUT')
            token,csrf,_=request_scope(request,worker,period,needs_digest=False)
            if header(request,'content-type','')!='application/json':reject(415,'RECEIPT_CONTENT_TYPE')
            prior=await run_in_threadpool(auth,token,csrf)
            data=await body(request)
            r=await run_in_threadpool(review,token,csrf,prior,worker,period,data)
            response.headers.update(HEADERS)
            return r
        except HTTPException as e:
            raise HTTPException(e.status_code,e.detail,headers={**(e.headers or {}),**HEADERS}) from None
    return router

def register_review(app,*,drafts,write,preview,v90):
    """Explicit integration point for a future isolated PG17 test app only."""
    if not enabled() or not drafts.kr_enabled():return False
    import psycopg
    from app.naruv_kr_payroll_review import verify_fixed_week_statement_source_2026
    v90._origins()
    app.include_router(create_router(prefix=drafts.PREFIX,original_enabled=drafts.kr_enabled,request_scope=write._request,auth=write._auth,header=preview._one_header,validated_cursor=v90._pg_validated_cursor,verify_identity=preview._verify_identity,verifier=verify_fixed_week_statement_source_2026,db_error_type=psycopg.Error,db_error=write._db_error))
    return True
