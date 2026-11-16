"""Isolated V22.3 owner review adapter with a separate ASGI entrypoint.

Never replaces app.main:app. Existing 530+ baseline and schema guards remain
unaltered. Only the explicit review runtime installs additive account tables.
"""
from contextlib import asynccontextmanager
import os
import re
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from . import main as core
from .owner_review_public_qa_guard_v223 import check_public_qa_runtime, public_qa_middleware
from .owner_settings_v223 import install_schema, register_routes
from .owner_customer_cas_v223 import register_routes as register_customer_review_routes
from .owner_quote_cas_v223 import register_routes as register_quote_review_routes
from .owner_order_review_v223 import register_routes as register_order_review_routes


@asynccontextmanager
async def owner_review_lifespan(_app):
    # Before any database schema initialization, validate public QA isolation.
    check_public_qa_runtime()
    if not (os.environ.get('JW_ENV', '').lower() in ('review', 'test')
            and os.environ.get('JW_ROOT_UI') == 'owner-visual-review'
            and os.environ.get('JW_APPROVED_UI_REVIEW') == 'ISOLATED_REVIEW_ONLY'):
        raise RuntimeError('Owner account extension requires isolated explicit review mode')
    # The legacy application still owns its exact original schema and lifecycle.
    async with core.app.router.lifespan_context(core.app):
        # Only the isolated review application's database receives optional rows.
        install_schema(core.conn)
        yield


app = FastAPI(title='JARVIS WORKS isolated owner review', docs_url=None,
              redoc_url=None, openapi_url=None, lifespan=owner_review_lifespan)

# Applies to all mounted core and owner routes; other middleware may run first.
# No effect without JW_PUBLIC_QA_MODE=1.
app.middleware('http')(public_qa_middleware)


@app.middleware('http')
async def account_security_headers(request: Request, call_next):
    account = (request.url.path.startswith('/api/account/') or
               request.url.path.startswith('/api/review/quotes/') or
               request.url.path.startswith('/api/review/orders/') or
               (request.url.path.startswith('/api/review/customers/') and
                request.url.path.endswith('/update')))
    scoped_review_read = request.url.path == '/api/automation/statements'
    if account and request.method not in ('GET', 'HEAD', 'OPTIONS'):
        if request.headers.get('Sec-Fetch-Site') == 'cross-site':
            return JSONResponse(status_code=403, content={'detail':'외부 요청이 차단됐습니다'})
        origin=request.headers.get('Origin')
        if origin and origin != str(request.base_url).rstrip('/'):
            return JSONResponse(status_code=403,content={'detail':'요청 출처가 일치하지 않습니다'})
    response=await call_next(request)
    if account or scoped_review_read:
        response.headers['Cache-Control']='no-store'
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['Referrer-Policy']='no-referrer'
        response.headers['X-Frame-Options']='DENY'
        response.headers['Content-Security-Policy']=(
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        if request.url.scheme=='https':
            response.headers['Strict-Transport-Security']='max-age=31536000'
    return response


register_routes(app, current_user=core.current_user, conn=core.conn,
                transaction=core.transaction, now=core.now,
                audit=core.audit, fail=core.fail)
register_customer_review_routes(app)
register_quote_review_routes(app)
register_order_review_routes(app)

# A mounted sub-application keeps every original business route and middleware
# unchanged while the four account routes above take precedence.
class ReviewStaffRoleUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    expected_role: Literal['admin','member']
    target_role: Literal['admin','member']
    admin_password: str = Field(min_length=1,max_length=1000)


@app.post('/api/account/staff/{target_id}/role')
def review_staff_role_update(target_id: str, body: ReviewStaffRoleUpdate,
                             user=Depends(core.current_user)):
    # High-impact review-only action. Existing roles, password algorithm,
    # CSRF checks, audit trail, and tenant constraints remain authoritative.
    core.need_admin(user)
    if not re.fullmatch(r'[a-f0-9]{32}',target_id) or target_id==user['id']:
        core.fail('자기 계정 또는 잘못된 직원 ID는 변경할 수 없습니다',409)
    with core.transaction() as db:
        admin=db.execute('SELECT password_hash FROM users WHERE id=? AND org_id=?',
                         (user['id'],user['org_id'])).fetchone()
        if not admin or not core.verify_password(body.admin_password,admin['password_hash']):
            core.fail('관리자 재인증에 실패했습니다',403)
        target=db.execute("""SELECT u.id,u.role,d.disabled_at FROM users u
            LEFT JOIN staff_disabled d ON d.user_id=u.id
            WHERE u.id=? AND u.org_id=?""",(target_id,user['org_id'])).fetchone()
        if target is None:
            core.fail('직원을 찾을 수 없습니다',404)
        if target['disabled_at'] is not None:
            core.fail('비활성 직원은 역할을 변경할 수 없습니다',409)
        if target['role']!=body.expected_role:
            core.fail('직원 역할이 변경됐습니다. 다시 조회하세요',409)
        if target['role']==body.target_role:
            return {'ok':True,'user_id':target_id,'role':target['role'],
                    'sessions_revoked':False}
        if target['role']=='admin' and body.target_role=='member':
            active=db.execute("""SELECT COUNT(*) FROM users u
                LEFT JOIN staff_disabled d ON d.user_id=u.id
                WHERE u.org_id=? AND u.role='admin' AND d.user_id IS NULL""",
                (user['org_id'],)).fetchone()[0]
            if active<=1:
                core.fail('마지막 활성 관리자는 변경할 수 없습니다',409)
        updated=db.execute('UPDATE users SET role=? WHERE id=? AND org_id=?',
                           (body.target_role,target_id,user['org_id'])).rowcount
        if updated!=1:
            core.fail('직원을 찾을 수 없습니다',404)
        db.execute('DELETE FROM sessions WHERE user_id=?',(target_id,))
        core.audit(db,user,'security_role',target_id,'role_changed',
                   {'before':target['role'],'after':body.target_role})
    return {'ok':True,'user_id':target_id,'role':body.target_role,
            'sessions_revoked':True}


@app.get('/api/automation/statements')
def list_owner_review_statements(user=Depends(core.current_user)):
    # Protected, immutable trade documents: explicit tenant filter and bounded read.
    with core.conn() as db:
        rows=db.execute("""SELECT id,org_id,order_id,doc_no,created_at
            FROM automation_statements_v60 WHERE org_id=?
            ORDER BY created_at DESC,id DESC LIMIT 100""",(user['org_id'],)).fetchall()
    return [dict(x) for x in rows]


app.mount('/', core.app)
