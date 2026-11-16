"""Fail-closed perimeter for a separately approved PUBLIC Render review service.

The only supported public mode uses generated dummy SQLite and an additional
HTTPS Basic authentication barrier; no production data, Supabase DSNs or keys.
It is opt-in and never changes normal local review or the original core app.
Passwords are passed only via service-local environment and never logged.
"""
from __future__ import annotations

import base64
import binascii
import hmac
import os
import re

from fastapi import Request
from fastapi.responses import JSONResponse


class PublicQAGateError(RuntimeError):
    pass


def public_qa_enabled(env=None):
    env=os.environ if env is None else env
    marker=env.get('JW_PUBLIC_QA_MODE','')
    if marker and marker!='1':
        raise PublicQAGateError('BLOCKED_PUBLIC_QA_UNRECOGNIZED_MODE')
    return marker=='1'


def check_public_qa_runtime(env=None):
    env=os.environ if env is None else env
    if not public_qa_enabled(env):
        return False
    required={
        'JW_ENV':'review',
        'JW_ROOT_UI':'owner-visual-review',
        'JW_APPROVED_UI_REVIEW':'ISOLATED_REVIEW_ONLY',
        'JW_NO_EXTERNAL_DATABASE':'1',
        'DEMO_SEED':'1',
    }
    if any(env.get(k)!=v for k,v in required.items()):
        raise PublicQAGateError('BLOCKED_PUBLIC_QA_RUNTIME_NOT_ISOLATED')
    db_path=env.get('JARVIS_DB_PATH','')
    if not re.fullmatch(r'/tmp/jw-v223-qa-[a-z0-9_-]{6,48}\.sqlite3',db_path):
        raise PublicQAGateError('BLOCKED_PUBLIC_QA_DB_MUST_BE_DISPOSABLE')
    for k in ('DATABASE_URL','JW_PG_STAGE_DSN','JW_PG_SOURCE_DSN',
              'JW_PG_TARGET_ADMIN_DSN','SUPABASE_SERVICE_ROLE_KEY',
              'JW_PG_BACKUP_KEY','JW_PG_BACKUP_RO_PASSWORD'):
        if env.get(k):
            raise PublicQAGateError('BLOCKED_PUBLIC_QA_EXTERNAL_CREDENTIALS_PRESENT')
    user=env.get('JW_REVIEW_BASIC_USER','')
    password=env.get('JW_REVIEW_BASIC_PASSWORD','')
    if not re.fullmatch(r'[A-Za-z0-9_-]{4,40}',user):
        raise PublicQAGateError('BLOCKED_PUBLIC_QA_BASIC_USERNAME_REQUIRED')
    if not 24<=len(password)<=256 or password=='Demo!2026secure':
        raise PublicQAGateError('BLOCKED_PUBLIC_QA_STRONG_PASSWORD_REQUIRED')
    return True


def authorized_basic(value:str, username:str, password:str)->bool:
    if not isinstance(value,str) or len(value)>600 or not value.startswith('Basic '):
        return False
    try:
        raw=base64.b64decode(value[6:],validate=True)
        if len(raw)>300 or b':' not in raw:
            return False
        subject,provided=raw.split(b':',1)
        want_user=username.encode('ascii')
        want_password=password.encode('utf-8')
    except (ValueError,UnicodeError,binascii.Error):
        return False
    return hmac.compare_digest(subject,want_user) and hmac.compare_digest(provided,want_password)


async def public_qa_middleware(request:Request,call_next):
    if not public_qa_enabled():
        return await call_next(request)
    # Fail closed on missing/misconfigured deployment environment, before DB/API.
    try:
        check_public_qa_runtime()
    except PublicQAGateError:
        return JSONResponse(status_code=503,
          content={'detail':'QA 서비스 설정 검증 전입니다'},
          headers={'Cache-Control':'no-store'})
    if request.url.path=='/api/health' and request.method in ('GET','HEAD'):
        return await call_next(request)
    if not authorized_basic(request.headers.get('Authorization',''),
                            os.environ['JW_REVIEW_BASIC_USER'],
                            os.environ['JW_REVIEW_BASIC_PASSWORD']):
        return JSONResponse(status_code=401,
          content={'detail':'검토 서비스 접근 인증이 필요합니다'},
          headers={
            'WWW-Authenticate':'Basic realm="JARVIS-WORKS isolated review", charset="UTF-8"',
            'Cache-Control':'no-store',
            'X-Content-Type-Options':'nosniff',
            'Vary':'Authorization',
          })
    resp=await call_next(request)
    resp.headers['Cache-Control']='no-store'
    resp.headers['Vary']='Authorization'
    return resp
