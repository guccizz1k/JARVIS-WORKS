"""Strict review-preview perimeter: synthetic only, no external DB, no open HTTP."""
from __future__ import annotations
import asyncio
import base64
import importlib.util
import os
from pathlib import Path
import pytest

SRC=Path(__file__).resolve().parents[1] / "scripts" / "ci_cinema_pg_v222_stage_preview.py"

def module():
    spec=importlib.util.spec_from_file_location("preview_local_test",SRC)
    m=importlib.util.module_from_spec(spec)
    cfg=dict(os.environ)
    cfg.update({"JW_ENV":"review","JW_ROOT_UI":"v222","DEMO_SEED":"1",
                "JARVIS_DB_PATH":"/tmp/jw_v222_test_preview.sqlite",
                "JW_PREVIEW_SECRET":"superlong-test-secret-only-0000000000000000000"})
    for key in ("DATABASE_URL","JW_PG_STAGE_DSN","JW_PG_CI_ROOT_DSN",
                "JW_PG_CI_RESTORE_DSN","SUPABASE_DSN","SUPABASE_DB_URL",
                "SUPABASE_SERVICE_ROLE_KEY","PGHOST","PGUSER",
                "BOOTSTRAP_EMAIL","BOOTSTRAP_PASSWORD"):
        cfg.pop(key,None)
    old=os.environ.copy()
    try:
        os.environ.clear();os.environ.update(cfg)
        spec.loader.exec_module(m)
    finally:
        os.environ.clear();os.environ.update(old)
    return m,cfg

@pytest.fixture(scope="module")
def preview():
    return module()

@pytest.mark.parametrize("field,value",[
    ("JW_ENV","production"),("JW_ENV","dev"),("JW_ROOT_UI","cinema"),
    ("DEMO_SEED","0"),("JARVIS_DB_PATH","/mnt/unsafe/customer.db"),
    ("JARVIS_DB_PATH","/tmp/jw_unsafe.txt"),("JW_PREVIEW_SECRET","weak"),
    ("DATABASE_URL","postgresql://live"),("JW_PG_STAGE_DSN","postgres://live"),
    ("JW_PG_CI_ROOT_DSN","postgres://live"),("SUPABASE_DSN","postgres://live"),
    ("PGHOST","db.internal"),("PGUSER","postgres"),
    ("SUPABASE_SERVICE_ROLE_KEY","unsafe"),
])
def test_fail_closed_for_invalid_runtime(preview,field,value):
    m,cfg=preview
    bad={**cfg,field:value}
    with pytest.raises(RuntimeError,match="PREVIEW_BLOCKED"):
        m.validate_sandbox(bad)

def test_accept_only_fresh_synthetic_review_configuration(preview):
    m,cfg=preview
    assert m.validate_sandbox(cfg)==cfg["JW_PREVIEW_SECRET"]
    assert m.app.inner is m._original_app

def test_unauthenticated_http_rejected_and_strong_auth_passed(preview):
    m,cfg=preview
    async def fake(scope,receive,send):
        await send({"type":"http.response.start","status":204,"headers":[]})
        await send({"type":"http.response.body","body":b""})
    wrapper=m.PreviewAccess(fake,cfg["JW_PREVIEW_SECRET"])
    async def check(headers):
        out=[]
        async def send(msg): out.append(msg)
        await wrapper({"type":"http","headers":headers},lambda:None,send)
        return out
    denied=asyncio.run(check([]))
    assert denied[0]["status"]==401
    assert any(k==b"www-authenticate" for k,v in denied[0]["headers"])
    token=base64.b64encode(("review:"+cfg["JW_PREVIEW_SECRET"]).encode())
    allowed=asyncio.run(check([(b"authorization",b"Basic "+token)]))
    assert allowed[0]["status"]==204
    assert (b"x-robots-tag",b"noindex, nofollow, noarchive") in allowed[0]["headers"]

def test_unauthenticated_websocket_rejected(preview):
    m,cfg=preview
    async def fake(scope,receive,send):
        raise AssertionError("Unauthorized websocket must not reach app")
    wrapper=m.PreviewAccess(fake,cfg["JW_PREVIEW_SECRET"])
    out=[]
    async def run():
        async def send(msg):out.append(msg)
        await wrapper({"type":"websocket","headers":[]},lambda:None,send)
    asyncio.run(run())
    assert out==[{"type":"websocket.close","code":1008}]
