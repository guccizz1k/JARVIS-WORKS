"""V15.5 HTTP and accessible console regression, synthetic credentials only."""
from contextlib import contextmanager
import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import pg_delivery_review_console_v155 as console
from app.pg_delivery_request_limit_v155 import ReviewBodyLimitV155


@pytest.fixture
def stage(monkeypatch):
    monkeypatch.setattr(console.sessions, "_session_hash", lambda _: "test", raising=False)
    @contextmanager
    def admin(_):
        yield object(), ("jw_app_dev","a"*32,"b"*32,"admin","csrf","Company")
    monkeypatch.setattr(console.sessions, "_pg_validated_cursor", admin, raising=False)
    app=FastAPI()
    assert console.register_v155_review_console(app,lambda:True)
    return TestClient(app), monkeypatch


def test_console_admin_html_csp_a11y_and_safe_js(stage):
    client,_=stage
    r=client.get("/api/pg-stage/v155/review-console")
    assert r.status_code==200
    assert r.headers["cache-control"]=="no-store"
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert 'lang="ko"' in r.text and 'aria-live="polite"' in r.text
    assert 'name="viewport"' in r.text
    assert "승인 대기" in r.text
    js=client.get("/api/pg-stage/v155/review-console.js")
    css=client.get("/api/pg-stage/v155/review-console.css")
    assert js.status_code==200 and css.status_code==200
    assert "innerHTML" not in js.text
    assert "textContent" in js.text
    assert "font-size:17px" in css.text
    assert "@media(max-width:480px)" in css.text


def test_console_same_company_member_denied(stage):
    client,monkeypatch=stage
    @contextmanager
    def member(_):
        yield object(), ("jw_app_dev","a"*32,"b"*32,"member","csrf","Company")
    monkeypatch.setattr(console.sessions,"_pg_validated_cursor",member)
    assert client.get("/api/pg-stage/v155/review-console").status_code==403


async def run_raw_guard(headers,frames):
    seen=[]
    async def inner(scope,receive,send):
        while True:
            frame=await receive()
            if not frame.get("more_body"):break
        await send({"type":"http.response.start","status":204,"headers":[]})
        await send({"type":"http.response.body","body":b""})
    stream=iter(frames)
    async def receive():return next(stream)
    async def send(event):seen.append(event)
    await ReviewBodyLimitV155(inner)(
        {"type":"http","method":"POST",
         "path":"/api/pg-stage/v154/orders/"+("a"*32)+"/delivery-review",
         "headers":headers},receive,send)
    return seen[0]["status"]


def test_actual_streaming_byte_limit_before_json():
    result=asyncio.run(run_raw_guard([],
      [{"type":"http.request","body":b"x"*9000,"more_body":True},
       {"type":"http.request","body":b"y"*9000,"more_body":False}]))
    assert result==413


@pytest.mark.parametrize("value,expected",[
    (b"16385",413),(b"-1",400),(b"abc",400),(b"16384",204)])
def test_request_length_boundary(value,expected):
    result=asyncio.run(run_raw_guard([(b"content-length",value)],
      [{"type":"http.request","body":b"x","more_body":False}]))
    assert result==expected
