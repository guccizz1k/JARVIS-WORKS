"""Externally observed, credential-free Render HTTPS black-box security acceptance.

Runs in a fresh GitHub-hosted Ubuntu runner, not in Render's own network.
Never obtains, logs or submits real stage keys, passwords or customer data.
A green pass establishes HTTPS ingress confidentiality and DENIAL ONLY;
it is NOT an authenticated session, role, financial posting or bank E2E proof.
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx
from playwright.sync_api import sync_playwright

BASE = "https://jw-stage1-secure-20261030.onrender.com"
VERSION = "V16.4"
ENDPOINTS = [
    "/", "/docs", "/redoc", "/openapi.json",
    "/api/pg-stage/v84/me", "/api/pg-stage/v84/customers",
    "/api/pg-stage/v84/quotes", "/api/pg-stage/v85/login",
    "/api/pg-stage/v90/me", "/api/pg-stage/v90/companies",
    "/api/pg-stage/v90/chats/aaaa/attachments/bbbb",
    "/api/pg-stage/v92/quotes", "/api/pg-stage/v92/order-drafts",
    "/api/pg-stage/v93/quotes",
    "/api/pg-stage/v145/orders/"+"c"*32+"/invoice-preview",
    "/api/pg-stage/v154/orders/"+"c"*32+"/delivery-review",
    "/api/pg-stage/v155/review-console",
    "/api/pg-stage/v158/quotes/"+"a"*32+"/lineage",
    "/api/pg-stage/v160/imports/"+"a"*32+"/quote-draft",
    "/api/pg-stage/v161/invoices/"+"a"*32+"/balance-preview",
    "/evil", "/.env", "/admin", "/static/../../.env",
]
assert len(ENDPOINTS) >= 20

def assert_denied(response,endpoint):
    assert response.status_code == 403, (endpoint,response.status_code)
    assert response.headers.get("content-type","").startswith("application/json"),endpoint
    assert response.json() == {"detail":"Staging access denied"},endpoint
    assert "no-store" in response.headers.get("cache-control",""),endpoint
    assert not response.headers.get("location"),endpoint

def main():
    with httpx.Client(timeout=httpx.Timeout(35.0),follow_redirects=False,
                      verify=True,trust_env=False) as c:
        probe=c.get(BASE+"/healthz")
        assert probe.status_code==200,(probe.status_code,probe.text[:220])
        obj=probe.json()
        assert obj.get("release")=="BLOCKED",obj
        assert obj.get("mode")=="isolated_pg_api_only",obj
        assert probe.url.scheme=="https"
        assert not probe.history

        for path in ENDPOINTS:
            assert_denied(c.get(BASE+path),path)
            # Forged but sufficiently long key must NOT bypass the shared gate.
            assert_denied(c.get(BASE+path,
                headers={"X-JW-Stage-Key":"0"*96}),path+" bad-key")
        for path in ("/api/pg-stage/v85/login",
                     "/api/pg-stage/v92/quotes",
                     "/api/pg-stage/v154/orders/"+"c"*32+"/delivery-review"):
            assert_denied(c.post(BASE+path,json={
                "email":"nobody@invalid.test",
                "password":"deliberately-not-a-valid-password"}),
                path+" POST")
        print("PASS_V165_TRUSTED_PUBLIC_HTTPS_HEALTH_PG_MODE_NO_RELEASE",flush=True)
        print("PASS_V165_"+str(len(ENDPOINTS))+
              "_ENDPOINTS_PUBLIC_AND_FORGED_KEYS_REJECTED",flush=True)

    out=Path("artifacts/v165")
    out.mkdir(parents=True,exist_ok=True)
    with sync_playwright() as pw:
        browser=pw.chromium.launch(headless=True,args=["--no-sandbox"])
        try:
            for width in (320,390,768,1280):
                context=browser.new_context(
                    viewport={"width":width,"height":850},
                    ignore_https_errors=False)
                page=context.new_page()
                health=page.goto(BASE+"/healthz",
                    wait_until="networkidle",timeout=45000)
                assert health and health.status==200,(width,health.status if health else None)
                assert '"isolated_pg_api_only"' in page.locator("body").inner_text()
                blocked=page.goto(BASE+"/api/pg-stage/v155/review-console",
                    wait_until="networkidle",timeout=45000)
                assert blocked and blocked.status==403,width
                assert "Staging access denied" in page.locator("body").inner_text()
                if width==390:
                    page.screenshot(path=str(out/"hosted-public-gate-390.png"))
                context.close()
        finally:
            browser.close()
    print("PASS_V165_CHROMIUM_4_VIEWPORTS_REAL_RENDER_TLS_AND_PUBLIC_GATE",flush=True)
    print("LIMIT_V165_NO_PRIVATE_STAGE_KEY_NO_AUTHENTICATED_BROWSER_E2E",flush=True)

if __name__=="__main__":
    main()
