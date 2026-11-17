"""Real Chromium/WebKit browser QA against SYNTHETIC local HTTPS CutoverFront.

No real customer account, database, staging deployment, production source or
outside network access. Not a test of the actual V22.2 product UI.
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures"
ARTIFACTS = ROOT / "artifacts" / "v223-a-list-integrity"
LEGACY_COOKIE = "__Host-jw_legacy_v223"
PG_COOKIE = "__Host-jw_pg_v223"
PG_ID = "pg_" + "a" * 32
LEGACY = "L" * 40
PG = "P" * 40
WRONG_PG = "Q" * 40


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_https_server(temp: Path, name: str, cert: Path, key: Path):
    port = free_port()
    origin = f"https://127.0.0.1:{port}"
    log = (temp / f"{name}.log").open("w")
    proc = subprocess.Popen([
        sys.executable, "-m", "uvicorn", f"v223_list_integrity_asgi:{name}_app",
        "--app-dir", str(FIXTURE), "--host", "127.0.0.1", "--port", str(port),
        "--ssl-certfile", str(cert), "--ssl-keyfile", str(key),
        "--no-access-log",
    ], cwd=ROOT, env={
        **os.environ, "JW_ENV": "test", "JW_NO_EXTERNAL_DATABASE": "1",
        "JW_NO_PAID_MODEL_RUNTIME": "1",
    }, stdout=log, stderr=subprocess.STDOUT)
    try:
        context = ssl.create_default_context(cafile=str(cert))
        with httpx.Client(verify=context, trust_env=False, timeout=3) as client:
            for _ in range(100):
                if proc.poll() is not None:
                    raise AssertionError(f"{name} synthetic server terminated")
                try:
                    if client.get(origin + "/").status_code == 200:
                        return proc, log, origin
                except httpx.TransportError:
                    pass
                time.sleep(0.1)
        raise AssertionError(f"{name} synthetic TLS readiness failed")
    except BaseException:
        proc.terminate()
        proc.wait(timeout=8)
        log.close()
        raise


def add_cookies(context, origin, legacy=True, pg=PG):
    cookies = []
    if legacy:
        cookies.append({
            "name": LEGACY_COOKIE, "value": LEGACY, "url": origin,
            "secure": True, "httpOnly": True, "sameSite": "Strict",
        })
    if pg is not None:
        cookies.append({
            "name": PG_COOKIE, "value": pg, "url": origin,
            "secure": True, "httpOnly": True, "sameSite": "Strict",
        })
    context.clear_cookies()
    if cookies:
        context.add_cookies(cookies)


def click_check(page, variant, expected):
    page.locator("#" + variant).click()
    expect(page.locator("#status")).to_have_text(str(expected), timeout=8000)
    result = page.locator("#result").inner_text()
    return json.loads(result)


def run_browser(playwright, engine, viewport, origin, mode):
    browser_type = getattr(playwright, engine)
    browser = browser_type.launch(headless=True)
    try:
        width, height = viewport
        context = browser.new_context(
            viewport={"width": width, "height": height},
            ignore_https_errors=True,
            reduced_motion="reduce",
        )
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        try:
            add_cookies(context, origin)
            response = page.goto(origin + "/", wait_until="domcontentloaded", timeout=25000)
            assert response and response.status == 200
            assert page.locator("h1").inner_text() == "격리된 통합 목록 검증"
            valid = click_check(page, "normal", 200)
            assert valid == [
                {"id": "legacy-1", "amount": 500, "source": "legacy"},
                {"id": PG_ID, "amount": 100, "source": "pg"},
            ]
            duplicated = click_check(page, "duplicate", 503 if mode == "guarded" else 200)
            if mode == "guarded":
                assert duplicated == {"code": "duplicate_merged_list_id"}
                assert "legacy-1" not in page.locator("#result").inner_text()
                assert PG_ID not in page.locator("#result").inner_text()
            else:
                assert len(duplicated) == 3
                assert [r["id"] for r in duplicated].count(PG_ID) == 2

            # Captures are synthetic by design; never present as customer UI.
            path = ARTIFACTS / f"{engine}-{width}-{mode}.png"
            page.screenshot(path=str(path), full_page=True)

            add_cookies(context, origin, legacy=True, pg=WRONG_PG)
            assert click_check(page, "normal", 403) == {"code": "identity_mismatch"}
            add_cookies(context, origin, legacy=True, pg=None)
            assert click_check(page, "normal", 401) == {"code": "reauthentication_required"}
            add_cookies(context, origin, legacy=False, pg=PG)
            assert click_check(page, "normal", 401) == {"code": "reauthentication_required"}
            add_cookies(context, origin, legacy=True, pg=PG)
            assert click_check(page, "normal", 200) == valid
            assert not errors, errors
            print(f"PASS browser={engine} viewport={width}x{height} route={mode} "
                  "normal duplicate denied-identity missing-sessions reauth")
        finally:
            context.close()
    finally:
        browser.close()


def main():
    if os.getenv("JW_ENV") != "test" or os.getenv("JW_NO_EXTERNAL_DATABASE") != "1":
        raise RuntimeError("BLOCKED: synthetic-only browser test requires isolated flags")
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="jw-list-qa-") as temp_dir:
        temp = Path(temp_dir)
        key, cert = temp / "server.key", temp / "server.crt"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256",
            "-days", "1", "-nodes", "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-keyout", str(key), "-out", str(cert),
        ], check=True, capture_output=True)
        key.chmod(0o600)
        servers = []
        try:
            for name in ("guarded", "original"):
                servers.append(start_https_server(temp, name, cert, key))
            with sync_playwright() as p:
                for engine in ("chromium", "webkit"):
                    for viewport in ((1440, 900), (390, 844)):
                        for (_, _, origin), mode in zip(servers, ("guarded", "original")):
                            run_browser(p, engine, viewport, origin, mode)
            print("PASS 8 real-browser HTTPS scenarios (4 viewport/engine combinations "
                  "x guarded and original) with synthetic store cookies")
        finally:
            for proc, log, _origin in servers:
                if proc.poll() is None:
                    proc.terminate()
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=8)
                log.close()


if __name__ == "__main__":
    main()
