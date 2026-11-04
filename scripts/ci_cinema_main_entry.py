"""Real isolated FastAPI + Chromium gate for unchanged CINEMA main-route."""
from __future__ import annotations
import os
import re
import tempfile
import urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright
from scripts.ci_v213_real_auth_ui_browser import isolated_server
from scripts.ci_v202_bento_browser import ROOT


def run():
    assert os.environ.get('JW_ENV') == 'review'
    original = (ROOT / 'app/static/cinema/JARVIS_WORKS_CINEMA.html').read_text()
    proc = log = None
    with tempfile.TemporaryDirectory(prefix='cinema-main-e2e-') as tmp:
        proc, log, url = isolated_server(tmp)
        try:
            with urllib.request.urlopen(url + '/') as r:
                assert r.status == 200
                html = r.read().decode()
                assert 'sha256-' in r.headers['Content-Security-Policy']
                assert r.headers['X-Frame-Options'] == 'DENY'
                assert r.headers['Cache-Control'] == 'no-store'
            assert re.search(r'<style>(.*?)</style>', html, re.S).group(1) == re.search(r'<style>(.*?)</style>', original, re.S).group(1)
            assert 'async function cinemaBoot()' in html
            assert 'canvas id="gl"' in html
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True,args=['--no-sandbox','--use-gl=angle','--use-angle=swiftshader','--enable-unsafe-swiftshader'])
                try:
                    ctx = browser.new_context(viewport={'width':1440,'height':900})
                    page = ctx.new_page()
                    failures = []
                    page.on('pageerror', lambda e: failures.append(str(e)))
                    page.goto(url + '/', wait_until='domcontentloaded')
                    page.locator('#login:not([hidden]) input[type="email"]').wait_for(state='visible',timeout=25000)
                    assert page.locator('#gl').count() == 1
                    assert page.evaluate("() => fetch('/api/me').then(x=>x.status)") == 401
                    page.evaluate("localStorage.setItem('jw3.db', JSON.stringify({company:{name:'FAKE'},users:[{role:'admin'}]}))")
                    page.reload()
                    page.locator('#login:not([hidden]) input[type="email"]').wait_for(state='visible',timeout=25000)
                    page.locator('#login input[type=email]').fill('demo@hanbit.example')
                    page.locator('#login input[type=password]').fill('Demo!2026secure')
                    page.locator('#login button[type=submit]').click()
                    page.locator('#app.on').wait_for(state='visible',timeout=35000)
                    user=page.evaluate("async()=>{const r=await fetch('/api/me');return r.ok?await r.json():null}")
                    assert user and user['org_id'] and user['email']=='demo@hanbit.example', user
                    assert page.evaluate("async()=>{const r=await fetch('/api/customers');return r.status}")==200
                    assert page.evaluate("async()=>{const r=await fetch('/api/logout',{method:'POST'});return r.status}")==403
                    assert page.evaluate("async()=>{const r=await fetch('/api/me');return r.status}")==200
                    assert page.locator('canvas#gl').count()==1
                    assert page.locator('#app').is_visible()
                    assert not failures,failures
                    print('PASS: original visuals, real server login, no local auth bypass, real API, CSRF, CINEMA shell')
                    ctx.close()
                finally:
                    browser.close()
        finally:
            if proc is not None:
                proc.terminate()
                try: proc.wait(timeout=10)
                except Exception: proc.kill()
            if log is not None: log.close()


if __name__ == '__main__': run()
