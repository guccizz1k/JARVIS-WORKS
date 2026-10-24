"""Real HTTP + Chromium smoke via Microsoft's Playwright CLI (J1–J5 additive).

Use ONLY an ephemeral loopback FastAPI DEMO_SEED=1 server. No production URL or
real customer login is accepted. Covers login, isolated organizations, dashboard
and responsive viewport. This does not exercise PostgreSQL staging.
"""
from __future__ import annotations
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request

BASE = "http://127.0.0.1:8765"
ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "artifacts/playwright-cli"

def cli(*args: str, timeout: int = 80) -> str:
    result = subprocess.run(["playwright-cli", *args], cwd=ROOT,
                            text=True, capture_output=True, timeout=timeout,
                            env=os.environ.copy())
    if result.returncode != 0:
        raise RuntimeError(f"playwright-cli {args[0]} failed ({result.returncode}): "
                           + (result.stderr or result.stdout)[-1000:])
    return result.stdout

def assertion(script: str, proof: str, timeout: int = 80) -> str:
    output = cli("eval", script, timeout=timeout)
    if proof not in output:
        raise AssertionError(f"Playwright assertion missing {proof!r}: {output[-900:]}")
    return output

def wait_http() -> None:
    for _ in range(70):
        try:
            with urllib.request.urlopen(BASE + "/api/health", timeout=2) as response:
                if response.status == 200:
                    return
        except Exception:
            time.sleep(0.2)
    raise RuntimeError("Local-only FastAPI demo did not respond to /api/health")

def login(email: str, label: str) -> str:
    # CLI eval interacts with the real DOM and waits for the real HTTP/API result.
    script = """async () => {
      const input = (name, value) => {
        const node = document.querySelector('#login-form [name='+name+']');
        if (!node) throw new Error('Missing login field '+name);
        node.value = value;
        node.dispatchEvent(new Event('input',{bubbles:true}));
      };
      input('email', '__EMAIL__');
      input('password', 'Demo!2026secure');
      document.querySelector('#login-form').requestSubmit();
      for (let i=0; i<100; i++) {
        const visible = !document.querySelector('#app-shell')?.classList.contains('hidden');
        if (visible) {
          const r = await fetch('/api/me', {credentials:'same-origin'});
          if (!r.ok) throw new Error('Browser session failed HTTP '+r.status);
          const user=await r.json();
          if (!user.org_id || !user.org_name) throw new Error('Org ID absent');
          return '__LABEL__:' + user.org_id;
        }
        await new Promise(resolve => setTimeout(resolve,100));
      }
      throw new Error('Real demo login did not complete');
    }""".replace("__EMAIL__", email).replace("__LABEL__", label)
    output = assertion(script,label+":",timeout=90)
    match = re.search(re.escape(label)+r":([0-9a-zA-Z_-]+)",output)
    if not match:
        raise AssertionError("Cannot parse verified synthetic tenant ID")
    return match.group(1)

def main() -> int:
    if os.getenv("JW_BROWSER_CI_ONLY") != "ISOLATED_LOOPBACK_DEMO":
        raise RuntimeError("Refusing browser test outside explicitly isolated demo")
    if os.getenv("JW_INSECURE_LOCAL_DEV") != "1" or os.getenv("DEMO_SEED") != "1":
        raise RuntimeError("Synthetic local demo flags required")
    if os.getenv("JW_ENV","").lower() in {"prod","production"}:
        raise RuntimeError("Production URL/credentials prohibited")
    wait_http()
    PROOF.mkdir(parents=True,exist_ok=True)
    opened=False
    try:
        cli("open",BASE)
        opened=True
        assertion("() => {if (location.origin !== 'http://127.0.0.1:8765' || !document.querySelector('#login-form')) throw new Error('Unexpected web origin or missing login DOM'); return 'JW_HTTP_LOGIN_RENDER_PASS'}","JW_HTTP_LOGIN_RENDER_PASS")
        a = login("demo@hanbit.example","JW_TENANT_A")
        assertion("""async () => {
          document.querySelector('nav [data-page="dashboard"]').click();
          for(let i=0;i<60;i++) {
            if(document.body.innerText.includes('업무 대시보드')) return 'JW_DASHBOARD_PASS';
            await new Promise(r=>setTimeout(r,100));
          }
          throw new Error('Dashboard not rendered');
        }""","JW_DASHBOARD_PASS")
        cli("screenshot",f"--filename={PROOF/'tenant_a_dashboard.png'}")
        assertion("""async () => {
          document.querySelector('#logout').click();
          for(let i=0;i<60;i++) {
            if(!document.querySelector('#login-view')?.classList.contains('hidden')) {
              const r=await fetch('/api/me',{credentials:'same-origin'});
              if(r.status!==401) throw new Error('Logout did not revoke login: '+r.status);
              return 'JW_LOGOUT_REVOKED_PASS';
            }
            await new Promise(r=>setTimeout(r,100));
          }
          throw new Error('Logout form not visible');
        }""","JW_LOGOUT_REVOKED_PASS")
        b = login("demo@bada.example","JW_TENANT_B")
        if a==b:
            raise AssertionError("Cross-company demo logins returned same organization")
        cli("resize","390","844")
        assertion("""() => {
          if(window.innerWidth > 420 || document.querySelector('#app-shell')?.classList.contains('hidden')) throw new Error('Mobile workspace not visible');
          if(!document.querySelector('#toggle-menu')) throw new Error('Mobile menu missing');
          return 'JW_MOBILE_VIEW_PASS';
        }""","JW_MOBILE_VIEW_PASS")
        cli("screenshot",f"--filename={PROOF/'tenant_b_mobile.png'}")
        print("PASS: Playwright CLI actual Chromium over loopback FastAPI: login A, dashboard, logout revocation, login B, tenant isolation, mobile viewport",flush=True)
        return 0
    finally:
        if opened:
            try:cli("close",timeout=15)
            except Exception:pass

if __name__=="__main__":
    try:raise SystemExit(main())
    except Exception as exc:
        print(f"FAIL: {type(exc).__name__}: {exc}",file=sys.stderr)
        raise SystemExit(1)
