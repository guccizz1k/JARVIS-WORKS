"""Serve CINEMA as the main page without changing the original visual source.

Original HTML/CSS/WebGL asset is immutable. Server API remains authoritative.

Root UI selector (candidate, default OFF)
-----------------------------------------
``JW_ROOT_UI=v222`` makes ``/`` serve the confirmed V22.2 silver-infinity
cinematic workspace (``static/index.html`` plus its V22.2 assets) instead of
CINEMA. Every other value, including unset, keeps the protected CINEMA page,
so the default behaviour and the original CINEMA HTML stay byte-identical.
The selector only chooses which existing document is returned: no API, RLS,
auth or data-processing code is touched, and ``/_legacy-ui`` is unchanged.
"""
import base64
import hashlib
import os
import re
from pathlib import Path
from fastapi.responses import HTMLResponse

ROOT = Path(__file__).resolve().parent
ROOT_UI_ENV = 'JW_ROOT_UI'


def root_ui_mode():
    """Return 'v222' only for an explicit opt-in; anything else is CINEMA (fail closed)."""
    return 'v222' if os.environ.get(ROOT_UI_ENV, '').strip().lower() == 'v222' else 'cinema'


def v222_main_response():
    # The page references only same-origin /static assets and has no inline
    # script, so app.main's default CSP (script-src 'self') applies unchanged.
    # The internal X-JW-Cinema-Main marker is deliberately NOT set here, so the
    # security middleware attaches that default CSP instead of skipping it.
    html = (ROOT / 'static' / 'index.html').read_text(encoding='utf-8')
    return HTMLResponse(html, headers={'Cache-Control': 'no-store'})


def cinema_main_response():
    if root_ui_mode() == 'v222':
        return v222_main_response()
    original =(ROOT / 'static' / 'cinema' / 'JARVIS_WORKS_CINEMA.html').read_text(encoding='utf-8')
    # Capture the unmodified source handlers BEFORE v1 installs fail-closed stubs.
    # V2 wraps these original form builders; otherwise its UI buttons are inert.
    preserved = ("const _jwOriginalCINEMAPartnerForm=partnerForm;"
                 "const _jwOriginalCINEMADealForm=dealForm;")
    bridge = preserved + (ROOT / 'cinema_bridge_v1.js').read_text(encoding='utf-8') + '\n' + (ROOT / 'cinema_bridge_v2.js').read_text(encoding='utf-8')
    # v3 (PostgreSQL trade ledger) is inert unless /api/pg-stage/cinema-trade answers for the signed-in user.
    bridge += '\n' + (ROOT / 'cinema_bridge_v3.js').read_text(encoding='utf-8')
    needle = 'boot();\n})();'
    if original.count(needle) != 1 or '</script>' in bridge.lower():
        raise RuntimeError('CINEMA adapter insertion point rejected')
    html = original.replace(needle, bridge + '\ncinemaBoot();\n})();')
    match = re.search(r'<script>(.*?)</script>', html, re.S)
    if not match or html.count('<script>') != 1:
        raise RuntimeError('Unexpected CINEMA inline script layout')
    digest = base64.b64encode(hashlib.sha256(match.group(1).encode('utf-8')).digest()).decode('ascii')
    csp = ("default-src 'self'; script-src 'self' 'sha256-" + digest + "'; "
           "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
           "font-src 'self' https://fonts.gstatic.com; "
           "img-src 'self' data:; connect-src 'self'; form-action 'self'; "
           "frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
    return HTMLResponse(html, headers={'Cache-Control': 'no-store',
            'Content-Security-Policy': csp, 'X-JW-Cinema-Main': '1'})
