"""Serve CINEMA as the main page without changing the original visual source.

Original HTML/CSS/WebGL asset is immutable. Server API remains authoritative.
"""
import base64
import hashlib
import re
from pathlib import Path
from fastapi.responses import HTMLResponse

ROOT = Path(__file__).resolve().parent


def cinema_main_response():
    original = (ROOT / 'static' / 'cinema' / 'JARVIS_WORKS_CINEMA.html').read_text(encoding='utf-8')
    # Capture the unmodified source handlers BEFORE v1 installs fail-closed stubs.
    # V2 wraps these original form builders; otherwise its UI buttons are inert.
    preserved = ("const _jwOriginalCINEMAPartnerForm=partnerForm;"
                 "const _jwOriginalCINEMADealForm=dealForm;")
    bridge = preserved + (ROOT / 'cinema_bridge_v1.js').read_text(encoding='utf-8') + '\n' + (ROOT / 'cinema_bridge_v2.js').read_text(encoding='utf-8')
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
