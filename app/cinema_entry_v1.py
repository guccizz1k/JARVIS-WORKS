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
    selected = os.environ.get(ROOT_UI_ENV, '').strip().lower()
    if selected == 'v222':
        return 'v222'
    if (selected in ('owner-review', 'owner-visual-review') and os.environ.get('JW_ENV', '').lower() in ('review', 'test')
            and os.environ.get('JW_APPROVED_UI_REVIEW', '') == 'ISOLATED_REVIEW_ONLY'):
        return selected
    return 'cinema'


def v222_main_response():
    # The page references only same-origin /static assets and has no inline
    # script, so app.main's default CSP (script-src 'self') applies unchanged.
    # The internal X-JW-Cinema-Main marker is deliberately NOT set here, so the
    # security middleware attaches that default CSP instead of skipping it.
    html = (ROOT / 'static' / 'index.html').read_text(encoding='utf-8')
    return HTMLResponse(html, headers={'Cache-Control': 'no-store'})


def _owner_review_response():
    """HTTPS review-only; CSP hashes the exact approved inline JS, no unsafe script execution."""
    original = (ROOT / 'static' / 'approved_v223_secure_review.html').read_text('utf8')
    match = re.search(r'<script>(.*?)</script>', original, re.S)
    if not match or original.count('<script>') != 1:
        raise RuntimeError('Approved review source layout invalid')
    digest = base64.b64encode(hashlib.sha256(match.group(1).encode('utf8')).digest()).decode('ascii')
    policy = ("default-src 'self'; script-src 'self' 'sha256-" + digest + "'; "
              "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
              "font-src 'self' https://fonts.gstatic.com; "
              "img-src 'self' data:; connect-src 'self'; form-action 'self'; "
              "frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
    return HTMLResponse(original, headers={
        'Cache-Control': 'no-store', 'Content-Security-Policy': policy,
        'X-JW-Cinema-Main': '1',
    })



OWNER_VISUAL_SHA256 = '953c1b00cead79173c0c7a9c40319344e510bec9f6a1f646f30e0a147356076d'

def owner_visual_review_response():
    """Review-only visual bridge using the EXACT original approved CSS bytes.

    The protected original remains untouched. Critically, its browser-local
    account/storage and business scripts never execute: ONLY authenticated,
    same-origin server bridge JS loads. This is NOT the full production UI.
    """
    original_bytes = (ROOT / 'static' / 'approved_v223_owner_original.html').read_bytes()
    if hashlib.sha256(original_bytes).hexdigest() != OWNER_VISUAL_SHA256:
        raise RuntimeError('Approved owner source has changed; refuse visual review')
    original = original_bytes.decode('utf-8')
    styles = re.findall(r'<style>([\s\S]*?)</style>', original)
    if len(styles) != 1 or original.count('<script>') != 1 or original.count('boot();') != 1:
        raise RuntimeError('Unexpected approved source layout; refuse execution')
    font_links = re.findall(r'<link\b[^>]*>', original[:original.index('<style>')], re.I)
    if not font_links or any('javascript:' in x.lower() or 'onload=' in x.lower() for x in font_links):
        raise RuntimeError('Approved source font references changed')
    fonts = '\n'.join(font_links)
    html = (
        '<!doctype html><html lang="ko" data-theme="dark"><head>'
        '<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">'
        '<title>JARVIS WORKS · 보호된 서버 연결 검토</title>' + fonts
        + '<style>' + styles[0] + '</style>'
        + '<link rel="stylesheet" href="/static/approved_ui_server_review_v223.css">'
        + '<link rel="stylesheet" href="/static/approved_ui_owner_visual_v223.css">'
        + '</head><body data-jw-review-mode="owner-visual">'
        + '<div id="login"></div><div id="app"></div><div id="intro" hidden></div>'
        + '<div id="toasts" aria-live="polite"></div>'
        + '<script defer src="/static/approved_ui_server_bridge_v223.js"></script>'
        + '<script defer src="/static/approved_ui_server_review_v223.js"></script>'
        + '<script defer src="/static/approved_ui_owner_visual_v223.js"></script>'
        + '</body></html>'
    )
    return HTMLResponse(html, headers={
        'Cache-Control': 'no-store, private',
        'Content-Security-Policy': (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        ),
        'X-JW-Cinema-Main': '1',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
    })

def cinema_main_response():
    if root_ui_mode() == 'owner-visual-review':
        return owner_visual_review_response()
    if root_ui_mode() == 'owner-review':
        return _owner_review_response()
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
