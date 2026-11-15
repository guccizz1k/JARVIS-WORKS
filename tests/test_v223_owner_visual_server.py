"""Immutable owner-visual review: exact CSS, no original local DB boot, explicit opt-in."""
from pathlib import Path
from unittest.mock import patch
import hashlib, re
from app.cinema_entry_v1 import root_ui_mode, owner_visual_review_response, OWNER_VISUAL_SHA256
ROOT=Path(__file__).resolve().parents[1]

def test_original_owner_asset_unmodified():
    raw=(ROOT/'app/static/approved_v223_owner_original.html').read_bytes()
    assert len(raw)==229028
    assert hashlib.sha256(raw).hexdigest()==OWNER_VISUAL_SHA256

def test_opt_in_only_explicit_nonproduction_review():
    for env,flag in [
        ({},'cinema'),
        ({'JW_ROOT_UI':'owner-visual-review'},'cinema'),
        ({'JW_ROOT_UI':'owner-visual-review','JW_ENV':'production','JW_APPROVED_UI_REVIEW':'ISOLATED_REVIEW_ONLY'},'cinema'),
        ({'JW_ROOT_UI':'owner-visual-review','JW_ENV':'review','JW_APPROVED_UI_REVIEW':'ISOLATED_REVIEW_ONLY'},'owner-visual-review')
    ]:
        with patch.dict('os.environ',env,clear=True):assert root_ui_mode()==flag

def test_generated_visual_reuses_exact_approved_css_but_never_its_script():
    r=owner_visual_review_response()
    s=r.body.decode('utf-8')
    original=(ROOT/'app/static/approved_v223_owner_original.html').read_text('utf-8')
    css=re.search(r'<style>(.*?)</style>',original,re.S).group(1)
    assert css in s and s.count(css)==1
    assert 'function registerCompany(' not in s
    assert 'function login(email,password' not in s
    assert 'jw3.db' not in s
    assert 'boot();' not in s
    assert 'localStorage' not in s
    assert 'indexedDB' not in s
    assert 'script defer src="/static/approved_ui_server_bridge_v223.js"' in s
    assert 'script defer src="/static/approved_ui_server_review_v223.js"' in s
    assert 'data-jw-review-mode="owner-visual"' in s

def test_strict_review_security_headers_and_no_inline_javascript():
    r=owner_visual_review_response();csp=r.headers['content-security-policy']
    assert "script-src 'self';" in csp
    assert "'unsafe-inline'" not in csp.split('style-src')[0]
    assert "connect-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp and "object-src 'none'" in csp
    assert 'no-store' in r.headers['cache-control']
    assert r.headers['x-content-type-options']=='nosniff'
    assert '<script>' not in r.body.decode()

def test_owner_source_has_only_one_expected_style_and_boot():
    original=(ROOT/'app/static/approved_v223_owner_original.html').read_text('utf8')
    assert len(re.findall(r'<style>(.*?)</style>',original,re.S))==1
    assert original.count('<script>')==1
    assert original.count('boot();')==1
