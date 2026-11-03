"""V23.1: user's FIXED cinematic artwork safely bridged to real app DOM."""
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
STATIC=ROOT/"app/static"
HTML=(STATIC/"index.html").read_text()
BRIDGE=(STATIC/"cinematic_v231_fixed_bridge.js").read_text()
CINE=(STATIC/"jw231_fixed/cine_live.js").read_text()
CSS=(STATIC/"cinematic_v231_fixed.css").read_text()

def test_original_auth_fields_and_otp_recovery_preserved():
    for s in ('id="login-form"','name="email"','name="password"','name="otp"','name="recovery_code"'):
        assert s in HTML

def test_original_business_navigation_and_logic_scripts():
    for s in ('id="nav"','id="main-content"','/static/app.js','/static/automation_v62.js',
              '/static/cinematic_v222.js'):
        assert s in HTML

def test_visual_additions_are_loaded_without_remote_dependencies():
    for s in ('/static/cinematic_v231_fixed.css','/static/cinematic_v231_flag.js',
              '/static/cinematic_v231_fixed_bridge.js','/static/jw231_fixed/cine_live.js'):
        assert s in HTML
    assert '<script>window.JW231_USE_FIXED' not in HTML
    assert '<script src="/static/cinematic_v230_stage1.bundle.js" defer></script>' not in HTML

def test_original_uploaded_visual_resources_present():
    for name in ('sculpt_cut.webp',):
        assert (STATIC/"jw231_fixed"/name).is_file()

def test_visual_files_never_handle_credentials_or_business_api():
    for source in (BRIDGE,CINE,CSS):
        assert not re.search(r"\bfetch\s*\(|XMLHttpRequest|indexedDB|localStorage|sessionStorage",source)
        assert "/api/login" not in source
        assert "document.cookie" not in source
        assert "JARVIS_DB_PATH" not in source

def test_bridge_checks_actual_login_and_navigation():
    assert 'form#login-form' in BRIDGE
    assert "getElementById('nav')" in BRIDGE
    assert "JW231_FIXED" in BRIDGE

def test_visual_canvas_never_intercepts_inputs():
    assert 'pointer-events:none' in CSS
    assert "setAttribute('aria-hidden','true')" in CINE

def test_user_supplied_depth_art_used_not_fake_kpi():
    assert 'sculpt_cut.webp' in CINE
    assert 'drawPhoton(' in CINE
    assert 'drawRings(' in CINE
    assert 'window.JW231_FRAME_COUNT' in CINE
