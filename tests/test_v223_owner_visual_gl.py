from pathlib import Path
from app.cinema_entry_v1 import owner_visual_review_response
import re
ROOT=Path(__file__).resolve().parents[1]
def test_visual_webgl_has_exact_original_independent_gl_segment():
    approved=(ROOT/'app/static/approved_v223_owner_original.html').read_text('utf8')
    actual=(ROOT/'app/static/approved_ui_owner_gl_v223.js').read_text('utf8')
    source=approved.split('const GL=(()=>{',1)[1].split('\n})();',1)[0]
    segment='const GL=(()=>{'+source+'\n})();'
    assert actual.count(segment)==1
    assert len(segment)>11000
    for forbidden in ('localStorage','indexedDB','sessionStorage','DB.','fetch(','document.cookie'):
        assert forbidden not in actual

def test_server_visual_shell_uses_pinned_webgl_with_strict_csp():
    response=owner_visual_review_response()
    html=response.body.decode()
    assert '<canvas id="gl" aria-hidden="true"></canvas>' in html
    assert '<div class="vig" aria-hidden="true"></div>' in html
    assert '<script defer src="/static/approved_ui_owner_gl_v223.js"></script>' in html
    assert html.index('approved_ui_owner_gl_v223.js') < html.index('approved_ui_owner_visual_v223.js')
    assert "script-src 'self';" in response.headers['content-security-policy']
    assert '<script>' not in html
