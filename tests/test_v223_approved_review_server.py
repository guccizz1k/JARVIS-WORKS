from pathlib import Path
import os
import re
import hashlib
from unittest.mock import patch
from app.cinema_entry_v1 import root_ui_mode, cinema_main_response
ROOT=Path(__file__).resolve().parents[1]

def test_review_mode_disabled_by_default():
    with patch.dict(os.environ, {}, clear=True):
        assert root_ui_mode()=='cinema'

def test_review_mode_requires_strict_environment():
    for env,flag in [('production','ISOLATED_REVIEW_ONLY'),('review',''),('','ISOLATED_REVIEW_ONLY')]:
        with patch.dict(os.environ, {'JW_ROOT_UI':'owner-review','JW_ENV':env,'JW_APPROVED_UI_REVIEW':flag},clear=True):
            assert root_ui_mode()=='cinema'

def test_review_csp_is_hash_bound_and_owner_original_unmodified():
    with patch.dict(os.environ,{'JW_ROOT_UI':'owner-review','JW_ENV':'review','JW_APPROVED_UI_REVIEW':'ISOLATED_REVIEW_ONLY'},clear=True):
        response=cinema_main_response()
        original=response.body.decode('utf8')
        match=re.search(r'<script>(.*?)</script>',original,re.S)
        assert match and original.count('<script>')==1
        import base64
        sha=base64.b64encode(hashlib.sha256(match.group(1).encode('utf8')).digest()).decode('ascii')
        csp=response.headers['content-security-policy']
        assert "'sha256-"+sha+"'" in csp
        assert "script-src 'self' 'sha256-" in csp and "'unsafe-inline'" not in csp.split('style-src')[0]
        assert response.headers['cache-control']=='no-store'
        assert response.headers['x-jw-cinema-main']=='1'
        approved=(ROOT/'app/static/approved_v223_owner_original.html').read_bytes()
        assert hashlib.sha256(approved).hexdigest()=='953c1b00cead79173c0c7a9c40319344e510bec9f6a1f646f30e0a147356076d'
