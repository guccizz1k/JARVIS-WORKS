"""Guard against the isolated owner-review adapter mutating legacy main or DB."""
import os
import sqlite3
from fastapi.testclient import TestClient
import pytest
from app import main
from app.owner_review_app_v223 import app as owner_app


def test_default_app_still_uses_unchanged_table_set(tmp_path,monkeypatch):
    monkeypatch.setenv('JW_ENV','review')
    monkeypatch.setenv('DEMO_SEED','1')
    monkeypatch.setattr(main,'DB_PATH',tmp_path/'base-only.db')
    with TestClient(main.app,base_url='https://testserver') as client:
        assert client.get('/api/health').status_code==200
        assert client.get('/api/account/profile').status_code==404
        assert client.get('/api/account/preferences').status_code==404
    with sqlite3.connect(tmp_path/'base-only.db') as db:
        tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert 'jw_owner_profile_versions_v223' not in tables
    assert 'jw_owner_preferences_v223' not in tables


def test_owner_wrapper_denied_without_explicit_safe_review_mode(tmp_path,monkeypatch):
    monkeypatch.setattr(main,'DB_PATH',tmp_path/'not-created.db')
    monkeypatch.setenv('JW_ENV','production')
    monkeypatch.setenv('JW_ROOT_UI','owner-visual-review')
    monkeypatch.setenv('JW_APPROVED_UI_REVIEW','ISOLATED_REVIEW_ONLY')
    with pytest.raises(RuntimeError,match='isolated explicit review'):
        with TestClient(owner_app,base_url='https://testserver'):
            pass
    assert not (tmp_path/'not-created.db').exists()


def test_owner_review_keeps_core_routes_and_new_account_routes(tmp_path,monkeypatch):
    monkeypatch.setenv('JW_ENV','review')
    monkeypatch.setenv('JW_ROOT_UI','owner-visual-review')
    monkeypatch.setenv('JW_APPROVED_UI_REVIEW','ISOLATED_REVIEW_ONLY')
    monkeypatch.setenv('DEMO_SEED','1')
    monkeypatch.setattr(main,'DB_PATH',tmp_path/'safe-review.db')
    with TestClient(owner_app,base_url='https://testserver') as c:
        assert c.get('/api/health').status_code==200
        assert c.get('/api/account/profile').status_code==401
        assert c.get('/api/account/preferences').status_code==401
        assert c.post('/api/account/preferences',json={
            'version':0,'compact_view':True,'messenger_auto_refresh':False},
            headers={'Origin':'https://attacker.invalid'}).status_code==403
        page=c.get('/')
        assert page.status_code==200
        assert 'approved_ui_profile_v223.js' in page.text
    with sqlite3.connect(tmp_path/'safe-review.db') as db:
        tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert 'jw_owner_profile_versions_v223' in tables
    assert 'jw_owner_preferences_v223' in tables
