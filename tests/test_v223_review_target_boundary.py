"""Owner review target must be validated before protected core initialization.

Only temporary synthetic sentinel files are opened. The default-path test
replaces core lifespan with a spy, so it never reads/initializes the real path.
"""
from contextlib import asynccontextmanager
from pathlib import Path
import sqlite3

import pytest
from fastapi.testclient import TestClient
from app import main as core
from app.owner_review_app_v223 import app as owner_app


@pytest.fixture
def review_flags(monkeypatch):
    for key, value in {
        'JW_ENV': 'review',
        'JW_ROOT_UI': 'owner-visual-review',
        'JW_APPROVED_UI_REVIEW': 'ISOLATED_REVIEW_ONLY',
        'DEMO_SEED': '1',
    }.items():
        monkeypatch.setenv(key, value)
    for key in ('JW_PUBLIC_QA_MODE', 'JARVIS_DB_PATH',
                'BOOTSTRAP_EMAIL', 'BOOTSTRAP_PASSWORD'):
        monkeypatch.delenv(key, raising=False)


def test_parent_symlink_target_refused_without_mutating_sentinel(
        tmp_path, monkeypatch, review_flags):
    destination = tmp_path/'synthetic-persisted'
    destination.mkdir()
    target = destination/'review.db'
    with sqlite3.connect(target) as db:
        db.execute('CREATE TABLE independent_target_sentinel(id INTEGER PRIMARY KEY)')
        db.execute('INSERT INTO independent_target_sentinel VALUES(1)')
    before = target.read_bytes()
    alias = tmp_path/'alias'
    alias.symlink_to(destination, target_is_directory=True)
    monkeypatch.setattr(core, 'DB_PATH', alias/'review.db')
    with pytest.raises(RuntimeError, match=r'(?i)(review|database|target|symlink|disposable)'):
        with TestClient(owner_app, base_url='https://testserver'):
            pass
    unchanged = target.read_bytes() == before
    assert unchanged, 'Rejected review target must remain byte-for-byte unchanged'


def test_default_core_target_refused_before_core_lifespan(
        monkeypatch, review_flags):
    # Do not touch this path: only the path object is used to check rejection.
    monkeypatch.setattr(core, 'DB_PATH', core.ROOT.parent/'data'/'works.db')
    entered = []

    @asynccontextmanager
    async def forbidden_core_lifespan(_app):
        entered.append(True)
        raise AssertionError('Core startup reached before target validation')
        yield  # pragma: no cover -- keeps the sentinel an async generator

    monkeypatch.setattr(core.app.router, 'lifespan_context', forbidden_core_lifespan)
    with pytest.raises(RuntimeError, match=r'(?i)(review|database|target|disposable)'):
        with TestClient(owner_app, base_url='https://testserver'):
            pass
    assert entered == [], 'Unsafe target must be refused before any core startup'


def test_explicit_ordinary_temporary_target_still_starts(
        tmp_path, monkeypatch, review_flags):
    target = tmp_path/'ordinary-synthetic-review.sqlite3'
    monkeypatch.setattr(core, 'DB_PATH', target)
    with TestClient(owner_app, base_url='https://testserver') as client:
        assert client.get('/api/health').status_code == 200
    with sqlite3.connect(target) as db:
        names = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {'users', 'jw_owner_profile_versions_v223',
            'jw_owner_preferences_v223'} <= names
