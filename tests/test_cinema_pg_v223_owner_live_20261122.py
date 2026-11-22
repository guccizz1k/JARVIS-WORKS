"""Offline approval-boundary tests. No DB, credentials, Docker, or role mutation."""
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import pytest

from scripts import ci_cinema_pg_v223_owner_live_20261122 as d


def kst(y, m, day, h, minute, sec=0):
    return datetime(y, m, day, h, minute, sec, tzinfo=ZoneInfo("Asia/Seoul"))


def test_approval_deadline_is_fixed():
    assert d.END == kst(2026, 11, 22, 20, 50, 58)


def test_expired_refused():
    for instant in (d.END, d.END + timedelta(seconds=1), d.END + timedelta(days=1)):
        with pytest.raises(d.old.Blocked, match="owner_approval_window_expired"):
            d.expiry_value(instant)


def test_before_deadline_is_bounded():
    now = kst(2026, 11, 22, 16, 0)
    result = datetime.strptime(d.expiry_value(now), "%Y-%m-%d %H:%M:%S+09")
    assert result == datetime(2026, 11, 22, 20, 50, 58)
    assert result - now.replace(tzinfo=None) < timedelta(hours=5)


def test_near_deadline_is_clamped():
    now = kst(2026, 11, 22, 20, 50, 57)
    assert d.expiry_value(now) == "2026-11-22 20:50:58+09"


def test_original_expired_approval_is_unchanged():
    assert d.old.OWNER_DEADLINE == kst(2026, 11, 17, 14, 30)


def test_new_sql_is_distinct_from_original():
    assert d.SQL_PATH != "scripts/review/cinema_pg_v223_backup_role_20261117.sql"
    assert d.NEW == frozenset((d.SQL_PATH, d.DRIVER_PATH, d.TEST_PATH))


def test_source_pin_requires_codespaces(monkeypatch):
    monkeypatch.delenv("CODESPACES", raising=False)
    with pytest.raises(d.old.Blocked, match="approved_codespace_required"):
        d.check_sources()


def test_source_pin_rejects_wrong_branch(monkeypatch):
    monkeypatch.setenv("CODESPACES", "true")
    monkeypatch.setattr(d, "git", lambda *args: "main")
    with pytest.raises(d.old.Blocked, match="wrong_review_branch"):
        d.check_sources()


def test_source_pin_rejects_dirty_worktree(monkeypatch):
    monkeypatch.setenv("CODESPACES", "true")
    def fake_git(*args):
        if args == ("branch", "--show-current"):
            return d.BRANCH
        if args == ("rev-parse", "HEAD") or args == ("rev-parse", "refs/remotes/origin/" + d.BRANCH):
            return "same"
        if args[:2] == ("diff", "--name-only"):
            return "\n".join(sorted(d.NEW))
        if args[:2] == ("status", "--porcelain"):
            return " M original.py"
        return ""
    monkeypatch.setattr(d, "git", fake_git)
    with pytest.raises(d.old.Blocked, match="dirty_checkout"):
        d.check_sources()
