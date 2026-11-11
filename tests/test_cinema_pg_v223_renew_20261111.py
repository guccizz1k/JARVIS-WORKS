"""2026-11-10 owner re-approval: isolated expiry-only SQL provenance, no database access.

The historical expiry proposal remains immutable. The reviewed renewal file
changes only the approved absolute deadline and tightens the ceiling to five hours.
"""
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from scripts import ci_cinema_pg_v223_codespace_run as run

ROOT = Path(__file__).resolve().parents[1]
OLD = ROOT / "scripts/review/cinema_pg_v223_backup_role_renew_proposal.sql"
NEW = ROOT / "scripts/review/cinema_pg_v223_backup_role_renew_20261111.sql"
OLD_LIMIT = "2026-11-10 09:00:00+09"
NEW_LIMIT = "2026-11-11 09:00:00+09"


def test_proposal_is_expiry_only_and_previous_approved_sql_is_preserved():
    old, new = OLD.read_bytes(), NEW.read_bytes()
    assert OLD_LIMIT.encode() in old
    assert NEW_LIMIT.encode() in new
    assert old != new
    assert new.replace(NEW_LIMIT.encode(), OLD_LIMIT.encode()).replace(b"5 hours", b"24 hours") == old
    # The SQL body carries the absolute deadline once; the remaining references
    # are documentation, never an environment override or moving approval window.
    code = "\n".join(line for line in NEW.read_text().splitlines()
                     if not line.lstrip().startswith("--"))
    assert code.count(NEW_LIMIT) == 1
    assert code.count("ALTER ROLE jw_backup_ro VALID UNTIL :'valid_until';") == 1
    assert "interval ''5 hours''" in code and "interval ''24 hours''" not in code
    assert "interval ''7 days''" not in code
    assert "BEGIN;" in code and "COMMIT;" in code


def test_launcher_targets_only_the_new_approval_and_new_sql():
    assert run.RENEW_SQL.resolve() == NEW.resolve()
    assert run.APPROVAL_COMMENT == "6755130318"
    limit = datetime(2026, 11, 11, 9, 0, tzinfo=ZoneInfo("Asia/Seoul"))
    assert run.APPROVED_LIMIT == limit
    assert run.MAX_WINDOW == timedelta(hours=4, minutes=59)
    assert "interval ''5 hours''" in run.TEMP_LOGIN_SQL.read_text()
    assert run.renew_value(limit - timedelta(minutes=1)) == NEW_LIMIT
    with pytest.raises(run.Blocked):
        run.renew_value(limit)
    with pytest.raises(run.Blocked):
        run.check_window(limit + timedelta(seconds=1))
