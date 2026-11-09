"""Static guards for the B1 renewal/revocation proposals of jw_backup_ro (no database needed).

Behaviour is proven by scripts/ci_cinema_pg_v223_backup_role_renew_gate.py on a disposable PostgreSQL; these tests keep the two
proposal files and the gate's bookkeeping honest in the ordinary pytest run.
"""
from __future__ import annotations

import re
from pathlib import Path

from scripts import ci_cinema_pg_v223_backup_role_renew_gate as rg

ROOT = Path(__file__).resolve().parents[1]
RENEW = (ROOT / "scripts/review/cinema_pg_v223_backup_role_renew_proposal.sql").read_text()
REVOKE = (ROOT / "scripts/review/cinema_pg_v223_backup_role_revoke.sql").read_text()


def code(text: str) -> str:
    return "\n".join(line.split("--", 1)[0] for line in text.splitlines())


def test_gate_expectations_are_unique_and_complete():
    assert len(rg.EXPECTED) == len(set(rg.EXPECTED)) == 8


def test_renewal_changes_exactly_one_attribute_in_one_transaction():
    body = code(RENEW).strip()
    assert body.upper().startswith("BEGIN;") and body.upper().endswith("COMMIT;")
    assert body.upper().count("BEGIN;") == 1 and body.upper().count("COMMIT;") == 1
    alters = re.findall(r"(?is)ALTER\s+ROLE\s+jw_backup_ro\s+(.*?);", body)
    assert alters == ["VALID UNTIL :'valid_until'"]
    assert not re.search(r"(?i)\b(password|grant|revoke|create|drop|login|bypassrls|superuser|connection)\b|postgres(?:ql)?://", body)


def test_renewal_guard_refuses_past_far_future_and_missing_role():
    for needle in ("<= now()", "interval ''7 days''", "does not exist", "renewal window"):
        assert needle in RENEW, needle
    assert "\\gexec" in RENEW and RENEW.index("\\gexec") < RENEW.index("ALTER ROLE jw_backup_ro")


def test_revoke_never_drops_or_grants_and_ends_sessions():
    body = code(REVOKE)
    assert "ALTER ROLE jw_backup_ro NOLOGIN;" in body and "pg_terminate_backend" in body
    assert not re.search(r"(?i)\b(drop|grant|revoke|password)\b", body)
    assert body.upper().count("BEGIN;") == 1 and body.upper().count("COMMIT;") == 1
