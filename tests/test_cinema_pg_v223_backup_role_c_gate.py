"""Static guards for change C (jw_backup_ro) and its disposable-database gate (no database needed).

Behaviour is proven by scripts/ci_cinema_pg_v223_backup_role_c_gate.py on a disposable PostgreSQL; these tests only keep
the proposal SQL and the gate's bookkeeping honest in the ordinary pytest run.
"""
from __future__ import annotations

import re
from pathlib import Path

from scripts import ci_cinema_pg_v223_backup_role_c_gate as cg

ROOT = Path(__file__).resolve().parents[1]
C = (ROOT / "scripts/review/cinema_pg_v223_backup_role_proposal.sql").read_text()
RB = (ROOT / "scripts/review/cinema_pg_v223_backup_role_rollback.sql").read_text()


def code(text: str) -> str:
    return "\n".join(line.split("--", 1)[0] for line in text.splitlines())


def test_gate_expectations_are_unique_and_complete():
    assert len(cg.EXPECTED) == len(set(cg.EXPECTED)) == 16


def test_c_is_one_transaction_with_no_secret_and_no_privilege_escalation():
    body = code(C).strip()
    assert body.upper().startswith("BEGIN;") and body.upper().endswith("COMMIT;")
    assert body.upper().count("BEGIN;") == 1 and body.upper().count("COMMIT;") == 1
    assert not re.search(r"(?i)\bpassword\b|postgres(?:ql)?://|\bSUPERUSER\b(?<!NOSUPERUSER)", body.replace("NOSUPERUSER", ""))
    for needle in ("NOSUPERUSER", "NOCREATEROLE", "NOCREATEDB", "NOREPLICATION", "CONNECTION LIMIT 2", ":'valid_until'",
                   "default_transaction_read_only = on", "SET FALSE"):
        assert needle in body, needle


def test_c_grants_only_select_and_usage_and_always_revokes_the_temporary_membership():
    grants = re.findall(r"(?im)^GRANT\s+(.*?)\s+(?:ON|TO)\b", code(C))
    assert sorted(g.strip().upper() for g in grants) == ["JW_CINEMA_OWNER", "SELECT", "SELECT", "USAGE"]
    assert not re.search(r"(?i)\bGRANT\s+(INSERT|UPDATE|DELETE|ALL|TRUNCATE|REFERENCES|TRIGGER)\b", code(C))
    assert re.search(r"(?im)^REVOKE\s+jw_cinema_owner\s+FROM\s+CURRENT_USER\s+GRANTED\s+BY\s+CURRENT_USER;", code(C))
    # the revoke must come after every grant and before COMMIT
    assert code(C).rfind("GRANT ") < code(C).find("REVOKE jw_cinema_owner") < code(C).rfind("COMMIT;")


def test_rollback_is_one_transaction_and_drops_the_role_only_when_present():
    body = code(RB).upper()
    assert body.count("BEGIN;") == 1 and body.count("COMMIT;") == 1
    assert "DROP ROLE JW_BACKUP_RO" in body and "NOLOGIN" in body and "GRANTED BY CURRENT_USER" in body
