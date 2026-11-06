"""Pins the V22.3 dev-DB migration candidates. Behaviour is proven on PG17 by
scripts/ci_cinema_pg_v223_migration_gate.py (36 checks); this file pins the shape offline."""
from pathlib import Path

REV = Path(__file__).resolve().parents[1] / "scripts/review"


def read(name: str) -> str:
    """SQL without comment lines (comments explain the history and may name forbidden statements)."""
    text = (REV / name).read_text(encoding="utf-8")
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("--"))


def test_backup_role_recipe_is_one_transaction_and_has_no_secret():
    sql = read("cinema_pg_v223_backup_role_proposal.sql")
    body = [l for l in sql.splitlines() if l.strip() and not l.lstrip().startswith("--")]
    assert body[0] == "BEGIN;" and body[-1] == "COMMIT;"
    assert "PASSWORD" not in sql.upper()
    assert "pg_read_all_data" not in sql and "SUPERUSER" in sql and "NOSUPERUSER" in sql
    assert "INHERIT TRUE, SET FALSE" in sql and "REVOKE jw_cinema_owner FROM CURRENT_USER GRANTED BY CURRENT_USER" in sql


def test_backup_role_rollback_does_not_rely_on_drop_owned():
    sql = read("cinema_pg_v223_backup_role_rollback.sql")
    assert "DROP OWNED" not in sql and "NOLOGIN" in sql and "DROP ROLE jw_backup_ro" in sql
    assert sql.index("NOLOGIN") < sql.index("DROP ROLE")


def test_terms_disable_is_lossless_and_hard_rollback_refuses_data_loss():
    off = read("cinema_pg_v223_terms_disable.sql")
    assert "REVOKE EXECUTE" in off and "DROP" not in off and "DELETE" not in off
    hard = read("cinema_pg_v223_terms_rollback.sql")
    assert "row_security = off" in hard and "55000" in hard and hard.index("RAISE EXCEPTION") < hard.index("DROP TABLE")


def test_two_person_rollback_drops_only_its_constraint():
    sql = read("cinema_pg_v223_quote_two_person_rollback.sql")
    assert "DROP CONSTRAINT IF EXISTS cinema_pg_quote_two_person" in sql
    assert sql.count("DROP") == 1


def test_gate_count_is_exact():
    src = (REV.parent / "ci_cinema_pg_v223_migration_gate.py").read_text(encoding="utf-8")
    assert "EXPECTED_CHECKS = 36" in src and "len(results) == EXPECTED_CHECKS" in src
