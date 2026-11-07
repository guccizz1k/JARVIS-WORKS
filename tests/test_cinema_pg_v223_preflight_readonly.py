"""Static guards for the V22.3 Track B read-only preflight (no database needed).

The behavioural proof is scripts/ci_cinema_pg_v223_preflight_gate.py on a disposable PostgreSQL. These tests only
keep the SQL file honest in the ordinary pytest run: one SELECT statement, no write/DDL/privilege verbs, no secret
shaped content, and the same rule names as the backup tool's least-privilege check.
"""
from __future__ import annotations

import re
from pathlib import Path

from scripts import ci_cinema_pg_v223_preflight_gate as gate
from scripts import pg_backup_v223 as pb

ROOT = Path(__file__).resolve().parents[1]
SQL = (ROOT / "scripts/review/cinema_pg_v223_preflight_readonly.sql").read_text()
FORBIDDEN = ("INSERT", "UPDATE", "DELETE", "MERGE", "CREATE", "DROP", "ALTER", "GRANT", "REVOKE", "TRUNCATE",
             "COPY", "CALL", "DO", "SET", "RESET", "BEGIN", "COMMIT", "LOCK", "VACUUM", "ANALYZE", "REINDEX",
             "NOTIFY", "LISTEN", "EXECUTE", "PREPARE")


def code_only(text: str) -> str:
    """Remove -- comments and '...' literals (with '' escapes) so only executable tokens remain."""
    out, i, n = [], 0, len(text)
    while i < n:
        if text.startswith("--", i):
            while i < n and text[i] != "\n":
                i += 1
        elif text[i] == "'":
            i += 1
            while i < n:
                if text[i] == "'" and text[i + 1:i + 2] == "'":
                    i += 2
                elif text[i] == "'":
                    i += 1
                    break
                else:
                    i += 1
            out.append("''")
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def test_single_select_statement():
    code = code_only(SQL).strip()
    assert code.upper().startswith("WITH")
    assert code.endswith(";") and code.count(";") == 1
    assert "\\" not in code, "psql meta-commands are not allowed"


def test_no_write_ddl_or_privilege_verbs_in_executable_text():
    words = set(re.findall(r"[A-Za-z_]+", code_only(SQL).upper()))
    assert not [w for w in FORBIDDEN if w in words]


def test_inner_dynamic_sql_is_read_only_too():
    # the two query_to_xml() strings are the only SQL built as text; they must be pure counts
    for literal in re.findall(r"'((?:[^']|'')*)'", SQL):
        if literal.upper().startswith("SELECT COUNT"):
            assert not re.search(r"\b(INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|GRANT|REVOKE|TRUNCATE)\b", literal.upper())


def test_documents_how_to_run_it_read_only_and_keeps_secrets_out():
    header = SQL.split("WITH\ncfg", 1)[0]
    assert "default_transaction_read_only=on" in header
    assert "no secret" in header.lower() or "contains no secret" in header.lower()
    assert not re.search(r"postgres(?:ql)?://\S+:\S+@", SQL)


def test_violation_names_match_the_backup_tool_rules():
    ours = set(re.findall(r"THEN '([a-z_]+)' END", SQL))
    ours = {name for name in ours if name in {
        "superuser", "createrole", "createdb", "replication", "privileged_builtin_member", "database_create",
        "schema_create", "role_switched", "settable_other_roles", "schema_no_usage", "no_tables_visible",
        "tables_unreadable", "tables_writable", "sequences_writable", "rls_rows_not_fully_readable"}}
    tool_src = Path(pb.__file__).read_text()
    # every violation name the SQL can emit is a rule name that evaluate_source_privileges can emit
    assert ours and all(f'"{name}"' in tool_src for name in ours), sorted(ours)
    # and none of the tool's rules is missing from the SQL mirror
    tool_rules = {"superuser", "createrole", "createdb", "replication", "privileged_builtin_member",
                  "database_create", "schema_create", "role_switched", "settable_other_roles", "schema_no_usage",
                  "no_tables_visible", "tables_unreadable", "tables_writable", "sequences_writable",
                  "rls_rows_not_fully_readable"}
    assert tool_rules <= ours


def test_privileged_builtin_roles_equal_the_tool_list():
    for role in pb.PRIVILEGED_BUILTIN_ROLES:
        assert f"'{role}'" in SQL


def test_sequence_privilege_is_only_evaluated_on_rows_that_passed_the_relkind_filter():
    # has_sequence_privilege() raises "is not a sequence" for any other relation. A plain WHERE qual may be planned
    # before the relkind = 'S' filter inside the `seq` CTE (seen on the live project), so only FILTER is allowed.
    code = code_only(SQL)
    allowed = re.compile(r"FILTER\s*\(\s*WHERE\s+has_sequence_privilege", re.IGNORECASE)
    assert allowed.search(code), "the sequence privilege check must be an aggregate FILTER"
    assert "has_sequence_privilege" not in allowed.sub("", code), "a bare has_sequence_privilege() call is not allowed"


def test_gate_expectation_list_has_no_duplicates_and_covers_order_trap():
    assert len(gate.EXPECTED) == len(set(gate.EXPECTED))
    assert {"PF.20", "PF.21"} <= set(gate.EXPECTED)
