"""Static contract tests over the CINEMA trade write engine SQL.

These read the SQL text only (no PostgreSQL, no FastAPI), so they run anywhere.
They guard structural promises; behaviour is proven by scripts/ci_cinema_pg_sql_gate.py
against a disposable PostgreSQL, which is a separate run.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SQL = (ROOT / "scripts" / "review" / "cinema_pg_write_engine.sql").read_text(encoding="utf-8")
TEST_SQL = (ROOT / "scripts" / "review" / "cinema_pg_write_engine_test.sql").read_text(encoding="utf-8")

PUBLIC_API = [
    "cinema_pg_partner_upsert", "cinema_pg_evidence_put", "cinema_pg_evidence_open", "cinema_pg_quote_create", "cinema_pg_quote_update",
    "cinema_pg_quote_transition", "cinema_pg_order_create", "cinema_pg_delivery_record",
    "cinema_pg_delivery_confirm", "cinema_pg_delivery_cancel", "cinema_pg_delivery_reverse",
    "cinema_pg_statement_create", "cinema_pg_statement_confirm", "cinema_pg_statement_void",
    "cinema_pg_invoice_create", "cinema_pg_invoice_review", "cinema_pg_invoice_confirm",
    "cinema_pg_invoice_void", "cinema_pg_payment_record", "cinema_pg_payment_reverse",
    "cinema_pg_trade_trace", "cinema_pg_integrity_check",
]
TENANT_TABLES = [
    "cinema_pg_requests", "cinema_pg_trade_counters", "cinema_pg_audit", "cinema_pg_partners",
    "cinema_pg_quotes", "cinema_pg_quote_items", "cinema_pg_orders", "cinema_pg_order_items",
    "cinema_pg_deliveries", "cinema_pg_delivery_items", "cinema_pg_statements",
    "cinema_pg_statement_items", "cinema_pg_invoices", "cinema_pg_payments",
    "cinema_pg_payment_reversals", "cinema_pg_evidence_files",
]


def function_blocks():
    """name -> text from CREATE FUNCTION up to the next top-level statement start."""
    starts = [(m.start(), m.group(1)) for m in re.finditer(r"^CREATE FUNCTION jw_dev\.(\w+)\(", SQL, re.M)]
    blocks = {}
    for i, (pos, name) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(SQL)
        blocks[name] = SQL[pos:end]
    return blocks


BLOCKS = function_blocks()


def header(block):
    return block.split("$$", 1)[0] if "$$" in block else block.split("$", 2)[0]


def test_engine_defines_every_public_function():
    for name in PUBLIC_API:
        assert name in BLOCKS, name


def test_every_security_definer_function_pins_search_path_to_pg_catalog():
    definers = [n for n, b in BLOCKS.items() if "SECURITY DEFINER" in b]
    assert len(definers) >= len(PUBLIC_API)
    for name in definers:
        assert "SET search_path=pg_catalog" in BLOCKS[name], name


@pytest.mark.parametrize("name", PUBLIC_API)
def test_public_function_is_security_definer(name):
    assert "SECURITY DEFINER" in BLOCKS[name]


@pytest.mark.parametrize("name", [n for n in PUBLIC_API if n not in ("cinema_pg_trade_trace", "cinema_pg_integrity_check")])
def test_write_function_takes_identity_from_session_not_arguments(name):
    head = header(BLOCKS[name])
    for forbidden in ("p_org", "p_actor", "p_role", "p_tenant"):
        assert forbidden not in head.split("RETURNS")[0], (name, forbidden)
    assert "cinema_pg_begin" in BLOCKS[name], name


def test_identity_comes_from_stage_identity_function():
    assert "jw_dev.stage_identity_v84()" in BLOCKS["cinema_pg_begin"]


@pytest.mark.parametrize("table", TENANT_TABLES)
def test_tenant_table_is_in_force_rls_loop(table):
    loop = SQL[SQL.index("-- RLS") - 30: SQL.index("transitions is global reference data")]
    assert f"'{table}'" in loop
    assert "FORCE ROW LEVEL SECURITY" in loop and "REVOKE ALL ON jw_dev.%I FROM PUBLIC" in loop


def test_every_created_table_has_org_scope_or_is_the_reference_table():
    for m in re.finditer(r"CREATE TABLE jw_dev\.(\w+)\((.*?)\n\);", SQL, re.S):
        if m.group(1) == "cinema_pg_transitions":
            continue
        assert "org_id" in m.group(2), m.group(1)


def test_money_columns_are_bigint_not_floating():
    found = list(re.finditer(r"^\s*(\w*_krw|amount\w*|unit_price\w*|line_total\w*)\s+(\w+)", SQL, re.M))
    assert len(found) >= 8  # the pattern must really find the money columns
    for m in found:
        assert m.group(2).lower() == "bigint", m.group(0)
    assert re.search(r"total_krw\s+bigint", SQL)


def test_bank_confirmation_is_pinned_false():
    assert re.search(r"bank_confirmed boolean NOT NULL DEFAULT false CHECK\(bank_confirmed=false\)", SQL)


def test_no_grant_to_public_and_no_superuser_or_bypassrls_role():
    assert not re.search(r"GRANT\s+[^;]*\bTO\s+PUBLIC", SQL, re.I)
    assert "SUPERUSER" not in SQL.upper().replace("NOSUPERUSER", "")
    assert re.search(r"CREATE ROLE jw_cinema_owner[^;]*NOBYPASSRLS", SQL, re.I | re.S)
    assert re.search(r"CREATE ROLE jw_cinema_writer[^;]*NOBYPASSRLS", SQL, re.I | re.S)


def test_writer_has_no_direct_write_privilege_on_tables():
    assert not re.search(r"GRANT\s+(INSERT|UPDATE|DELETE|ALL)[^;]*jw_cinema_writer", SQL, re.I)


def test_final_grants_revoke_public_execute_and_grant_only_listed_api():
    tail = SQL[SQL.index("$grants$"):]
    assert "REVOKE ALL ON FUNCTION %s FROM PUBLIC" in tail
    for name in PUBLIC_API:
        assert f"'{name}'" in tail


def test_helpers_are_not_granted_to_writer():
    tail = SQL[SQL.index("$grants$"):]
    for helper in ("cinema_pg_begin", "cinema_pg_finish", "cinema_pg_audit_add", "cinema_pg_new_id"):
        assert f"'{helper}'" not in tail


def test_create_privilege_is_revoked_again_at_end():
    assert SQL.index("GRANT CREATE ON SCHEMA jw_dev TO jw_cinema_owner") < SQL.index("REVOKE CREATE ON SCHEMA jw_dev FROM jw_cinema_owner")


def test_vat_rule_matches_existing_rounding():
    assert "(p_subtotal+5)/10" in BLOCKS["cinema_pg_vat"]


def test_engine_does_not_touch_existing_tables():
    # No ALTER/DROP/DELETE/UPDATE/INSERT against objects that are not cinema_pg_*.
    for m in re.finditer(r"\b(ALTER TABLE|DROP TABLE|TRUNCATE|DELETE FROM|UPDATE|INSERT INTO)\s+(?:ONLY\s+)?jw_dev\.(\w+)", SQL):
        target = m.group(2)
        assert target.startswith("cinema_pg_") or target == "%I", (m.group(0))
    assert not re.search(r"\bDROP\s+(SCHEMA|DATABASE|ROLE|OWNED)", SQL, re.I)


def test_engine_references_no_existing_object_except_the_two_identity_functions():
    # Stronger than the write-only check above: reads of the v92 ledger tables are also excluded.
    names = set(re.findall(r"\bjw_dev\.([a-z_0-9]+)", SQL))
    foreign = {n for n in names if not n.startswith("cinema_pg_")}
    assert foreign <= {"stage_identity_v84", "current_org_from_session"}, sorted(foreign)


def test_confirmed_history_is_append_only_or_guarded():
    for table in ("cinema_pg_audit", "cinema_pg_payment_reversals", "cinema_pg_delivery_items", "cinema_pg_statement_items"):
        assert table in SQL
    assert "cinema_pg_deny_change" in SQL and "cinema_pg_guard_update" in SQL


def test_state_transitions_are_table_driven():
    assert "cinema_pg_transitions" in SQL
    for edge in ("'draft'", "'submitted'", "'approved'"):
        assert edge in SQL


def test_approvals_require_admin_role():
    for name in ("cinema_pg_delivery_confirm", "cinema_pg_statement_confirm", "cinema_pg_invoice_review",
                 "cinema_pg_invoice_confirm", "cinema_pg_payment_record", "cinema_pg_payment_reverse"):
        assert "cinema_pg_require_admin" in BLOCKS[name], name


def test_delivery_confirmation_demands_evidence_and_second_person():
    block = BLOCKS["cinema_pg_delivery_confirm"]
    assert "d.recorded_by = c.o_actor" in block and "cinema_pg_require_admin" in block
    table = SQL[SQL.index("CREATE TABLE jw_dev.cinema_pg_deliveries"):SQL.index("CREATE TABLE jw_dev.cinema_pg_delivery_items")]
    assert "evidence_sha256 text NOT NULL CHECK(evidence_sha256 ~ '^[0-9a-f]{64}$')" in table
    assert "approved_by<>recorded_by" in table  # also enforced by a table CHECK


def test_trace_reports_honesty_flags():
    block = BLOCKS["cinema_pg_trade_trace"]
    for flag in ("bank_settlement_confirmed", "internal_record_only", "human_admin_attested_evidence_hash", "release_ready"):
        assert flag in block, flag


def test_idempotency_reserves_request_before_work():
    block = BLOCKS["cinema_pg_begin"]
    assert block.index("INSERT INTO jw_dev.cinema_pg_requests") < block.index("o_replay_type := r.entity_type")
    assert "ON CONFLICT (org_id,request_id) DO NOTHING" in block


def test_mutating_row_reads_use_row_locks():
    for name in ("cinema_pg_delivery_record", "cinema_pg_payment_record", "cinema_pg_invoice_confirm",
                 "cinema_pg_statement_confirm", "cinema_pg_order_create"):
        assert "FOR UPDATE" in BLOCKS[name], name


def test_test_sql_has_minimum_named_checks_and_no_placeholder_pass():
    names = re.findall(r"'(G[235]\.[A-Za-z0-9_]+)'", TEST_SQL)
    assert len(set(names)) >= 100
    assert not re.search(r"ok\([^;]*,\s*(true|1=1)\s*[,)]", TEST_SQL, re.I)


def test_evidence_table_rehashes_content_and_checks_type_and_magic_bytes():
    table = SQL[SQL.index("CREATE TABLE jw_dev.cinema_pg_evidence_files"):SQL.index("CREATE TABLE jw_dev.cinema_pg_deliveries")]
    assert "CHECK(content_sha256=encode(sha256(content),'hex'))" in table
    assert "CHECK(octet_length(content)=size_bytes)" in table
    assert "BETWEEN 1 AND 5242880" in table
    assert "'application/pdf','image/png','image/jpeg'" in table
    assert "\\x255044462d" in table and "\\x89504e470d0a1a0a" in table and "\\xffd8ff" in table


def test_delivery_row_is_bound_to_a_stored_evidence_file_by_foreign_key():
    table = SQL[SQL.index("CREATE TABLE jw_dev.cinema_pg_deliveries"):SQL.index("CREATE UNIQUE INDEX cinema_pg_delivery_evidence_uq")]
    assert "FOREIGN KEY(org_id,evidence_sha256) REFERENCES jw_dev.cinema_pg_evidence_files(org_id,content_sha256)" in table


def test_writer_never_gets_the_file_bytes_column():
    grant = re.search(r"GRANT SELECT \(([^)]*)\)\s+ON jw_dev\.cinema_pg_evidence_files TO jw_cinema_writer", SQL)
    assert grant and "content," not in grant.group(1) + "," and "content_sha256" in grant.group(1)


def test_record_requires_stored_evidence_uploaded_by_recorder_and_confirm_requires_open():
    record = BLOCKS["cinema_pg_delivery_record"]
    assert "cinema_pg_evidence_files" in record and "ef.uploaded_by <> c.o_actor" in record and "ef.file_name" in record
    confirm = BLOCKS["cinema_pg_delivery_confirm"]
    assert "a.action='evidence_open'" in confirm and "a.actor_id=c.o_actor" in confirm


def test_evidence_open_is_audited_and_limited_to_admin_or_uploader():
    block = BLOCKS["cinema_pg_evidence_open"]
    assert "'evidence_open'" in block and "o_role IS DISTINCT FROM 'admin'" in block and "uploaded_by IS DISTINCT FROM c.o_actor" in block


def test_evidence_open_must_postdate_specific_delivery_record():
    """Block reuse of a valid older audit entry from the same evidence file."""
    confirm = BLOCKS["cinema_pg_delivery_confirm"]
    assert "a.created_at >= d.recorded_at" in confirm
    assert "G3.91_pre_delivery_file_open_does_not_authorize_delivery_confirmation" in TEST_SQL
