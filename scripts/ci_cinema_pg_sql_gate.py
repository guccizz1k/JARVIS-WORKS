#!/usr/bin/env python3
"""Disposable-PostgreSQL gate for the CINEMA trade write engine.

Standard library + the `psql` client only (no psycopg/FastAPI needed).

Safety: refuses to run unless JW_CINEMA_PG_DISPOSABLE=1 AND the server is local
(unix socket path, localhost or loopback). It creates its own throw-away
database, never touches existing databases, and drops it afterwards.

Environment: PGHOST (socket dir or loopback), PGPORT, PGUSER (a superuser of the
disposable cluster), optional PGPASSWORD. Nothing here is a production credential.

Coverage reported honestly: this proves SQL-level behaviour only. It does NOT
prove HTTP routes, browser behaviour, UI preservation, OCR, restore/RPO or any
hosted deployment.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE_FILES = (
    "db/review/ci_v90_ephemeral_pg_schema.sql",
    "db/review/ci_qa_001_jw_dev_secure_messenger_directory.sql",
    "db/review/ci_qa_002_jw_dev_messenger_rpc.sql",
    "db/review/ci_qa_006_commit_order_cursor_guard_candidate.sql",
    "db/review/ci_v92_quote_ephemeral.sql",
)
# JW_CINEMA_ENGINE_SQL lets mutation checks point the gate at a deliberately broken copy.
ENGINE = os.environ.get("JW_CINEMA_ENGINE_SQL", "scripts/review/cinema_pg_write_engine.sql")
TESTS = "scripts/review/cinema_pg_write_engine_test.sql"
NOTICE = re.compile(r"TEST\|([^|\r\n]+)\|(PASS|FAIL)\|([^\r\n]*)")
MIN_PER_GATE = {"G2": 20, "G3": 20, "G5": 20}
# Exact inventory (in addition to the per-gate minimums): a test that silently disappears from the SQL test script or from this file
# (e.g. a deleted PERFORM line) used to leave the gate green with 221/221. Every name below must be reported exactly once, nothing else.
EXPECTED_RESULT_NAMES = (
    'G5.M1_migration_executor_owner_membership_revoked',
    'G1.01_engine_refuses_second_install',
    'G2.01_partner_create',
    'G2.02_partner_update_bumps_version',
    'G2.03_partner_without_business_number',
    'G2.04_member_creates_draft_quote',
    'G2.05_draft_quote_update_replaces_lines',
    'G2.06_submit_quote',
    'G2.07_admin_approves_quote',
    'G2.08_order_from_approved_quote',
    'G2.09_quote_marked_ordered',
    'G2.10_partial_delivery_recorded_pending',
    'G2.11_delivery_confirmed_by_other_admin',
    'G2.12_order_stays_open_after_partial',
    'G2.13_full_confirmation_fulfils_order',
    'G2.14_statement1_money',
    'G2.15_statement2_money',
    'G2.16_statement_confirmed',
    'G2.17_invoice_draft_from_statement',
    'G2.18_invoice_reviewed',
    'G2.19_invoice_confirmed',
    'G2.20_partial_payment_recorded',
    'G2.21_balance_after_partial',
    'G2.22_balance_zero_when_fully_paid',
    'G2.23_payment_reversal_restores_balance',
    'G2.24_trace_links_every_document',
    'G2.25_trace_never_claims_bank_settlement',
    'G2.26_trace_reports_measured_seconds_only',
    'G2.27_integrity_check_clean_after_full_flow',
    'G2.28_trace_audit_has_one_row_per_state_change',
    'G2.29_second_trade_gets_next_number',
    'G2.30_pending_delivery_cancel',
    'G2.31_cancel_releases_reserved_quantity',
    'G2.32_exempt_statement_has_zero_vat',
    'G2.33_reverse_delivery_blocked_while_statement_active',
    'G2.34_void_invoice_blocked_with_active_payment',
    'G2.35_invoice_void_after_payment_reversal',
    'G2.36_statement_void_after_invoice_void',
    'G2.37_confirmed_delivery_reversed_not_deleted',
    'G2.38_reversal_reopens_order',
    'G2.39_statement_on_reversed_delivery_blocked',
    'G2.41_vat_helper_matches_existing_rule',
    'G3.01_partner_replay_same_entity_no_duplicate',
    'G3.02_quote_replay_no_duplicate_and_no_extra_trade_number',
    'G3.03_payment_replay_posts_once',
    'G3.04_request_id_reused_with_different_payload',
    'G3.05_request_id_too_short',
    'G3.06_request_id_bad_characters',
    'G3.07_stale_partner_version',
    'G3.08_stale_quote_version',
    'G3.09_overpayment_by_one_krw_blocked',
    'G3.10_duplicate_payment_reference_new_request',
    'G3.11_zero_payment_blocked',
    'G3.12_negative_payment_blocked',
    'G3.13_future_dated_payment_blocked',
    'G3.14_quote_line_fractional_quantity',
    'G3.15_quote_line_fractional_price',
    'G3.16_quote_line_string_quantity',
    'G3.17_quote_line_negative_price',
    'G3.18_quote_line_quantity_over_limit',
    'G3.19_quote_line_price_over_limit',
    'G3.20_quote_with_41_lines',
    'G3.21_quote_with_empty_name_line',
    'G3.22_quote_with_no_lines',
    'G3.23_quote_items_not_an_array',
    'G3.24_quote_invalid_vat_mode',
    'G3.25_approve_draft_without_submit_is_illegal_transition',
    'G3.26_failed_create_leaves_no_partial_rows',
    'G3.27_failed_request_id_is_reusable_after_rollback',
    'G3.28_delivery_on_fulfilled_order_blocked',
    'G3.29_delivery_exceeding_remaining_blocked',
    'G3.30_delivery_zero_quantity_blocked',
    'G3.31_delivery_fractional_quantity_blocked',
    'G3.32_delivery_without_evidence_hash_blocked',
    'G3.33_delivery_with_malformed_evidence_hash_blocked',
    'G3.34_delivery_duplicate_line_in_one_request_blocked',
    'G3.35_delivery_item_from_another_order_blocked',
    'G3.36_pending_delivery_reserves_quantity',
    'G3.37_same_evidence_hash_cannot_back_two_deliveries',
    'G3.38_recorder_cannot_confirm_own_delivery',
    'G3.39_statement_from_unconfirmed_delivery_blocked',
    'G3.40_second_active_statement_for_same_delivery_blocked',
    'G3.41_second_active_invoice_for_same_statement_blocked',
    'G3.42_invoice_from_voided_statement_blocked',
    'G3.43_confirm_invoice_before_review_blocked',
    'G3.43b_payment_on_unconfirmed_invoice_blocked',
    'G3.44_order_from_unapproved_quote_blocked',
    'G3.45_second_order_from_same_quote_blocked',
    'G3.46_payment_on_voided_invoice_blocked',
    'G3.47_double_reversal_of_payment_blocked',
    'G3.48_cancel_confirmed_delivery_blocked',
    'G3.49_void_statement_with_active_invoice_blocked',
    'G3.50_writer_cannot_insert_payment_directly',
    'G3.51_writer_cannot_update_invoice_directly',
    'G3.52_writer_cannot_delete_audit',
    'G3.53_writer_cannot_forge_confirmed_statement',
    'G3.54_confirmed_statement_total_immutable_even_for_superuser',
    'G3.55_audit_rows_cannot_be_updated',
    'G3.56_audit_rows_cannot_be_deleted',
    'G3.57_payment_rows_are_append_only',
    'G3.58_confirmed_delivery_cannot_go_back_to_recorded',
    'G3.59_delivery_evidence_hash_immutable',
    'G3.60_approved_quote_content_frozen',
    'G3.61_order_items_are_append_only',
    'G3.62_quote_items_frozen_after_draft',
    'G3.63_voided_statement_cannot_be_reactivated',
    'G3.64_bank_confirmed_cannot_be_true',
    'G3.65_cross_tenant_foreign_key_rejected_even_for_superuser',
    'G3.66_deleting_a_partner_is_not_possible',
    'G3.67_invoice_confirm_rejects_total_that_differs_from_statement',
    'G3.68_integrity_check_detects_tampered_invoice',
    'G3.69_statement_confirm_rejects_totals_that_differ_from_delivery_source',
    'G3.70_statement_confirms_once_totals_are_restored',
    'G3.71_server_recomputes_evidence_sha256',
    'G3.72_identical_content_is_stored_once_per_tenant',
    'G3.73_same_request_replays_without_new_row',
    'G3.74_request_id_reused_for_different_file',
    'G3.75_empty_evidence_rejected',
    'G3.76_oversize_evidence_rejected',
    'G3.77_unlisted_content_type_rejected',
    'G3.78_content_not_matching_declared_type_rejected',
    'G3.79_blank_file_name_rejected',
    'G3.90_admin_opened_evidence_before_delivery_recorded',
    'G3.80_delivery_with_never_uploaded_evidence_hash_blocked',
    'G3.81_evidence_uploaded_by_someone_else_cannot_back_my_delivery',
    'G3.91_pre_delivery_file_open_does_not_authorize_delivery_confirmation',
    'G3.92_pre_delivery_open_test_can_cancel_pending_delivery',
    'G3.82_delivery_stores_server_file_name_not_client_name',
    'G3.83_confirm_without_opening_stored_evidence_blocked',
    'G3.84_another_admins_open_does_not_count',
    'G3.85_open_returns_exact_stored_bytes_and_matching_hash',
    'G3.86_confirm_succeeds_after_this_admin_opened_the_file',
    'G3.87_every_open_is_audited_with_actor',
    'G3.88_member_cannot_open_evidence_uploaded_by_another_user',
    'G3.89_uploader_can_open_own_file',
    'G5.S1_writer_cannot_read_file_bytes_directly',
    'G5.S2_writer_cannot_insert_evidence_directly',
    'G5.S3_writer_sees_evidence_metadata_only_for_own_tenant',
    'G5.S4_other_tenant_cannot_open_evidence',
    'G5.S5_other_tenant_cannot_see_evidence_metadata',
    'G5.S6_stored_evidence_bytes_cannot_be_replaced_even_by_superuser',
    'G5.S7_database_rejects_hash_that_does_not_match_the_bytes',
    'G5.S8_delivery_cannot_point_at_a_missing_evidence_file',
    'G5.01_tenant_b_has_independent_trade_numbering',
    'G5.02_each_tenant_sees_only_own_partners',
    'G5.03_tenant_c_sees_no_foreign_quotes',
    'G5.04_b_cannot_update_a_quote',
    'G5.05_b_cannot_transition_a_quote',
    'G5.06_b_cannot_create_order_from_a_quote',
    'G5.07_b_cannot_record_delivery_on_a_order',
    'G5.08_b_cannot_confirm_a_delivery',
    'G5.09_b_cannot_confirm_a_statement',
    'G5.10_b_cannot_confirm_an_invoice',
    'G5.11_b_cannot_pay_a_invoice',
    'G5.12_b_cannot_reverse_a_payment',
    'G5.13_b_cannot_trace_a_trade_number_it_does_not_own',
    'G5.13b_same_trade_number_shows_only_own_documents',
    'G5.14_b_cannot_quote_with_a_partner',
    'G5.15_b_cannot_update_a_partner',
    'G5.16_b_cannot_cancel_a_delivery',
    'G5.17_request_ids_are_tenant_scoped',
    'G5.18_member_cannot_approve_quote',
    'G5.19_member_cannot_create_order',
    'G5.20_member_cannot_confirm_delivery',
    'G5.21_member_cannot_confirm_statement',
    'G5.22_member_cannot_review_invoice',
    'G5.23_member_cannot_record_payment',
    'G5.24_member_cannot_reverse_payment',
    'G5.25_member_cannot_void_invoice',
    'G5.26_member_cannot_reverse_delivery',
    'G5.27_empty_session_rejected',
    'G5.28_unknown_session_rejected',
    'G5.29_expired_session_rejected',
    'G5.30_expired_session_cannot_read_integrity',
    'G5.31_no_session_sees_zero_rows_in_tables',
    'G5.32_writer_cannot_read_idempotency_table',
    'G5.33_writer_cannot_read_trade_counters',
    'G5.34_writer_cannot_read_transition_table',
    'G5.35_writer_cannot_call_internal_audit_helper',
    'G5.36_writer_cannot_call_internal_begin_helper',
    'G5.38_anon_cannot_execute_api',
    'G5.39_anon_cannot_read_tables',
    'G5.40_generic_trade_role_cannot_execute_engine',
    'G5.41_generic_trade_role_cannot_read_engine_tables',
    'G5.42_sql_metacharacters_stored_as_data',
    'G5.43_integrity_clean_for_tenant_a',
    'G5.44_integrity_clean_for_tenant_b',
    'G5.45_tenant_b_sees_only_own_audit_rows',
    'G5.46_audit_covers_all_entity_types',
    'G5.47_no_audit_row_lacks_actor_or_request',
    'G5.48_all_tenant_tables_force_rls',
    'G5.49_no_engine_table_is_readable_by_public',
    'G5.50_owner_role_cannot_log_in_or_bypass_rls',
    'G3.C1_identical_concurrent_requests_create_one_row',
    'G3.C2_concurrent_deliveries_cannot_oversell',
    'G3.C3_concurrent_confirmations_apply_once',
    'G3.C4_concurrent_quotes_get_unique_gapless_trade_numbers',
    'G3.C5_concurrent_payments_cannot_overpay',
    'G3.C6_integrity_clean_after_concurrency',
    'G3.D1_payment_in_flight_blocks_second_payment_on_same_invoice',
    'G3.D2_delivery_in_flight_blocks_second_record_on_same_order',
    'G3.D4_concurrent_delivery_waits_then_succeeds_with_next_sequence',
    'G3.D5_concurrent_delivery_sees_holder_reservation_and_is_refused',
    'G3.D3_delivery_confirmation_in_flight_blocks_new_record_on_same_order',
    'G5.L1_login_role_without_set_role_cannot_run_engine',
    'G5.L2_login_role_works_after_set_role',
    'G5.L3_login_role_has_no_direct_table_access',
    'G5.L4_login_role_is_unprivileged',
    'G5.L5_login_role_cannot_become_owner',
    'G5.S4_00_runtime_predicate_exists_exactly_once',
    'G5.S4_01_synthetic_legacy_fixtures_initialized',
    'G5.S4_02_all_empty_tenant_a',
    'G5.S4_03_all_empty_tenant_b',
    'G5.S4_05_quote_blocks_same_tenant',
    'G5.S4_06_other_tenant_not_blocked_by_quote',
    'G5.S4_09_order_blocks_same_tenant',
    'G5.S4_10_other_tenant_not_blocked_by_order',
    'G5.S4_13_invoice_blocks_same_tenant',
    'G5.S4_14_other_tenant_not_blocked_by_invoice',
    'G5.S4_17_payment_blocks_same_tenant',
    'G5.S4_18_other_tenant_not_blocked_by_payment',
    'G5.S4_20_cleanup_preserves_no_legacy_collision',
)


def gate_verdict(results: list[dict]) -> dict:
    """Pure verdict (unit-tested without a database): PASS only if every expected check was reported exactly once with PASS,
    nothing unexpected was reported, and every gate reaches its minimum."""
    names = [r["name"] for r in results]
    duplicates = [n for n, c in Counter(names).items() if c > 1]
    per_gate = Counter(r["name"].split(".")[0] for r in results)
    failed = [r for r in results if r["result"] != "PASS"]
    coverage_gaps = {g: f"{per_gate.get(g, 0)} < {need}" for g, need in MIN_PER_GATE.items() if per_gate.get(g, 0) < need}
    expected_set = set(EXPECTED_RESULT_NAMES)
    missing = [n for n in EXPECTED_RESULT_NAMES if n not in names]
    unexpected = [n for n in names if n not in expected_set]
    exact = not missing and not unexpected and len(results) == len(EXPECTED_RESULT_NAMES) == len(expected_set)
    overall = "PASS" if not failed and not duplicates and not coverage_gaps and exact else "FAIL"
    return {"overall": overall, "duplicates": duplicates, "per_gate": per_gate, "failed": failed, "coverage_gaps": coverage_gaps,
            "missing": missing, "unexpected": unexpected}


def local_server_or_die() -> None:
    host = os.environ.get("PGHOST", "")
    if os.environ.get("JW_CINEMA_PG_DISPOSABLE") != "1":
        raise SystemExit("BLOCKED: set JW_CINEMA_PG_DISPOSABLE=1 to confirm a throw-away local cluster")
    if not (host.startswith("/") or host in ("localhost", "127.0.0.1", "::1")):
        raise SystemExit("BLOCKED: PGHOST must be a unix socket directory or loopback address")
    if not shutil.which("psql"):
        raise SystemExit("BLOCKED: psql client not found")


class Psql:
    def __init__(self, dbname: str = "postgres", user: str | None = None, password: str | None = None):
        self.dbname, self.user, self.password = dbname, user, password

    def _cmd(self, *extra: str) -> tuple[list[str], dict]:
        env = dict(os.environ)
        if self.password:
            env["PGPASSWORD"] = self.password
        cmd = ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", self.dbname]
        if self.user:
            cmd += ["-U", self.user]
        return cmd + list(extra), env

    def file(self, path: str, single_transaction: bool = False) -> subprocess.CompletedProcess:
        extra = (["--single-transaction"] if single_transaction else []) + ["-f", str(ROOT / path)]
        cmd, env = self._cmd(*extra)
        return subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=600)

    def sql(self, *statements: str, tuples: bool = True) -> subprocess.CompletedProcess:
        extra = ["-A", "-t"] if tuples else []
        for s in statements:
            extra += ["-c", s]
        cmd, env = self._cmd(*extra)
        return subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=600)


def sqlstate_of(stderr: str) -> str:
    match = re.search(r"SQLSTATE[: ]+([0-9A-Z]{5})", stderr)
    if match:
        return match.group(1)
    mapping = (("permission denied", "42501"), ("not found", "P0002"), ("overpayment", "23514"),
               ("is stale", "40001"), ("already", "23505"), ("administrator", "42501"),
               ("valid session", "42501"))
    for needle, code in mapping:
        if needle in stderr:
            return code
    return "?????"


def ev_sha(db: Psql, session: str, text: str) -> str:
    """Store synthetic evidence on the server as `session`; return the SHA-256 the SERVER stored."""
    content = "%PDF-1.4 " + text
    sha = hashlib.sha256(content.encode()).hexdigest()
    proc = as_writer(db, session,
        f"SELECT jw_dev.cinema_pg_evidence_put('rq-ev-{sha[:40]}','{text}.pdf','application/pdf',convert_to('{content}','UTF8'))")
    if proc.returncode != 0:
        raise RuntimeError("evidence upload failed: " + proc.stderr.strip()[:300])
    return sha


def open_ev(db: Psql, session: str, delivery: str, tag: str) -> None:
    """The audited administrator 'open the evidence' step that delivery confirmation requires."""
    proc = as_writer(db, session,
        f"SELECT count(*) FROM jw_dev.cinema_pg_evidence_open('rq-vw-{tag}',"
        f"(SELECT e.id FROM jw_dev.cinema_pg_evidence_files e JOIN jw_dev.cinema_pg_deliveries d "
        f"ON d.org_id=e.org_id AND d.evidence_sha256=e.content_sha256 WHERE d.id='{delivery}'))")
    if proc.returncode != 0:
        raise RuntimeError("evidence open failed: " + proc.stderr.strip()[:300])


def as_writer(db: Psql, session: str, statement: str) -> subprocess.CompletedProcess:
    return db.sql("SET ROLE jw_cinema_writer",
                  f"SELECT set_config('jw.session_hash','{session}',false)",
                  statement)


def entity_id(proc: subprocess.CompletedProcess) -> str:
    if proc.returncode != 0:
        raise RuntimeError("setup call failed: " + proc.stderr.strip()[:300])
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    return lines[-1].strip()


def run_parallel(count: int, work) -> list:
    results: list = [None] * count
    barrier = threading.Barrier(count)

    def runner(i: int) -> None:
        barrier.wait()
        results[i] = work(i)

    threads = [threading.Thread(target=runner, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def concurrency_checks(db: Psql, record) -> None:
    N = 8
    ev = lambda s: "'" + ev_sha(db, "hash_a_member", s) + "'"  # noqa: E731  (server-stored evidence)

    # C1: identical request id fired concurrently -> exactly one partner row
    rid = "rq-conc-" + secrets.token_hex(6)
    out = run_parallel(N, lambda i: as_writer(db, "hash_a_admin1",
        f"SELECT jw_dev.cinema_pg_partner_upsert('{rid}',NULL,'Conc Partner',"
        f"'7770001112','','','',NULL)->'entity'->>'id'"))
    ids = {entity_id(p) for p in out if p.returncode == 0}
    rows = int(db.sql("SELECT count(*) FROM jw_dev.cinema_pg_partners WHERE name='Conc Partner'").stdout.strip())
    record("G3.C1_identical_concurrent_requests_create_one_row",
           rows == 1 and len(ids) == 1, f"rows={rows} distinct_ids={len(ids)} ok_calls={sum(p.returncode == 0 for p in out)}/{N}")

    # shared fixture: partner -> quote (qty 5 @ 1000, exempt) -> approved -> order
    partner = entity_id(as_writer(db, "hash_a_admin1",
        "SELECT jw_dev.cinema_pg_partner_upsert('rq-conc-fx-p',NULL,'Conc Fixture','7770002223','','','',NULL)->'entity'->>'id'"))
    quote = entity_id(as_writer(db, "hash_a_admin1",
        f"SELECT jw_dev.cinema_pg_quote_create('rq-conc-fx-q','{partner}','Conc Q','exempt',"
        "'[{\"name\":\"Part\",\"quantity\":5,\"unit_price\":1000}]'::jsonb)->'entity'->>'id'"))
    as_writer(db, "hash_a_admin1", f"SELECT jw_dev.cinema_pg_quote_transition('rq-conc-fx-q2','{quote}',1,'submitted')")
    as_writer(db, "hash_a_admin1", f"SELECT jw_dev.cinema_pg_quote_transition('rq-conc-fx-q3','{quote}',2,'approved')")
    order = entity_id(as_writer(db, "hash_a_admin1",
        f"SELECT jw_dev.cinema_pg_order_create('rq-conc-fx-o','{quote}')->'entity'->>'id'"))
    item = entity_id(db.sql(f"SELECT id FROM jw_dev.cinema_pg_order_items WHERE order_id='{order}'"))
    # (reads through superuser here only to obtain an id for the fixture)

    # C2: 8 concurrent deliveries of qty 1 against 5 units -> exactly 5 succeed
    def deliver(i: int):
        return as_writer(db, "hash_a_member",
            f"SELECT jw_dev.cinema_pg_delivery_record('rq-conc-dl-{i}-{rid}','{order}',"
            f"'[{{\"order_item_id\":\"{item}\",\"quantity\":1}}]'::jsonb,{ev(f'conc-ev-{i}-{rid}')},'c{i}.pdf')->'entity'->>'id'")
    out = run_parallel(N, deliver)
    ok = [p for p in out if p.returncode == 0]
    reserved = int(db.sql(
        f"SELECT coalesce(sum(di.quantity),0) FROM jw_dev.cinema_pg_delivery_items di "
        f"JOIN jw_dev.cinema_pg_deliveries d ON d.id=di.delivery_id WHERE d.order_id='{order}' "
        "AND d.status IN ('recorded','confirmed')").stdout.strip())
    record("G3.C2_concurrent_deliveries_cannot_oversell",
           len(ok) == 5 and reserved == 5, f"succeeded={len(ok)}/{N} reserved_units={reserved} (ordered 5)")
    delivery_ids = [entity_id(p) for p in ok]

    # C3: concurrent confirmations of the same delivery -> exactly one wins
    target = delivery_ids[0]
    open_ev(db, "hash_a_admin1", target, "c3a" + rid[-8:])
    open_ev(db, "hash_a_admin2", target, "c3b" + rid[-8:])
    out = run_parallel(6, lambda i: as_writer(db, "hash_a_admin1" if i % 2 == 0 else "hash_a_admin2",
        f"SELECT jw_dev.cinema_pg_delivery_confirm('rq-conc-cf-{i}-{rid}','{target}')->'entity'->>'status'"))
    wins = [p for p in out if p.returncode == 0]
    status = db.sql(f"SELECT status FROM jw_dev.cinema_pg_deliveries WHERE id='{target}'").stdout.strip()
    record("G3.C3_concurrent_confirmations_apply_once",
           len(wins) == 1 and status == "confirmed", f"winners={len(wins)}/6 final_status={status}")

    # C4: concurrent quote creation -> distinct, gapless trade numbers
    base = int(db.sql("SELECT count(*) FROM jw_dev.cinema_pg_quotes WHERE org_id='ci-a'").stdout.strip())
    out = run_parallel(N, lambda i: as_writer(db, "hash_a_admin1",
        f"SELECT jw_dev.cinema_pg_quote_create('rq-conc-tn-{i}-{rid}','{partner}','TN{i}','exempt',"
        "'[{\"name\":\"x\",\"quantity\":1,\"unit_price\":1}]'::jsonb)->'entity'->>'trade_no'"))
    nos = [entity_id(p) for p in out if p.returncode == 0]
    seqs = sorted(int(n.rsplit("-", 1)[1]) for n in nos)
    record("G3.C4_concurrent_quotes_get_unique_gapless_trade_numbers",
           len(nos) == N and len(set(nos)) == N and seqs == list(range(seqs[0], seqs[0] + N)),
           f"numbers={seqs} existing_quotes_before={base}")

    # C5: payments racing for the same balance -> exactly one full payment lands
    stmt_delivery = delivery_ids[0]
    st = entity_id(as_writer(db, "hash_a_member",
        f"SELECT jw_dev.cinema_pg_statement_create('rq-conc-st-{rid}','{stmt_delivery}')->'entity'->>'id'"))
    as_writer(db, "hash_a_admin1", f"SELECT jw_dev.cinema_pg_statement_confirm('rq-conc-stc-{rid}','{st}')")
    inv = entity_id(as_writer(db, "hash_a_member",
        f"SELECT jw_dev.cinema_pg_invoice_create('rq-conc-iv-{rid}','{st}')->'entity'->>'id'"))
    as_writer(db, "hash_a_admin1", f"SELECT jw_dev.cinema_pg_invoice_review('rq-conc-ivr-{rid}','{inv}')")
    as_writer(db, "hash_a_admin1", f"SELECT jw_dev.cinema_pg_invoice_confirm('rq-conc-ivc-{rid}','{inv}')")
    out = run_parallel(N, lambda i: as_writer(db, "hash_a_admin1",
        f"SELECT jw_dev.cinema_pg_payment_record('rq-conc-pay-{i}-{rid}','{inv}',1000,current_date,'CONC-{i}-{rid}')->'entity'->>'id'"))
    paid = int(db.sql(f"SELECT coalesce(sum(amount_krw),0) FROM jw_dev.cinema_pg_payments WHERE invoice_id='{inv}'").stdout.strip())
    wins = sum(p.returncode == 0 for p in out)
    record("G3.C5_concurrent_payments_cannot_overpay",
           wins == 1 and paid == 1000, f"succeeded={wins}/{N} paid_krw={paid} invoice_total=1000")

    # C6: the integrity audit is clean after all of the above
    bad = db.sql("SET ROLE jw_cinema_writer",
                 "SELECT set_config('jw.session_hash','hash_a_admin1',false)",
                 "SELECT count(*) FROM jw_dev.cinema_pg_integrity_check()").stdout.strip().splitlines()[-1]
    record("G3.C6_integrity_clean_after_concurrency", bad == "0", f"violations={bad}")


def build_order(db: Psql, tag: str, quantity: int, price: int) -> tuple[str, str]:
    """Approved quote -> open order with one line. Returns (order_id, order_item_id)."""
    partner = entity_id(as_writer(db, "hash_a_admin1",
        f"SELECT jw_dev.cinema_pg_partner_upsert('rq-fx-p-{tag}',NULL,'FX {tag}','','','','',NULL)->'entity'->>'id'"))
    quote = entity_id(as_writer(db, "hash_a_admin1",
        f"SELECT jw_dev.cinema_pg_quote_create('rq-fx-q-{tag}','{partner}','FX {tag}','exempt',"
        f"'[{{\"name\":\"Part\",\"quantity\":{quantity},\"unit_price\":{price}}}]'::jsonb)->'entity'->>'id'"))
    as_writer(db, "hash_a_admin1", f"SELECT jw_dev.cinema_pg_quote_transition('rq-fx-q2-{tag}','{quote}',1,'submitted')")
    as_writer(db, "hash_a_admin1", f"SELECT jw_dev.cinema_pg_quote_transition('rq-fx-q3-{tag}','{quote}',2,'approved')")
    order = entity_id(as_writer(db, "hash_a_admin1",
        f"SELECT jw_dev.cinema_pg_order_create('rq-fx-o-{tag}','{quote}')->'entity'->>'id'"))
    item = entity_id(db.sql(f"SELECT id FROM jw_dev.cinema_pg_order_items WHERE order_id='{order}'"))
    return order, item


def timed_hold_and_probe(db: Psql, hold_sql: str, probe_sql: str, probe_timeout: str = "300ms") -> tuple[subprocess.CompletedProcess, subprocess.CompletedProcess]:
    """Session 1 runs hold_sql inside a transaction and keeps it open ~2.5s; session 2
    (lock_timeout 300ms) probes the same row after 0.8s. Deterministic lock-presence check."""
    holder: dict = {}

    def hold() -> None:
        holder["p"] = db.sql(
            "BEGIN; SET LOCAL ROLE jw_cinema_writer; SELECT set_config('jw.session_hash','hash_a_admin1',true); "
            + hold_sql + "; SELECT pg_sleep(2.5); COMMIT")

    t = threading.Thread(target=hold)
    t.start()
    time.sleep(0.8)
    probe = db.sql("SET ROLE jw_cinema_writer", f"SET lock_timeout='{probe_timeout}'",
                   "SELECT set_config('jw.session_hash','hash_a_admin1',false)", probe_sql)
    t.join()
    return holder["p"], probe


def deterministic_lock_checks(db: Psql, record) -> None:
    ev = lambda s: "'" + ev_sha(db, "hash_a_member", s) + "'"  # noqa: E731  (server-stored evidence)
    tag = secrets.token_hex(3)
    eva = lambda s: "'" + ev_sha(db, "hash_a_admin1", s) + "'"  # noqa: E731  (hold/probe sessions run as admin1)

    # D1: a payment in flight holds the invoice row; a second payment must wait (not race).
    order, item = build_order(db, "d1" + tag, 4, 1000)
    dl = entity_id(as_writer(db, "hash_a_member",
        f"SELECT jw_dev.cinema_pg_delivery_record('rq-d1-dl-{tag}','{order}',"
        f"'[{{\"order_item_id\":\"{item}\",\"quantity\":4}}]'::jsonb,{ev('d1-ev-' + tag)},'d1.pdf')->'entity'->>'id'"))
    open_ev(db, "hash_a_admin1", dl, "d1" + tag)
    as_writer(db, "hash_a_admin1", f"SELECT jw_dev.cinema_pg_delivery_confirm('rq-d1-dc-{tag}','{dl}')")
    st = entity_id(as_writer(db, "hash_a_member", f"SELECT jw_dev.cinema_pg_statement_create('rq-d1-st-{tag}','{dl}')->'entity'->>'id'"))
    as_writer(db, "hash_a_admin1", f"SELECT jw_dev.cinema_pg_statement_confirm('rq-d1-stc-{tag}','{st}')")
    inv = entity_id(as_writer(db, "hash_a_member", f"SELECT jw_dev.cinema_pg_invoice_create('rq-d1-iv-{tag}','{st}')->'entity'->>'id'"))
    as_writer(db, "hash_a_admin1", f"SELECT jw_dev.cinema_pg_invoice_review('rq-d1-ivr-{tag}','{inv}')")
    as_writer(db, "hash_a_admin1", f"SELECT jw_dev.cinema_pg_invoice_confirm('rq-d1-ivc-{tag}','{inv}')")
    hold, probe = timed_hold_and_probe(
        db,
        f"SELECT jw_dev.cinema_pg_payment_record('rq-d1-hold-{tag}','{inv}',1000,current_date,'D1-HOLD-{tag}')",
        f"SELECT jw_dev.cinema_pg_payment_record('rq-d1-probe-{tag}','{inv}',1000,current_date,'D1-PROBE-{tag}')")
    probed = db.sql(f"SELECT count(*) FROM jw_dev.cinema_pg_payments WHERE reference='D1-PROBE-{tag}'").stdout.strip()
    record("G3.D1_payment_in_flight_blocks_second_payment_on_same_invoice",
           hold.returncode == 0 and probe.returncode != 0 and "lock timeout" in probe.stderr and probed == "0",
           f"holder_rc={hold.returncode} probe_rc={probe.returncode} probe_err={probe.stderr.strip()[:80]!r} probe_rows={probed}")

    # D2: a delivery in flight holds the order row; a second record on that order must wait.
    order2, item2 = build_order(db, "d2" + tag, 4, 1000)
    hold, probe = timed_hold_and_probe(
        db,
        f"SELECT jw_dev.cinema_pg_delivery_record('rq-d2-hold-{tag}','{order2}',"
        f"'[{{\"order_item_id\":\"{item2}\",\"quantity\":1}}]'::jsonb,{eva('d2-hold-' + tag)},'h.pdf')",
        f"SELECT jw_dev.cinema_pg_delivery_record('rq-d2-probe-{tag}','{order2}',"
        f"'[{{\"order_item_id\":\"{item2}\",\"quantity\":1}}]'::jsonb,{eva('d2-probe-' + tag)},'p.pdf')")
    record("G3.D2_delivery_in_flight_blocks_second_record_on_same_order",
           hold.returncode == 0 and probe.returncode != 0 and "lock timeout" in probe.stderr,
           f"holder_rc={hold.returncode} probe_rc={probe.returncode} probe_err={probe.stderr.strip()[:80]!r}")

    # D4: serialised, not rejected: with the order lock the waiting request is re-evaluated after
    # the holder commits and succeeds with the next sequence number.
    order4, item4 = build_order(db, "d4" + tag, 4, 1000)
    hold, probe = timed_hold_and_probe(
        db,
        f"SELECT jw_dev.cinema_pg_delivery_record('rq-d4-hold-{tag}','{order4}',"
        f"'[{{\"order_item_id\":\"{item4}\",\"quantity\":1}}]'::jsonb,{eva('d4-hold-' + tag)},'h.pdf')",
        f"SELECT jw_dev.cinema_pg_delivery_record('rq-d4-probe-{tag}','{order4}',"
        f"'[{{\"order_item_id\":\"{item4}\",\"quantity\":1}}]'::jsonb,{eva('d4-probe-' + tag)},'p.pdf')",
        probe_timeout="10s")
    seqs = db.sql(f"SELECT string_agg(seq::text,',' ORDER BY seq) FROM jw_dev.cinema_pg_deliveries WHERE order_id='{order4}'").stdout.strip()
    record("G3.D4_concurrent_delivery_waits_then_succeeds_with_next_sequence",
           hold.returncode == 0 and probe.returncode == 0 and seqs == "1,2",
           f"holder_rc={hold.returncode} probe_rc={probe.returncode} seqs={seqs} err={probe.stderr.strip()[:80]!r}")

    # D5: the waiting request sees the holder's reservation and is refused for exceeding the remainder.
    order5, item5 = build_order(db, "d5" + tag, 4, 1000)
    hold, probe = timed_hold_and_probe(
        db,
        f"SELECT jw_dev.cinema_pg_delivery_record('rq-d5-hold-{tag}','{order5}',"
        f"'[{{\"order_item_id\":\"{item5}\",\"quantity\":3}}]'::jsonb,{eva('d5-hold-' + tag)},'h.pdf')",
        f"SELECT jw_dev.cinema_pg_delivery_record('rq-d5-probe-{tag}','{order5}',"
        f"'[{{\"order_item_id\":\"{item5}\",\"quantity\":2}}]'::jsonb,{eva('d5-probe-' + tag)},'p.pdf')",
        probe_timeout="10s")
    record("G3.D5_concurrent_delivery_sees_holder_reservation_and_is_refused",
           hold.returncode == 0 and probe.returncode != 0 and "exceeds remaining quantity (1)" in probe.stderr,
           f"holder_rc={hold.returncode} probe_rc={probe.returncode} err={probe.stderr.strip()[:100]!r}")

    # D3: confirming a delivery takes the order lock too (so it cannot interleave with a record).
    order3, item3 = build_order(db, "d3" + tag, 4, 1000)
    pending = entity_id(as_writer(db, "hash_a_member",
        f"SELECT jw_dev.cinema_pg_delivery_record('rq-d3-dl-{tag}','{order3}',"
        f"'[{{\"order_item_id\":\"{item3}\",\"quantity\":1}}]'::jsonb,{ev('d3-ev-' + tag)},'d3.pdf')->'entity'->>'id'"))
    open_ev(db, "hash_a_admin1", pending, "d3" + tag)
    hold, probe = timed_hold_and_probe(
        db,
        f"SELECT jw_dev.cinema_pg_delivery_confirm('rq-d3-hold-{tag}','{pending}')",
        f"SELECT jw_dev.cinema_pg_delivery_record('rq-d3-probe-{tag}','{order3}',"
        f"'[{{\"order_item_id\":\"{item3}\",\"quantity\":1}}]'::jsonb,{eva('d3-probe-' + tag)},'p.pdf')")
    record("G3.D3_delivery_confirmation_in_flight_blocks_new_record_on_same_order",
           hold.returncode == 0 and probe.returncode != 0 and "lock timeout" in probe.stderr,
           f"holder_rc={hold.returncode} probe_rc={probe.returncode} probe_err={probe.stderr.strip()[:80]!r}")


def login_role_checks(db_name: str, record) -> None:
    password = secrets.token_urlsafe(24)
    admin = Psql(db_name)
    r = admin.sql("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='jw_ci_cinema') THEN "
                  "CREATE ROLE jw_ci_cinema LOGIN NOINHERIT NOBYPASSRLS NOSUPERUSER NOCREATEROLE NOCREATEDB; END IF; END $$",
                  f"ALTER ROLE jw_ci_cinema PASSWORD '{password}'",
                  "GRANT jw_cinema_writer TO jw_ci_cinema WITH INHERIT FALSE, SET TRUE")
    if r.returncode != 0:
        record("G5.L0_login_role_setup", False, r.stderr.strip()[:200])
        return
    login = Psql(db_name, user="jw_ci_cinema", password=password)
    plain = login.sql("SELECT set_config('jw.session_hash','hash_a_admin1',false)",
                      "SELECT jw_dev.cinema_pg_trade_trace('x')")
    record("G5.L1_login_role_without_set_role_cannot_run_engine",
           plain.returncode != 0 and "permission denied" in plain.stderr, plain.stderr.strip()[:120])
    via = login.sql("SET ROLE jw_cinema_writer",
                    "SELECT set_config('jw.session_hash','hash_a_admin1',false)",
                    "SELECT count(*) FROM jw_dev.cinema_pg_integrity_check()")
    record("G5.L2_login_role_works_after_set_role",
           via.returncode == 0 and via.stdout.strip().splitlines()[-1] == "0", via.stderr.strip()[:120])
    direct = login.sql("SELECT count(*) FROM jw_dev.cinema_pg_quotes")
    record("G5.L3_login_role_has_no_direct_table_access",
           direct.returncode != 0 and "permission denied" in direct.stderr, direct.stderr.strip()[:120])
    attrs = admin.sql("SELECT rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb FROM pg_roles WHERE rolname='jw_ci_cinema'")
    record("G5.L4_login_role_is_unprivileged", attrs.stdout.strip() == "f")
    owner = login.sql("SET ROLE jw_cinema_owner")
    record("G5.L5_login_role_cannot_become_owner", owner.returncode != 0 and "permission denied" in owner.stderr)


def s4_legacy_collision_checks(db: Psql, record) -> None:
    """Execute the EXACT Python S4 predicate against disposable PG17 + FORCE RLS.

    All data is synthetic and in the already disposable database. No real
    role, tenant, customer or invoice is created or modified.
    """
    import ast

    tree = ast.parse((ROOT / "app/pg_cinema_register_v1.py").read_text(encoding="utf-8"))
    expressions = [
        n.value for n in tree.body
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "S4_LEGACY_COLLISION_SQL" for t in n.targets)
    ]
    if len(expressions) != 1:
        record("G5.S4_00_runtime_predicate_exists_exactly_once", False)
        return
    predicate = ast.literal_eval(expressions[0])
    expected = ("jw_dev.quotes", "jw_dev.orders", "jw_dev.invoices", "jw_dev.payments")
    if predicate.count("%s") != 4 or any(table not in predicate for table in expected):
        record("G5.S4_00_runtime_predicate_exists_exactly_once", False, "unexpected query")
        return
    record("G5.S4_00_runtime_predicate_exists_exactly_once", True, "same literal source as application")

    # The existing CI v92 fixture creates quotes only, while real jw_dev has
    # all four ledger tables. Add the three missing synthetic tables here.
    setup = [
        "CREATE TABLE jw_dev.orders(id text PRIMARY KEY, org_id text NOT NULL)",
        "CREATE TABLE jw_dev.invoices(id text PRIMARY KEY, org_id text NOT NULL)",
        "CREATE TABLE jw_dev.payments(id text PRIMARY KEY, org_id text NOT NULL)",
    ]
    for table in ("orders", "invoices", "payments"):
        setup += [
            f"ALTER TABLE jw_dev.{table} ENABLE ROW LEVEL SECURITY",
            f"ALTER TABLE jw_dev.{table} FORCE ROW LEVEL SECURITY",
            f"GRANT SELECT ON jw_dev.{table} TO jw_app_dev",
            f"CREATE POLICY s4_tenant_select ON jw_dev.{table} "
            "FOR SELECT TO jw_app_dev USING(org_id=jw_dev.current_org_from_session())",
        ]
    p = db.sql(*setup)
    if p.returncode != 0:
        record("G5.S4_01_synthetic_legacy_fixtures_initialized", False, p.stderr.strip()[:180])
        return
    record("G5.S4_01_synthetic_legacy_fixtures_initialized", True)

    sessions = {"ci-a": "hash_a_admin1", "ci-b": "hash_b_admin", "ci-c": "hash_c_admin"}

    def collision(org: str) -> tuple[bool | None, str]:
        # Exact runtime SQL literal; four fixed tenant parameters. Authentication
        # is done by V90 before it reaches this SQL in the real application.
        query = predicate.replace("%s", "'" + org + "'")
        p = db.sql("SET ROLE jw_app_dev",
                   f"SELECT set_config('jw.session_hash','{sessions[org]}',false)",
                   query)
        if p.returncode != 0:
            return None, p.stderr.strip()[:140]
        lines = [x.strip() for x in p.stdout.splitlines() if x.strip()]
        if not lines or lines[-1] not in ("t", "f"):
            return None, "nonboolean predicate result"
        return lines[-1] == "t", ""

    def expect(tag: str, org: str, value: bool) -> None:
        got, err = collision(org)
        record(tag, got is value, f"org={org} expected={value} actual={got} err={err}")

    def mutate(statement: str, tag: str) -> bool:
        p = db.sql(statement)
        if p.returncode != 0:
            record(tag, False, p.stderr.strip()[:180])
            return False
        return True

    expect("G5.S4_02_all_empty_tenant_a", "ci-a", False)
    expect("G5.S4_03_all_empty_tenant_b", "ci-b", False)
    if mutate(
        "INSERT INTO jw_dev.quotes(id,org_id,customer_id,customer_name_snapshot,doc_no,title,status,vat_mode,created_at,updated_at) "
        "VALUES ('s4-legacy-a','ci-a','ci-customer-a','S4 Synthetic','Q-S4-001','S4 synthetic','draft','exempt',now()::text,now()::text)",
        "G5.S4_04_seed_quote"
    ):
        expect("G5.S4_05_quote_blocks_same_tenant", "ci-a", True)
        expect("G5.S4_06_other_tenant_not_blocked_by_quote", "ci-b", False)
        mutate("DELETE FROM jw_dev.quotes WHERE id='s4-legacy-a'", "G5.S4_07_remove_quote")
    if mutate("INSERT INTO jw_dev.orders(id,org_id) VALUES('s4-order-a','ci-a')",
              "G5.S4_08_seed_order"):
        expect("G5.S4_09_order_blocks_same_tenant", "ci-a", True)
        expect("G5.S4_10_other_tenant_not_blocked_by_order", "ci-b", False)
        mutate("DELETE FROM jw_dev.orders WHERE id='s4-order-a'", "G5.S4_11_remove_order")
    if mutate("INSERT INTO jw_dev.invoices(id,org_id) VALUES('s4-invoice-b','ci-b')",
              "G5.S4_12_seed_invoice"):
        expect("G5.S4_13_invoice_blocks_same_tenant", "ci-b", True)
        expect("G5.S4_14_other_tenant_not_blocked_by_invoice", "ci-a", False)
        mutate("DELETE FROM jw_dev.invoices WHERE id='s4-invoice-b'", "G5.S4_15_remove_invoice")
    if mutate("INSERT INTO jw_dev.payments(id,org_id) VALUES('s4-payment-c','ci-c')",
              "G5.S4_16_seed_payment"):
        expect("G5.S4_17_payment_blocks_same_tenant", "ci-c", True)
        expect("G5.S4_18_other_tenant_not_blocked_by_payment", "ci-b", False)
        mutate("DELETE FROM jw_dev.payments WHERE id='s4-payment-c'", "G5.S4_19_remove_payment")
    expect("G5.S4_20_cleanup_preserves_no_legacy_collision", "ci-a", False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", help="write JSON report to this path")
    args = parser.parse_args()
    local_server_or_die()

    results: list[dict] = []

    def record(name: str, ok: bool, detail: str = "") -> None:
        results.append({"name": name, "result": "PASS" if ok else "FAIL", "detail": detail})

    dbname = "jw_cinema_gate_" + secrets.token_hex(4)
    admin = Psql("postgres")
    started = time.time()
    steps: list[dict] = []
    try:
        r = admin.sql(f"CREATE DATABASE {dbname}")
        if r.returncode != 0:
            raise SystemExit("BLOCKED: cannot create disposable database: " + r.stderr.strip()[:200])
        db = Psql(dbname)
        for role in ("jw_app_dev", "jw_auth_stage_v85", "anon", "authenticated", "service_role"):
            admin.sql(f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{role}') "
                      f"THEN CREATE ROLE {role} NOLOGIN NOINHERIT NOBYPASSRLS; END IF; END $$")
        for path in BASE_FILES:
            p = db.file(path)
            steps.append({"step": "apply " + path, "ok": p.returncode == 0})
            if p.returncode != 0:
                raise SystemExit(f"FAIL: base schema {path}: {p.stderr.strip()[:300]}")
        p = db.file(ENGINE, single_transaction=True)
        steps.append({"step": "apply " + ENGINE, "ok": p.returncode == 0})
        if p.returncode != 0:
            raise SystemExit("FAIL: engine SQL: " + p.stderr.strip()[:600])
        # Managed-Postgres bootstrap must not leave a route from the migration
        # executor into the NOLOGIN owner role after COMMIT.
        owner_link = db.sql(
            "SELECT count(*) FROM pg_auth_members m "
            "JOIN pg_roles role ON role.oid=m.roleid "
            "JOIN pg_roles usr ON usr.oid=m.member "
            "WHERE role.rolname='jw_cinema_owner' AND usr.rolname=session_user"
        )
        record("G5.M1_migration_executor_owner_membership_revoked",
               owner_link.returncode == 0 and owner_link.stdout.strip() == "0",
               "temporary owner SET privilege removed before commit")
        # idempotence guard: installing twice must be refused, not silently re-run
        again = db.file(ENGINE, single_transaction=True)
        record("G1.01_engine_refuses_second_install", again.returncode != 0 and "already installed" in again.stderr,
               again.stderr.strip()[:100])
        p = db.file(TESTS)
        steps.append({"step": "run " + TESTS, "ok": p.returncode == 0})
        for name, verdict, detail in NOTICE.findall(p.stderr):
            record(name, verdict == "PASS", detail)
        if p.returncode != 0:
            record("G3.SQL_script_completed", False, p.stderr.strip()[-400:])
        concurrency_checks(db, record)       # probabilistic smoke (parallel psql sessions)
        deterministic_lock_checks(db, record)  # deterministic lock-presence proofs
        login_role_checks(dbname, record)
        s4_legacy_collision_checks(db, record)  # true PG17 RLS + exact S4 runtime SQL
    finally:
        if os.environ.get("JW_CINEMA_KEEP_DB") != "1":
            admin.sql(f"DROP DATABASE IF EXISTS {dbname} WITH (FORCE)")

    v = gate_verdict(results)
    overall, duplicates, per_gate, failed = v["overall"], v["duplicates"], v["per_gate"], v["failed"]
    coverage_gaps, missing, unexpected = v["coverage_gaps"], v["missing"], v["unexpected"]
    report = {
        "overall": overall, "total": len(results), "failed": len(failed),
        "per_gate": dict(per_gate), "duplicate_names": duplicates, "coverage_gaps": coverage_gaps,
        "expected_total": len(EXPECTED_RESULT_NAMES), "missing_names": missing, "unexpected_names": unexpected,
        "server": subprocess.run(["psql", "-X", "-At", "-d", "postgres", "-c", "show server_version"],
                                 capture_output=True, text=True).stdout.strip(),
        "seconds": round(time.time() - started, 1), "steps": steps, "results": results,
        "not_covered": ["G1 build/hash (see ci_cinema_pg_guard.py)", "G4 UI/DOM/pixels", "HTTP routes",
                        "browser E2E", "HTTPS staging", "OCR accuracy", "backup/restore RPO/RTO"],
    }
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.report:
        Path(args.report).write_text(text, encoding="utf-8")
    for r in results:
        if r["result"] == "FAIL":
            print(f"FAIL {r['name']}: {r['detail']}")
    print(f"{overall}: {len(results) - len(failed)}/{len(results)} passed; per gate {dict(per_gate)}; "
          f"duplicates={duplicates} gaps={coverage_gaps} expected={len(EXPECTED_RESULT_NAMES)} missing={missing} unexpected={unexpected}")
    return 0 if overall == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
