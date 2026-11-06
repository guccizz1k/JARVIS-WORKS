#!/usr/bin/env python3
"""Disposable-PostgreSQL gate for the PROPOSED order-terms / invoice-terms / payment-note side tables
(scripts/review/cinema_pg_v223_terms_proposal.sql). psql client + standard library only.

What it does: creates its own throw-away database, installs the audited base fixtures, the unchanged
CINEMA engine and the engine's own test script (which leaves the sessions/organisations the checks
use), applies the PROPOSAL in one transaction, then exercises it. The audited engine is never edited.

Safety is inherited from ci_cinema_pg_sql_gate: JW_CINEMA_PG_DISPOSABLE=1 and a local server only.
This proves SQL behaviour on the server it ran on; it is NOT an approval to change the dev project.
"""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import subprocess
import sys

from scripts import ci_cinema_pg_sql_gate as gate

ROOT = gate.ROOT
SQLFILE = ROOT / "scripts/review/cinema_pg_v223_terms_proposal.sql"
EXPECTED_MIN_CHECKS = 36
DB = ""
RID = secrets.token_hex(4)
results = []


def psql(*stmts, role_session=None, file=None):
    cmd = ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose", "-d", DB, "-A", "-t"]
    if file:
        cmd += ["-f", file]
    if role_session:
        stmts = ("SET ROLE jw_cinema_writer", f"SELECT set_config('jw.session_hash','{role_session}',false)") + stmts
    for s in stmts:
        cmd += ["-c", s]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120)


def last(p):
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip()[:400])
    return [l for l in p.stdout.splitlines() if l.strip()][-1].strip()


def state(p):
    m = re.search(r"ERROR:\s+([0-9A-Z]{5}):", p.stderr)
    return m.group(1) if m else ("OK" if p.returncode == 0 else "?????")


def rec(name, ok, detail=""):
    results.append((name, ok))
    print(("PASS" if ok else "FAIL"), name, detail)


def w(session, stmt):
    return psql(stmt, role_session=session)


def expect(name, session, stmt, code):
    p = w(session, stmt)
    s = state(p)
    rec(name, s == code, f"want={code} got={s}" + ("" if s == code else " :: " + p.stderr.strip()[:200]))
    return p


def run():
    # ---------------------------------------------------------------- install the proposal
    p = psql(file=str(SQLFILE))
    rec("T0.proposal_applies_in_one_transaction", p.returncode == 0, p.stderr.strip()[:300])
    if p.returncode != 0:
        raise SystemExit("FAIL: proposal did not apply: " + p.stderr.strip()[:300])

    # ---------------------------------------------------------------- build a confirmed chain
    def ev(session, tag):
        content = "%PDF-1.4 " + tag
        sha = hashlib.sha256(content.encode()).hexdigest()
        last(w(session, f"SELECT jw_dev.cinema_pg_evidence_put('rq-t-ev-{tag}-{RID}','{tag}.pdf','application/pdf',"
                         f"convert_to('{content}','UTF8'))"))
        return sha


    def open_ev(session, delivery, tag):
        last(w(session, f"SELECT count(*) FROM jw_dev.cinema_pg_evidence_open('rq-t-vw-{tag}-{RID}',"
                        f"(SELECT e.id FROM jw_dev.cinema_pg_evidence_files e JOIN jw_dev.cinema_pg_deliveries d "
                        f"ON d.org_id=e.org_id AND d.evidence_sha256=e.content_sha256 WHERE d.id='{delivery}'))"))


    def chain(tag, price=1000):
        A = "hash_a_admin1"
        partner = last(w(A, f"SELECT jw_dev.cinema_pg_partner_upsert('rq-t-p-{tag}-{RID}',NULL,'T {tag} {RID}','','','','',NULL)->'entity'->>'id'"))
        quote = last(w(A, f"SELECT jw_dev.cinema_pg_quote_create('rq-t-q-{tag}-{RID}','{partner}','T {tag}','exempt',"
                          f"'[{{\"name\":\"Part\",\"quantity\":2,\"unit_price\":{price}}}]'::jsonb)->'entity'->>'id'"))
        last(w(A, f"SELECT jw_dev.cinema_pg_quote_transition('rq-t-q2-{tag}-{RID}','{quote}',1,'submitted')"))
        last(w(A, f"SELECT jw_dev.cinema_pg_quote_transition('rq-t-q3-{tag}-{RID}','{quote}',2,'approved')"))
        order = last(w(A, f"SELECT jw_dev.cinema_pg_order_create('rq-t-o-{tag}-{RID}','{quote}')->'entity'->>'id'"))
        item = last(psql(f"SELECT id FROM jw_dev.cinema_pg_order_items WHERE order_id='{order}'"))
        sha = ev("hash_a_member", tag)
        delivery = last(w("hash_a_member", f"SELECT jw_dev.cinema_pg_delivery_record('rq-t-dl-{tag}-{RID}','{order}',"
                          f"'[{{\"order_item_id\":\"{item}\",\"quantity\":2}}]'::jsonb,'{sha}','{tag}.pdf')->'entity'->>'id'"))
        open_ev("hash_a_admin2", delivery, tag)
        last(w("hash_a_admin2", f"SELECT jw_dev.cinema_pg_delivery_confirm('rq-t-cf-{tag}-{RID}','{delivery}')->'entity'->>'status'"))
        st = last(w(A, f"SELECT jw_dev.cinema_pg_statement_create('rq-t-st-{tag}-{RID}','{delivery}')->'entity'->>'id'"))
        last(w(A, f"SELECT jw_dev.cinema_pg_statement_confirm('rq-t-sc-{tag}-{RID}','{st}')->'entity'->>'status'"))
        inv = last(w(A, f"SELECT jw_dev.cinema_pg_invoice_create('rq-t-iv-{tag}-{RID}','{st}')->'entity'->>'id'"))
        return order, inv



    def open_order(tag):
        A = "hash_a_admin1"
        partner = last(w(A, f"SELECT jw_dev.cinema_pg_partner_upsert('rq-t-p-{tag}-{RID}',NULL,'T {tag} {RID}','','','','',NULL)->'entity'->>'id'"))
        quote = last(w(A, f"SELECT jw_dev.cinema_pg_quote_create('rq-t-q-{tag}-{RID}','{partner}','T {tag}','exempt',"
                          f"'[{{\"name\":\"Part\",\"quantity\":2,\"unit_price\":1000}}]'::jsonb)->'entity'->>'id'"))
        last(w(A, f"SELECT jw_dev.cinema_pg_quote_transition('rq-t-q2-{tag}-{RID}','{quote}',1,'submitted')"))
        last(w(A, f"SELECT jw_dev.cinema_pg_quote_transition('rq-t-q3-{tag}-{RID}','{quote}',2,'approved')"))
        return last(w(A, f"SELECT jw_dev.cinema_pg_order_create('rq-t-o-{tag}-{RID}','{quote}')->'entity'->>'id'"))

    order, inv = chain("c1")
    open1 = open_order("o1")
    order2, inv2 = chain("c2")
    A, A2, M, B = "hash_a_admin1", "hash_a_admin2", "hash_a_member", "hash_b_admin"
    before_keys = last(w("hash_a_admin1", f"SELECT (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(jw_dev.cinema_pg_order_create('rq-t-o-c1-{RID}',(SELECT quote_id FROM jw_dev.cinema_pg_orders WHERE id='{order}'))->'entity') k)::text"))
    rec("T0.engine_order_result_shape_has_no_due_date", "due_date" not in before_keys, before_keys[:120])

    # ------------------------------------------------------------------------ order due date
    FAR = "(current_date + 30)"
    expect("T1.01_member_cannot_set_order_due_date", M, f"SELECT jw_dev.cinema_pg_order_terms_set('rq-t-od0-{RID}','{open1}',{FAR})", "42501")
    expect("T1.02_past_due_date_refused", A, f"SELECT jw_dev.cinema_pg_order_terms_set('rq-t-od1-{RID}','{open1}',current_date-1)", "23514")
    expect("T1.03_null_due_date_refused", A, f"SELECT jw_dev.cinema_pg_order_terms_set('rq-t-od1n-{RID}','{open1}',NULL)", "23514")
    expect("T1.04_other_org_admin_cannot_see_order", B, f"SELECT jw_dev.cinema_pg_order_terms_set('rq-t-od2-{RID}','{open1}',{FAR})", "P0002")
    expect("T1.05_admin_sets_due_date", A, f"SELECT jw_dev.cinema_pg_order_terms_set('rq-t-od3-{RID}','{open1}',{FAR})", "OK")
    p = w(A, f"SELECT jw_dev.cinema_pg_order_terms_set('rq-t-od3-{RID}','{open1}',{FAR})")
    rec("T1.06_same_request_replays", state(p) == "OK" and '"replayed": true' in p.stdout.replace('":true', '": true'), p.stdout.strip()[:80])
    expect("T1.07_second_set_refused", A2, f"SELECT jw_dev.cinema_pg_order_terms_set('rq-t-od4-{RID}','{open1}',{FAR})", "23505")
    expect("T1.08_same_request_id_other_payload_refused", A, f"SELECT jw_dev.cinema_pg_order_terms_set('rq-t-od3-{RID}','{open1}',current_date+31)", "23505")
    expect("T1.09_writer_cannot_update_terms_directly", A, f"UPDATE jw_dev.cinema_pg_order_terms SET due_date=current_date+99", "42501")
    expect("T1.10_writer_cannot_insert_terms_directly", A, f"INSERT INTO jw_dev.cinema_pg_order_terms(org_id,order_id,due_date,set_by) SELECT org_id,id,current_date,'x' FROM jw_dev.cinema_pg_orders WHERE id='{order2}'", "42501")
    rec("T1.11_own_org_reads_one_row", last(w(A, "SELECT count(*) FROM jw_dev.cinema_pg_order_terms")) == "1")
    rec("T1.12_other_org_reads_none", last(w(B, "SELECT count(*) FROM jw_dev.cinema_pg_order_terms")) == "0")
    rec("T1.13_audit_row_written", last(psql(f"SELECT count(*) FROM jw_dev.cinema_pg_audit WHERE entity_id='{open1}' AND action='due_date_set'")) == "1")

    expect("T1.14_fulfilled_order_cannot_get_a_due_date", A, f"SELECT jw_dev.cinema_pg_order_terms_set('rq-t-od9-{RID}','{order}',{FAR})", "23514")

    # ---------------------------------------------------------------------- invoice pay-by date
    expect("T2.01_past_pay_by_refused", A, f"SELECT jw_dev.cinema_pg_invoice_terms_set('rq-t-iv0-{RID}','{inv}',current_date-1)", "23514")
    expect("T2.02_other_org_cannot_see_invoice", B, f"SELECT jw_dev.cinema_pg_invoice_terms_set('rq-t-iv1-{RID}','{inv}',{FAR})", "P0002")
    expect("T2.03_unrelated_member_refused", M, f"SELECT jw_dev.cinema_pg_invoice_terms_set('rq-t-iv2-{RID}','{inv}',{FAR})", "42501")
    expect("T2.04_admin_sets_pay_by", A, f"SELECT jw_dev.cinema_pg_invoice_terms_set('rq-t-iv3-{RID}','{inv}',{FAR})", "OK")
    expect("T2.05_second_set_refused", A, f"SELECT jw_dev.cinema_pg_invoice_terms_set('rq-t-iv4-{RID}','{inv}',{FAR})", "23505")
    last(w(A, f"SELECT jw_dev.cinema_pg_invoice_review('rq-t-ir-{RID}','{inv2}')->'entity'->>'status'"))
    last(w(A, f"SELECT jw_dev.cinema_pg_invoice_confirm('rq-t-ic-{RID}','{inv2}')->'entity'->>'status'"))
    expect("T2.06_cannot_set_after_confirmation", A, f"SELECT jw_dev.cinema_pg_invoice_terms_set('rq-t-iv5-{RID}','{inv2}',{FAR})", "23514")

    # --------------------------------------------------------------------------- payment note
    pay = last(w(A, f"SELECT jw_dev.cinema_pg_payment_record('rq-t-pay1-{RID}','{inv2}',1000,current_date,'REF-{RID}-1')->'entity'->>'id'"))
    pay2 = last(w(A, f"SELECT jw_dev.cinema_pg_payment_record('rq-t-pay2-{RID}','{inv2}',500,current_date,'REF-{RID}-2')->'entity'->>'id'"))
    expect("T3.01_other_admin_cannot_note_someone_elses_payment", A2, f"SELECT jw_dev.cinema_pg_payment_note_set('rq-t-n0-{RID}','{pay}','x')", "42501")
    expect("T3.02_empty_note_refused", A, f"SELECT jw_dev.cinema_pg_payment_note_set('rq-t-n1-{RID}','{pay}','   ')", "23514")
    expect("T3.03_too_long_note_refused", A, f"SELECT jw_dev.cinema_pg_payment_note_set('rq-t-n2-{RID}','{pay}',repeat('a',501))", "23514")
    expect("T3.04_recorder_sets_note", A, f"SELECT jw_dev.cinema_pg_payment_note_set('rq-t-n3-{RID}','{pay}','bank transfer, 한글 메모')", "OK")
    rec("T3.05_note_stored_trimmed_exact", last(psql(f"SELECT note FROM jw_dev.cinema_pg_payment_notes WHERE payment_id='{pay}'")) == "bank transfer, 한글 메모")
    expect("T3.06_second_note_refused", A, f"SELECT jw_dev.cinema_pg_payment_note_set('rq-t-n4-{RID}','{pay}','again')", "23505")
    last(w(A, f"SELECT jw_dev.cinema_pg_payment_reverse('rq-t-pr-{RID}','{pay2}','test reversal')->'entity'->>'id'"))
    expect("T3.07_reversed_payment_cannot_get_note", A, f"SELECT jw_dev.cinema_pg_payment_note_set('rq-t-n5-{RID}','{pay2}','late')", "23514")
    expect("T3.08_other_org_cannot_see_payment", B, f"SELECT jw_dev.cinema_pg_payment_note_set('rq-t-n6-{RID}','{pay}','x')", "P0002")
    expect("T3.09_note_row_is_append_only_even_for_owner_path", A, "UPDATE jw_dev.cinema_pg_payment_notes SET note='z'", "42501")
    tbl = psql("SET ROLE jw_cinema_owner", "SELECT set_config('jw.session_hash','hash_a_admin1',false)",
               f"UPDATE jw_dev.cinema_pg_payment_notes SET note='z' WHERE payment_id='{pay}'")
    rec("T3.10_owner_update_blocked_by_trigger", state(tbl) == "23514", state(tbl))

    # ------------------------------------------------------------------- engine still consistent
    integ = last(w(A, "SELECT count(*) FROM jw_dev.cinema_pg_integrity_check()"))
    rec("T4.01_engine_integrity_check_reports_nothing", integ == "0", f"rows={integ}")
    rec("T4.02_no_public_execute_on_new_functions", last(psql(
        "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='jw_dev' "
        "AND p.proname IN ('cinema_pg_order_terms_set','cinema_pg_invoice_terms_set','cinema_pg_payment_note_set') "
        "AND has_function_privilege('public',p.oid,'EXECUTE')")) == "0")
    rec("T4.03_new_functions_pinned_search_path_and_definer", last(psql(
        "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='jw_dev' "
        "AND p.proname IN ('cinema_pg_order_terms_set','cinema_pg_invoice_terms_set','cinema_pg_payment_note_set') "
        "AND p.prosecdef AND p.proconfig::text LIKE '%search_path=pg_catalog%'")) == "3")
    rec("T4.04_new_tables_force_rls", last(psql(
        "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='jw_dev' "
        "AND c.relname IN ('cinema_pg_order_terms','cinema_pg_invoice_terms','cinema_pg_payment_notes') "
        "AND c.relrowsecurity AND c.relforcerowsecurity")) == "3")

    fails = [n for n, ok in results if not ok]
    print(f"\nTOTAL {len(results)} FAILED {len(fails)}", fails)

    return fails


def main() -> int:
    global DB
    gate.local_server_or_die()
    DB = "jw_cinema_terms_" + secrets.token_hex(4)
    admin = gate.Psql("postgres")
    if admin.sql(f"CREATE DATABASE {DB}").returncode != 0:
        raise SystemExit("BLOCKED: cannot create disposable database")
    try:
        db = gate.Psql(DB)
        for role in ("jw_app_dev", "jw_auth_stage_v85", "anon", "authenticated", "service_role"):
            admin.sql(f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{role}') "
                      f"THEN CREATE ROLE {role} NOLOGIN NOINHERIT NOBYPASSRLS; END IF; END $$")
        for path in gate.BASE_FILES:
            p = db.file(path)
            if p.returncode != 0:
                raise SystemExit(f"FAIL: base schema {path}: {p.stderr.strip()[:300]}")
        p = db.file(gate.ENGINE, single_transaction=True)
        if p.returncode != 0:
            raise SystemExit("FAIL: engine SQL: " + p.stderr.strip()[:600])
        p = db.file(gate.TESTS)                       # leaves the fixture sessions behind
        if p.returncode != 0:
            raise SystemExit("FAIL: engine test script (fixtures): " + p.stderr.strip()[-300:])
        fails = run()
    finally:
        if os.environ.get("JW_CINEMA_KEEP_DB") != "1":
            admin.sql(f"DROP DATABASE IF EXISTS {DB} WITH (FORCE)")
    ok = not fails and len(results) >= EXPECTED_MIN_CHECKS
    print(("PASS" if ok else "FAIL") + f": {len(results)} checks, {len(fails)} failed, expected >= {EXPECTED_MIN_CHECKS}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
