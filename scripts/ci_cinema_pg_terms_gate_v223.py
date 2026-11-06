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
import pathlib
import re
import secrets
import subprocess
import sys

from scripts import ci_cinema_pg_sql_gate as gate
from app import pg_cinema_compat_v1 as compat
from app import pg_cinema_compat_view_v1 as view

ROOT = gate.ROOT
SQLFILE = ROOT / "scripts/review/cinema_pg_v223_terms_proposal.sql"
EXPECTED_MIN_CHECKS = 59
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

    # ------------------------- T5: database-level two-person rule for quotes (separate migration)
    # JW_V223_TWO_PERSON_SQL lets a mutation check point the gate at a deliberately broken copy.
    TP = pathlib.Path(os.environ.get("JW_V223_TWO_PERSON_SQL") or ROOT / "scripts/review/cinema_pg_v223_quote_two_person_proposal.sql")
    def qflow(tag, creator, submitter, approver):
        A_ = "hash_a_admin1"
        part = last(w(A_, f"SELECT jw_dev.cinema_pg_partner_upsert('rq-t5-p-{tag}-{RID}',NULL,'T5 {tag} {RID}','','','','',NULL)->'entity'->>'id'"))
        qid = last(w(creator, f"SELECT jw_dev.cinema_pg_quote_create('rq-t5-q-{tag}-{RID}','{part}','T5 {tag}','exempt',"
                              f"'[{{\"name\":\"Part\",\"quantity\":1,\"unit_price\":100}}]'::jsonb)->'entity'->>'id'"))
        last(w(submitter, f"SELECT jw_dev.cinema_pg_quote_transition('rq-t5-s-{tag}-{RID}','{qid}',1,'submitted')"))
        return qid

    def approve(tag, session, qid, version, rid=""):
        return w(session, f"SELECT jw_dev.cinema_pg_quote_transition('rq-t5-a{rid}-{tag}-{RID}','{qid}',{version},'approved')->'entity'->>'status'")

    q_pre = qflow("pre", A, A, A)
    last(approve("pre", A, q_pre, 2))                    # allowed BEFORE the migration: same administrator
    selfrows = last(psql("SELECT count(*) FROM jw_dev.cinema_pg_quotes WHERE status IN ('approved','ordered') "
                         "AND (submitted_by IS NULL OR approved_by IS NOT DISTINCT FROM submitted_by)"))
    rec("T5.00_audited_fixtures_contain_self_approved_quotes_before_migration", int(selfrows) > 0, f"rows={selfrows}")
    p = psql(file=str(TP))
    rec("T5.01_migration_applies_after_the_engine_and_its_tests", p.returncode == 0, p.stderr.strip()[:200])
    rec("T5.02_constraint_exists_and_is_not_yet_validated",
        last(psql("SELECT convalidated::text FROM pg_constraint WHERE conname='cinema_pg_quote_two_person'")) == "false")
    v = psql("ALTER TABLE jw_dev.cinema_pg_quotes VALIDATE CONSTRAINT cinema_pg_quote_two_person")
    rec("T5.03_validate_is_refused_while_self_approved_rows_exist", state(v) == "23514", state(v))

    q1 = qflow("self", A, A, A)
    p = approve("self", A, q1, 2)
    rec("T5.04_submitter_cannot_approve_own_quote", state(p) == "23514" and "cinema_pg_quote_two_person" in p.stderr, state(p))
    mapped = compat.map_pg_error(state(p), p.stderr)
    rec("T5.05_real_pg_error_maps_to_the_stable_app_code", (mapped.code, mapped.http_status) == ("quote_second_person_required", 409), mapped.code)
    rec("T5.06_refused_approval_leaves_the_quote_submitted",
        last(psql(f"SELECT status FROM jw_dev.cinema_pg_quotes WHERE id='{q1}'")) == "submitted")
    p = approve("self", A2, q1, 2, "2")
    rec("T5.07_a_different_administrator_can_then_approve_it", state(p) == "OK" and "approved" in p.stdout, state(p))
    q2 = qflow("mem", M, M, M)
    rec("T5.08_member_submits_admin_approves", state(approve("mem", A, q2, 2)) == "OK")
    q3 = qflow("ord", A, A, A)
    approve("ord", A2, q3, 2)
    o = w(A, f"SELECT jw_dev.cinema_pg_order_create('rq-t5-o-{RID}','{q3}')->'entity'->>'status'")
    rec("T5.09_approved_quote_still_converts_to_an_order", state(o) == "OK",
        state(o) + " " + o.stderr.strip()[:120])
    q4 = qflow("rej", A, A, A)
    last(w(A2, f"SELECT jw_dev.cinema_pg_quote_transition('rq-t5-rj-{RID}','{q4}',2,'rejected')"))
    last(w(M, f"SELECT jw_dev.cinema_pg_quote_transition('rq-t5-dr-{RID}','{q4}',3,'draft')"))
    last(w(M, f"SELECT jw_dev.cinema_pg_quote_transition('rq-t5-rs-{RID}','{q4}',4,'submitted')"))
    rec("T5.10_resubmission_by_a_member_is_approvable_by_an_admin", state(approve("rej", A, q4, 5)) == "OK")
    q5 = qflow("rs2", A, A, A)
    last(w(A2, f"SELECT jw_dev.cinema_pg_quote_transition('rq-t5-rj2-{RID}','{q5}',2,'rejected')"))
    last(w(A2, f"SELECT jw_dev.cinema_pg_quote_transition('rq-t5-dr2-{RID}','{q5}',3,'draft')"))
    last(w(A2, f"SELECT jw_dev.cinema_pg_quote_transition('rq-t5-rs2-{RID}','{q5}',4,'submitted')"))
    p = approve("rs2", A2, q5, 5)
    rec("T5.11_whoever_resubmitted_cannot_approve_the_resubmission", state(p) == "23514", state(p))
    rec("T5.12_other_transitions_are_unaffected_cancel_an_approved_quote",
        state(w(A, f"SELECT jw_dev.cinema_pg_quote_transition('rq-t5-cn-{RID}','{q1}',3,'cancelled')")) == "OK")
    o = w(A, f"SELECT jw_dev.cinema_pg_order_create('rq-t5-opre-{RID}','{q_pre}')->'entity'->>'status'")
    rec("T5.14_CONSEQUENCE_a_quote_self_approved_before_the_migration_can_no_longer_become_an_order",
        state(o) == "23514" and "cinema_pg_quote_two_person" in o.stderr, state(o))
    c = w(A, f"SELECT jw_dev.cinema_pg_quote_transition('rq-t5-cnpre-{RID}','{q_pre}',3,'cancelled')")
    rec("T5.15_CONSEQUENCE_but_it_can_still_be_cancelled_so_the_owner_can_clear_such_rows", state(c) == "OK", state(c))
    integ = last(w(A, "SELECT count(*) FROM jw_dev.cinema_pg_integrity_check()"))
    rec("T5.13_engine_integrity_check_still_reports_nothing", integ == "0", f"rows={integ}")

    # ---------------- T6: the legacy-shaped views against REAL engine output on this server
    import json as _json

    def entity(session, expr):
        return _json.loads(last(w(session, f"SELECT ({expr})->'entity'")))
    pt = entity(A, f"jw_dev.cinema_pg_partner_upsert('rq-t6-p-{RID}',NULL,'T6 {RID}','','','','',NULL)")
    rec("T6.01_partner_entity_has_every_key_the_view_reads", set(view.ENTITY_KEYS["partner"]) <= set(pt), sorted(set(view.ENTITY_KEYS["partner"]) - set(pt)))
    qt = entity(M, f"jw_dev.cinema_pg_quote_create('rq-t6-q-{RID}','{pt['id']}','T6','taxable',"
                   f"'[{{\"name\":\"X\",\"quantity\":3,\"unit_price\":1005}}]'::jsonb)")
    rec("T6.02_quote_entity_has_every_key_the_view_reads", set(view.ENTITY_KEYS["quote"]) <= set(qt) and set(view.ENTITY_KEYS["quote_item"]) <= set(qt["items"][0]))
    last(w(M, f"SELECT jw_dev.cinema_pg_quote_transition('rq-t6-s-{RID}','{qt['id']}',1,'submitted')"))
    last(w(A, f"SELECT jw_dev.cinema_pg_quote_transition('rq-t6-a-{RID}','{qt['id']}',2,'approved')"))
    od = entity(A, f"jw_dev.cinema_pg_order_create('rq-t6-o-{RID}','{qt['id']}')")
    rec("T6.03_order_entity_has_every_key_the_view_reads", set(view.ENTITY_KEYS["order"]) <= set(od) and set(view.ENTITY_KEYS["order_item"]) <= set(od["items"][0]))
    shown = view.order_view(od, partner_name=pt["name"], title="T6")
    qshown = view.quote_view({**qt, "status": "approved"}, partner_name=pt["name"])
    rec("T6.04_order_view_joins_to_quote_view_like_the_ui_expects", shown["quote_id"] == qshown["id"] and shown["status"] == "received")
    bad = [(sub, mode) for sub in (0, 1, 4, 5, 6, 14, 15, 16, 25, 95, 105, 1000, 3015, 3265, 999999995)
           for mode in ("taxable", "exempt")
           if int(last(psql(f"SELECT jw_dev.cinema_pg_vat({sub},'{mode}')")))
           != view.money([{"quantity": 1, "unit_price": sub}], mode)["vat"]]
    rec("T6.05_python_vat_equals_the_server_vat_function", not bad, bad[:3])
    pay_inv = last(psql("SELECT i.id FROM jw_dev.cinema_pg_invoices i WHERE i.status='confirmed' LIMIT 1"))
    prow = entity(A, f"jw_dev.cinema_pg_payment_record('rq-t6-pay-{RID}','{pay_inv}',1,current_date,'T6-{RID}')")
    rec("T6.06_payment_entity_has_every_key_the_view_reads", set(view.ENTITY_KEYS["payment"]) <= set(prow), sorted(set(view.ENTITY_KEYS["payment"]) - set(prow)))
    rec("T6.07_every_engine_id_is_32_lowercase_hex", all(view.RAW_ID.fullmatch(x["id"]) for x in (pt, qt, od, prow)))

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
