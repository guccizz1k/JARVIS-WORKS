#!/usr/bin/env python3
"""V22.3 Track B (issue #140): gate for the READ-ONLY preflight and for the order in which the dev-DB
proposals are applied. psql client + standard library only (no psycopg), disposable local server only.

  JW_CINEMA_PG_DISPOSABLE=1 PGHOST=/path/to/socket PGUSER=postgres python3 -m scripts.ci_cinema_pg_v223_preflight_gate

What is proven (on the server it ran on; PG17 is the target, PG16 is supplemental evidence):
  * scripts/review/cinema_pg_v223_preflight_readonly.sql runs inside default_transaction_read_only=on, changes
    nothing (catalog + ACL + role + row-count fingerprint equal before and after) and prints no row value.
  * its counts and object facts equal independent SQL; before/after applying the existing proposals it reports
    the difference (constraint, side tables, hardened functions, jw_backup_ro) and after the backup-role rollback
    it reports the role gone.
  * its least-privilege `violations` equal scripts/pg_backup_v223.py evaluate_source_privileges for an accepted
    role (jw_backup_ro) and for a rejected one (the simulated admin), so the SQL mirror cannot drift silently.
  * a role that does not bypass row level security gets an honest `row_visibility_complete=false` and no error.
  * ORDER TRAP (measured): creating jw_backup_ro BEFORE the terms migration leaves the 3 new tables unreadable
    to it, and the backup tool then refuses the role (tables_unreadable); the documented remedy clears it.
The existing proposals are applied here exactly as the migration gate applies them; none of this touches Supabase.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import ci_cinema_pg_sql_gate as gate  # noqa: E402
from scripts import pg_backup_v223 as pb  # noqa: E402

REV = ROOT / "scripts/review"
PREFLIGHT = REV / "cinema_pg_v223_preflight_readonly.sql"
TWO, TERMS = REV / "cinema_pg_v223_quote_two_person_proposal.sql", REV / "cinema_pg_v223_terms_proposal.sql"
BK, BK_RB = REV / "cinema_pg_v223_backup_role_proposal.sql", REV / "cinema_pg_v223_backup_role_rollback.sql"
SIM_ADMIN, NOBYPASS = "jw_sim_pf_admin", "jw_pf_nobypass"
SENTINEL = "PF-SECRET-SENTINEL-" + secrets.token_hex(6)
# CI-only throw-away passwords (a TCP server with password auth would refuse the simulated roles otherwise);
# they exist only for the life of this process and never reach a log. The real jw_backup_ro password is typed by the owner.
PASSWORDS = {name: "ci-only-" + secrets.token_hex(8) for name in (SIM_ADMIN, NOBYPASS, "jw_backup_ro")}
EXPECTED = ["PF.01", "PF.02", "PF.03", "PF.04", "PF.05", "PF.06", "PF.07", "PF.08", "PF.09", "PF.10", "PF.11",
            "PF.12", "PF.17", "PF.13", "PF.14", "PF.15", "PF.16", "PF.20", "PF.21"]
results: list[tuple[str, bool, str]] = []


def rec(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, bool(ok), detail))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail[:300])


def psql(db: str, *, user: str | None = None, file: Path | None = None, sql: str | None = None,
         vars_: dict | None = None, readonly: bool = False, single: bool = False) -> subprocess.CompletedProcess:
    cmd = ["psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-d", db]
    if single:
        cmd.append("--single-transaction")      # the engine file relies on SET LOCAL ROLE, as in the other gates
    if user:
        cmd += ["-U", user]
    for k, v in (vars_ or {}).items():
        cmd += ["-v", f"{k}={v}"]
    cmd += ["-f", str(file)] if file else ["-c", sql or ""]
    env = dict(os.environ)
    if user in PASSWORDS:
        env["PGPASSWORD"] = PASSWORDS[user]
    if readonly:
        env["PGOPTIONS"] = "-c default_transaction_read_only=on"
    return subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env)


def scalar(db: str, sql: str, user: str | None = None) -> str:
    p = psql(db, user=user, sql=sql)
    if p.returncode != 0:
        raise SystemExit("FAIL: " + p.stderr.strip()[:300])
    return p.stdout.strip()


def preflight(db: str, user: str | None = None) -> tuple[dict, str]:
    p = psql(db, user=user, file=PREFLIGHT, readonly=True)
    if p.returncode != 0:
        raise SystemExit("FAIL: preflight did not run: " + p.stderr.strip()[:300])
    return json.loads(p.stdout), p.stdout


FINGERPRINT = """SELECT md5(concat_ws('|',
 (SELECT string_agg(c.relname||coalesce(c.relacl::text,'')||c.relrowsecurity::text||c.relforcerowsecurity::text
        ||c.relowner::regrole::text, ',' ORDER BY c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='jw_dev'),
 (SELECT string_agg(conname||pg_get_constraintdef(oid), ',' ORDER BY conname) FROM pg_constraint WHERE connamespace='jw_dev'::regnamespace),
 (SELECT string_agg(rolname||rolcanlogin::text||rolbypassrls::text||coalesce(rolconfig::text,''), ',' ORDER BY rolname) FROM pg_roles),
 (SELECT string_agg(roleid::text||'-'||member::text||'-'||admin_option::text||inherit_option::text||set_option::text,
        ',' ORDER BY roleid, member, grantor) FROM pg_auth_members),
 (SELECT count(*) FROM pg_proc WHERE pronamespace='jw_dev'::regnamespace)::text,
 (SELECT sum(((xpath('/row/c/text()', query_to_xml(format('select count(*) as c from jw_dev.%I', relname), false, true, '')))[1]::text)::bigint)
    FROM pg_class WHERE relnamespace='jw_dev'::regnamespace AND relkind='r')::text))"""
INDEPENDENT_COUNTS = """SELECT coalesce(jsonb_object_agg(relname, (xpath('/row/c/text()', query_to_xml(
    format('select count(*) as c from jw_dev.%I', relname), false, true, '')))[1]::text::bigint), '{}')
  FROM pg_class WHERE relnamespace='jw_dev'::regnamespace AND relkind IN ('r','p')"""
INDEPENDENT_CONFLICTS = """SELECT count(*) FROM jw_dev.cinema_pg_quotes WHERE status IN ('approved','ordered')
  AND (submitted_by IS NULL OR approved_by IS NULL OR approved_by IS NOT DISTINCT FROM submitted_by)"""


def make_db(admin_db: str = "postgres") -> str:
    name = "jw_cinema_pf_" + secrets.token_hex(4)
    if psql(admin_db, sql=f"CREATE DATABASE {name}").returncode != 0:
        raise SystemExit("BLOCKED: cannot create disposable database")
    for role in ("jw_app_dev", "jw_auth_stage_v85", "anon", "authenticated", "service_role"):
        psql(admin_db, sql=f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{role}') "
                           f"THEN CREATE ROLE {role} NOLOGIN NOINHERIT NOBYPASSRLS; END IF; END $$")
    for path in gate.BASE_FILES:
        if psql(name, file=ROOT / path).returncode != 0:
            raise SystemExit(f"FAIL: base schema {path}")
    eng = psql(name, file=ROOT / gate.ENGINE, single=True)
    if eng.returncode != 0 or psql(name, file=ROOT / gate.TESTS).returncode != 0:
        raise SystemExit("FAIL: engine or fixtures: " + eng.stderr.strip()[:200])
    return name


def shape_admin(admin_db: str, db: str) -> None:
    """Imitate the observed Supabase `postgres`: LOGIN CREATEROLE BYPASSRLS, not superuser, owner of jw_dev and of
    every table jw_cinema_owner does not own, ADMIN-only member of jw_cinema_owner (same recipe as the migration gate)."""
    for stmt in (f"CREATE ROLE {SIM_ADMIN} LOGIN CREATEROLE BYPASSRLS NOSUPERUSER PASSWORD '{PASSWORDS[SIM_ADMIN]}'",
                 f"GRANT jw_cinema_owner TO {SIM_ADMIN} WITH ADMIN TRUE, INHERIT FALSE, SET FALSE"):
        if psql(admin_db, sql=stmt).returncode != 0:
            raise SystemExit("FAIL: " + stmt)
    psql(db, sql=f"ALTER SCHEMA jw_dev OWNER TO {SIM_ADMIN}")
    rels = scalar(db, "SELECT c.oid::regclass::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                      "JOIN pg_roles o ON o.oid=c.relowner WHERE n.nspname='jw_dev' AND c.relkind IN ('r','p','S') "
                      "AND o.rolname<>'jw_cinema_owner' AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid=c.oid "
                      "AND d.deptype IN ('a','i'))").splitlines()
    for rel in rels:
        psql(db, sql=f"ALTER TABLE {rel} OWNER TO {SIM_ADMIN}")


def apply_backup_role(db: str) -> subprocess.CompletedProcess:
    until = (date.today() + timedelta(days=2)).isoformat() + " 00:00:00+09"
    done = psql(db, user=SIM_ADMIN, file=BK, vars_={"valid_until": until})
    if done.returncode == 0:   # CI only; the real password is set by the owner with \password on their own PC
        psql("postgres", sql=f"ALTER ROLE jw_backup_ro PASSWORD '{PASSWORDS['jw_backup_ro']}'")
    return done


def tool_violations(db: str, user: str) -> list[str]:
    """Run the backup tool's OWN role SQL (pb.ROLE_SQL) and rule function through psql."""
    builtin = "ARRAY[" + ",".join(f"'{r}'" for r in pb.PRIVILEGED_BUILTIN_ROLES) + "]::text[]"
    text = pb.ROLE_SQL.replace("%(builtin)s::text[]", builtin).replace("%(s)s", "'jw_dev'")
    p = psql(db, user=user, sql=text.strip())
    if p.returncode != 0:
        raise SystemExit("FAIL: tool role sql: " + p.stderr.strip()[:300])
    cols = p.stdout.strip().split("|")
    facts = {}
    for key, raw in zip(pb.ROLE_FACT_KEYS, cols):
        facts[key] = (raw == "t") if raw in ("t", "f") else int(raw)
    return pb.evaluate_source_privileges(facts)


def cleanup(db: str | None) -> None:
    if db and os.environ.get("JW_CINEMA_KEEP_DB") != "1":
        psql("postgres", sql=f"DROP DATABASE IF EXISTS {db} WITH (FORCE)")
    for role in ("jw_backup_ro", SIM_ADMIN, NOBYPASS):
        psql("postgres", sql=f"DROP ROLE IF EXISTS {role}")


def phase_main() -> None:
    db = None
    try:
        db = make_db()
        scalar(db, f"INSERT INTO jw_dev.organizations(id,name,created_at) VALUES ('pf-sentinel','{SENTINEL}','x') RETURNING 1")
        before_fp = scalar(db, FINGERPRINT)
        pre, raw = preflight(db)
        after_fp = scalar(db, FINGERPRINT)
        rec("PF.01_json_document_with_tool_header", pre.get("tool") == "cinema_pg_v223_preflight_readonly"
            and pre.get("version") == 1 and pre["schema"]["exists"] is True, str(pre.get("tool")))
        c = pre["candidates"]
        rec("PF.02_before_apply_reports_nothing_applied",
            c["quote_two_person_constraint"]["present"] is False and c["backup_role"]["exists"] is False
            and not any(v["exists"] for v in c["terms_tables"].values())
            and not any(v["exists"] for v in c["terms_functions"].values()), json.dumps(c)[:200])
        indep = json.loads(scalar(db, INDEPENDENT_COUNTS))
        rec("PF.03_before_counts_equal_independent_sql",
            pre["data"]["row_counts"] == indep and pre["schema"]["tables"] == len(indep)
            and pre["data"]["total_rows"] == sum(indep.values()) and pre["data"]["row_visibility_complete"] is True,
            f"{pre['data']['total_rows']} vs {sum(indep.values())}")
        want = int(scalar(db, INDEPENDENT_CONFLICTS))
        rec("PF.04_before_self_approval_count_equals_independent_sql",
            pre["data"]["quotes_self_approved_or_approver_missing"] == want and want > 0,
            f"{pre['data']['quotes_self_approved_or_approver_missing']} vs {want}")
        rec("PF.05_runs_under_default_transaction_read_only", pre["server"]["current_user"] == "postgres", "")
        rec("PF.06_changes_nothing_fingerprint_equal", before_fp == after_fp and len(before_fp) == 32, f"{before_fp} {after_fp}")
        rec("PF.07_output_has_no_row_value_dsn_or_password", SENTINEL not in raw and "postgres://" not in raw
            and "postgresql://" not in raw and "password" not in raw.lower(), "sentinel or secret-like text leaked")

        for stmt_file in (TWO, TERMS):
            p = psql(db, file=stmt_file)
            if p.returncode != 0:
                raise SystemExit(f"FAIL: apply {stmt_file.name}: {p.stderr.strip()[:300]}")
        shape_admin("postgres", db)
        p = apply_backup_role(db)
        if p.returncode != 0:
            raise SystemExit("FAIL: backup role proposal: " + p.stderr.strip()[:300])
        post, _ = preflight(db, SIM_ADMIN)
        c = post["candidates"]
        two = c["quote_two_person_constraint"]
        rec("PF.08_after_apply_constraint_present_not_validated_requires_approver",
            two == {"present": True, "validated": False, "requires_non_null_approver": True}, json.dumps(two))
        tt = c["terms_tables"]
        rec("PF.09_after_apply_side_tables_force_rls_with_policies",
            all(v["exists"] and v["force_rls"] and v["policies"] >= 2 and v["owner"] == "jw_cinema_owner" for v in tt.values()),
            json.dumps(tt)[:250])
        tf = c["terms_functions"]
        rec("PF.10_after_apply_functions_security_definer_pinned_no_public_execute",
            all(v["exists"] and v["security_definer"] and v["search_path_pinned"] and not v["public_execute"]
                for v in tf.values()), json.dumps(tf)[:250])
        bk = c["backup_role"]
        rec("PF.11_after_apply_backup_role_accepted",
            bk.get("exists") is True and bk["violations"] == [] and bk["bypassrls"] and bk["can_login"]
            and bk["default_read_only"] and bk["member_of"] == [] and bk["tables_unreadable"] == 0
            and bk["tables_writable"] == 0 and bk["superuser"] is False and bk["createrole"] is False, json.dumps(bk)[:300])
        indep2 = json.loads(scalar(db, INDEPENDENT_COUNTS))
        post_su, _ = preflight(db)
        rec("PF.12_after_apply_tables_and_counts_equal_independent_sql",
            post_su["schema"]["tables"] == 33 == len(indep2) == bk["tables"] and post_su["data"]["row_counts"] == indep2
            and post_su["data"]["row_visibility_complete"] is True
            and post_su["data"]["quotes_self_approved_or_approver_missing"] == int(scalar(db, INDEPENDENT_CONFLICTS)),
            f"{post_su['schema']['tables']} {len(indep2)}")
        # BYPASSRLS is not SELECT: the simulated admin (ADMIN-only member of jw_cinema_owner, like Supabase `postgres`)
        # cannot read the tables jw_cinema_owner owns, so its picture must be "unknown", never "complete".
        hidden = scalar(db, "SELECT coalesce(string_agg(relname, ',' ORDER BY relname), '') FROM pg_class "
                            "WHERE relnamespace='jw_dev'::regnamespace AND relkind IN ('r','p') "
                            f"AND NOT has_table_privilege('{SIM_ADMIN}', oid, 'SELECT')")
        hidden_list = [h for h in hidden.split(",") if h]
        quotes_hidden = "cinema_pg_quotes" in hidden_list
        sim_data = post["data"]
        sim_ok = (sim_data["rls_bypassed"] is True and sim_data["row_visibility_complete"] is False
                  and sim_data["unreadable_tables"] == hidden_list and sim_data["tables_not_readable"] == len(hidden_list)
                  and (sim_data["quotes_self_approved_or_approver_missing"] is None) == quotes_hidden
                  and any("unknown, not zero" in s for s in post["limitations"]))
        rec("PF.17_bypassrls_without_table_select_is_reported_unknown_not_complete",
            sim_ok and len(hidden_list) > 0, f"hidden={len(hidden_list)} {json.dumps(sim_data)[:160]}")
        as_bk, _ = preflight(db, "jw_backup_ro")
        rec("PF.13_parity_with_backup_tool_for_accepted_role",
            tool_violations(db, "jw_backup_ro") == [] == as_bk["session_role"]["violations"],
            str(as_bk["session_role"]["violations"]))
        tv = sorted(tool_violations(db, SIM_ADMIN))
        rec("PF.14_parity_with_backup_tool_for_rejected_role",
            tv and tv == sorted(post["session_role"]["violations"]), f"{tv} vs {sorted(post['session_role']['violations'])}")

        psql("postgres", sql=f"CREATE ROLE {NOBYPASS} LOGIN NOBYPASSRLS NOSUPERUSER PASSWORD '{PASSWORDS[NOBYPASS]}'")
        psql(db, sql=f"GRANT USAGE ON SCHEMA jw_dev TO {NOBYPASS}")
        psql(db, sql=f"GRANT SELECT ON jw_dev.cinema_pg_partners TO {NOBYPASS}")
        nb, _ = preflight(db, NOBYPASS)
        rec("PF.15_non_bypass_role_gets_incomplete_visibility_and_no_error",
            nb["data"]["row_visibility_complete"] is False and nb["data"]["tables_counted"] == 1
            and nb["data"]["tables_not_readable"] == 32
            and any("row level security" in s for s in nb["limitations"]), json.dumps(nb["data"])[:200])
        rb = psql(db, user=SIM_ADMIN, file=BK_RB)
        after_rb, _ = preflight(db, SIM_ADMIN)
        rec("PF.16_backup_role_rollback_is_visible",
            rb.returncode == 0 and after_rb["candidates"]["backup_role"] == {"exists": False}
            and after_rb["candidates"]["quote_two_person_constraint"]["present"] is True, rb.stderr[-200:])
    finally:
        cleanup(db)


def phase_order_trap() -> None:
    db = None
    try:
        db = make_db()
        shape_admin("postgres", db)
        p = apply_backup_role(db)                       # backup role FIRST ...
        if p.returncode != 0:
            raise SystemExit("FAIL: backup role proposal: " + p.stderr.strip()[:300])
        t = psql(db, file=TERMS)                         # ... terms migration SECOND
        if t.returncode != 0:
            raise SystemExit("FAIL: terms proposal: " + t.stderr.strip()[:300])
        pre, _ = preflight(db)
        bk = pre["candidates"]["backup_role"]
        rec("PF.20_backup_role_before_terms_leaves_three_tables_unreadable",
            bk["tables"] == 33 and bk["tables_unreadable"] == 3 and bk["violations"] == ["tables_unreadable"]
            and tool_violations(db, "jw_backup_ro") == ["tables_unreadable"], json.dumps(bk)[:300])
        fix = psql(db, user=SIM_ADMIN, sql=(
            "BEGIN; GRANT jw_cinema_owner TO CURRENT_USER WITH ADMIN FALSE, INHERIT TRUE, SET FALSE; "
            "GRANT SELECT ON ALL TABLES IN SCHEMA jw_dev TO jw_backup_ro; "
            "REVOKE jw_cinema_owner FROM CURRENT_USER GRANTED BY CURRENT_USER; COMMIT;"))
        fixed, _ = preflight(db)
        back_to_admin_only = scalar(db, (
            "SELECT bool_and(m.admin_option AND NOT m.inherit_option AND NOT m.set_option) AND count(*)=1 FROM pg_auth_members m "
            f"JOIN pg_roles r ON r.oid=m.roleid JOIN pg_roles u ON u.oid=m.member WHERE r.rolname='jw_cinema_owner' AND u.rolname='{SIM_ADMIN}'"))
        rec("PF.21_remedy_regrant_clears_violation_and_restores_admin_only_membership",
            fix.returncode == 0 and fixed["candidates"]["backup_role"]["violations"] == []
            and tool_violations(db, "jw_backup_ro") == [] and back_to_admin_only == "t", fix.stderr[-200:])
    finally:
        cleanup(db)


def main() -> int:
    gate.local_server_or_die()
    server = scalar("postgres", "SHOW server_version_num")
    if not server.isdigit() or (int(server) < 170000 and "--allow-pg16-local" not in sys.argv):
        print("BLOCKED: PostgreSQL 17 required (pass --allow-pg16-local for supplemental local evidence)")
        return 2
    cleanup(None)
    phase_main()
    phase_order_trap()
    failed = [n for n, ok, _ in results if not ok]
    names = [re.match(r"PF\.\d+", n).group(0) for n, _, _ in results]
    ok = not failed and names == EXPECTED
    print(json.dumps({"server_version_num": server, "total": len(results), "expected": len(EXPECTED), "failed": failed}))
    print(("PASS" if ok else "FAIL") + f": {len(results)} checks, {len(failed)} failed, expected exactly {len(EXPECTED)}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
