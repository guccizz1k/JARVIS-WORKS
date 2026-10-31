"""V16.8 adversarial REAL PostgreSQL 17 forced-RLS policy acceptance.

Runs ONLY against a fresh, disposable Actions 127.0.0.1 postgres:17.
NEVER shared Supabase, Never PROD, Never existing schema, Never application data.
Proves baseline vulnerable orphan-parent relation is hidden by 13 ALTER POLICY
statements, tenant A/B separation, member denials and rollback fail-closed.
"""
from __future__ import annotations

from pathlib import Path
import os
import secrets
from collections import defaultdict

import psycopg
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg import errors

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = ROOT / "scripts/review/v168_dev_rls_parent_tenant_candidate.sql"
DSN = os.environ.get("JW_PG_CI_ROOT_DSN", "")
TENANTS = ("orga", "orgb")
CHILDREN = {
    "automation_statements_v60": ("orders", "order_id", "o"),
    "evidence_lines_v66": ("evidence_records_v64", "record_id", "r"),
    "evidence_links_v65": ("evidence_records_v64", "record_id", "r"),
    "evidence_records_v64": ("evidence_previews_v64", "preview_id", "p"),
    "invoice_adjustment_decisions_v69": ("invoice_adjustments_v69", "adjustment_id", "a"),
    "invoice_adjustments_v69": ("invoices", "invoice_id", "i"),
    "payments": ("invoices", "invoice_id", "i"),
    "reconciliation_reviews_v67": ("evidence_records_v64", "record_id", "r"),
}
SELECT_POLICIES = {
    "automation_statements_v60": "jw_stage_read_automation_statements_v60",
    "evidence_lines_v66": "jw_stage_read_evidence_lines_v66",
    "evidence_links_v65": "jw_stage_read_evidence_links_v65",
    "evidence_records_v64": "jw_stage_read_evidence_records_v64",
    "invoice_adjustment_decisions_v69": "jw_stage_read_invoice_adjustment_decisions_v69",
    "invoice_adjustments_v69": "jw_stage_read_invoice_adjustments_v69",
    "payments": "jw_stage_read_payments",
    "reconciliation_reviews_v67": "jw_stage_read_reconciliation_reviews_v67",
}
RECEIPT_CHILDREN = {
    "review_delivery_items_v151": ("v153_delivery_line_select", "v159_item_read"),
    "review_delivery_nonces_v151": ("v153_delivery_nonce_select", "v159_nonce_read"),
}
PARENT_TABLES = {
    "orders", "evidence_records_v64", "evidence_previews_v64",
    "invoice_adjustments_v69", "invoices", "review_delivery_receipts_v151",
}
ALL_TABLES = set(CHILDREN) | PARENT_TABLES | set(RECEIPT_CHILDREN)
COUNT_PAD = 40-len(ALL_TABLES)
assert COUNT_PAD >= 0


def guard_root():
    if os.getenv("JW_PG_CI_ALLOW") != "ONLY_EPHEMERAL_LOCAL_DATABASE":
        raise RuntimeError("BLOCKED: isolated PG17 CI consent missing")
    d = conninfo_to_dict(DSN)
    if any((
        d.get("host") != "127.0.0.1",
        d.get("port", "5432") != "5432",
        d.get("dbname") != "postgres",
        d.get("user") != "postgres",
    )):
        raise RuntimeError("BLOCKED: nonlocal or non-disposable PostgreSQL")
    with psycopg.connect(DSN) as c:
        assert int(c.execute("SHOW server_version_num").fetchone()[0])//10000 == 17
        assert c.execute("SELECT to_regclass('jw_dev.payments')").fetchone() == (None,)
        assert c.execute("SELECT count(*) FROM pg_roles WHERE rolname IN "
                         "('jw_app_dev','jw_delivery_writer_v159','jw_ci_v168_login')").fetchone() == (0,)
        assert c.execute("SELECT count(*) FROM pg_database WHERE NOT datistemplate AND datname<>'postgres'").fetchone() == (0,)


def bootstrap():
    pwd = secrets.token_urlsafe(32)
    with psycopg.connect(DSN, autocommit=True) as root:
        root.execute("CREATE SCHEMA jw_dev")
        for role in ("jw_app_dev", "jw_delivery_writer_v159"):
            root.execute("CREATE ROLE " + role + " NOLOGIN NOINHERIT NOBYPASSRLS")
        root.execute("CREATE ROLE jw_ci_v168_login LOGIN NOINHERIT NOBYPASSRLS PASSWORD %s" % psycopg.sql.Literal(pwd).as_string(root))
        root.execute("GRANT jw_app_dev, jw_delivery_writer_v159 TO jw_ci_v168_login WITH INHERIT FALSE, SET TRUE")
        root.execute("GRANT USAGE ON SCHEMA jw_dev TO jw_app_dev,jw_delivery_writer_v159")
        root.execute("""CREATE FUNCTION jw_dev.current_org_from_session() RETURNS text
            LANGUAGE SQL STABLE SECURITY INVOKER AS $$
              SELECT nullif(current_setting('jw.test_org',true),'')::text
            $$""")
        root.execute("""CREATE FUNCTION jw_dev.stage_identity_v84()
            RETURNS TABLE(actor_id text,org_id text,actor_role text,csrf_token text,org_name text)
            LANGUAGE SQL STABLE SECURITY INVOKER AS $$
              SELECT 'actor',nullif(current_setting('jw.test_org',true),''),
                     nullif(current_setting('jw.test_role',true),''),
                     'csrf','Synthetic Organization'
            $$""")
        root.execute("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA jw_dev TO jw_app_dev,jw_delivery_writer_v159")
        for table in sorted(ALL_TABLES):
            cols = "id text PRIMARY KEY,org_id text NOT NULL"
            if table=="orders":
                cols += ",status text NOT NULL DEFAULT 'fulfilled',review_state text NOT NULL DEFAULT 'acknowledged'"
            if table in CHILDREN:
                cols += ","+CHILDREN[table][1]+" text NOT NULL"
            if table in RECEIPT_CHILDREN or table=="review_delivery_receipts_v151":
                cols += ",order_id text NOT NULL"
            root.execute("CREATE TABLE jw_dev."+table+" ("+cols+")")
        for i in range(COUNT_PAD):
            root.execute(f"CREATE TABLE jw_dev.ci_v168_padding_{i:02d} (id text PRIMARY KEY,org_id text)")
        for table in sorted(ALL_TABLES):
            root.execute("ALTER TABLE jw_dev."+table+" ENABLE ROW LEVEL SECURITY")
            root.execute("ALTER TABLE jw_dev."+table+" FORCE ROW LEVEL SECURITY")
        for i in range(COUNT_PAD):
            table=f"ci_v168_padding_{i:02d}"
            root.execute("ALTER TABLE jw_dev."+table+" ENABLE ROW LEVEL SECURITY")
            root.execute("ALTER TABLE jw_dev."+table+" FORCE ROW LEVEL SECURITY")
        root.execute("GRANT SELECT ON ALL TABLES IN SCHEMA jw_dev TO jw_app_dev,jw_delivery_writer_v159")
        root.execute("GRANT INSERT ON jw_dev.review_delivery_receipts_v151 TO jw_delivery_writer_v159")
        # Deliberately permissive parent RLS models an accidental relaxation.
        # Baseline child policy must NOT trust unbound parent IDs.
        for parent in sorted(PARENT_TABLES):
            root.execute(f"CREATE POLICY ci_parent_read_{parent} ON jw_dev.{parent} "
                         "FOR SELECT TO jw_app_dev,jw_delivery_writer_v159 USING (true)")
        for child,(parent,foreign,alias) in CHILDREN.items():
            policy=SELECT_POLICIES[child]
            predicate=(f"org_id=jw_dev.current_org_from_session() AND EXISTS "
                       f"(SELECT 1 FROM jw_dev.{parent} {alias} WHERE {alias}.id={child}.{foreign} "
                       f"AND {alias}.org_id={alias}.org_id)")
            root.execute(f"CREATE POLICY {policy} ON jw_dev.{child} FOR SELECT TO jw_app_dev "
                         f"USING ({predicate})")
        for child,policies in RECEIPT_CHILDREN.items():
            predicate=(f"EXISTS(SELECT 1 FROM jw_dev.review_delivery_receipts_v151 r "
                       f"WHERE r.order_id={child}.order_id)")
            for policy,role in zip(policies,("jw_app_dev","jw_delivery_writer_v159")):
                root.execute(f"CREATE POLICY {policy} ON jw_dev.{child} FOR SELECT TO {role} USING ({predicate})")
        root.execute("""CREATE POLICY v159_receipt_insert
            ON jw_dev.review_delivery_receipts_v151 FOR INSERT TO jw_delivery_writer_v159
            WITH CHECK (org_id=jw_dev.current_org_from_session()
              AND EXISTS (SELECT 1 FROM jw_dev.stage_identity_v84() a
                          WHERE a.org_id=a.org_id AND a.actor_role='admin')
              AND EXISTS (SELECT 1 FROM jw_dev.orders o
                          WHERE o.id=review_delivery_receipts_v151.order_id
                            AND o.org_id=review_delivery_receipts_v151.org_id
                            AND o.status='fulfilled' AND o.review_state='acknowledged'))""")
        root.execute("""CREATE POLICY ci_receipt_read ON jw_dev.review_delivery_receipts_v151
            FOR SELECT TO jw_app_dev,jw_delivery_writer_v159
            USING(org_id=jw_dev.current_org_from_session())""")
        for table in sorted(PARENT_TABLES):
            for org in TENANTS:
                # A parent table may also be a child with a NOT NULL source.
                # Preserve the complete valid chain in real PostgreSQL.
                columns=["id","org_id"]
                values=[f"{table}-{org}",org]
                if table in CHILDREN:
                    parent,foreign,_=CHILDREN[table]
                    columns.append(foreign)
                    values.append(f"{parent}-{org}")
                if table=="review_delivery_receipts_v151":
                    columns.append("order_id")
                    values.append(f"orders-{org}")
                placeholders=",".join("%s" for _ in values)
                root.execute(
                    f"INSERT INTO jw_dev.{table} ({','.join(columns)}) VALUES ({placeholders})",
                    tuple(values),
                )
        for child,(parent,foreign,_) in CHILDREN.items():
            for actor,linked,id_suffix in [
                ("orga","orga","good"),
                ("orga","orgb","bad"),
                ("orgb","orgb","good-b"),
            ]:
                root.execute(f"INSERT INTO jw_dev.{child} (id,org_id,{foreign}) VALUES (%s,%s,%s)",
                             (f"{child}-{id_suffix}",actor,f"{parent}-{linked}"))
        for child in RECEIPT_CHILDREN:
            for actor,linked,id_suffix in [
                ("orga","orga","good"),("orga","orgb","bad"),("orgb","orgb","good-b")
            ]:
                root.execute(f"INSERT INTO jw_dev.{child} (id,org_id,order_id) VALUES (%s,%s,%s)",
                             (f"{child}-{id_suffix}",actor,f"orders-{linked}"))
    return make_conninfo(DSN,user="jw_ci_v168_login",password=pwd)


def check_failed_guard():
    source=CANDIDATE.read_text()
    assert "DEV_ONLY_V168_EXPLICIT" in source
    with psycopg.connect(DSN) as root:
        try:
            with root.transaction():
                root.execute(source)
        except psycopg.errors.RaiseException as err:
            assert "V168 isolated DEV policy change not approved" in str(err)
        else:
            raise AssertionError("Candidate accepted missing explicit approval")
        root.execute("ALTER TABLE jw_dev.ci_v168_padding_00 NO FORCE ROW LEVEL SECURITY")
        try:
            with root.transaction():
                root.execute("SELECT set_config('jw.v168_review_approval','DEV_ONLY_V168_EXPLICIT',true)")
                root.execute(source)
        except psycopg.errors.RaiseException as err:
            assert "expected exactly 40 FORCE RLS tables" in str(err)
        else:
            raise AssertionError("Candidate accepted weakened RLS inventory")
        root.execute("ALTER TABLE jw_dev.ci_v168_padding_00 FORCE ROW LEVEL SECURITY")


def query_as(dsn,role,org,table,suffix):
    with psycopg.connect(dsn) as client:
        client.execute("SET LOCAL ROLE "+role)
        client.execute("SELECT set_config('jw.test_org',%s,true)",(org,))
        client.execute("SELECT set_config('jw.test_role','admin',true)")
        return client.execute("SELECT id FROM jw_dev."+table+" WHERE id=%s",
                              (table+"-"+suffix,)).fetchall()


def check_business_rows(dsn,expected_deny_bad,check_member=False):
    count=defaultdict(int)
    for child in CHILDREN:
        assert query_as(dsn,"jw_app_dev","orga",child,"good"),(child,"owned")
        assert query_as(dsn,"jw_app_dev","orgb",child,"good-b"),(child,"B owned")
        assert not query_as(dsn,"jw_app_dev","orga",child,"good-b"),(child,"foreign")
        invalid=query_as(dsn,"jw_app_dev","orga",child,"bad")
        if expected_deny_bad:
            assert not invalid,(child,"forged cross-tenant parent")
        else:
            assert invalid,(child,"baseline expected exposure")
        count["child_read_cases"]+=4
    for child in RECEIPT_CHILDREN:
        for role in ("jw_app_dev","jw_delivery_writer_v159"):
            assert query_as(dsn,role,"orga",child,"good")
            assert query_as(dsn,role,"orgb",child,"good-b")
            assert not query_as(dsn,role,"orga",child,"bad")
            assert not query_as(dsn,role,"orga",child,"good-b")
            count["receipt_cases"]+=4
    return count


def check_inserts(dsn):
    def insert(org,identity,order,receipt_id):
        with psycopg.connect(dsn) as c:
            try:
                c.execute("SET LOCAL ROLE jw_delivery_writer_v159")
                c.execute("SELECT set_config('jw.test_org',%s,true)",(org,))
                c.execute("SELECT set_config('jw.test_role',%s,true)",(identity,))
                c.execute("""INSERT INTO jw_dev.review_delivery_receipts_v151
                             (id,org_id,order_id) VALUES (%s,%s,%s)""",
                          (receipt_id,org,order))
                return True
            except (errors.InsufficientPrivilege,errors.CheckViolation):
                return False
    assert insert("orga","admin","orders-orga","insert-good-a")
    assert insert("orgb","admin","orders-orgb","insert-good-b")
    assert not insert("orga","member","orders-orga","insert-member")
    assert not insert("orgb","member","orders-orgb","insert-b-member")
    assert not insert("orga","admin","orders-orgb","insert-cross-order")
    assert not insert("orgb","admin","orders-orga","insert-cross-b")
    assert not insert("orga","admin","missing","insert-missing-order")
    with psycopg.connect(DSN) as root:
        assert root.execute("""SELECT count(*) FROM jw_dev.review_delivery_receipts_v151
                    WHERE id LIKE 'insert-%'""").fetchone() == (2,)
    return 7


def main():
    guard_root()
    dsn=bootstrap()
    initial=check_business_rows(dsn,expected_deny_bad=False)
    check_failed_guard()
    # Only after proving absent approval and weakened RLS inventory fail closed
    # may this ephemeral postgres:17 use a temporary guarded test opt-in.
    with psycopg.connect(DSN) as root:
        root.execute("SELECT set_config('jw.v168_review_approval','DEV_ONLY_V168_EXPLICIT',true)")
        root.execute(CANDIDATE.read_text())
        policies=root.execute("""SELECT policyname,tablename,qual,with_check
                      FROM pg_policies WHERE schemaname='jw_dev' AND
                      policyname IN ('jw_stage_read_payments','v159_receipt_insert',
                                     'v153_delivery_nonce_select') ORDER BY policyname""").fetchall()
        assert len(policies)==3,policies
        assert "i.org_id = payments.org_id" in next(x[2] for x in policies if x[0]=="jw_stage_read_payments")
        assert "r.org_id = jw_dev.current_org_from_session()" in next(x[2] for x in policies if x[0]=="v153_delivery_nonce_select")
    after=check_business_rows(dsn,expected_deny_bad=True)
    write_cases=check_inserts(dsn)
    for label in ("child_read_cases","receipt_cases"):
        assert initial[label] == after[label],(label,initial,after)
    assert after["child_read_cases"] >= 32
    assert after["receipt_cases"] >= 16
    print("PASS_V168_REAL_PG17_BASELINE_REPRODUCED_BAD_PARENT_FOREIGN_LINKS",flush=True)
    print("PASS_V168_13_ALTER_POLICIES_GUARDED_AND_40_FORCE_RLS_PRESERVED",flush=True)
    print("PASS_V168_REAL_TWO_RESTRICTED_ROLES_CROSS_TENANT_READ_DENIAL",flush=True)
    print("PASS_V168_SIGNED_REVIEW_WRITER_ADMIN_MEMBER_CROSS_ORG_WRITE_DENIAL",flush=True)
    print(f"PASS_V168_REAL_PG17_CHECKS {sum(after.values())+write_cases} post-fix checks; "
          f"{sum(initial.values())} vulnerable-baseline probes; zero skips",flush=True)
    print("LIMIT: disposable PG17 simulation; actual shared DEV/PROD never modified",flush=True)


if __name__=="__main__":
    main()
