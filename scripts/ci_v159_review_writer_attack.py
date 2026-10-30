"""V15.9 exploit reproduction and fail-closed dedicated writer role boundary.

Disposable, freshly bootstrapped PostgreSQL 17 service ONLY. Proves legacy
general trade role can forge pending evidence via direct SQL; then proves
REVOKE blocks it while a separately credentialed writer role is still allowed
to store audit-backed records. Neither role can certify shipment/post payment.
"""
from pathlib import Path
import secrets
import psycopg
from psycopg import errors,sql
from psycopg.conninfo import make_conninfo
from scripts import ci_v157_real_pg_delivery_http as fixture

ROOT=Path(__file__).resolve().parents[1]


def raw_receipt(conn, *, role, session, order_id, org_id, marker):
    with conn.cursor() as cur:
        cur.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(role)))
        cur.execute("SELECT pg_catalog.set_config('jw.session_hash',%s,true)",
                    (fixture.sha256(fixture.TOKENS[session].encode()).hexdigest(),))
        cur.execute("""INSERT INTO jw_dev.review_delivery_receipts_v151(
          order_id,org_id,source_sha256,evidence_sha256,
          dispatch_document_sha256,recipient_document_sha256,
          dispatch_actor,recipient_actor,subtotal_krw,vat_krw,total_krw)
          VALUES(%s,%s,%s,%s,%s,%s,%s,%s,7000,700,7700)""",
          (order_id,org_id,"1"*64,marker*64,"2"*64,"3"*64,"5"*32,"6"*32))


def main():
    fixture.bootstrap()   # Enforces 127.0.0.1:5432; no other DB/roles/tables.
    # Prove vulnerable old schema permits fabricated pending reviews WITHOUT
    # the independently attested signed HTTP evidence.
    with psycopg.connect(fixture.TRADE_DSN) as trade:
        raw_receipt(trade,role="jw_app_dev",session="A",
                    order_id=fixture.ORDER_A,org_id=fixture.ORG_A,marker="e")
        assert trade.execute(
            "SELECT count(*) FROM jw_dev.review_delivery_receipts_v151"
        ).fetchone()==(1,)
        trade.rollback()
    with psycopg.connect(fixture.DSN) as root:
        assert root.execute(
            "SELECT count(*) FROM jw_dev.review_delivery_receipts_v151"
        ).fetchone()==(0,)
    print("REPRO_V159_LEGACY_DIRECT_INSERT_BYPASSES_SIGNATURE_CHECK",flush=True)

    with psycopg.connect(fixture.DSN,autocommit=True) as root:
        root.execute(
            (ROOT/"scripts/review/v159_dedicated_delivery_writer_candidate.sql").read_text()
        )
        password=secrets.token_urlsafe(36)
        root.execute(sql.SQL(
            "CREATE ROLE jw_ci_v159_writer LOGIN NOINHERIT NOBYPASSRLS "
            "NOSUPERUSER NOCREATEROLE NOCREATEDB PASSWORD {}"
        ).format(sql.Literal(password)))
        root.execute("""GRANT jw_delivery_writer_v159 TO jw_ci_v159_writer
                     WITH INHERIT FALSE, SET TRUE""")
        assert root.execute("""SELECT has_table_privilege(
            'jw_app_dev','jw_dev.review_delivery_receipts_v151','INSERT')""").fetchone()==(False,)
        assert root.execute("""SELECT has_table_privilege(
            'jw_delivery_writer_v159','jw_dev.review_delivery_receipts_v151','INSERT')""").fetchone()==(True,)
        assert root.execute("""SELECT has_table_privilege(
            'jw_delivery_writer_v159','jw_dev.orders','UPDATE')""").fetchone()==(False,)
        assert root.execute("""SELECT pg_has_role(
            'jw_ci_v157_trade','jw_delivery_writer_v159','MEMBER')""").fetchone()==(False,)
        assert root.execute("""SELECT pg_has_role(
            'jw_ci_v159_writer','jw_auth_stage_v85','MEMBER')""").fetchone()==(False,)
        assert root.execute("""SELECT pg_has_role(
            'jw_ci_v159_writer','jw_app_dev','MEMBER')""").fetchone()==(False,)

    # The stolen general trade SQL login can no longer forge even an A-tenant
    # valid-order receipt and cannot adopt the writer role.
    with psycopg.connect(fixture.TRADE_DSN) as trade:
        try:
            with trade.transaction():
                raw_receipt(trade,role="jw_app_dev",session="A",
                            order_id=fixture.ORDER_A,org_id=fixture.ORG_A,
                            marker="e")
        except errors.InsufficientPrivilege:
            pass
        else:
            raise AssertionError("FAIL_V159_TRADE_STILL_CAN_FORGE_RECEIPT")
        try:
            with trade.transaction():
                trade.execute("SET LOCAL ROLE jw_delivery_writer_v159")
        except errors.InsufficientPrivilege:
            pass
        else:
            raise AssertionError("FAIL_V159_TRADE_CAN_IMPERSONATE_WRITER")

    # Writer is a DIFFERENT credential/role. It may add a pending row
    # only under the same verified company-admin RLS and source checks.
    writer_dsn=make_conninfo(
        fixture.DSN,user="jw_ci_v159_writer",password=password)
    with psycopg.connect(writer_dsn) as writer:
        with writer.transaction():
            raw_receipt(writer,role="jw_delivery_writer_v159",session="A",
                        order_id=fixture.ORDER_A,org_id=fixture.ORG_A,marker="e")

    with psycopg.connect(fixture.DSN) as admin:
        assert admin.execute(
            "SELECT count(*) FROM jw_dev.review_delivery_receipts_v151"
        ).fetchone()==(1,)
    with psycopg.connect(writer_dsn) as writer:
        # Valid B session cannot insert for tenant A.
        try:
            with writer.transaction():
                raw_receipt(writer,role="jw_delivery_writer_v159",session="B",
                            order_id=fixture.ORDER_B,org_id=fixture.ORG_A,marker="f")
        except (errors.InsufficientPrivilege,errors.CheckViolation,errors.ForeignKeyViolation):
            pass
        else:
            raise AssertionError("FAIL_V159_CROSS_ORG_WRITE")
        # A non-admin in company A cannot inject a receipt either.
        try:
            with writer.transaction():
                raw_receipt(writer,role="jw_delivery_writer_v159",session="M",
                            order_id=fixture.ORDER_B,org_id=fixture.ORG_B,marker="f")
        except (errors.InsufficientPrivilege,errors.CheckViolation,errors.ForeignKeyViolation):
            pass
        else:
            raise AssertionError("FAIL_V159_MEMBER_WRITE")

    with psycopg.connect(fixture.DSN) as admin:
        assert admin.execute(
            "SELECT count(*) FROM jw_dev.review_delivery_receipts_v151"
        ).fetchone()==(1,)
        assert admin.execute(
            "SELECT count(*) FROM jw_dev.invoices"
        ).fetchone()==(0,)
        assert admin.execute(
            "SELECT count(*) FROM jw_dev.audit_logs"
        ).fetchone()==(0,)
    print("PASS_V159_GENERAL_TRADE_DIRECT_FORGERY_DENIED",flush=True)
    print("PASS_V159_SEPARATE_LIMITED_WRITER_ROLE_NOT_ADOPTABLE_BY_TRADE",flush=True)
    print("PASS_V159_INDEPENDENT_LOGIN_RLS_TENANT_AND_MEMBER_DENIED",flush=True)
    print("PASS_V159_NO_SOURCE_ORDER_UPDATE_INVOICE_PAYMENT_PRIVILEGE",flush=True)
    print("LIMIT: dedicated writer can still write arbitrary review rows if its OWN "
          "credential is stolen; actual issuer validation and service binding are "
          "required before deploying. Existing V154 POST fails closed after REVOKE.",
          flush=True)


if __name__=="__main__":
    main()
