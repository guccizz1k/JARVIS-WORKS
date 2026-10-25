"""Independent V9.7 catalog-only boundary audit; no customer rows or writes.

Call only after V9.7 validates both secret DSNs and the pinned verify-full CA.
The injected connector must preserve that TLS configuration. Two concurrent,
separate sessions inspect catalog metadata, use SET LOCAL ROLE and roll back.
FORCE RLS metadata is not evidence of actual tenant-row attack resistance.
"""
from __future__ import annotations

import os

from app.pg_full_shadow_v76 import EXPECTED_TABLES


LOGINS = {"auth": "jw_auth_gateway_v90", "trade": "jw_trade_gateway_v90"}
STAGES = {"auth": "jw_auth_stage_v85", "trade": "jw_app_dev"}
ACK = "READ_ONLY_SUPAVISOR_ACCEPTANCE_V97"

LOGIN_SQL = """SELECT current_database(), session_user, current_user,
 r.rolcanlogin, r.rolinherit, r.rolsuper, r.rolbypassrls, r.rolcreatedb,
 r.rolcreaterole, r.rolreplication,
 current_setting('server_version_num')::integer / 10000,
 current_setting('transaction_read_only'),
 (SELECT ssl FROM pg_catalog.pg_stat_ssl WHERE pid=pg_backend_pid()),
 pg_backend_pid()
 FROM pg_catalog.pg_roles r WHERE r.rolname=session_user"""

LOGIN_MEMBERSHIP_SQL = """SELECT
 pg_catalog.pg_has_role(session_user,%s,'MEMBER'),
 pg_catalog.pg_has_role(session_user,%s,'SET'),
 pg_catalog.pg_has_role(session_user,%s,'MEMBER'),
 pg_catalog.pg_has_role(session_user,%s,'SET'),
 pg_catalog.pg_has_role(session_user,%s,'MEMBER'),
 pg_catalog.pg_has_role(session_user,%s,'SET')"""

RAW_PRIVILEGES_SQL = """SELECT EXISTS (
 SELECT 1 FROM pg_catalog.pg_class c
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname IN ('public','jw_dev') AND c.relkind IN ('r','p')
 AND pg_catalog.has_table_privilege(session_user,c.oid,
 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))"""

STAGE_SQL = """SELECT session_user, current_user,
 r.rolcanlogin, r.rolinherit, r.rolsuper, r.rolbypassrls, r.rolcreatedb,
 r.rolcreaterole, r.rolreplication, current_setting('transaction_read_only')
 FROM pg_catalog.pg_roles r WHERE r.rolname=current_user"""

STAGE_MEMBERSHIP_SQL = """SELECT
 pg_catalog.pg_has_role(current_user,%s,'MEMBER'),
 pg_catalog.pg_has_role(current_user,%s,'SET'),
 pg_catalog.pg_has_role(current_user,%s,'MEMBER'),
 pg_catalog.pg_has_role(current_user,%s,'SET')"""

# OIDs avoid private-schema name resolution by NOINHERIT raw gateways.
# All canonical 35 business tables must be in jw_dev; inspect every r/p table
# there so extras cannot hide behind an allowlist. public has no required
# business tables; retain security checks on any canonical names found there.
# No table contents, auth functions or policy expressions are evaluated.
TABLES_SQL = """SELECT n.nspname,c.relname,c.relrowsecurity,c.relforcerowsecurity,
 (c.relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)
  OR pg_catalog.pg_has_role(current_user,c.relowner,'MEMBER')) AS owner_access,
 CASE WHEN c.relname='payments'
  THEN pg_catalog.has_table_privilege(current_user,c.oid,'INSERT')
  ELSE FALSE END AS direct_payment_insert
 FROM pg_catalog.pg_class c
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE c.relkind IN ('r','p') AND
 ((n.nspname='public' AND c.relname=ANY(%s)) OR n.nspname='jw_dev')
 ORDER BY n.nspname,c.relname"""


def _inspect(connection, kind, *, trusted_pooler_tls=False):
    """Return only fixed diagnostic codes and non-customer catalog metadata."""
    other = "trade" if kind == "auth" else "auth"
    with connection.cursor() as cur:
        cur.execute("SET TRANSACTION READ ONLY")
        cur.execute(LOGIN_SQL)
        login = cur.fetchone()
        if (not login or len(login) != 14 or login[:3] != (
                "postgres", LOGINS[kind], LOGINS[kind])
                or login[3:10] != (True, False, False, False, False, False, False)
                or login[10:12] != (17, "on")
                or (login[12] is not True and
                    not (trusted_pooler_tls and login[12] is False))
                or type(login[13]) is not int or login[13] <= 0):
            return ["gateway_attributes_or_transport"], None

        cur.execute(LOGIN_MEMBERSHIP_SQL, (
            STAGES[kind], STAGES[kind], STAGES[other], STAGES[other],
            LOGINS[other], LOGINS[other]))
        if cur.fetchone() != (True, True, False, False, False, False):
            return ["gateway_role_membership"], None
        cur.execute(RAW_PRIVILEGES_SQL)
        if cur.fetchone() != (False,):
            return ["raw_gateway_table_privileges"], None

        # No input-derived identifier is interpolated into SQL.
        cur.execute("SET LOCAL ROLE jw_auth_stage_v85" if kind == "auth"
                    else "SET LOCAL ROLE jw_app_dev")
        cur.execute(STAGE_SQL)
        if cur.fetchone() != (LOGINS[kind], STAGES[kind], False, False, False,
                               False, False, False, False, "on"):
            return ["stage_identity_or_attributes"], None
        cur.execute(STAGE_MEMBERSHIP_SQL, (
            STAGES[other], STAGES[other], LOGINS[other], LOGINS[other]))
        if cur.fetchone() != (False, False, False, False):
            return ["stage_cross_role_membership"], None

        cur.execute(TABLES_SQL, (sorted(EXPECTED_TABLES),))
        rows = cur.fetchall()
        if (not rows or any(len(row) != 6 for row in rows)
                or len({row[:2] for row in rows}) != len(rows)):
            return ["catalog_metadata_missing"], None
        public = {row[1] for row in rows if row[0] == "public"}
        stage = {row[1] for row in rows if row[0] == "jw_dev"}
        issues = []
        if stage != EXPECTED_TABLES:
            issues.append("jw_dev_application_table_set")
        for schema, _table, enabled, forced, owner, insert in rows:
            if schema not in ("public", "jw_dev"):
                issues.append("unexpected_catalog_scope")
            if enabled is not True or forced is not True:
                issues.append("rls_not_enabled_and_forced")
            if owner is not False:
                issues.append("stage_owns_or_is_member_of_table_owner")
            if insert is not False:
                issues.append("direct_payment_insert")
        # The snapshot omits grants, which intentionally differ between stages.
        snapshot = (login[13], tuple(sorted((r[0], r[1], r[2], r[3]) for r in rows)),
                    len(stage), len(public))
        return sorted(set(issues)), snapshot


def check_independent_boundaries(*, connector, trade_dsn, auth_dsn, env=None,
                                 trusted_pooler_tls=False):
    """Fixed, redacted verdict only; neither imports a driver nor reads secrets.

    The caller supplies already validated DSNs and its verified-full connector.
    Every opened connection is rolled back and closed even on probe failure.
    """
    base = {"decision": "BLOCKED", "checked": False, "catalog_only": True,
            "tenant_row_isolation": "NOT RUN", "production_cutover": False,
            "production_deployed": False}
    e = os.environ if env is None else env
    if e.get("JW_ENV") != "review" or e.get("JW_V97_LIVE_ACK") != ACK:
        return {**base, "failed_checks": ["review_opt_in_missing"]}
    if not trade_dsn or not auth_dsn or trade_dsn == auth_dsn or connector is None:
        return {**base, "failed_checks": ["two_independent_validated_dsns_required"]}

    connections = []
    snapshots = []
    issues = []
    try:
        for kind, dsn in (("auth", auth_dsn), ("trade", trade_dsn)):
            try:
                db = connector(dsn, sslmode="verify-full", connect_timeout=5)
                if any(db is previous for _, previous in connections):
                    issues.append("independent_connections_required")
                    break
                connections.append((kind, db))
            except Exception:
                issues.append(kind + ":connection_failed")
                break
        if len(connections) == 2 and not issues:
            for kind, db in connections:
                try:
                    findings, snapshot = _inspect(db, kind, trusted_pooler_tls=trusted_pooler_tls)
                    issues.extend(kind + ":" + code for code in findings)
                    snapshots.append(snapshot)
                except Exception:
                    issues.append(kind + ":catalog_query_failed")
            if not issues:
                if snapshots[0][0] == snapshots[1][0]:
                    issues.append("independent_backends_required")
                if snapshots[0][1:] != snapshots[1][1:]:
                    issues.append("catalog_changed_between_sessions")
    finally:
        for kind, db in connections:
            try:
                db.rollback()
            except Exception:
                issues.append(kind + ":rollback_failed")
            finally:
                try:
                    db.close()
                except Exception:
                    issues.append(kind + ":close_failed")
    if issues or len(snapshots) != 2:
        return {**base, "checked": bool(connections),
                "failed_checks": sorted(set(issues or ["independent_probe_incomplete"]))}
    return {**base, "decision": "PASS", "checked": True,
            "public_application_tables": snapshots[0][3],
            "jw_dev_tables": snapshots[0][2], "catalog_boundaries": "PASS",
            "read_only_rollback": "PASS", "backend_tls_active": True}
