"""Read-only V10.8 source-to-target PG17 catalog equivalence (NO migration).

The source snapshot contains counts and MD5 digests ONLY, not function bodies,
business rows or database secrets. This code is intentionally incapable of
creating schema objects, setting RLS, granting privileges, or executing DML.
It is BLOCKED without the V10.7 independent restricted-role boundary PASS.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from . import jw_v107_render_pg_schema_gate as role_gate

MANIFEST = Path(__file__).resolve().parents[1] / "db/review/v108_source_schema_fingerprints.json"

EXPECTED_COUNTS = {
    "tables": 35,
    "columns": 282,
    "constraints": 183,
    "indexes": 87,
    "policies": 40,
    "triggers": 45,
    "functions": 28,
    "sequences": 1,
    "table_acl": 40,
    "function_acl": 18,
}
HEX_MD5 = re.compile(r"^[a-f0-9]{32}$")


# Each digest excludes catalog object OIDs and real data rows. The queries are
# anchored to schema jw_dev (PostgreSQL17). Source query texts are versioned to
# ensure the source and target apply identical deterministic normalizations.
QUERIES: dict[str, str] = {
    "tables": """SELECT count(*) n, md5(string_agg(c.relname,E'\\n' ORDER BY c.relname)) digest FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='jw_dev' AND c.relkind IN('r','p')""",
    "columns": """WITH c AS MATERIALIZED (
 SELECT cls.relname AS tbl,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod) AS typ,a.attnotnull,coalesce(pg_get_expr(d.adbin,d.adrelid),'<none>') AS default_expr
 FROM pg_class cls JOIN pg_namespace n ON n.oid=cls.relnamespace JOIN pg_attribute a ON a.attrelid=cls.oid AND a.attnum>0 AND NOT a.attisdropped LEFT JOIN pg_attrdef d ON d.adrelid=cls.oid AND d.adnum=a.attnum
 WHERE n.nspname='jw_dev' AND cls.relkind IN('r','p'))
 SELECT count(*) n,md5(string_agg(concat_ws('|',tbl,attnum,attname,typ,attnotnull,default_expr),E'\\n' ORDER BY tbl,attnum)) digest FROM c""",
    "constraints": """WITH c AS MATERIALIZED (SELECT cls.relname AS tbl,k.conname,k.contype,pg_get_constraintdef(k.oid,true) AS def FROM pg_constraint k JOIN pg_class cls ON cls.oid=k.conrelid JOIN pg_namespace n ON n.oid=cls.relnamespace WHERE n.nspname='jw_dev')
 SELECT count(*) n,md5(string_agg(concat_ws('|',tbl,conname,contype,def),E'\\n' ORDER BY tbl,conname)) digest FROM c""",
    "indexes": """WITH x AS MATERIALIZED(SELECT c.relname tbl,i.relname index_name,pg_get_indexdef(i.oid) AS def FROM pg_index ix JOIN pg_class c ON c.oid=ix.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_class i ON i.oid=ix.indexrelid WHERE n.nspname='jw_dev')
 SELECT count(*) n,md5(string_agg(concat_ws('|',tbl,index_name,def),E'\\n' ORDER BY tbl,index_name)) digest FROM x""",
    "policies": """WITH x AS MATERIALIZED (SELECT tablename,policyname,permissive,roles::text AS roles,cmd,coalesce(qual,'<none>') AS qual,coalesce(with_check,'<none>') AS with_check FROM pg_policies WHERE schemaname='jw_dev')
 SELECT count(*) n,md5(string_agg(concat_ws('|',tablename,policyname,permissive,roles,cmd,qual,with_check),E'\\n' ORDER BY tablename,policyname)) digest FROM x""",
    "triggers": """WITH x AS MATERIALIZED (SELECT c.relname tbl,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid,true) AS def FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='jw_dev' AND NOT t.tgisinternal)
 SELECT count(*) n,md5(string_agg(concat_ws('|',tbl,tgname,tgenabled,def),E'\\n' ORDER BY tbl,tgname)) digest FROM x""",
    "functions": """WITH x AS MATERIALIZED (SELECT p.oid,p.proname,pg_get_function_identity_arguments(p.oid) args FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='jw_dev' AND p.prokind='f')
 SELECT count(*) n,md5(string_agg(pg_get_functiondef(oid),E'\\n' ORDER BY proname,args)) digest FROM x""",
    "sequences": """WITH x AS MATERIALIZED(SELECT c.relname AS seq_name,format_type(s.seqtypid,NULL) AS data_type,s.seqstart,s.seqincrement,s.seqmin,s.seqmax,s.seqcache,s.seqcycle FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_sequence s ON s.seqrelid=c.oid WHERE n.nspname='jw_dev')
 SELECT count(*) n,md5(string_agg(concat_ws('|',seq_name,data_type,seqstart,seqincrement,seqmin,seqmax,seqcache,seqcycle),E'\\n' ORDER BY seq_name)) digest FROM x""",
    "table_acl": """WITH x AS MATERIALIZED (SELECT c.relname AS tbl,r.rolname AS grantee,a.privilege_type,a.is_grantable FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a JOIN pg_roles r ON r.oid=a.grantee WHERE n.nspname='jw_dev' AND c.relkind='r' AND r.rolname IN('jw_app_dev','jw_auth_stage_v85'))
 SELECT count(*) n,md5(string_agg(concat_ws('|',tbl,grantee,privilege_type,is_grantable),E'\\n' ORDER BY tbl,grantee,privilege_type)) digest FROM x""",
    "function_acl": """WITH x AS MATERIALIZED (SELECT p.proname AS name,pg_get_function_identity_arguments(p.oid) AS args,r.rolname AS grantee,a.privilege_type,a.is_grantable FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a JOIN pg_roles r ON r.oid=a.grantee WHERE n.nspname='jw_dev' AND p.prokind='f' AND r.rolname IN('jw_app_dev','jw_auth_stage_v85'))
 SELECT count(*) n,md5(string_agg(concat_ws('|',name,args,grantee,privilege_type,is_grantable),E'\\n' ORDER BY name,args,grantee,privilege_type)) digest FROM x""",
    "forced_rls": """SELECT count(*) AS n, count(*) FILTER (WHERE c.relrowsecurity AND c.relforcerowsecurity) AS force_rls FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='jw_dev' AND c.relkind IN('r','p')""",
}


def source_baseline() -> dict:
    """Validate pinned shape and types, not just digest lengths.

    This is a REVIEW FINGERPRINT, not independent authorization to migrate.
    """
    source = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if (type(source) is not dict
        or source.get("schema") != "jw_dev"
        or source.get("source_kind") != "development_postgresql_catalog_metadata_only"
        or source.get("source_pg_major") != 17
        or source.get("source_checked_date") != "2026-10-25"
        or source.get("data_rows_extracted") is not False
        or source.get("function_source_extracted_to_repository") is not False
        or source.get("migration_authorized") is not False):
        raise RuntimeError("Source fingerprint manifest has an invalid scope")
    counts = source.get("counts_and_md5")
    if type(counts) is not dict or set(counts) != set(QUERIES):
        raise RuntimeError("Source fingerprint sections are missing or unexpected")
    for key, row in counts.items():
        if type(row) is not dict:
            raise RuntimeError("Invalid fingerprint section type: " + key)
        if key == "forced_rls":
            if (set(row) != {"n", "force_rls"}
                or type(row["n"]) is not int
                or type(row["force_rls"]) is not int
                or row != {"n": 35, "force_rls": 35}):
                raise RuntimeError("Malformed FORCE RLS source fingerprint")
        else:
            if (set(row) != {"n", "digest"}
                or type(row["n"]) is not int
                or row["n"] != EXPECTED_COUNTS[key]
                or type(row["digest"]) is not str
                or HEX_MD5.fullmatch(row["digest"]) is None):
                raise RuntimeError("Malformed source fingerprint: " + key)
    return counts


def verify(*, env: dict | None = None, connector: Any = None,
           role_boundary: Any = None) -> dict:
    """Read-only, redacted and cleanup-fail-closed metadata comparison.

    A PASS is only scoped to catalogue fingerprints. It is NEVER an RLS
    penetration-test PASS, signed approval, or deploy authorization.
    """
    settings = os.environ if env is None else env
    result = {
        "decision": "BLOCKED",
        "scope": "V108_RENDER_PRIVATE_CATALOG_FINGERPRINT",
        "read_only": True,
        "customer_rows_read": False,
        "migration_executed": False,
        "production_deployed": False,
        "tls_hostname_verification": "NOT_ATTESTED",
    }
    try:
        expected = source_baseline()
    except Exception:
        return {**result, "reason": "SOURCE_BASELINE_INVALID"}
    try:
        boundary_checker = role_gate.check if role_boundary is None else role_boundary
        boundary = boundary_checker(env=settings, connector=connector)
        if type(boundary) is not dict or boundary.get("decision") != "PASS":
            return {**result, "reason": "TWO_ROLE_BOUNDARY_NOT_VERIFIED"}
    except Exception:
        return {**result, "reason": "TWO_ROLE_BOUNDARY_CHECK_FAILED"}
    try:
        dsn = settings.get("JW_RENDER_PG_TRADE_DSN", "")
        valid = role_gate.valid_dsn(dsn, "trade")
    except Exception:
        valid = False
    if not valid:
        return {**result, "reason": "TRADE_DSN_INVALID"}
    if connector is None:
        import psycopg
        def connector(dsn: str, *, kind: str):
            return psycopg.connect(
                dsn, connect_timeout=5,
                options="-c default_transaction_read_only=on -c statement_timeout=5000 -c lock_timeout=1000",
                application_name="jw_v108_schema_metadata_only", gssencmode="disable")
    try:
        conn = connector(dsn, kind="trade")
    except Exception:
        return {**result, "reason": "RESTRICTED_DB_UNREACHABLE"}
    mismatches = []
    query_failed = False
    cleanup_failed = False
    try:
        with conn.cursor() as cursor:
            cursor.execute("SET TRANSACTION READ ONLY")
            for key, query in QUERIES.items():
                cursor.execute(query)
                values = cursor.fetchone()
                if (not isinstance(values, (tuple, list)) or len(values) != 2
                    or type(values[0]) is not int):
                    raise ValueError("Invalid catalog response shape")
                if key == "forced_rls":
                    if type(values[1]) is not int:
                        raise ValueError("Invalid FORCE RLS count")
                    actual = {"n": values[0], "force_rls": values[1]}
                else:
                    if type(values[1]) is not str or HEX_MD5.fullmatch(values[1]) is None:
                        raise ValueError("Invalid catalog hash")
                    actual = {"n": values[0], "digest": values[1]}
                if actual != expected[key]:
                    mismatches.append(key)
    except Exception:
        query_failed = True
    finally:
        try:
            conn.rollback()
        except Exception:
            cleanup_failed = True
        try:
            conn.close()
        except Exception:
            cleanup_failed = True
    if cleanup_failed:
        return {**result, "reason": "CONNECTION_CLEANUP_FAILED"}
    if query_failed:
        return {**result, "reason": "CATALOG_QUERY_FAILED"}
    if mismatches:
        return {**result, "reason": "SCHEMA_FINGERPRINT_MISMATCH",
                "mismatched_sections": sorted(mismatches)}
    return {**result, "decision": "PASS",
            "reason": "METADATA_EQUIVALENT_ONLY",
            "verified_sections": len(QUERIES),
            "tenant_row_isolation": "NOT_RUN"}


def main() -> int:
    out = verify()
    print(json.dumps(out, sort_keys=True))
    return 0 if out["decision"] == "PASS" else 3


if __name__ == "__main__":
    raise SystemExit(main())
