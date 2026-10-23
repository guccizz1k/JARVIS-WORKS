"""Read-only defense-in-depth audit of V2.0 PostgreSQL RLS.

This audits real PostgreSQL catalog state, NOT SQLite. It does NOT prove actual
cross-tenant behavior; run `scripts/test_postgres_rls_runtime.py` as well.
Requires JW_PG_CHECK_DSN; no external DB is contacted when the variable is unset.
"""
import os
import sys

TENANT_TABLES = {
    'organizations', 'users', 'customers', 'quotes', 'quote_items', 'orders',
    'order_items', 'invoices', 'invoice_items', 'payments', 'audit_logs',
    'security_events', 'import_previews',
}
AUTH_TABLES = {'sessions', 'mfa_credentials', 'mfa_recovery_codes', 'login_failures', 'users', 'security_events'}
PRIVATE_TABLES = {'signing_key', 'authenticated_sessions'}
COMPOSITE_FOREIGN_KEYS = {
    ('quotes', 'customers', ('customer_id', 'org_id'), ('id', 'org_id')),
    ('quote_items', 'quotes', ('quote_id', 'org_id'), ('id', 'org_id')),
    ('orders', 'quotes', ('quote_id', 'org_id'), ('id', 'org_id')),
    ('order_items', 'orders', ('order_id', 'org_id'), ('id', 'org_id')),
    ('order_items', 'quote_items', ('source_quote_item_id', 'org_id'), ('id', 'org_id')),
    ('invoices', 'orders', ('order_id', 'org_id'), ('id', 'org_id')),
    ('invoice_items', 'invoices', ('invoice_id', 'org_id'), ('id', 'org_id')),
    ('payments', 'invoices', ('invoice_id', 'org_id'), ('id', 'org_id')),
}
PROTECTED_FUNCTIONS = {'bind_session', 'current_tenant'}


def audit(connection):
    issues = []
    with connection.cursor() as cur:
        cur.execute("""SELECT oid,rolsuper,rolbypassrls,rolcreaterole
            FROM pg_roles WHERE rolname='jw_app'""")
        role = cur.fetchone()
        if not role or any(role[1:]):
            issues.append('jw_app missing or has prohibited privileges')
        cur.execute("""SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity,
                    pg_get_userbyid(c.relowner),c.relowner
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relkind IN ('r','p')""")
        tables = {r[0]: r[1:] for r in cur.fetchall()}
        for name in sorted(TENANT_TABLES):
            item = tables.get(name)
            if not item or item[:2] != (True, True):
                issues.append('RLS not ENABLED and FORCEd: ' + name)
            elif role:
                cur.execute("SELECT pg_has_role(%s::oid,%s::oid,'MEMBER')", (role[0], item[3]))
                if item[2] == 'jw_app' or cur.fetchone()[0]:
                    issues.append('jw_app owns or inherits table owner: ' + name)
        cur.execute("""SELECT tablename,policyname,roles,cmd,qual,with_check,permissive
            FROM pg_policies WHERE schemaname='public'""")
        policies = {}
        for row in cur.fetchall():
            policies.setdefault(row[0], []).append(row)
        for name in sorted(TENANT_TABLES):
            entries = policies.get(name, [])
            if len(entries) != 1:
                issues.append('Exactly one policy required: ' + name)
                continue
            _, policy, roles, cmd, qual, check, permissive = entries[0]
            if (policy != 'jw_rls_guard' or 'jw_app' not in roles or cmd != 'ALL'
                or 'jw_guard.current_tenant()' not in (qual or '')
                or 'jw_guard.current_tenant()' not in (check or '')):
                issues.append('Weak or unexpected policy: ' + name)
        # Verify real catalog constraint *columns*, not just constraint names.
        # A renamed single-column FK is NOT an acceptable tenant composite FK.
        cur.execute("""SELECT child.relname,parent.relname,c.convalidated,
            (SELECT array_agg(a.attname ORDER BY k.ord)
             FROM unnest(c.conkey) WITH ORDINALITY k(attnum,ord)
             JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum),
            (SELECT array_agg(a.attname ORDER BY k.ord)
             FROM unnest(c.confkey) WITH ORDINALITY k(attnum,ord)
             JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.attnum)
            FROM pg_constraint c
            JOIN pg_class child ON child.oid=c.conrelid
            JOIN pg_class parent ON parent.oid=c.confrelid
            JOIN pg_namespace ns ON ns.oid=child.relnamespace
            JOIN pg_namespace ps ON ps.oid=parent.relnamespace
            WHERE c.contype='f' AND ns.nspname='public' AND ps.nspname='public'""")
        found = {(row[0],row[1],tuple(row[3] or []),tuple(row[4] or []))
                 for row in cur.fetchall() if row[2]}
        for item in sorted(COMPOSITE_FOREIGN_KEYS):
            if item not in found:
                issues.append('Missing validated tenant composite FK: '+str(item))
        for name in sorted(TENANT_TABLES):
            cur.execute("SELECT has_table_privilege('jw_app',%s,%s)",
                        ('public.'+name, 'TRUNCATE, REFERENCES, TRIGGER'))
            if cur.fetchone()[0]:
                issues.append('Dangerous privilege bypassing RLS: ' + name)
        for name, forbidden in [
            ('audit_logs', 'UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'),
            ('security_events', 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'),
        ]:
            cur.execute("SELECT has_table_privilege('jw_app',%s,%s)", ('public.'+name,forbidden))
            if cur.fetchone()[0]:
                issues.append('Unsafe privileges on '+name)
        for name in sorted(AUTH_TABLES):
            if name not in tables:
                issues.append('Auth table missing: ' + name)
            else:
                cur.execute("SELECT has_table_privilege('jw_app',%s,'SELECT, INSERT, UPDATE, DELETE')", ('public.' + name,))
                if cur.fetchone()[0]:
                    issues.append('jw_app can directly access auth table: ' + name)
        for name in sorted(PRIVATE_TABLES):
            cur.execute("SELECT to_regclass(%s)", ('jw_guard.' + name,))
            if cur.fetchone()[0] is None:
                issues.append('Private table missing: ' + name)
            else:
                cur.execute("SELECT has_table_privilege('jw_app',%s,'SELECT, INSERT, UPDATE, DELETE')", ('jw_guard.' + name,))
                if cur.fetchone()[0]:
                    issues.append('jw_app can directly access private table: ' + name)
        cur.execute("SELECT has_schema_privilege('jw_app','public','CREATE')")
        if cur.fetchone()[0]:
            issues.append('jw_app can CREATE objects in public')
        cur.execute("SELECT has_schema_privilege('jw_app','jw_guard','CREATE')")
        if cur.fetchone()[0]:
            issues.append('jw_app can CREATE objects in jw_guard')
        for fname, args in [('bind_session', 'text'), ('current_tenant', '')]:
            signature = 'jw_guard.' + fname + '(' + args + ')'
            cur.execute("""SELECT p.prosecdef, array_to_string(p.proconfig,',')
                 FROM pg_proc p WHERE p.oid=to_regprocedure(%s)""", (signature,))
            f = cur.fetchone()
            if not f or not f[0] or 'search_path=pg_catalog,jw_guard,pg_temp' not in (f[1] or '').replace(' ', ''):
                issues.append('Missing secure SECURITY DEFINER function: ' + fname)
            cur.execute("""SELECT EXISTS (
                SELECT 1 FROM pg_proc p,
                     LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
                WHERE p.oid=to_regprocedure(%s) AND a.grantee=0
                  AND a.privilege_type='EXECUTE')""", (signature,))
            if cur.fetchone()[0]:
                issues.append('Public can execute guarded function: ' + fname)
    return issues


def main():
    dsn = os.environ.get('JW_PG_CHECK_DSN')
    if not dsn:
        print('NOT RUN: JW_PG_CHECK_DSN not supplied', file=sys.stderr)
        return 2
    try:
        import psycopg
    except ImportError:
        print('NOT RUN: psycopg not installed', file=sys.stderr)
        return 2
    try:
        with psycopg.connect(dsn) as conn:
            issues = audit(conn)
    except Exception as exc:
        print('FAIL: PostgreSQL catalog audit could not complete: ' + type(exc).__name__, file=sys.stderr)
        return 1
    if issues:
        print('FAIL: ' + '; '.join(issues), file=sys.stderr)
        return 1
    print('PASS: PostgreSQL hardened RLS CATALOG audit; runtime attack tests still required')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
