"""Disposable two-PG17 integration test; NEVER connect to customer data.

The source schema must be absent. Only CI hosts explicitly declared local and
synthetic are accepted; this must not be labeled as actual Supabase P0-1 PASS.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import psycopg

from scripts import pg_backup_v223 as pb
from scripts.pg_backup_v223 import BackupError, guard_target, parse_dsn, run


def expect_blocked(label: str, code: str, call) -> None:
    """A negative test passes only when the call raises BackupError with this exact code."""
    try:
        call()
    except BackupError as exc:
        assert str(exc).startswith(code), f'{label}: wrong refusal {str(exc)[:80]}'
        print(f'NEGATIVE_OK {label}')
        return
    raise AssertionError(f'{label}: was NOT refused')


def leftover_databases(dsn: str) -> list:
    with psycopg.connect(dsn, autocommit=True) as conn:
        return [r[0] for r in conn.execute("SELECT datname FROM pg_database WHERE datname LIKE 'jw_v223_%'")]


def role_dsn(base: str, role: str, password: str) -> str:
    o = parse_dsn(base)
    return f"postgresql://{role}:{password}@{o['host']}:{o['port']}/{o['dbname']}"


def f2_role_privilege_tests(source: str) -> None:
    """F2 on a real PG17: the live catalog decides, never the role name."""
    with psycopg.connect(source, autocommit=True) as admin:
        for role in ('jw_ci_ro', 'jw_ci_ro_nobypass', 'jw_ci_rw', 'jw_ci_creator', 'jw_ci_ro_switch'):
            admin.execute(f"DROP ROLE IF EXISTS {role}")
        admin.execute("CREATE ROLE jw_ci_ro LOGIN BYPASSRLS PASSWORD 'ci-only-ro'")
        admin.execute("CREATE ROLE jw_ci_ro_nobypass LOGIN PASSWORD 'ci-only-ro2'")
        admin.execute("CREATE ROLE jw_ci_rw LOGIN BYPASSRLS PASSWORD 'ci-only-rw'")
        admin.execute("CREATE ROLE jw_ci_creator LOGIN BYPASSRLS PASSWORD 'ci-only-cr'")
        admin.execute("CREATE ROLE jw_ci_ro_switch LOGIN BYPASSRLS PASSWORD 'ci-only-sr'")
        for role in ('jw_ci_ro', 'jw_ci_ro_nobypass', 'jw_ci_rw', 'jw_ci_creator', 'jw_ci_ro_switch'):
            admin.execute(f"GRANT USAGE ON SCHEMA jw_dev TO {role}")
            admin.execute(f"GRANT SELECT ON ALL TABLES IN SCHEMA jw_dev TO {role}")
        admin.execute("GRANT INSERT ON jw_dev.audit_log TO jw_ci_rw")
        # Can SET ROLE to a writer without inheriting its grants in current session.
        admin.execute("GRANT jw_ci_rw TO jw_ci_ro_switch WITH INHERIT FALSE, SET TRUE")
        admin.execute("GRANT CREATE ON SCHEMA jw_dev TO jw_ci_creator")
    cases = (('jw_ci_ro', 'ci-only-ro', []),
             ('jw_ci_ro_nobypass', 'ci-only-ro2', ['rls_rows_not_fully_readable']),
             ('jw_ci_rw', 'ci-only-rw', ['tables_writable']),
             ('jw_ci_creator', 'ci-only-cr', ['schema_create']),
             ('jw_ci_ro_switch', 'ci-only-sr', ['settable_other_roles']))
    try:
        for role, password, expected in cases:
            with psycopg.connect(role_dsn(source, role, password), autocommit=True) as conn:
                got = pb.evaluate_source_privileges(pb.fetch_role_facts(conn, 'jw_dev'))
            assert got == expected, f'F2 {role}: {got}'
            print(f'NEGATIVE_OK F2 {role} -> {got or "accepted"}')
        with psycopg.connect(source, autocommit=True) as conn:       # the admin account itself
            got = pb.evaluate_source_privileges(pb.fetch_role_facts(conn, 'jw_dev'))
        assert 'superuser' in got and 'tables_writable' in got, got
        print('NEGATIVE_OK F2 superuser refused')
    finally:
        with psycopg.connect(source, autocommit=True) as admin:
            for role, _, _ in cases:
                admin.execute(f"REASSIGN OWNED BY {role} TO postgres")
                admin.execute(f"DROP OWNED BY {role}")
                admin.execute(f"DROP ROLE IF EXISTS {role}")


def f5_signature_tests(source: str) -> None:
    """F5 on a real PG17: exact caps, timeout, and an order-independent but change-sensitive digest."""
    with psycopg.connect(source, autocommit=True) as conn:
        conn.execute('CREATE SCHEMA jw_ci_sig')
        conn.execute('CREATE TABLE jw_ci_sig.a(id int, v text)')
        conn.execute('CREATE TABLE jw_ci_sig.b(id int, v text)')
        conn.execute("INSERT INTO jw_ci_sig.a SELECT g, 'v'||g FROM generate_series(1,50) g")
        conn.execute("INSERT INTO jw_ci_sig.b SELECT g, 'v'||g FROM generate_series(50,1,-1) g")
        conn.execute('CREATE TABLE jw_ci_sig.big AS SELECT g AS id, md5(g::text) AS v FROM generate_series(1,300000) g')
    try:
        with psycopg.connect(source, autocommit=True) as conn:
            conn.execute('BEGIN')
            same = pb.fetch_signature(conn, 'jw_ci_sig')['rows']
            conn.execute('ROLLBACK')
        assert same['a'] == same['b'], 'digest must not depend on physical row order'
        with psycopg.connect(source, autocommit=True) as conn:
            conn.execute("UPDATE jw_ci_sig.b SET v='changed' WHERE id=7")
            conn.execute('BEGIN')
            changed = pb.fetch_signature(conn, 'jw_ci_sig')['rows']
            conn.execute('ROLLBACK')
        assert changed['a'][0] == changed['b'][0] and changed['a'][1] != changed['b'][1], 'one changed value must change the digest'
        print('NEGATIVE_OK F5 digest order-independent and change-sensitive')
        old_cap = pb.MAX_TABLE_ROWS
        pb.MAX_TABLE_ROWS = 1000
        try:
            with psycopg.connect(source, autocommit=True) as conn:
                conn.execute('BEGIN')
                expect_blocked('F5 exact per-table cap', 'BLOCKED_V223_TABLE_OVER_ROW_CAP:big',
                               lambda: pb.fetch_signature(conn, 'jw_ci_sig'))
                conn.execute('ROLLBACK')
        finally:
            pb.MAX_TABLE_ROWS = old_cap
        old_timeout = pb.STATEMENT_TIMEOUT
        pb.STATEMENT_TIMEOUT = '1ms'
        try:
            with psycopg.connect(source, autocommit=True) as conn:
                conn.execute('BEGIN')
                expect_blocked('F5 statement timeout', 'BLOCKED_V223_SIGNATURE_STATEMENT_TIMEOUT',
                               lambda: pb.fetch_signature(conn, 'jw_ci_sig'))
        finally:
            pb.STATEMENT_TIMEOUT = old_timeout
    finally:
        with psycopg.connect(source, autocommit=True) as conn:
            conn.execute('DROP SCHEMA IF EXISTS jw_ci_sig CASCADE')


def main() -> int:
    source = os.environ.get('JW_PG_SOURCE_DSN', '')
    target = os.environ.get('JW_PG_TARGET_ADMIN_DSN', '')
    if os.environ.get('JW_PG_CI_ALLOW') != 'ONLY_EPHEMERAL_LOCAL_DATABASE' or os.environ.get('JW_PG_CI_SYNTHETIC') != '1':
        raise BackupError('BLOCKED_V223_SYNTHETIC_CI_IDENTITY_REQUIRED')
    src = parse_dsn(source)
    if src['host'] not in ('127.0.0.1', 'localhost', '::1'):
        raise BackupError('BLOCKED_V223_SYNTHETIC_SOURCE_MUST_BE_LOCAL')
    guard_target(target, source)
    if (parse_dsn(target)['host'], parse_dsn(target)['port']) == (src['host'], src['port']):
        raise BackupError('BLOCKED_V223_INDEPENDENT_CLUSTER_REQUIRED')

    # Prevent destructive setup on reused or nonempty databases.
    with psycopg.connect(source, autocommit=True) as conn:
        if conn.execute("SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='jw_dev')").fetchone()[0]:
            raise BackupError('BLOCKED_V223_SYNTHETIC_SCHEMA_ALREADY_PRESENT')
        conn.execute('CREATE SCHEMA jw_dev')
        conn.execute('CREATE TABLE jw_dev.invoice(id bigint PRIMARY KEY, company text NOT NULL, amount numeric(16,2))')
        conn.execute('CREATE TABLE jw_dev.audit_log(id bigint PRIMARY KEY, memo text NOT NULL)')
        conn.execute("INSERT INTO jw_dev.invoice VALUES (1,'synthetic-a',123.45),(2,'synthetic-b',989.01)")
        conn.execute("INSERT INTO jw_dev.audit_log VALUES (1,'synthetic-only')")
        conn.execute('ALTER TABLE jw_dev.invoice ENABLE ROW LEVEL SECURITY')
        conn.execute('ALTER TABLE jw_dev.invoice FORCE ROW LEVEL SECURITY')
        conn.execute('CREATE POLICY invoice_isolation ON jw_dev.invoice FOR SELECT TO PUBLIC USING (true)')
        conn.execute("CREATE FUNCTION jw_dev.audit_identity() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NEW; END$$")
        conn.execute('CREATE TRIGGER invoice_audit BEFORE INSERT ON jw_dev.invoice FOR EACH ROW EXECUTE FUNCTION jw_dev.audit_identity()')

    os.environ['JW_PG_BACKUP_KEY'] = base64.urlsafe_b64encode(os.urandom(32)).decode('ascii')

    # F1: the restore cluster is marked by its OPERATOR (this CI step) with a secret token.
    token = secrets.token_hex(16)
    os.environ[pb.EPHEMERAL_TOKEN_ENV] = token
    pb.provision_ephemeral_marker(target, token)
    with TemporaryDirectory(prefix='jw_v223_f1_') as d:
        # wrong token: a cluster that was not marked for this run must be refused
        os.environ[pb.EPHEMERAL_TOKEN_ENV] = secrets.token_hex(16)
        expect_blocked('F1 wrong marker token', 'BLOCKED_V223_TARGET_NOT_PROVEN_EPHEMERAL:',
                       lambda: run(source, target, workdir=Path(d), real_source=False))
        os.environ[pb.EPHEMERAL_TOKEN_ENV] = token
        # an unmarked cluster (the source cluster, reached via another database name)
        unmarked = source.rsplit('/', 1)[0] + '/template1'
        expect_blocked('F1 unmarked cluster', 'BLOCKED_V223_TARGET_NOT_PROVEN_EPHEMERAL:',
                       lambda: run(source, unmarked, workdir=Path(d), real_source=False))
        assert leftover_databases(source) == [], 'a refused target must not get any CREATE DATABASE'
        # a cluster that already holds a foreign database
        with psycopg.connect(target, autocommit=True) as admin:
            admin.execute('CREATE DATABASE jw_foreign_probe')
        try:
            expect_blocked('F1 foreign database present', 'BLOCKED_V223_TARGET_NOT_PROVEN_EPHEMERAL:',
                           lambda: run(source, target, workdir=Path(d), real_source=False))
            expect_blocked('F1 marker refuses populated cluster', 'BLOCKED_V223_MARKER_REFUSED_CLUSTER_NOT_EMPTY',
                           lambda: pb.provision_ephemeral_marker(target, token))
        finally:
            with psycopg.connect(target, autocommit=True) as admin:
                admin.execute('DROP DATABASE IF EXISTS jw_foreign_probe')
        assert leftover_databases(target) == [], 'refusals must leave no restore databases behind'
    f2_role_privilege_tests(source)
    f5_signature_tests(source)
    with TemporaryDirectory(prefix='jw_v223_synthetic_') as d:
        result = run(source,target,workdir=Path(d),real_source=False)
        assert result.get('signature_mismatches') == [], 'Restored signature differed'
        for field in ('snapshot_consistent','restore_verified','decrypt_sha256_matches',
                      'tamper_rejected','wrong_key_rejected','truncation_rejected',
                      'partial_dump_restore_rejected'):
            assert result.get(field) is True, f'Backup acceptance condition failed: {field}'
        assert result.get('target_proven_ephemeral') is True
        assert result.get('tables') == 2, result.get('tables')
        assert result['verdict'].startswith('NOT_P0_1_PASS'), result['verdict']
        # Record no names, values, secrets, or plaintext backup.
        print('PASS_V223_SYNTHETIC_DOUBLE_PG17_BACKUP_ENCRYPT_RESTORE_AND_NEGATIVE_TESTS')
        print('LIMIT_V223_NOT_REAL_SUPABASE_BACKUP')
        print(json.dumps({'source_is_real_dev_db': False, 'tables': result['tables'],
                          'signature_sha256': result['signature_sha256'],
                          'signature_mismatches': 0,
                          'encrypted_dump_bytes': result['dump_bytes'],
                          'snapshot_consistent': result['snapshot_consistent']},sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print('FAIL_V223_SYNTHETIC_' + type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
