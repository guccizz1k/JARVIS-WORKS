"""Disposable two-PG17 integration test; NEVER connect to customer data.

The source schema must be absent. Only CI hosts explicitly declared local and
synthetic are accepted; this must not be labeled as actual Supabase P0-1 PASS.
"""
from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import psycopg

from scripts.pg_backup_v223 import BackupError, guard_target, parse_dsn, run


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
    with TemporaryDirectory(prefix='jw_v223_synthetic_') as d:
        result = run(source,target,workdir=Path(d),real_source=False)
        assert result.get('signature_mismatches') == [], 'Restored signature differed'
        for field in ('snapshot_consistent','restore_verified','decrypt_sha256_matches',
                      'tamper_rejected','wrong_key_rejected','truncation_rejected',
                      'partial_dump_restore_rejected'):
            assert result.get(field) is True, f'Backup acceptance condition failed: {field}'
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
