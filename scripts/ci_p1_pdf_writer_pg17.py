"""Review-only PG17 proof for V20.1 PDF upload RLS gap.
Only a disposable localhost postgres:17 service. No hosted DB or Render writes.
"""
from __future__ import annotations
import os
from pathlib import Path
import psycopg
from scripts import ci_v195_atomic_approval_receipt_https as upstream
from scripts import ci_v157_real_pg_delivery_http as fixture
from scripts import ci_v201_inactive_migration_pg17 as v201

ROOT = Path(__file__).resolve().parents[1]
UP = ROOT / 'scripts/review/vp1_pdf_writer_policy_candidate.sql'
DOWN = ROOT / 'scripts/review/vp1_pdf_writer_policy_rollback.sql'

def row(i: int, filename: str) -> list[str]:
    return [f'{i:032x}', v201.ORGA, v201.ACTOR_A, f'{i:064x}', filename,
            'sealed-disposable-review-only', f'{i+10000:064x}',
            'pending', '2026-11-02T10:00:00+00:00']

def attempt(i: int, filename: str, *, actor: str = 'A', allowed: bool = False) -> None:
    actual = v201.check_as(v201.WRITER, actor, v201.SQL_WRITE,
                           row(i, filename), accepted=allowed)
    assert actual is (None if allowed else False), (filename, actual)

def prepare() -> None:
    if os.environ.get('JW_ENV') != 'review' or os.environ.get('JW_PG_CI_ALLOW') != 'ONLY_EPHEMERAL_LOCAL_DATABASE':
        raise RuntimeError('BLOCKED_P1_DISPOSABLE_ENV_REQUIRED')
    fixture.disposable_root_check()
    upstream.prepare()
    with psycopg.connect(fixture.DSN) as conn:
        conn.execute("""CREATE ROLE jw_ci_v199_import_writer
            NOLOGIN NOINHERIT NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE""")
        conn.execute((ROOT / 'scripts/review/v199_disposable_actual_shape_import_writer.sql').read_text())
        conn.execute('DROP POLICY v199_writer_only_verified_pending ON jw_dev.import_previews')
        conn.execute('DROP POLICY v199_writer_verified_read ON jw_dev.import_previews')
        conn.execute('DROP INDEX jw_dev.v199_import_pending_unique')
        conn.execute('CREATE SCHEMA extensions')
        conn.execute('ALTER EXTENSION pgcrypto SET SCHEMA extensions')
        conn.execute('DELETE FROM jw_dev.import_previews')
        assert conn.execute('SELECT count(*) FROM jw_dev.import_previews').fetchone() == (0,)
    v201.setup_nonsuper_migration_owner()
    v201.execute_migration_as_nonsuper(v201.MIG.read_text())

def main() -> None:
    prepare()
    attempt(101, '견적서.pdf', allowed=False)
    attempt(102, '견적서.xlsx', allowed=True)
    print('PASS_P1_BASELINE_PDF_DENIED_XLSX_ALLOWED', flush=True)
    v201.execute_migration_as_nonsuper(UP.read_text())
    safe = ['견적서.pdf', 'quote.PDF', '거래명세.PdF', 'quote_2026.pdf',
            'quote v2.pdf', 'receipt.pdf', '2026_11.pdf', 'a.pdf',
            '견적서.xlsx', 'quote.XLSX', 'quote_2026.xlsx', 'a.xlsx']
    for i, filename in enumerate(safe, 200):
        attempt(i, filename, allowed=True)
    print('PASS_P1_12_ALLOWED_PDF_XLSX_VARIANTS', flush=True)
    hostile = [
        '../invoice.pdf', 'dir/invoice.pdf', 'dir\\invoice.pdf',
        'invoice\n.pdf', 'invoice\r.pdf', 'invoice\t.pdf',
        'invoice\x7f.pdf', 'invoice\u202e.pdf', 'invoice\u202a.pdf',
        'invoice\u2066.pdf', 'invoice\u2069.pdf', 'invoice.pdf.xlsx',
        'invoice.xlsx.pdf', ' invoice.pdf', 'invoice.pdf ', '.xlsx',
        'invoice.exe', 'invoice.pdf.exe', 'x'*121+'.pdf',
        'invoice/../.pdf',
    ]
    assert len(hostile) == 20 and len(set(hostile)) == 20
    for i, filename in enumerate(hostile, 300):
        attempt(i, filename, allowed=False)
    print('PASS_P1_20_DISTINCT_HOSTILE_FILENAMES_REJECTED', flush=True)
    attempt(401, 'valid.pdf', actor='B', allowed=False)
    attempt(402, 'valid.pdf', actor='bogus', allowed=False)
    assert v201.check_as('jw_app_dev', 'A', v201.SQL_WRITE, row(403, 'valid.pdf')) is False
    assert v201.check_as(v201.WRITER, 'A',
                         "UPDATE jw_dev.import_previews SET status='confirmed' WHERE id=%s",
                         (f'{200:032x}',)) is False
    print('PASS_P1_TENANT_SESSION_CLIENT_AND_STATUS_BOUNDARIES', flush=True)
    try:
        v201.execute_migration_as_nonsuper(DOWN.read_text())
    except psycopg.Error as exc:
        assert 'BLOCKED_P1_ROLLBACK_PDF_ROWS_PRESENT' in str(exc), str(exc)
    else:
        raise AssertionError('PDF-bearing rollback must fail closed')
    print('PASS_P1_PDF_BEARING_ROLLBACK_REFUSED', flush=True)
    with psycopg.connect(fixture.DSN) as conn:
        count = conn.execute('SELECT count(*) FROM jw_dev.import_previews').fetchone()[0]
        assert count == 13, count
        conn.execute('DELETE FROM jw_dev.import_previews')
    v201.execute_migration_as_nonsuper(DOWN.read_text())
    attempt(501, 'new.pdf', allowed=False)
    attempt(502, 'new.xlsx', allowed=True)
    print('PASS_P1_ROLLBACK_RESTORES_EXACT_XLSX_ONLY_BOUNDARY', flush=True)
    print('LIMIT_P1_REVIEW_ONLY_NO_DEV_RLS_MIGRATION_NO_RENDER_DEPLOY', flush=True)

if __name__ == '__main__':
    main()
