"""PostgreSQL cutover must fail closed until all live gates are met."""
from pathlib import Path
from app import main
from app.ops_cutover_v71 import schema_inventory


def test_preflight_detects_unmigrated_tables_and_does_not_read_rows(api):
    ddl=Path('security/pg_rls_test_fixture.sql').read_text()
    with main.conn() as c:
        out=schema_inventory(c,ddl)
    assert out['sqlite_table_count']>out['pg_reference_table_count']
    assert 'invoice_adjustments_v69' in out['unrepresented_sqlite_tables']
    assert not out['operational_cutover_permitted']
    assert 'LIVE_STORAGE_ADAPTER_STILL_SQLITE' in out['blockers']
    assert len(out['schema_ddl_sha256'])==64
    assert 'demo@hanbit.example' not in str(out)


def test_contract_never_claims_cutover_even_with_complete_schema(api):
    with main.conn() as c:
        sql='\n'.join('CREATE TABLE '+r[0]+'(id text);' for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall())
        out=schema_inventory(c,sql)
    assert not out['unrepresented_sqlite_tables']
    assert not out['operational_cutover_permitted']
    assert 'LIVE_POSTGRES_RLS_ATTACK_GATE_NOT_RUN' in out['blockers']
