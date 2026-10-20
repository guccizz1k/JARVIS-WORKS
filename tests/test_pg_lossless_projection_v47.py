"""Regression of actual V4.7 DDL plan/rollback module with fake PG catalog.

Never require Docker to execute these unit tests. Real PG17 must pass separately.
"""
from __future__ import annotations

import pytest
from app.pg_migration_compat_v37 import COLUMNS
from app.pg_cutover_readiness_v46 import SchemaInventory, SEMANTIC_BLOCKERS, TABLES
from app import pg_lossless_projection_v47 as v47


def source():
    return {table: tuple(cols) for table, cols in COLUMNS.items()}


def original_inventory():
    missing = v47.expected_missing()
    return SchemaInventory({t: tuple(c for c in COLUMNS[t] if c not in missing[t])
                            for t in TABLES}, {t: True for t in TABLES})


class Cursor:
    def __init__(self, pg):
        self.pg = pg
        self.rows = []
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def execute(self, command):
        self.pg.executed.append(command)
        if command == 'BEGIN':
            assert not self.pg.transaction
            self.pg.transaction = True
        elif command == 'ROLLBACK':
            if self.pg.rollback_fails: raise RuntimeError('rollback failed')
            self.pg.transaction = False
            self.pg.added.clear()
        elif command.startswith('ALTER TABLE '):
            assert self.pg.transaction
            if self.pg.fail_at == len(self.pg.added):
                raise RuntimeError('injected SQL failure')
            table, field = command.split('"')[1], command.split('"')[3]
            assert (table, field) not in self.pg.added
            self.pg.added.add((table, field))
        elif command.startswith('SET LOCAL '):
            assert self.pg.transaction
        else:
            raise AssertionError('Unexpected SQL in the fake PG cursor: '+command)


class Pg:
    def __init__(self):
        self.autocommit = True
        self.transaction = False
        self.added = set()
        self.executed = []
        self.fail_at = -1
        self.rollback_fails = False
        self.forced_false = False
        self.restore_drift = False
        self.bad_type = False
        self.catalog_calls = 0
    def cursor(self): return Cursor(self)


@pytest.fixture
def mock_catalog(monkeypatch):
    def inventory(cur):
        pg = cur.pg
        pg.catalog_calls += 1
        before = original_inventory()
        cols = {t: list(before.columns[t]) for t in TABLES}
        for table, col in pg.added:
            cols[table].append(col)
        if pg.restore_drift and not pg.transaction and pg.catalog_calls > 1:
            cols['messenger_receipts'].append('unexpected_column')
        rls = dict(before.force_rls)
        if pg.forced_false: rls['messenger_messages'] = False
        return SchemaInventory({t:tuple(c) for t,c in cols.items()}, rls)
    def types(cur):
        result = {(t,f):(kind,False,False) for t,m in v47.PROJECTION_TYPES.items()
                  for f,kind in m.items() if (t,f) in cur.pg.added}
        if cur.pg.bad_type:
            result['messenger_messages','version'] = ('text',False,False)
        return result
    monkeypatch.setattr(v47,'postgres_inventory',inventory)
    monkeypatch.setattr(v47,'projected_types',types)


def test_plan_all_13_fields_and_canonical_table_names():
    assert v47.validate_plan() == 13
    statements = v47.create_plan(original_inventory().columns)
    assert len(statements) == 13 and len(set(statements)) == 13
    assert all(s.startswith('ALTER TABLE public."messenger_') for s in statements)
    assert all(' ADD COLUMN "' in s for s in statements)
    assert all(' CASCADE' not in s and ' DROP ' not in s for s in statements)
    assert all(s.endswith((' text',' bigint',' integer')) for s in statements)


def test_success_always_rolls_back_and_denies_cutover(mock_catalog):
    pg = Pg()
    outcome = v47.rehearse_additive_columns(pg,source())
    assert outcome.projected_columns == 13
    assert outcome.rollback_verified and outcome.force_rls_preserved
    assert outcome.decision == 'BLOCKED' and outcome.cutover_approved is False
    assert len([s for s in pg.executed if s.startswith('ALTER TABLE ')]) == 13
    assert pg.executed.count('BEGIN') == pg.executed.count('ROLLBACK') == 1
    assert not pg.transaction and not pg.added
    assert pg.catalog_calls >= 3


@pytest.mark.parametrize('fail_at',[0,1,5,12])
def test_sql_failure_rolls_back_all_columns(mock_catalog,fail_at):
    pg=Pg();pg.fail_at=fail_at
    with pytest.raises(v47.ProjectionRefused,match='failed'):
        v47.rehearse_additive_columns(pg,source())
    assert pg.executed[-1]=='ROLLBACK' and not pg.transaction and not pg.added


@pytest.mark.parametrize('attribute', ['forced_false','bad_type','restore_drift'])
def test_rls_type_and_rollback_drift_never_pass(mock_catalog,attribute):
    pg=Pg();setattr(pg,attribute,True)
    with pytest.raises(v47.ProjectionRefused):
        v47.rehearse_additive_columns(pg,source())
    if attribute != 'forced_false':
        assert 'ROLLBACK' in pg.executed and not pg.added


def test_rollback_failure_prevents_success(mock_catalog):
    pg=Pg();pg.rollback_fails=True
    with pytest.raises(v47.ProjectionRefused,match='rollback failed'):
        v47.rehearse_additive_columns(pg,source())
    assert pg.executed[-1] == 'ROLLBACK'


def test_refuses_non_autocommit_connection(mock_catalog):
    pg=Pg();pg.autocommit=False
    with pytest.raises(v47.ProjectionRefused,match='Autocommit'):
        v47.rehearse_additive_columns(pg,source())
    assert pg.executed==[]


def test_refuses_partially_patched_db():
    inv=original_inventory()
    patched={t:list(v) for t,v in inv.columns.items()}
    patched['messenger_messages'].append('version')
    with pytest.raises(v47.ProjectionRefused,match='Baseline drift'):
        v47.create_plan(patched)


def test_refuses_missing_table():
    inv=dict(original_inventory().columns)
    del inv['messenger_receipts']
    with pytest.raises(v47.ProjectionRefused,match='Incomplete'):
        v47.create_plan(inv)


def test_refuses_duplicate_existing_field():
    inv={t:list(v) for t,v in original_inventory().columns.items()}
    inv['messenger_receipts'].append('message_id')
    with pytest.raises(v47.ProjectionRefused,match='Duplicate'):
        v47.create_plan(inv)


def test_projection_still_contains_every_semantic_cutover_blocker(mock_catalog):
    pg=Pg()
    assert v47.rehearse_additive_columns(pg,source()).decision=='BLOCKED'
    assert len(SEMANTIC_BLOCKERS) >= 5
    assert 'PRODUCTION_CUTOVER_NOT_AUTHORIZED' in SEMANTIC_BLOCKERS


def test_schema_type_catalog_query_reads_only_known_fields():
    class C:
        def execute(self,sql):
            assert 'pg_catalog.pg_class' in sql
            assert 'pg_catalog.format_type' in sql
            assert 'attisdropped' in sql
        def fetchall(self):
            return [('messenger_messages','version','integer',False,False),
                    ('unexpected','anything','text',False,False)]
    assert v47.projected_types(C())=={('messenger_messages','version'):('integer',False,False)}


def test_catalog_duplicate_field_refused():
    class C:
        def execute(self,sql):pass
        def fetchall(self):
            return [('messenger_receipts','actor_name','text',False,False)]*2
    with pytest.raises(v47.ProjectionRefused,match='Duplicate'):
        v47.projected_types(C())


def test_review_files_do_not_touch_operating_server():
    from pathlib import Path
    root=Path(__file__).resolve().parents[1]
    app=(root/'app/pg_lossless_projection_v47.py').read_text()
    shell=(root/'scripts/run_pg17_codespaces_v47.sh').read_text()
    runner=(root/'scripts/test_postgres_lossless_projection_v47.py').read_text()
    assert 'ROLLBACK' in app and 'ADD COLUMN' in app
    assert 'rehearse_additive_columns' in runner
    assert 'JW_ENV' in runner and "'production'" in runner
    assert 'jw_v20_test_' not in runner or 'LAB_DATABASE' in runner
    assert 'V2_8' in shell and 'V4_7' in shell
    assert '127.0.0.1::5432' in shell and 'docker rm -f' in shell
    assert 'git push' not in shell and 'app/main.py' not in shell
