"""Deterministic V4.6 catalog-gap audit with no live network or writes."""
from __future__ import annotations
import sqlite3
import re
import pytest

from app.pg_migration_compat_v37 import COLUMNS
from app.pg_cutover_readiness_v46 import (
    TABLES, SEMANTIC_BLOCKERS, AuditBlocked, SchemaInventory,
    sqlite_contract, postgres_inventory, audit_cutover_gap,
)

@pytest.fixture
def synthetic():
    conn = sqlite3.connect(':memory:')
    for table, cols in COLUMNS.items():
        definitions = ', '.join('"'+name+'" TEXT' for name in cols)
        conn.execute('CREATE TABLE "'+table+'" ('+definitions+')')
    yield conn
    conn.close()


def full_inventory():
    return SchemaInventory({k:tuple(v) for k,v in COLUMNS.items()},
                           {k:True for k in TABLES})


def test_synthetic_full_legacy_shape(synthetic):
    assert sqlite_contract(synthetic)=={k:tuple(v) for k,v in COLUMNS.items()}


def test_missing_legacy_table_blocks(synthetic):
    synthetic.execute('DROP TABLE messenger_receipts')
    with pytest.raises(AuditBlocked,match='missing'):
        sqlite_contract(synthetic)


def test_schema_column_rename_blocks(synthetic):
    synthetic.execute('ALTER TABLE messenger_messages RENAME COLUMN actor_name TO wrong_name')
    with pytest.raises(AuditBlocked,match='changed'):
        sqlite_contract(synthetic)


def test_all_columns_still_cannot_approve_operating_cutover(synthetic):
    report=audit_cutover_gap(sqlite_contract(synthetic),full_inventory())
    assert report['decision']=='BLOCKED'
    assert report['cutover_approved'] is False
    assert not report['missing_legacy_columns']
    assert report['reason_codes']==list(SEMANTIC_BLOCKERS)
    assert report['synthetic_only'] is True


def test_real_v27_shape_requires_lossless_fields(synthetic):
    target=full_inventory()
    columns={k:list(v) for k,v in target.columns.items()}
    for table, missing in {
        'messenger_companies':('verification_kind',),
        'messenger_connections':('accepted_at','connection_seq'),
        'messenger_messages':('order_id','immutable_order_snapshot','actor_name','version','edited_at'),
        'messenger_edits':('edited_at',),
        'messenger_attachments':('mime','size_bytes'),
        'messenger_read_positions':('last_read_rowid',),
        'messenger_receipts':('actor_name',),
    }.items():
        for name in missing:columns[table].remove(name)
    report=audit_cutover_gap(sqlite_contract(synthetic),SchemaInventory(columns,target.force_rls))
    assert len(report['missing_legacy_columns'])==7
    assert report['missing_essential_fields']['messenger_messages']==[
        'actor_name','edited_at','immutable_order_snapshot','order_id','version']
    assert report['reason_codes'][0]=='OPERATIONAL_SCHEMA_MISSING_LEGACY_FIELDS'
    assert report['rls_not_forced']==[]
    assert not report['cutover_approved']


def test_missing_forced_rls_blocks_approval(synthetic):
    full=full_inventory()
    rls=dict(full.force_rls, messenger_receipts=False)
    result=audit_cutover_gap(sqlite_contract(synthetic),SchemaInventory(full.columns,rls))
    assert result['rls_not_forced']==['messenger_receipts']
    assert 'OPERATIONAL_RLS_NOT_FORCED' in result['reason_codes']


@pytest.mark.parametrize('bad',[{}, {'wrong':['id']}, {'messenger_messages': ['id']}])
def test_missing_seven_table_boundary_rejected(synthetic,bad):
    with pytest.raises(AuditBlocked):
        audit_cutover_gap(bad,full_inventory())


def test_duplicate_catalog_columns_rejected(synthetic):
    good=full_inventory()
    columns={k:list(v) for k,v in good.columns.items()}
    columns['messenger_messages'].append('id')
    with pytest.raises(AuditBlocked,match='Unrepresentable'):
        audit_cutover_gap(sqlite_contract(synthetic),SchemaInventory(columns,good.force_rls))


def test_missing_security_metadata_rejected(synthetic):
    good=full_inventory()
    rls={k:True for k in TABLES if k!='messenger_receipts'}
    with pytest.raises(AuditBlocked,match='security'):
        audit_cutover_gap(sqlite_contract(synthetic),SchemaInventory(good.columns,rls))


class Cursor:
    def __init__(self,db='jw_v20_test_aaaaaaaaaaaa',user='postgres',version='170008',rls=True):
        self.db=db;self.user=user;self.version=version;self.rls=rls
        self.values=[];self.sql=[]
    def execute(self,sql,*args):
        self.sql.append(sql)
        if 'server_version_num' in sql:
            self.values=[(self.db,self.user,self.version)]
        elif 'pg_catalog.pg_attribute' in sql:
            self.values=[(table,self.rls,self.rls,col)
                    for table,cols in COLUMNS.items() for col in cols]
        else:raise AssertionError('Unexpected SQL')
    def fetchone(self):return self.values.pop(0)
    def fetchall(self):return self.values


def test_catalog_reader_query_is_read_only():
    cursor=Cursor()
    result=postgres_inventory(cursor)
    assert len(result.columns)==7 and all(result.force_rls.values())
    assert len(cursor.sql)==2
    assert all(q.strip().upper().startswith('SELECT') for q in cursor.sql)
    assert all(not re.search(r'\b(DROP|INSERT|UPDATE|DELETE|ALTER|TRUNCATE)\b', q.upper()) for q in cursor.sql)


@pytest.mark.parametrize('db,user,version',[
    ('production','postgres','170008'),
    ('jw_v20_test_aaaaaaaaaaaa','jw_app','170008'),
    ('jw_v20_test_aaaaaaaaaaaa','postgres','160008'),
    ('jw_v20_test_abc','postgres','170008'),
])
def test_reject_unsafe_catalog_connection(db,user,version):
    cursor=Cursor(db,user,version)
    with pytest.raises(AuditBlocked):postgres_inventory(cursor)
    assert len(cursor.sql)==1


def test_readonly_data_audit_never_returns_credentials_or_user_rows(synthetic):
    report=audit_cutover_gap(sqlite_contract(synthetic),full_inventory())
    assert 'secret' not in str(report).lower()
    assert 'postgresql://' not in str(report)
    assert 'cutover_approved' in report and report['cutover_approved'] is False
