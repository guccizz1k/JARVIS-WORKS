"""V3.7 semantic mapping and fail-closed attack-path unit tests (no live database)."""
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path

import pytest

from app.pg_migration_shadow_v36 import MigrationBlocked, canonical_bytes, source_records, row_key
from app.pg_migration_compat_v37 import build_contract, COLUMNS, DDL, TABLES, PK, stage_compat
from scripts.v36_synthetic_fixture import fixture


def records():
    conn=fixture()
    try:return source_records(conn)
    finally:conn.close()


def mutate(rows,table,match,update):
    result=list(rows)
    for i,record in enumerate(result):
        if record.entity!=table:continue
        obj=json.loads(record.payload)
        data=dict(zip(obj['columns'],obj['values']))
        if data.get(match[0], [None,None])[1]!=match[1]:continue
        for col,token in update.items():data[col]=token
        obj['values']=[data[col] for col in obj['columns']]
        new=json.dumps(obj,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
        result[i]=replace(record,payload=new,digest=sha256(new).hexdigest())
        return result
    raise AssertionError('source case not found')


def test_exact_7_table_mapping_includes_all_protected_semantics():
    r=records();plan=build_contract(r)
    assert set(plan)==set(TABLES)
    assert sum(map(len,plan.values()))==11
    assert plan['messenger_messages'][2]['kind']=='order' or any(m['kind']=='order' for m in plan['messenger_messages'])
    a=plan['messenger_attachments'][0]
    assert a['filename']=='synthetic-한글.png' and a['data']==b'\x00\xff\x01\xfePNG-demo-bytes\x00'
    assert any(m['kind']=='text' and m['id']==a['message_id'] for m in plan['messenger_messages'])
    assert any('lineItems' in m['immutable_order_snapshot'] for m in plan['messenger_messages'] if m['kind']=='order')
    assert len(plan['messenger_receipts'])==1 and len(plan['messenger_edits'])==1


def test_poisoned_source_hash_refused():
    r=records();r[0]=replace(r[0],digest='0'*64)
    with pytest.raises(MigrationBlocked,match='hash'):build_contract(r)

@pytest.mark.parametrize('table,match,changes,error',[
 ('messenger_messages',('id','msg_order'),{'immutable_order_snapshot':['null',None]},'snapshot'),
 ('messenger_messages',('id','msg_order'),{'immutable_order_snapshot':['text','{"orderId":"other"}']},'source ID'),
 ('messenger_messages',('id','msg_text'),{'kind':['text','order']},'snapshot'),
 ('messenger_messages',('id','msg_file'),{'sender_org':['text','tenant_c']},'sender'),
 ('messenger_connections',('id','thread_ab'),{'status':['text','pending']},'sender'),
 ('messenger_messages',('id','msg_text'),{'message_seq':['integer','0']},'sequence'),
 ('messenger_attachments',('message_id','msg_file'),{'content_hash':['text','0'*64]},'length/hash'),
 ('messenger_attachments',('message_id','msg_file'),{'size_bytes':['integer','99']},'length/hash'),
 ('messenger_receipts',('message_id','msg_order'),{'receiver_org':['text','tenant_a']},'receiver'),
 ('messenger_read_positions',('org_id','tenant_b'),{'last_read_seq':['integer','1000']},'cursor'),
 ('messenger_edits',('id','edit1'),{'actor_user':['text','different']},'edited'),
 ('messenger_receipts',('message_id','msg_order'),{'message_id':['text','msg_text']},'Primary key'),
 ('messenger_messages',('id','msg_text'),{'version':['integer','3']},'edit history'),
 ('messenger_messages',('id','msg_text'),{'body':['text','tampered']},'current body'),
])
def test_invalid_legacy_records_blocked(table,match,changes,error):
    r=mutate(records(),table,match,changes)
    with pytest.raises(MigrationBlocked,match=error):build_contract(r)


def test_new_column_or_unknown_type_fail_closed():
    r=records();x=r[0];obj=json.loads(x.payload)
    obj['columns'].append('unknown');obj['values'].append(['text','must not drop'])
    bs=json.dumps(obj,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()
    r[0]=replace(x,payload=bs,digest=sha256(bs).hexdigest())
    with pytest.raises(MigrationBlocked,match='Schema mismatch'):build_contract(r)
    r=records();x=r[0];obj=json.loads(x.payload);obj['values'][0]=['float','0x1.3p+4']
    bs=json.dumps(obj,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()
    r[0]=replace(x,payload=bs,digest=sha256(bs).hexdigest())
    with pytest.raises(MigrationBlocked,match='Unsupported'):build_contract(r)


def test_pg_policy_is_explicit_signed_tenant_rls_and_read_only():
    assert DDL.count('ENABLE ROW LEVEL SECURITY')==7
    assert DDL.count('FORCE ROW LEVEL SECURITY')==7
    assert DDL.count('CREATE POLICY jw_v37_')==7
    assert DDL.count('jw_guard.current_tenant()')>=7
    assert 'GRANT SELECT ON jw_migration_v37' in DDL
    assert 'GRANT INSERT' not in DDL
    assert 'GRANT SELECT(org_id)' in DDL
    assert 'jw_v37_file_sha256' in DDL


def test_live_gate_is_opt_in_and_never_uses_customer_db():
    s=Path(__file__).resolve().parents[1]
    text=(s/'scripts/test_postgres_migration_v37.py').read_text()
    assert 'ONLY_EPHEMERAL_DATABASE' in text and 'ONLY_DISPOSABLE_LAB' in text
    assert 'jw_v20_test_' in text and "a.get('host')" in text
    assert 'Production FastAPI PostgreSQL cutover remains' in text
    assert (s/'scripts/run_pg17_codespaces_v37.sh').exists()
