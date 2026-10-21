"""V4.8 synthetic semantic and fault-injection tests. Never use real org data."""
from __future__ import annotations
from dataclasses import replace
from hashlib import sha256
import json
import pytest

from app.pg_migration_compat_v37 import COLUMNS, PK
from app.pg_migration_shadow_v36 import Record, canonical_bytes, row_key
from app.pg_semantic_envelope_v48 import (
    SemanticRefused, make_envelopes, verify_envelopes, rehearse_semantic_envelopes,
)


def fictional_records():
    stamp = '2026-10-20T08:01:00+09:00'
    blob = b'\x00\xff\x01synthetic\x00bytes'
    tables = {
        'messenger_companies':[
            ('tenant_a','0000000001',stamp,'demo'),
            ('tenant_b','0000000002',stamp,'demo'),
        ],
        'messenger_connections':[
            ('thread_ab','tenant_a','tenant_b','tenant_a','active',stamp,None,1),
        ],
        'messenger_messages':[
            ('msg_text','thread_ab','tenant_a','ua','text','안녕하세요',None,None,'',
             'request_text',2,stamp,stamp,1),
            ('msg_file','thread_ab','tenant_b','ub','text','첨부',None,None,'',
             'request_file',1,stamp,None,2),
            ('msg_order','thread_ab','tenant_a','ua','order','발주서 확인',
             'order_fake_001','{"orderId":"order_fake_001"}','담당자',
             'request_order',1,stamp,None,3),
        ],
        'messenger_edits':[
            ('edit_1','msg_text','안녕','안녕하세요','ua',stamp,2),
        ],
        'messenger_attachments':[
            ('msg_file','synthetic-한글.png','image/png',blob,len(blob),sha256(blob).hexdigest()),
        ],
        'messenger_read_positions':[
            ('thread_ab','tenant_a',1,stamp,1),('thread_ab','tenant_b',2,stamp,2),
        ],
        'messenger_receipts':[
            ('msg_order','tenant_b','담당자 B','ub',stamp),
        ],
    }
    records = []
    for table, rows in tables.items():
        cols = COLUMNS[table]
        for row in rows:
            data = dict(zip(cols,row))
            p = canonical_bytes(table,cols,row)
            k = row_key([data[c] for c in PK[table]])
            records.append(Record(table,k,p,sha256(p).hexdigest()))
    return records


def mutate_field(records, entity, field, value, index=0):
    changed=[]
    count=0
    for r in records:
        if r.entity==entity and count==index:
            raw=json.loads(r.payload)
            column=raw['columns'].index(field)
            original_token=raw['values'][column]
            raw['values'][column]=['null',None] if value is None else ['text',value]
            data=dict(zip(raw['columns'],raw['values']))
            # For nonprimary keys, key remains unchanged.
            raw_bytes=json.dumps(raw,sort_keys=True,ensure_ascii=False,
                                 separators=(',',':'),allow_nan=False).encode('utf-8')
            r=replace(r,payload=raw_bytes,digest=sha256(raw_bytes).hexdigest())
        if r.entity==entity:
            count+=1
        changed.append(r)
    return changed


def test_valid_full_semantic_source_is_byte_identical():
    source=fictional_records()
    envelopes=make_envelopes(source)
    assert len(envelopes)==len(source)==11
    assert verify_envelopes(envelopes,[(e.entity,e.row_key,e.payload,e.digest,
                                       e.original_kind,e.candidate_kind) for e in envelopes])==11
    kinds={(e.original_kind,e.candidate_kind) for e in envelopes}
    assert ('text','attachment') in kinds
    assert ('order','order') in kinds
    assert ('text','text') in kinds
    assert all(e.digest==sha256(e.payload).hexdigest() for e in envelopes)


@pytest.mark.parametrize('change',["payload","digest","kind","missing","repeated","extra"])
def test_semantic_mutation_or_omission_is_rejected(change):
    env=make_envelopes(fictional_records())
    raw=[(e.entity,e.row_key,e.payload,e.digest,e.original_kind,e.candidate_kind) for e in env]
    if change=='payload':
        r=list(raw[0]);r[2]=b'tampered';raw[0]=tuple(r)
    elif change=='digest':
        r=list(raw[0]);r[3]='a'*64;raw[0]=tuple(r)
    elif change=='kind':
        target=next(i for i,x in enumerate(raw) if x[5]=='attachment')
        r=list(raw[target]);r[5]='text';raw[target]=tuple(r)
    elif change=='missing':raw.pop()
    elif change=='repeated':raw[-1]=raw[0]
    else:raw.append(('malicious','extra',b'a','0'*64,None,None))
    with pytest.raises(SemanticRefused):verify_envelopes(env,raw)


@pytest.mark.parametrize('field,value',[('verified_at','2026-10-20T08:01:00'),
                                        ('verified_at','not-a-time'),
                                        ('verified_at','2026-10-19T23:01:00Z'),
                                        ('verified_at','2026-10-20T08:01:00+0900')])
def test_nonreversible_timestamp_representation_blocked(field,value):
    with pytest.raises(SemanticRefused):
        make_envelopes(mutate_field(fictional_records(),'messenger_companies',field,value))


def test_attachment_hash_tamper_cannot_be_silently_mapped():
    changed=mutate_field(fictional_records(),'messenger_attachments','content_hash','0'*64)
    with pytest.raises(Exception):make_envelopes(changed)


def test_order_snapshot_mutation_or_missing_receipt_detected():
    bad=mutate_field(fictional_records(),'messenger_messages',
                     'immutable_order_snapshot','{"orderId":"wrong"}',2)
    with pytest.raises(Exception):make_envelopes(bad)
    # Removal of a receipt cannot still compare as 11 intact source records.
    valid=fictional_records()
    assert len(make_envelopes(valid))==11
    with pytest.raises(SemanticRefused):verify_envelopes(
        make_envelopes(valid), [(e.entity,e.row_key,e.payload,e.digest,e.original_kind,e.candidate_kind)
                                 for e in make_envelopes(valid) if e.entity!='messenger_receipts'])


def test_missing_fixture_semantics_refuses_pass():
    source=fictional_records()
    for name in ('messenger_edits','messenger_receipts','messenger_read_positions'):
        if name=='messenger_read_positions':
            partial=[r for r in source if r.entity!=name] + [next(r for r in source if r.entity==name)]
        else:
            partial=[r for r in source if r.entity!=name]
        with pytest.raises(Exception):make_envelopes(partial)



class FakeCursor:
    def __init__(self,fail=None):
        self.fail=fail;self.data=[];self.created=False;self.events=[];self.last=None
    def __enter__(self):return self
    def __exit__(self,*exc):return False
    def execute(self,query,args=()):
        q=' '.join(query.strip().split())
        self.events.append(q)
        if self.fail=='insert' and q.startswith('INSERT INTO'):
            raise RuntimeError('synthetic-insert-failed')
        if self.fail=='rollback' and q=='ROLLBACK':
            raise RuntimeError('synthetic-rollback-failed')
        if q.startswith('SELECT to_regclass'):
            self.last=('jw_v48_semantic_evidence' if self.created else None,)
        elif q.startswith('CREATE TEMP TABLE'):
            self.created=True
        elif q.startswith('INSERT INTO pg_temp'):
            self.data.append(tuple(args))
        elif q.startswith('SELECT entity,row_key,payload'):
            output=list(self.data)
            if self.fail=='mutate' and output:
                row=list(output[0]);row[2]=b'bad';output[0]=tuple(row)
            self.last=output
        elif q=='ROLLBACK':
            if self.fail!='surviving_temp':self.created=False
            self.data=[]
    def fetchone(self):return self.last
    def fetchall(self):return self.last


class FakePG:
    autocommit=True
    def __init__(self,fail=None):self.cur=FakeCursor(fail)
    def cursor(self):return self.cur


def patch_catalog(monkeypatch,rls=True):
    from app import pg_cutover_readiness_v46 as lib
    inventory=lib.SchemaInventory(
        {t:tuple(lib.COLUMNS[t]) for t in lib.TABLES},
        {t:rls for t in lib.TABLES})
    monkeypatch.setattr(lib,'postgres_inventory',lambda cur:inventory)


def test_disposable_temp_roundtrip_and_unconditional_rollback(monkeypatch):
    patch_catalog(monkeypatch)
    pg=FakePG()
    result=rehearse_semantic_envelopes(pg,fictional_records())
    assert (result.rows,result.attachments_as_candidate_kind)==(11,1)
    assert result.rollback_verified and result.force_rls_preserved
    assert result.decision=='BLOCKED' and result.cutover_approved is False
    assert not pg.cur.created and 'ROLLBACK' in pg.cur.events
    assert any('CREATE TEMP TABLE' in sql for sql in pg.cur.events)
    assert not any(sql.startswith(('DROP ','ALTER ','UPDATE public.','INSERT INTO public.'))
                   for sql in pg.cur.events)


@pytest.mark.parametrize('failure',["insert","mutate","rollback","surviving_temp"])
def test_pg_failure_or_cleanup_leak_never_passes(monkeypatch,failure):
    patch_catalog(monkeypatch)
    pg=FakePG(failure)
    with pytest.raises(SemanticRefused):rehearse_semantic_envelopes(pg,fictional_records())
    assert 'ROLLBACK' in pg.cur.events


def test_missing_rls_refused_before_writes(monkeypatch):
    patch_catalog(monkeypatch,rls=False)
    pg=FakePG()
    with pytest.raises(SemanticRefused):rehearse_semantic_envelopes(pg,fictional_records())
    assert not any(x.startswith('CREATE TEMP') for x in pg.cur.events)


def test_non_autocommit_pg_refused(monkeypatch):
    patch_catalog(monkeypatch)
    pg=FakePG();pg.autocommit=False
    with pytest.raises(SemanticRefused):rehearse_semantic_envelopes(pg,fictional_records())
    assert not pg.cur.events
