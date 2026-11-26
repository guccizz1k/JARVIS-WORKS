"""Local contract tests. Upstream parsers and PostgreSQL are NOT emulated as evidence."""
import hashlib
import json
import sys
from types import ModuleType, SimpleNamespace
import pytest
from app.erp_migration_file_transaction import _encode_rows,build_payload,stage_reviewed_file

def item(code='001',name='품목',**kw):
    return tuple(sorted({'source_item_id':code,'name':name,**kw}.items()))

def customer(code='C1',**kw):
    return tuple(sorted({'source_customer_id':code,'name':'회사',**kw}.items()))

@pytest.mark.parametrize('rows,ids,reason',[
    ((item('A'),item('a')),(),'TX_DUPLICATE'),
    ((item('A'),),('a',),'TX_DUPLICATE'),
    ((item(),),('A','a'),'TX_TARGET_DUPLICATE'),
    ((item(extra='x'),),(),'TX_FIELDS'),
    ((item(unit='x'*33),),(),'TX_UNIT'),
    ((item(name=''),),(),'TX_NAME'),
    ((item(code='bad id'),),(),'TX_ID'),
    ((item()+(('name','duplicate'),),),(),'TX_FIELDS'),
    ((item()+((1,'x'),),),(),'TX_ROW_SHAPE'),
    ((),(),'TX_ROWS'),
    ((item(),),tuple('A'+str(i) for i in range(10000)),'TX_TARGET_CAPACITY'),
])
def test_rejections(rows,ids,reason):
    with pytest.raises(ValueError,match=reason): _encode_rows('item',rows,ids)

def test_preserves_unit_empty_vs_absent_and_ids():
    data,ids=_encode_rows('item',(item('001',unit='EA'),item('002',unit=''),item('003')),('000',))
    assert json.loads(data)==[{'source_item_id':'001','name':'품목','unit':'EA'}, {'source_item_id':'002','name':'품목','unit':''},{'source_item_id':'003','name':'품목'}]
    assert ids==('000','001','002','003')

def test_customer_number():
    data,_=_encode_rows('customer',(customer(business_number='012-34-56789'),),())
    assert json.loads(data)[0]['business_number']=='012-34-56789'
    with pytest.raises(ValueError,match='TX_BUSINESS_NUMBER'):
        _encode_rows('customer',(customer(business_number='invalid'),),())

def test_cap_and_order():
    data,ids=_encode_rows('item',tuple(item(str(i)) for i in range(1000)),())
    assert len(json.loads(data))==len(ids)==1000
    assert ids==tuple(sorted(ids))

def test_payload_call_boundary(monkeypatch):
    # Test doubles are explicitly limited to the upstream interface contract.
    # Real check_file_stage and make_target_snapshot require the original repo.
    raw=b'fixture'; sha=hashlib.sha256(raw).hexdigest(); calls=[]
    preflight=SimpleNamespace(row_count=1,binding_sha256='b'*64,rows_sha256='c'*64)
    stage=SimpleNamespace(row_import_authorized=False,raw_sha256=sha,byte_count=len(raw),canonical_rows=(item(unit='EA'),),stage_sha256='d'*64,preflight=preflight)
    def target(org,src,entity,rev,ids):
        calls.append((org,src,entity,rev,ids));return SimpleNamespace(snapshot_sha256=('a' if rev=='rev-0' else 'e')*64)
    def checked(previous,data,**kw):
        assert previous is stage and data==raw and kw['target'].snapshot_sha256=='a'*64;return stage
    for name,func,f in [('app.erp_migration_file_stage','check_file_stage',checked),('app.erp_migration_preflight','make_target_snapshot',target)]:
        mod=ModuleType(name);setattr(mod,func,f);monkeypatch.setitem(sys.modules,name,mod)
    args=dict(file_format='csv',organization_id='org-a',source_id='source',entity='item',stage_id='stage',revision=0,expected_ids=(),stored_snapshot_sha256='a'*64,previously_reviewed=stage)
    p=build_payload(raw,**args)
    assert p.stage_sha256=='d'*64 and p.next_snapshot_sha256=='e'*64 and p.next_revision==1
    assert calls[-1][-1]==('001',) and len(p.params())==16
    assert 'fixture' not in repr(p) and '품목' not in repr(p)
    with pytest.raises(ValueError,match='TX_TARGET_CHANGED'):build_payload(raw,**(args|{'stored_snapshot_sha256':'f'*64}))
    stage.row_import_authorized=True
    with pytest.raises(ValueError,match='TX_STAGE_AUTHORITY'):build_payload(raw,**args)

def test_no_db_connection_before_environment_guard(monkeypatch):
    class Conn:
        autocommit=False
        def execute(self,*args):raise AssertionError('DB should not be contacted')
    monkeypatch.delenv('NARUV_APPROVAL_PG_ALLOW',raising=False)
    with pytest.raises(ValueError,match='TX_DISPOSABLE_CI_REQUIRED'):
        stage_reviewed_file(Conn(),b'x',file_format='csv',organization_id='a',source_id='s',entity='item',stage_id='x',previously_reviewed=None)
