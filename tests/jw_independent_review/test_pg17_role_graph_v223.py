import pytest
from scripts import jw_pg17_role_graph_v223 as m

@pytest.fixture
def doc():
    return {'format':m.FORMAT,'server_major':17,'unresolved_refs':0,
            'sections':{k:[2, str(i+1)*64] for i,k in enumerate(m.SECTIONS)}}

def test_identical_checkpoint_never_authorizes_release(doc):
    raw=m.canonical(doc); result=m.compare(raw,raw,expected_reference_pin=m.pin(raw))
    assert result['role_graph_checkpoint'].startswith('PASS_')
    assert result['overall']=='BLOCKED' and result['historical_role_equivalence']=='NOT_ATTESTED'

@pytest.mark.parametrize('name',m.SECTIONS)
@pytest.mark.parametrize('field,value',[(0,3),(1,'f'*64)])
def test_section_mutation(doc,name,field,value):
    raw=m.canonical(doc); doc['sections'][name][field]=value
    assert m.compare(raw,m.canonical(doc),expected_reference_pin=m.pin(raw))['blocker']=='MISMATCH_'+name.upper()

@pytest.mark.parametrize('field,value',[('server_major',16),('server_major',True),('server_major',17.0),('unresolved_refs',1),('unresolved_refs',False),('format','unknown')])
def test_metadata_rejected(doc,field,value):
    raw=m.canonical(doc); doc[field]=value
    assert m.compare(raw,m.canonical(doc),expected_reference_pin=m.pin(raw))['role_graph_checkpoint']=='BLOCKED'

@pytest.mark.parametrize('value',[[True,'a'*64],[-1,'a'*64],[100001,'a'*64],[2,None],[2,'A'*64],[2,'a'*63],[],[2,'a'*64,0]])
def test_malformed_section(doc,value):
    doc['sections']['memberships']=value
    with pytest.raises(m.Blocked): m.parse(m.canonical(doc))

def test_zero_roles(doc):
    doc['sections']['roles'][0]=0
    with pytest.raises(m.Blocked):m.parse(m.canonical(doc))

def test_empty_memberships_valid(doc):
    doc['sections']['memberships'][0]=0
    assert m.parse(m.canonical(doc))==doc

def test_missing_section(doc):
    del doc['sections']['all_database_role_settings']
    with pytest.raises(m.Blocked):m.parse(m.canonical(doc))

def test_wrong_pin(doc):
    raw=m.canonical(doc)
    assert m.compare(raw,raw,expected_reference_pin='0'*64)['blocker']=='REFERENCE_PIN_MISMATCH'

@pytest.mark.parametrize('raw',[b'',b'x',b'{}',b'{"a":1,"a":2}',b' '*8193,b'\xff'])
def test_invalid_input(raw):
    with pytest.raises(m.Blocked):m.parse(raw)

def test_sql_boundary():
    assert 'REPEATABLE READ READ ONLY' in m.SQL and 'ROLLBACK;' in m.SQL
    assert 'rolpassword' not in m.SQL and 'pg_authid' not in m.SQL
    assert all(x in m.SQL for x in ('m.admin_option','m.inherit_option','m.set_option','m.grantor','pg_db_role_setting'))
    assert 'current_database()' not in m.SQL
