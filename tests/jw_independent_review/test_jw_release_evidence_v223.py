import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from scripts import jw_release_evidence_v223 as m

NOW=1700000000
EXPECT={'review_sha':'a'*40,'old_vault_sha':'b'*40,'new_vault_sha':'c'*40,'scope_sha256':'d'*64,'challenge_sha256':'e'*64}
@pytest.fixture
def case():
    keys={k:Ed25519PrivateKey.generate() for k in m.CHECKS}
    pubs={k:v.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw) for k,v in keys.items()}
    pins={k:m.digest(v) for k,v in pubs.items()}
    docs={k:dict(schema=m.SCHEMA,kind=k,**EXPECT,observed_at=NOW-10,expires_at=NOW+60,evidence_sha256=m.digest(('test-only-'+k).encode()),checks=v.copy()) for k,v in m.CHECKS.items()}
    def bundle(k,doc=None):
        raw=m.canonical(docs[k] if doc is None else doc)
        return raw,keys[k].sign(m.DOM+raw),pubs[k],('test-only-'+k).encode()
    return docs,bundle,pins

def verify(case,claims=None,pins=None,expected=EXPECT,now=NOW):
    d,b,p=case
    return m.evaluate({k:b(k) for k in d} if claims is None else claims,expected=expected,trust_pins=p if pins is None else pins,now=now)

def test_all_claims_still_no_release(case):
    r=verify(case); assert r['signature_binding']=='PASS' and r['live_release']=='BLOCKED'
@pytest.mark.parametrize('missing',list(m.CHECKS))
def test_missing_claim(case,missing):
    d,b,p=case;r=verify(case,{k:b(k) for k in d if k!=missing});assert r['signature_binding']=='BLOCKED' and r[missing]=='BLOCKED'
@pytest.mark.parametrize('field,value',[('review_sha','f'*40),('old_vault_sha','f'*40),('new_vault_sha','f'*40),('scope_sha256','f'*64),('challenge_sha256','f'*64),('observed_at',NOW+1),('expires_at',NOW),('expires_at',NOW+90000),('expires_at',True),('evidence_sha256','f'*64),('kind','custody'),('schema','other'),('extra',1)])
def test_resigned_bad_claim(case,field,value):
    d,b,p=case;d['archive'][field]=value;r=verify(case);assert r['archive']=='BLOCKED' and r['signature_binding']=='BLOCKED'
@pytest.mark.parametrize('field,value',[('cipher_count',10),('restore_count',12),('table_count_per_archive',True),('historical_row_comparison_count',0),('catalog_comparison_count',10),('cleanup',1)])
def test_archive_counts(case,field,value):
    d,b,p=case;d['archive']['checks'][field]=value;assert verify(case)['archive']=='BLOCKED'
@pytest.mark.parametrize('kind,field',[('custody','independent_key_retrieval'),('custody','separate_administrator'),('custody','separate_host'),('operations','roles_and_memberships_complete'),('operations','source_era_signature_verified'),('operations','main_protection_verified'),('operations','real_https_e2e_verified'),('operations','release_ci_verified')])
def test_incomplete_real_world_checks(case,kind,field):
    d,b,p=case;d[kind]['checks'][field]=False;assert verify(case)[kind]=='BLOCKED'
@pytest.mark.parametrize('index',[0,1,2,3])
def test_tamper(case,index):
    d,b,p=case;claims={k:b(k) for k in d};a=list(claims['archive']);a[index]=bytes([a[index][0]^1])+a[index][1:];claims['archive']=tuple(a);assert verify(case,claims)['archive']=='BLOCKED'
def test_duplicate_signer(case):
    d,b,p=case;p['custody']=p['archive'];assert verify(case)['blocker']=='INDEPENDENT_SIGNER_PINS'
def test_duplicate_json(case):
    d,b,p=case;raw,sig,pub,ev=b('archive');claims={'archive':(raw[:-1]+b',"schema":"JW-RELEASE-EVIDENCE-V1"}',sig,pub,ev)};assert verify(case,claims)['archive']=='BLOCKED'
def test_missing_anchor(case):
    d,b,p=case;del p['operations'];assert verify(case)['signature_binding']=='BLOCKED'
def test_invalid_clock(case):assert verify(case,now=True)['signature_binding']=='BLOCKED'
