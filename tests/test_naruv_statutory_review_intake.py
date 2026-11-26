import hashlib
import json
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app import naruv_statutory_review_intake as m


def fixture():
    inv = json.dumps({'classification':'SYNTHETIC_ONLY_NOT_LEGAL_ACCEPTANCE','submission_authorized':False,'reviewer_expected_values':None,'cases':[{'id':f'KR{i:02}','questions':['q']} for i in range(1,10)]}).encode()
    pin = hashlib.sha256(inv).hexdigest()
    keys = {r:Ed25519PrivateKey.generate() for r in m.ROLES}
    pub = {r:k.public_key().public_bytes_raw() for r,k in keys.items()}
    rows = {f'KR{i:02}':{'answers':{'q':'Missing evidence'},'official_sources':['https://example.invalid/rule'],'disposition':'MISSING_FACTS'} for i in range(1,10)}
    def sign(role,payload):
        return m.canonical({'payload':payload,'signature_hex':keys[role].sign(b'NARUV_STATUTORY_REVIEW_V1\0'+m.canonical(payload)).hex()})
    reports = {r:sign(r,{'role':r,'inventory_sha256':pin,'cases':rows}) for r in m.ROLES}
    return inv,pin,pub,reports,sign


def test_valid_not_legal_acceptance():
    inv,pin,pub,reports,_ = fixture()
    out = m.verify(inv,pin,reports,pub)
    assert out['signed_response_structure_verified'] and out['assessed_case_counts']=={'labor':0,'tax':0}
    assert not out['production_authorized'] and not out['legal_correctness_verified']


@pytest.mark.parametrize('mutation',['pin','same_key','missing_role','tamper','wrong_role','missing_case','missing_answer','wrong_pin','bad_signature','duplicate'])
def test_deny(mutation):
    inv,pin,pub,reports,sign = fixture()
    p=json.loads(reports['labor'])['payload']
    if mutation=='pin':pin='0'*64
    elif mutation=='same_key':pub['tax']=pub['labor']
    elif mutation=='missing_role':del reports['tax']
    elif mutation=='tamper':reports['labor']=reports['labor'].replace(b'Missing evidence',b'Changed evidence')
    elif mutation=='bad_signature':reports['labor']=m.canonical({'payload':p,'signature_hex':'0'*128})
    elif mutation=='duplicate':reports['labor']=b'{"payload":{},"payload":{}}'
    else:
        if mutation=='wrong_role':p['role']='tax'
        elif mutation=='missing_case':del p['cases']['KR01']
        elif mutation=='missing_answer':p['cases']['KR01']['answers']={}
        elif mutation=='wrong_pin':p['inventory_sha256']='0'*64
        reports['labor']=sign('labor',p)
    with pytest.raises(ValueError):m.verify(inv,pin,reports,pub)
