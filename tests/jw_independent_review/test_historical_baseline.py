import copy, hashlib, struct
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from scripts import jw_historical_baseline_v223 as b
from scripts import jw_independent_equivalence_v223 as eq
from scripts import jw_independent_catalog_v223 as cat


def enc(p,k,i,legacy=False,chunk=17):
    magic=b.LEGACY if legacy else b.MAGIC
    prefix=i.to_bytes(4 if legacy else 8,'big'); out=bytearray(magic+prefix)
    for j,start in enumerate(range(0,len(p),chunk)):
        raw=AESGCM(k).encrypt(prefix+struct.pack('>Q' if legacy else '>I',j),p[start:start+chunk],magic+struct.pack('>QB',j,int(start+chunk>=len(p))))
        out+=struct.pack('>I',len(raw))+raw
    return bytes(out)


def H(x):return hashlib.sha256(str(x).encode()).hexdigest()


@pytest.fixture
def scenario():
    k1=b'A'*32;k2=b'B'*32;old={};new={};p1={};p2={};rows=[];calls=[];seen=[];old_tree={};new_tree={}
    for i in range(11):
        p=b'PGDMP'+str(i).encode()+b'x'*42
        a=enc(p,k1,i,legacy=i%2==0); c=enc(p,k2,i+100)
        x=b.git_blob(a);y=b.git_blob(c);old[x]=a;new[y]=c;p1[x]=b.sha(a);p2[y]=b.sha(c)
        rows.append(dict(source_blob_sha1=x,blob_sha1=y,cipher_sha256=p2[y]));old_tree['orig/'+x+'.jwpgbk']=x;new_tree['rekey/'+y+'.jwpgbk']=y
    old_tree['orig/historical-extra.jwpgbk']='f'*40;new_tree.update(old_tree)
    source=eq.canonical({'vault_commit_sha1':'a'*40,'archives':[dict(blob_sha1=x,cipher_sha256=y) for x,y in p1.items()]})
    receipt=eq.canonical(dict(stage='complete',verified=11,activated=False,remote_writes=False,archives=rows,new_scope_sha256=eq.owner_scope(p2)))
    def fetch_old(x,y):calls.append('old');return old[x]
    def fetch_new(x,y):calls.append('new');return new[x]
    def restore(p,i):
        calls.append('restore');seen.append(p);h=H(bytes(p));metadata=(H('a'),H('b'),1,H('c'),H('d'),H('names'),H('empty'),h,None)
        return ('LOCAL_DISPOSABLE_RESTORED',65,None,H('legacy'),3,H('constraint'),None,metadata),{s:(65 if s in ('relations','columns','rls_flags') else 1,H(s+str(bytes(p)))) for s in cat.SECTIONS}
    def cleanup():calls.append('cleanup');return 'PASS'
    args=dict(source_raw=source,source_pin=b.sha(source),old_vault='a'*40,old_scope=eq.owner_scope(p1),receipt_raw=receipt,receipt_pin=b.sha(receipt),new_vault='b'*40,new_scope=eq.owner_scope(p2),old_tree=old_tree,new_tree=new_tree,new_provider=p2,old_key=k1,new_key=k2,fetch_old=fetch_old,fetch_new=fetch_new,restore_old=restore,cleanup=cleanup)
    return args,calls,old,new,seen


def test_build_v4_compatible(scenario):
    a,c,_,_,seen=scenario;raw,r=b.build(**a);assert r['plaintext_pairs_equal']==r['old_archives_restored']==11 and r['reference_approval']=='NOT_APPROVED' and r['overall']=='BLOCKED'
    assert c.count('restore')==c.count('old')==c.count('new')==11 and c[-1]=='cleanup';assert all(not p for p in seen)
    rows,cats=cat.load_reference(raw,expected_reference_sha256=r['candidate_sha256'],expected_vault=a['new_vault'],expected_scope=a['new_scope'],provider_pairs=list(a['new_provider'].items())); assert len(rows)==len(cats)==11
    assert all(x.git_blob_sha1 in a['new_provider'] for x in rows)


def change_doc(a,name,fn):
    import json
    d=json.loads(a[name+'_raw']);fn(d);raw=eq.canonical(d);a[name+'_raw']=raw;a[name+'_pin']=b.sha(raw)


@pytest.mark.parametrize('key,value',[('source_pin','0'*64),('receipt_pin','0'*64),('old_scope','0'*64),('new_scope','0'*64),('new_vault','a'*40),('old_key',b'B'*32),('new_key',b'C'),('old_vault','e'*40)])
def test_pins_prevent_io(scenario,key,value):
    a,c,*_=scenario;a[key]=value
    with pytest.raises(eq.Blocked):b.build(**a)
    assert c==[]


@pytest.mark.parametrize('field,val',[('activated',True),('remote_writes',True),('verified',10),('verified',True),('stage','partial'),('new_scope_sha256','0'*64),('extra',1)])
def test_receipt_flags(scenario,field,val):
    a,c,*_=scenario;change_doc(a,'receipt',lambda d:d.__setitem__(field,val))
    with pytest.raises(eq.Blocked):b.build(**a)
    assert not c


@pytest.mark.parametrize('kind',['old_duplicate','new_duplicate','new_digest_duplicate','old_unknown','new_old','extra_field','missing','extra','wrong_digest','wrong_scope'])
def test_mapping_attacks(scenario,kind):
    a,c,*_=scenario
    def attack(d):
        rows=d['archives'];r=rows[0]
        if kind=='old_duplicate':r['source_blob_sha1']=rows[1]['source_blob_sha1']
        elif kind=='new_duplicate':r['blob_sha1']=rows[1]['blob_sha1']
        elif kind=='new_digest_duplicate':r['cipher_sha256']=rows[1]['cipher_sha256']
        elif kind=='old_unknown':r['source_blob_sha1']='e'*40
        elif kind=='new_old':r['blob_sha1']=r['source_blob_sha1']
        elif kind=='extra_field':r['plaintext_sha256']='0'*64
        elif kind=='missing':rows.pop()
        elif kind=='extra':rows.append(copy.copy(r))
        elif kind=='wrong_digest':r['cipher_sha256']='e'*64
        else:d['new_scope_sha256']='f'*64
    change_doc(a,'receipt',attack)
    with pytest.raises(eq.Blocked):b.build(**a)
    assert not c


def test_swap_pairs_even_with_new_approved_receipt_pin(scenario):
    a,c,*_=scenario
    def swap(d):
        x,y=d['archives'][:2];x['blob_sha1'],y['blob_sha1']=y['blob_sha1'],x['blob_sha1'];x['cipher_sha256'],y['cipher_sha256']=y['cipher_sha256'],x['cipher_sha256']
    change_doc(a,'receipt',swap)
    with pytest.raises(eq.Blocked,match='BRIDGE_PLAINTEXT_MISMATCH'):b.build(**a)
    assert c[-1]=='cleanup'


@pytest.mark.parametrize('kind',['remove','replace','rename','extra','invalid_path','provider_missing','provider_extra','old_tree_missing','duplicate_new'])
def test_tree_attacks(scenario,kind):
    a,c,*_=scenario;nt=a['new_tree'];ot=a['old_tree'];k=next(iter(ot));n=next(k for k in nt if k not in ot)
    if kind=='remove':nt.pop(k)
    elif kind=='replace':nt[k]='e'*40
    elif kind=='rename':nt['renamed']=nt.pop(k)
    elif kind=='extra':nt['new/extra.jwpgbk']='d'*40
    elif kind=='invalid_path':nt['new/wrong.jwpgbk']=nt.pop(n)
    elif kind=='provider_missing':a['new_provider'].pop(next(iter(a['new_provider'])))
    elif kind=='provider_extra':a['new_provider']['e'*40]='d'*64
    elif kind=='old_tree_missing':ot.pop(k)
    else:nt[n]=next(v for kk,v in nt.items() if kk!=n and kk not in ot)
    with pytest.raises(eq.Blocked):b.build(**a)
    assert not c


@pytest.mark.parametrize('side',['old','new'])
def test_provider_tamper(scenario,side):
    a,c,old,new,_=scenario;data=old if side=='old' else new
    for k in data:data[k]=data[k][:-1]+bytes([data[k][-1]^1])
    with pytest.raises(eq.Blocked,match='BRIDGE_CIPHER_HASH'):b.build(**a)
    assert c[-1]=='cleanup' and 'restore' not in c


def test_wrong_distinct_key(scenario):
    a,c,*_=scenario;a['new_key']=b'C'*32
    with pytest.raises(eq.Blocked,match='BRIDGE_AEAD_FAILED'):b.build(**a)
    assert c[-1]=='cleanup' and 'restore' not in c


@pytest.mark.parametrize('kind',['status','count','rows','metadata','catalog','hash','rls'])
def test_restore_bad(scenario,kind):
    a,c,*_=scenario;f=a['restore_old']
    def broken(p,i):
        r,s=f(p,i);r=list(r)
        if kind=='status':r[0]='FAIL'
        elif kind=='count':r[1]=64
        elif kind=='rows':r[4]=True
        elif kind=='metadata':r[7]=None
        elif kind=='catalog':s.pop('policies')
        elif kind=='hash':r[5]='bad'
        else:s['rls_flags']=(64,H('bad'))
        return r,s
    a['restore_old']=broken
    with pytest.raises(eq.Blocked):b.build(**a)
    assert c.count('restore')==1 and c[-1]=='cleanup'


def test_cleanup_failure(scenario):
    a,c,*_=scenario;a['cleanup']=lambda:'FAIL'
    with pytest.raises(eq.Blocked,match='BRIDGE_CLEANUP_FAILED'):b.build(**a)
    assert c.count('restore')==11


def test_restore_exception_wipes_plaintext(scenario):
    a,c,*_=scenario;seen=[]
    def fail(p,i):seen.append(p);raise RuntimeError('synthetic failure')
    a['restore_old']=fail
    with pytest.raises(RuntimeError):b.build(**a)
    assert c[-1]=='cleanup' and seen==[bytearray()]


@pytest.mark.parametrize('mutate',[lambda x:x[:-1],lambda x:x+b'x',lambda x:b'UNKNOWN!'+x[8:],lambda x:x[:20]+bytes([x[20]^1])+x[21:]])
def test_decrypt_invalid(mutate):
    k=b'k'*32;raw=enc(b'PGDMPtest archive multi',k,1)
    with pytest.raises(eq.Blocked):b.decrypt(mutate(raw),k)


@pytest.mark.parametrize('legacy',[False,True])
def test_decrypt_legacy_and_v2(legacy):
    k=b'k'*32;p=b'PGDMPtest archive multi';assert b.decrypt(enc(p,k,1,legacy),k)==p


def test_reference_parse_duplicate_key():
    raw=b'{"a":1,"a":2}'
    with pytest.raises(eq.Blocked):b.parse_pinned(raw,b.sha(raw))
