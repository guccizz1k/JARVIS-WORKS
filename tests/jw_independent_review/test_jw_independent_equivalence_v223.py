import copy
import hashlib
import json
from dataclasses import replace
import pytest
from scripts.jw_independent_equivalence_v223 import *

def H(s): return hashlib.sha256(str(s).encode()).hexdigest()
def fixture():
    rows=[dict(cipher_sha256=H(f'cipher{i}'),git_blob_sha1=hashlib.sha1(str(i).encode()).hexdigest(),table_count=65,row_count=i+1,constraint_sha256=H(f'constraint{i}'),row_manifest_c_sha256=H(f'row{i}'),table_names_c_sha256=H('names'),empty_table_names_c_sha256=H(f'empty{i}'),populated_tables=1) for i in range(11)]
    doc=dict(format=FORMAT,algorithm=ALGORITHM,vault_commit_sha1='a'*40,archives=rows)
    pairs=[(r['git_blob_sha1'],r['cipher_sha256']) for r in rows]
    return doc,pairs

def admit(doc=None,pairs=None,**kwargs):
    d,p=fixture(); d=d if doc is None else doc; p=p if pairs is None else pairs
    raw=canonical(d); options=dict(expected_reference_sha256=hashlib.sha256(raw).hexdigest(),expected_vault='a'*40,expected_scope=owner_scope(x[0] for x in fixture()[1]),provider_pairs=p);options.update(kwargs)
    return load_reference(raw,**options)

def observation(r):
    return ('LOCAL_DISPOSABLE_RESTORED',65,'1'*32,H('legacy'),r.row_count,r.constraint_sha256,None,(H('a'),H('b'),r.populated_tables,H('c'),H('d'),r.table_names_c_sha256,r.empty_table_names_c_sha256,r.row_manifest_c_sha256,None))

def test_all_11_never_claims_release_or_acl():
    rows=admit(); eq=Equivalence(rows)
    for r in reversed(rows): eq.compare(r.git_blob_sha1,r.cipher_sha256,observation(r))
    assert eq.receipt(cleanup='PASS')=={'normalized_archive_comparison':'PASS_11_ARCHIVE_CHECKPOINTS','matched_archives':11,'cleanup_pass':True,'row_digest_collision_proof':False,'full_schema_equivalence':'NOT_RUN','rls_policy_equivalence':'NOT_RUN','original_owner_acl_equivalence':'NOT_RUN_RESTORE_STRIPS_OWNER_ACL','independent_key_custody':'NOT_ATTESTED','overall':'BLOCKED'}
    assert eq.receipt(cleanup='FAIL')['normalized_archive_comparison']=='BLOCKED'

@pytest.mark.parametrize('field,value',[('expected_reference_sha256',''),('expected_reference_sha256','0'*64),('expected_vault','b'*40),('expected_scope','0'*64)])
def test_wrong_independent_pins(field,value):
    with pytest.raises(Blocked): admit(**{field:value})

@pytest.mark.parametrize('field,value',[('row_count',True),('row_count',-1),('row_count',5_000_001),('table_count',64),('table_count',65.0),('populated_tables',True),('populated_tables',0),('populated_tables',66),('cipher_sha256','bad'),('row_manifest_c_sha256','BAD'),('constraint_sha256',''),('git_blob_sha1','z'*40)])
def test_reference_shape(field,value):
    d,p=fixture();d['archives'][0][field]=value
    with pytest.raises(Blocked): admit(d,p)

@pytest.mark.parametrize('mutation',['remove','add','duplicate_blob','duplicate_cipher','unknown_field','wrong_format','wrong_algorithm','cross_cipher','wrong_pairs','pair_replay','swap_pair'])
def test_scope_and_reference_mutations(mutation):
    d,p=fixture();a=d['archives']
    if mutation=='remove': a.pop()
    elif mutation=='add': a.append(copy.deepcopy(a[0]))
    elif mutation=='duplicate_blob': a[1]['git_blob_sha1']=a[0]['git_blob_sha1']
    elif mutation=='duplicate_cipher': a[1]['cipher_sha256']=a[0]['cipher_sha256']
    elif mutation=='unknown_field': a[0]['pass']=True
    elif mutation=='wrong_format': d['format']='V2'
    elif mutation=='wrong_algorithm': d['algorithm']='untrusted'
    elif mutation=='cross_cipher': a[0]['cipher_sha256']=H('other')
    elif mutation=='wrong_pairs': p.pop()
    elif mutation=='pair_replay': p[1]=p[0]
    elif mutation=='swap_pair': p[0]=(p[0][0],p[1][1])
    with pytest.raises(Blocked): admit(d,p)

@pytest.mark.parametrize('raw',[b'',b'{}',b'{"x":1,"x":2}',b'{"x":NaN}',b'\xff',b'x'*32769,b'['*1500+b']'*1500])
def test_json_and_size(raw):
    with pytest.raises(Blocked): load_reference(raw,expected_reference_sha256=hashlib.sha256(raw).hexdigest(),expected_vault='a'*40,expected_scope='b'*64,provider_pairs=[])

@pytest.mark.parametrize('index,value',[(0,'FAIL'),(1,64),(1,65.0),(3,None),(4,True),(4,999),(5,'0'*64),(7,None),(7,()),(7,('a',)*9)])
def test_restore_result_mutation(index,value):
    rr=admit();eq=Equivalence(rr);r=rr[0];obs=list(observation(r));obs[index]=value
    with pytest.raises(Blocked):eq.compare(r.git_blob_sha1,r.cipher_sha256,obs)
    assert eq.receipt(cleanup='PASS')['normalized_archive_comparison']=='BLOCKED'
    with pytest.raises(Blocked,match='RUN_ALREADY_FAILED'):eq.compare(r.git_blob_sha1,r.cipher_sha256,observation(r))

@pytest.mark.parametrize('idx,value',[(2,True),(2,0),(5,'0'*64),(6,'0'*64),(7,'0'*64),(7,'bad')])
def test_metadata_mismatch(idx,value):
    rr=admit();eq=Equivalence(rr);r=rr[0];obs=list(observation(r));meta=list(obs[7]);meta[idx]=value;obs[7]=meta
    with pytest.raises(Blocked):eq.compare(r.git_blob_sha1,r.cipher_sha256,obs)

@pytest.mark.parametrize('kind',['unknown','cipher','replay','cross_observation','missing'])
def test_identity_replay_and_missing(kind):
    rr=admit();eq=Equivalence(rr);r=rr[0]
    if kind=='missing':
        for x in rr[:-1]:eq.compare(x.git_blob_sha1,x.cipher_sha256,observation(x))
    else:
        if kind=='replay': eq.compare(r.git_blob_sha1,r.cipher_sha256,observation(r))
        with pytest.raises(Blocked):eq.compare('f'*40 if kind=='unknown' else r.git_blob_sha1,H('bad') if kind=='cipher' else r.cipher_sha256,observation(rr[1] if kind=='cross_observation' else r))
    assert eq.receipt(cleanup='PASS')['normalized_archive_comparison']=='BLOCKED'

@pytest.mark.parametrize('kind',['count','duplicate','invalid_row'])
def test_constructor_rejects_malformed_direct_objects(kind):
    rr=list(admit())
    if kind=='count':rr.pop()
    elif kind=='duplicate':rr[1]=rr[0]
    else:rr[0]=replace(rr[0],row_count=-1)
    with pytest.raises(Blocked):Equivalence(rr)

import os
import threading
from contextlib import contextmanager

@contextmanager
def pipes():
    fds=[os.pipe() for _ in range(3)]
    try:
        env=dict(zip(('JW_PG_RESTORE_REFERENCE_FD','JW_PG_CLEANROOM_KEY_FD','JW_PG_CLEANROOM_MANIFEST_FD'),[str(x[0]) for x in fds]))
        yield fds,env
    finally:
        for pair in fds:
            for fd in pair:
                try: os.close(fd)
                except OSError:pass

def test_real_pipe_segmented_reference():
    with pipes() as (fds,env):
        raw=canonical(fixture()[0]);w=fds[0][1]
        def writer():
            for i in range(0,len(raw),31):os.write(w,raw[i:i+31])
            os.close(w)
        t=threading.Thread(target=writer);t.start()
        assert read_reference_pipe(env)==raw
        t.join()

def test_pipe_alias_duplicate_descriptor():
    with pipes() as (fds,env):
        fd=os.dup(fds[1][0])
        try:
            env['JW_PG_RESTORE_REFERENCE_FD']=str(fd)
            with pytest.raises(Blocked,match='REFERENCE_PIPE_ALIAS_OR_INVALID'): read_reference_pipe(env)
        finally:os.close(fd)

def test_pipe_timeout():
    with pipes() as (_,env):
        with pytest.raises(Blocked,match='REFERENCE_PIPE_TIMEOUT'):read_reference_pipe(env,timeout=.01)

def test_empty_pipe():
    with pipes() as (fds,env):
        os.close(fds[0][1])
        with pytest.raises(Blocked,match='REFERENCE_SIZE'):read_reference_pipe(env)

def test_regular_file_rejected(tmp_path):
    p=tmp_path/'ref';p.write_bytes(b'abc')
    with pipes() as (_,env),p.open('rb') as f:
        env['JW_PG_RESTORE_REFERENCE_FD']=str(f.fileno())
        with pytest.raises(Blocked,match='REFERENCE_NOT_PIPE'):read_reference_pipe(env)
