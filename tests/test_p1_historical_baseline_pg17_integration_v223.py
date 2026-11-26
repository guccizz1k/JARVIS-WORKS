"""Actual PG17 synthetic historical capture -> independent V4 comparison.
Only run in the existing isolated review CI job; no real provider or keys.
"""
from __future__ import annotations
import os
import json
import struct
import subprocess
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from scripts import jw_historical_baseline_v223 as bridge
from scripts import jw_historical_baseline_owner_v223 as owner
from scripts import jw_independent_equivalence_v223 as eq
from scripts import p1_owner_offline_restore_v223 as offline
from scripts import p1_external_custodian_pg17_v223 as ext
from scripts import p1_cleanroom_key_recovery_v223 as clean


def docker(*args, data=None):
    return subprocess.run(['docker', *args], input=data, capture_output=True,
                          check=True, timeout=150).stdout


def cipher(plain, key, seed, legacy):
    magic = bridge.LEGACY if legacy else bridge.MAGIC
    prefix = seed.to_bytes(4 if legacy else 8, 'big')
    out = bytearray(magic + prefix)
    chunk = 1024 * 1024
    for i, start in enumerate(range(0, len(plain), chunk)):
        record = AESGCM(key).encrypt(prefix + struct.pack('>Q' if legacy else '>I', i),
                                    plain[start:start+chunk],
                                    magic + struct.pack('>QB', i, int(start+chunk >= len(plain))))
        out += struct.pack('>I', len(record)) + record
    return bytes(out)


def test_historical_old_to_new_actual_pg17(monkeypatch):
    # Fail rather than skip if the required dedicated CI context is absent.
    assert os.environ.get('JW_V5_SYNTHETIC_CI') == '1'
    assert os.environ.get('GITHUB_ACTIONS') == 'true'
    assert os.environ.get('GITHUB_REPOSITORY') == 'guccizz1k/JARVIS-WORKS'
    assert not any(os.environ.get(x) for x in ext.SOURCE_SECRETS)
    assert not os.environ.get('DOCKER_TLS_VERIFY')
    assert not os.environ.get('DOCKER_HOST') or os.environ['DOCKER_HOST'].startswith('unix://')
    assert docker('context', 'inspect', '--format', '{{.Endpoints.docker.Host}}').strip().startswith(b'unix://')
    source = 'jw-p1-source'
    assert b'PostgreSQL) 17.' in docker('exec', source, 'postgres', '--version')
    db = 'jw_v5_synthetic_' + secrets.token_hex(6)
    def sql(s):
        return docker('exec','-i',source,'psql','-X','-q','-v','ON_ERROR_STOP=1','-U','postgres','-d',db,data=s.encode())
    old_key,new_key = b'A'*32,b'B'*32
    old_vault,new_vault = 'a'*40,'b'*40
    old,new,old_provider,new_provider,old_tree,new_tree = {},{},{},{},{},{}
    rows=[]
    docker('exec',source,'createdb','-U','postgres',db)
    try:
        sql("""CREATE SCHEMA jw_dev;
        DO $$ DECLARE i int; BEGIN
          FOR i IN 0..64 LOOP
            EXECUTE format('CREATE TABLE jw_dev.test_%s (id int PRIMARY KEY, value text NOT NULL)',i);
            EXECUTE format('INSERT INTO jw_dev.test_%s VALUES (1, %L)',i,'synthetic-only');
          END LOOP;
        END $$;
        ALTER TABLE jw_dev.test_0 ENABLE ROW LEVEL SECURITY;
        ALTER TABLE jw_dev.test_0 FORCE ROW LEVEL SECURITY;
        CREATE POLICY synthetic_policy ON jw_dev.test_0 USING (id=1) WITH CHECK (id=1);
        """)
        for i in range(11):
            sql(f"UPDATE jw_dev.test_0 SET value='synthetic-revision-{i}' WHERE id=1;")
            plain=docker('exec',source,'pg_dump','-Fc','-U','postgres','--dbname',db,'--schema=jw_dev')
            assert plain.startswith(b'PGDMP')
            a=cipher(plain,old_key,i+1,i%2==0); b=cipher(plain,new_key,i+101,False)
            x,y=bridge.git_blob(a),bridge.git_blob(b)
            old[x]=a;new[y]=b;old_provider[x]=bridge.sha(a);new_provider[y]=bridge.sha(b)
            old_tree['old/'+x+'.jwpgbk']=x;new_tree['new/'+y+'.jwpgbk']=y
            rows.append({'source_blob_sha1':x,'blob_sha1':y,'cipher_sha256':new_provider[y]})
    finally:
        docker('exec',source,'dropdb','-U','postgres','--force',db)
    assert len(old)==len(new)==11
    new_tree.update(old_tree)
    source_raw=eq.canonical({'vault_commit_sha1':old_vault,'archives':[{'blob_sha1':x,'cipher_sha256':s} for x,s in old_provider.items()]})
    scope=eq.owner_scope(new_provider)
    receipt_raw=eq.canonical({'stage':'complete','verified':11,'activated':False,'remote_writes':False,'archives':rows,'new_scope_sha256':scope})
    adapter=owner.RestoreAdapter(offline)
    ref,report=bridge.build(source_raw=source_raw,source_pin=bridge.sha(source_raw),old_vault=old_vault,old_scope=eq.owner_scope(old_provider),receipt_raw=receipt_raw,receipt_pin=bridge.sha(receipt_raw),new_vault=new_vault,new_scope=scope,old_tree=old_tree,new_tree=new_tree,new_provider=new_provider,old_key=old_key,new_key=new_key,fetch_old=lambda x,s:old[x],fetch_new=lambda x,s:new[x],restore_old=adapter.restore,cleanup=adapter.cleanup)
    assert report['old_archives_restored']==report['plaintext_pairs_equal']==11
    assert report['cleanup']=='PASS' and report['reference_approval']=='NOT_APPROVED' and report['overall']=='BLOCKED'
    doc=json.loads(ref)
    assert len({a['row_manifest_c_sha256'] for a in doc['data_reference']['archives']})==11
    # Only the NEW key enters the separate restore path. No live provider is used.
    pairs=list(new_provider.items())
    monkeypatch.setenv('JW_WORM_OWNER_SCOPE_SHA256',scope)
    monkeypatch.setattr(ext,'preflight',lambda:'PASS')
    monkeypatch.setattr(clean,'_inputs',lambda:(new_vault,new_key,pairs))
    monkeypatch.setattr(clean,'_head_tree',lambda _:set(new))
    monkeypatch.setattr(clean,'_download',lambda x,s:bridge.check_cipher(new[x],x,s))
    checked=ext.run(ref,report['candidate_sha256'],catalog_required=True)
    assert checked['normalized_archive_comparison']=='PASS_11_ARCHIVE_CHECKPOINTS',checked
    assert checked['normalized_catalog_comparison']=='PASS_11_SCOPED_CATALOG_CHECKPOINTS',checked
    assert checked['restored_pg17_archive_count']==11 and checked['disposable_pg17_removed']=='PASS'
    assert checked['overall']=='BLOCKED' and checked['independent_key_custody']=='NOT_ATTESTED'
    # An otherwise valid reference with one tampered historical row count must fail.
    target=next(x for x in doc['data_reference']['archives'] if x['git_blob_sha1']==pairs[0][0])
    target['row_count']+=1
    bad=eq.canonical(doc)
    denied=ext.run(bad,bridge.sha(bad),catalog_required=True)
    assert denied['normalized_archive_comparison']=='BLOCKED' and denied['normalized_catalog_comparison']=='BLOCKED',denied
    assert denied['disposable_pg17_removed']=='PASS' and denied['overall']=='BLOCKED'
    print('PASS_V5_SYNTHETIC_11_OLD_TO_11_NEW_PG17_AND_REFERENCE_TAMPER')
