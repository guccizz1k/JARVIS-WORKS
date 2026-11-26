#!/usr/bin/env python3
"""Local owner-only preflight and optional V5 capture; no keys or DB contact in preflight."""
from __future__ import annotations
import argparse, base64, hashlib, hmac, json, os, re, resource, stat, subprocess, sys, tempfile
from pathlib import Path

SHA='800b2c861b4f1471ba125c0c1b9d717335547480'
OLD=NEW=OLD_SCOPE=NEW_SCOPE=SOURCE_PIN=RECEIPT_PIN=ENVELOPE_PIN=None
HEX40=re.compile(r'[0-9a-f]{40}'); HEX64=re.compile(r'[0-9a-f]{64}')
class Blocked(Exception): pass
def need(ok,code):
    if not ok: raise Blocked(code)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def scope(ids): return sha(('JW-WORM-OWNER-SCOPE-V1\n'+'\n'.join(sorted(ids))+'\n').encode())
def hexval(x,pat=HEX64): return type(x) is str and pat.fullmatch(x) is not None
def unique(pairs):
    d={}
    for k,v in pairs:
        need(k not in d,'DUPLICATE_JSON');d[k]=v
    return d
def doc(raw): return json.loads(raw.decode('ascii'),object_pairs_hook=unique,parse_constant=lambda _: (_ for _ in ()).throw(Blocked('INVALID_JSON_CONSTANT')))
def private_dir(p):
    s=p.lstat();need(stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode)==0o700 and s.st_uid==os.getuid(),'PRIVATE_DIRECTORY')
def read(p,limit):
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        a=os.fstat(f.fileno());need(stat.S_ISREG(a.st_mode) and stat.S_IMODE(a.st_mode)==0o600 and a.st_uid==os.getuid() and 0<a.st_size<=limit,'PRIVATE_INPUT')
        raw=f.read(limit+1);b=os.fstat(f.fileno());need(len(raw)==a.st_size and (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns),'INPUT_CHANGED');return raw

def verify_source(raw):
    need(hmac.compare_digest(sha(raw),SOURCE_PIN),'SOURCE_PIN');d=doc(raw)
    need(type(d) is dict and set(d)=={'vault_commit_sha1','archives'} and d['vault_commit_sha1']==OLD,'SOURCE_SHAPE')
    rows=d['archives'];need(type(rows) is list and len(rows)==11,'SOURCE_COUNT');out={}
    for r in rows:
        need(type(r) is dict and set(r)=={'blob_sha1','cipher_sha256'},'SOURCE_ROW');b,s=r['blob_sha1'],r['cipher_sha256'];need(hexval(b,HEX40) and hexval(s) and b not in out,'SOURCE_ID');out[b]=s
    need(len(set(out.values()))==11 and scope(out)==OLD_SCOPE,'SOURCE_SCOPE');return out

def verify_receipt(raw,source):
    d=doc(raw);need(type(d) is dict and set(d)=={'stage','verified','activated','remote_writes','archives','new_scope_sha256'},'RECEIPT_SHAPE')
    need(d['stage']=='complete' and type(d['verified']) is int and d['verified']==11 and d['activated'] is False and d['remote_writes'] is False and d['new_scope_sha256']==NEW_SCOPE,'RECEIPT_STATE');rows=d['archives'];need(type(rows) is list and len(rows)==11,'RECEIPT_COUNT');old=set();new=set();digests=set()
    for r in rows:
        need(type(r) is dict and set(r)=={'source_blob_sha1','blob_sha1','cipher_sha256'},'RECEIPT_ROW');a,b,s=r['source_blob_sha1'],r['blob_sha1'],r['cipher_sha256'];need(hexval(a,HEX40) and hexval(b,HEX40) and hexval(s) and a in source and a not in old and b not in source and b not in new and s not in source.values() and s not in digests,'RECEIPT_MAPPING');old.add(a);new.add(b);digests.add(s)
    need(old==set(source) and scope(new)==NEW_SCOPE,'RECEIPT_SCOPE');return d

def verify_envelope(raw):
    magic=b'JW-KEY-ESCROW-V1\0';need(len(raw)==len(magic)+16+12+48 and raw.startswith(magic),'ENVELOPE_SHAPE')

def inputs(home,source_raw):
    source=verify_source(source_raw); rr=home/'.jw-rekey-candidate-20261124'; er=home/'.jw-key-escrow-20261124';private_dir(rr);private_dir(er);receipt=read(rr/'receipt.json',65536);env=read(er/'candidate-key.jwescrow',512);verify_receipt(receipt,source);verify_envelope(env);return receipt,env

REVIEW_BLOBS={
'jw_historical_baseline_owner_v223.py':'13d3c9b2febae3e2ed4b35dd00191a263d69a30d',
'jw_historical_baseline_v223.py':'33f95e9ae3dce10f749b5d8849f42b2d05eaa2c3',
'jw_independent_equivalence_v223.py':'25bc78e8d0d52f6c4e4fe46b4874a1f82238845e',
'jw_independent_catalog_v223.py':'75b29b4bb5bf5d5ebe5ae7ef52d4aa43b72afee8',
'jw_key_escrow_v223.py':'718b74a25e9d0b65344f46ba18772eaff52364e0',
'p1_owner_offline_restore_v223.py':'dd45462ba81711d237d077605e2d8e3fa63f5bc4',
'p1_owner_one_shot_v223.py':'cbbdc2e49b3fe0aa0fdb4af6a96980f90452179f',
'p1_owner_archive_deep_v223.py':'b47f902fb17e3af79a40d55af7edaa92a90407ba',
'p1_owner_archive_inventory_v223.py':'accc6b097ae26b4ff847e0f92be5e0da72b71480',
'pg_backup_v223.py':'01d8e6b57d6f8607b1803af7ac04f65181d982c3',
}
def git_blob(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode('ascii')+b'\0'+raw).hexdigest()
def stage_review(repo,dest):
    # No checkout, remote write, arbitrary working-tree import, or hooks.
    git_env={k:v for k,v in os.environ.items() if k in {'PATH','HOME','LANG','LC_ALL'}};git_env['GIT_NO_REPLACE_OBJECTS']='1'
    def git(*args):
        p=subprocess.run(['git','-C',str(repo),*args],env=git_env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15,check=False)
        need(p.returncode==0,'PINNED_REVIEW_OBJECT_UNAVAILABLE');return p.stdout
    try:
        found=git('rev-parse',SHA+'^{commit}').strip().decode('ascii')
    except Blocked:
        # Fetch only the pinned public review commit into the local object store.
        # No checkout, ref update, hooks, remote write or branch switch.
        p=subprocess.run(['git','-C',str(repo),'-c','core.hooksPath=/dev/null','-c','fetch.recurseSubmodules=false','fetch','--no-tags','--no-write-fetch-head','--no-recurse-submodules','https://github.com/guccizz1k/JARVIS-WORKS.git',SHA],env={**git_env,'GIT_TERMINAL_PROMPT':'0'},stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=120,check=False)
        need(p.returncode==0,'PINNED_REVIEW_FETCH_FAILED')
        found=git('rev-parse',SHA+'^{commit}').strip().decode('ascii')
    need(found==SHA,'REVIEW_SHA_MISMATCH')
    scripts=dest/'scripts';scripts.mkdir(mode=0o700)
    for name,want in REVIEW_BLOBS.items():
        raw=git('show',SHA+':scripts/'+name);need(0<len(raw)<=1024*1024 and git_blob(raw)==want,'REVIEW_BLOB_MISMATCH')
        (scripts/name).write_bytes(raw)
    (scripts/'__init__.py').write_bytes(b'')

def run(repo,home,source_raw,receipt,env,receipt_pin,envelope_pin):
    need(hexval(receipt_pin) and hexval(envelope_pin) and hmac.compare_digest(sha(receipt),receipt_pin) and hmac.compare_digest(sha(env),envelope_pin),'SEPARATELY_CONFIRMED_PINS_REQUIRED')
    need(os.environ.get('CODESPACES','').lower()=='true','OWNER_CODESPACE_REQUIRED')
    need(not os.environ.get('DOCKER_TLS_VERIFY') and (not os.environ.get('DOCKER_HOST') or os.environ['DOCKER_HOST'].startswith('unix://')),'REMOTE_DOCKER_BLOCKED')
    out=home/'.jw-historical-baseline-20261124'
    if not os.path.lexists(out):out.mkdir(mode=0o700)
    private_dir(out);target=out/'reference-candidate.json';need(not os.path.lexists(target),'OUTPUT_ALREADY_EXISTS')
    with tempfile.TemporaryDirectory(prefix='jw-baseline-input-',dir=out) as tmp:
        tmp=Path(tmp);stage_review(repo,tmp)
        old_encoded=os.environ.get('JW_PG_BACKUP_KEY','').encode('ascii');need(re.fullmatch(rb'[A-Za-z0-9_-]{43}=?',old_encoded) is not None,'OLD_KEY_NOT_AVAILABLE')
        need(sys.stdin.isatty() and sys.stdout.isatty(),'TTY_REQUIRED')
        import importlib.util
        spec=importlib.util.spec_from_file_location('jw_verified_escrow',tmp/'scripts/jw_key_escrow_v223.py');escrow=importlib.util.module_from_spec(spec);spec.loader.exec_module(escrow)
        new=escrow.unseal(env,escrow.masked('Escrow passphrase: '));need(len(new)==32,'NEW_KEY_FORMAT');new_encoded=base64.urlsafe_b64encode(new);new=None
        need(not hmac.compare_digest(base64.urlsafe_b64decode(old_encoded.rstrip(b'=')+b'='),base64.urlsafe_b64decode(new_encoded)),'KEY_NOT_DISTINCT')
        env_child={k:v for k,v in os.environ.items() if k in {'PATH','HOME','USER','LOGNAME','LANG','LC_ALL','TMPDIR','GH_CONFIG_DIR','DOCKER_HOST','DOCKER_CONFIG','CODESPACES'}}
        token=os.environ.get('JW_VAULT_READ_TOKEN') or os.environ.get('GH_TOKEN')
        if token:env_child['GH_TOKEN']=token
        env_child['JW_OWNER_BASELINE_ACK']='OWNER_APPROVES_ARCHIVED_BASELINE_CAPTURE_ONLY'
        for path,raw in [(tmp/'source.json',source_raw),(tmp/'receipt.json',receipt)]:
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as f:f.write(raw)
        fds=[]
        try:
            for val in (old_encoded,new_encoded):
                r,w=os.pipe();fds.append(r)
                try:os.write(w,val)
                finally:os.close(w)
            old_encoded=new_encoded=None
            cmd=[sys.executable,'-I','-c','import sys,runpy; sys.path.insert(0,sys.argv.pop(1)); runpy.run_module("scripts.jw_historical_baseline_owner_v223",run_name="__main__")',str(tmp),'--source',str(tmp/'source.json'),'--source-pin',SOURCE_PIN,'--receipt',str(tmp/'receipt.json'),'--receipt-pin',receipt_pin,'--old-vault',OLD,'--new-vault',NEW,'--old-scope',OLD_SCOPE,'--new-scope',NEW_SCOPE,'--old-key-fd',str(fds[0]),'--new-key-fd',str(fds[1]),'--output',str(target)]
            return subprocess.run(cmd,cwd=tmp,env=env_child,pass_fds=tuple(fds),check=False).returncode
        finally:
            for fd in fds:os.close(fd)

def source_from_originals(home,receipt):
    need(hmac.compare_digest(sha(receipt),RECEIPT_PIN),'RECEIPT_PIN');d=doc(receipt)
    need(type(d) is dict and type(d.get('archives')) is list and len(d['archives'])==11,'RECEIPT_COUNT')
    ids=set()
    for row in d['archives']:
        need(type(row) is dict and hexval(row.get('source_blob_sha1'),HEX40),'RECEIPT_MAPPING');ids.add(row['source_blob_sha1'])
    need(len(ids)==11 and scope(ids)==OLD_SCOPE,'SOURCE_SCOPE')
    root=home/'.local/share/jw-v223-restore/backups';private_dir(root);rows={};count=0;total=0
    for base,dirs,names in os.walk(root,followlinks=False):
        p=Path(base);private_dir(p);need(len(p.relative_to(root).parts)<=2,'SOURCE_DEPTH')
        for dn in dirs:private_dir(p/dn)
        for name in names:
            if not name.endswith('.jwpgbk'):continue
            count+=1;need(count<=11,'SOURCE_COUNT');raw=read(p/name,32*1024*1024);total+=len(raw);need(total<=128*1024*1024,'SOURCE_BUDGET')
            i=git_blob(raw);need(i in ids and i not in rows,'SOURCE_ARCHIVE_ID');rows[i]=sha(raw)
    need(count==11 and set(rows)==ids,'SOURCE_COUNT')
    raw=(json.dumps({'vault_commit_sha1':OLD,'archives':[{'blob_sha1':i,'cipher_sha256':rows[i]} for i in sorted(rows)]},indent=2)+'\n').encode('ascii')
    verify_source(raw);verify_receipt(receipt,rows);return raw

def main(argv=None):
    global OLD,NEW,OLD_SCOPE,NEW_SCOPE,SOURCE_PIN,RECEIPT_PIN,ENVELOPE_PIN
    p=argparse.ArgumentParser(description='Owner V5 capture. All private pins are supplied locally; never embedded in source.')
    for x in ('old_vault','new_vault','old_scope','new_scope','source_pin','receipt_pin','envelope_pin'):p.add_argument(x)
    p.add_argument('--preflight',action='store_true');p.add_argument('--repo',type=Path,default=Path.cwd());a=p.parse_args(argv)
    try:
        os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE,(0,0));need(os.environ.get('CODESPACES','').lower()=='true','OWNER_CODESPACE_REQUIRED')
        OLD,NEW,OLD_SCOPE,NEW_SCOPE,SOURCE_PIN,RECEIPT_PIN,ENVELOPE_PIN=(a.old_vault,a.new_vault,a.old_scope,a.new_scope,a.source_pin,a.receipt_pin,a.envelope_pin)
        need(hexval(OLD,HEX40) and hexval(NEW,HEX40) and OLD!=NEW and all(hexval(x) for x in (OLD_SCOPE,NEW_SCOPE,SOURCE_PIN,RECEIPT_PIN,ENVELOPE_PIN)),'PIN_FORMAT')
        home=Path.home();rr=home/'.jw-rekey-candidate-20261124';er=home/'.jw-key-escrow-20261124';private_dir(rr);private_dir(er);receipt=read(rr/'receipt.json',65536);env=read(er/'candidate-key.jwescrow',512)
        need(hmac.compare_digest(sha(receipt),RECEIPT_PIN) and hmac.compare_digest(sha(env),ENVELOPE_PIN),'SEPARATELY_CONFIRMED_PINS_REQUIRED');verify_envelope(env);source=source_from_originals(home,receipt)
        if a.preflight:
            print(json.dumps({'source_scope':'PASS','receipt_scope':'PASS','envelope_format':'PASS','pins_match':True,'keys_read':False,'actual_baseline':'NOT_RUN','overall':'BLOCKED'},sort_keys=True));return 0
        print('INPUT_PINS_PASS; starting pinned owner capture',flush=True)
        return run(a.repo.resolve(),home,source,receipt,env,RECEIPT_PIN,ENVELOPE_PIN)
    except (Exception,KeyboardInterrupt) as e:
        print(json.dumps({'blocker':str(e) if isinstance(e,Blocked) else 'OWNER_LAUNCHER_FAIL_CLOSED','overall':'BLOCKED'}));return 1

if __name__=='__main__':sys.exit(main())
