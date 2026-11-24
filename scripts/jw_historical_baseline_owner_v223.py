"""Owner-only V4 baseline capture adapter. Never run on the independent site or CI.

Read-only private GitHub vault + disposable, local networkless PG17. Both keys
are supplied on distinct anonymous pipes, not environment variables or argv.
The reference is written only into an existing owner-private directory.
No real key or metadata is included in this source or test fixtures.
"""
from __future__ import annotations
import argparse, base64, hashlib, json, os, re, resource, secrets, select, stat, subprocess, sys, time
from pathlib import Path
from scripts import jw_historical_baseline_v223 as bridge
from scripts import jw_independent_equivalence_v223 as eq
from scripts import jw_independent_catalog_v223 as cat

REPO='repos/guccizz1k/jw-backup-vault-261111'
ACK='OWNER_APPROVES_ARCHIVED_BASELINE_CAPTURE_ONLY'
# No DB, backup, B2, cloud service or proxy credentials are forwarded.
ALLOW_ENV={'PATH','HOME','USER','LOGNAME','LANG','LC_ALL','TMPDIR','GH_TOKEN','GH_CONFIG_DIR','CODESPACES','JW_OWNER_BASELINE_ACK','DOCKER_HOST','DOCKER_CONFIG'}


def private_read(path, limit=eq.MAX_JSON):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        a=os.fstat(f.fileno());eq.require(stat.S_ISREG(a.st_mode) and a.st_uid==os.getuid() and stat.S_IMODE(a.st_mode)==0o600 and 0<a.st_size<=limit,'BASELINE_PRIVATE_INPUT')
        raw=f.read(limit+1);z=os.fstat(f.fileno())
        eq.require(len(raw)==a.st_size and (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns),'BASELINE_INPUT_CHANGED')
        return raw


def keys_from_pipes(a,b):
    eq.require(type(a) is int and type(b) is int and 3<=a<=1048576 and 3<=b<=1048576 and a!=b,'BASELINE_KEY_FDS')
    sa,sb=os.fstat(a),os.fstat(b)
    eq.require(stat.S_ISFIFO(sa.st_mode) and stat.S_ISFIFO(sb.st_mode) and (sa.st_dev,sa.st_ino)!=(sb.st_dev,sb.st_ino),'BASELINE_KEY_PIPE_ALIAS')
    def read(fd):
        raw=bytearray();deadline=time.monotonic()+15
        try:
            while True:
                remain=deadline-time.monotonic();eq.require(remain>0 and select.select([fd],[],[],remain)[0],'BASELINE_KEY_TIMEOUT')
                p=os.read(fd,129-len(raw))
                if not p:break
                raw.extend(p);eq.require(len(raw)<=128,'BASELINE_KEY_SIZE')
            stripped=bytes(raw).strip();eq.require(re.fullmatch(rb'[A-Za-z0-9_-]{43}=?',stripped) is not None,'BASELINE_KEY_ENCODING')
            k=base64.urlsafe_b64decode(stripped.rstrip(b'=')+b'=');eq.require(len(k)==32,'BASELINE_KEY_SIZE');return k
        finally:bridge.wipe(raw)
    return read(a),read(b)


def sanitize_environment():
    eq.require(os.environ.get('CODESPACES','').lower()=='true' and os.environ.get('JW_OWNER_BASELINE_ACK')==ACK,'BASELINE_OWNER_APPROVAL_REQUIRED')
    eq.require(not os.environ.get('DOCKER_TLS_VERIFY') and (not os.environ.get('DOCKER_HOST') or os.environ['DOCKER_HOST'].startswith('unix://')),'BASELINE_REMOTE_DOCKER_BLOCKED')
    # Only invoked in a dedicated CLI subprocess, never the owner shell itself.
    keep={k:v for k,v in os.environ.items() if k in ALLOW_ENV}
    os.environ.clear();os.environ.update(keep);os.environ.update(GH_PROMPT_DISABLED='1',GH_NO_UPDATE_NOTIFIER='1',GIT_TERMINAL_PROMPT='0')


def api(endpoint,limit=65536):
    eq.require(endpoint.startswith(REPO+'/') or endpoint==REPO,'BASELINE_PROVIDER_ENDPOINT')
    p=subprocess.run(['gh','api',endpoint,'--method','GET','--header','Accept: application/vnd.github+json'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=90,check=False)
    eq.require(p.returncode==0 and 0<len(p.stdout)<=limit,'BASELINE_PROVIDER_READ_FAILED')
    try:d=json.loads(p.stdout,object_pairs_hook=eq.no_duplicates,parse_constant=eq.reject_constant)
    except Exception:raise eq.Blocked('BASELINE_PROVIDER_JSON') from None
    eq.require(type(d) is dict,'BASELINE_PROVIDER_JSON');return d


def tree(commit):
    eq.require(eq.valid_hex(commit,eq.GIT),'BASELINE_TREE_PIN')
    d=api(REPO+'/git/commits/'+commit);t=d.get('tree')
    eq.require(d.get('sha')==commit and type(t) is dict and eq.valid_hex(t.get('sha'),eq.GIT),'BASELINE_TREE_PIN')
    d=api(REPO+'/git/trees/'+t['sha']+'?recursive=1');rows=d.get('tree')
    eq.require(d.get('sha')==t['sha'] and d.get('truncated') is False and type(rows) is list and 11<=len(rows)<=80,'BASELINE_TREE_SHAPE')
    out={}
    for r in rows:
        eq.require(type(r) is dict,'BASELINE_TREE_ENTRY')
        if r.get('type')=='tree' and r.get('mode')=='040000':continue
        k,v=r.get('path'),r.get('sha');size=r.get('size')
        eq.require(r.get('type')=='blob' and r.get('mode')=='100644' and type(k) is str and k.endswith('.jwpgbk') and all(x not in ('','.','..') for x in k.split('/')) and k not in out and eq.valid_hex(v,eq.GIT) and type(size) is int and 24<size<=bridge.MAX_CIPHER,'BASELINE_TREE_ENTRY')
        out[k]=v
    return out


def fetch(blob,digest):
    eq.require(eq.valid_hex(blob,eq.GIT) and eq.valid_hex(digest),'BASELINE_PROVIDER_PAIR')
    d=api(REPO+'/git/blobs/'+blob,2*bridge.MAX_CIPHER+8192)
    raw=d.get('content');size=d.get('size')
    eq.require(d.get('sha')==blob and d.get('encoding')=='base64' and type(raw) is str and type(size) is int and 24<size<=bridge.MAX_CIPHER and len(raw)<=2*bridge.MAX_CIPHER,'BASELINE_PROVIDER_BLOB')
    try:c=base64.b64decode(''.join(raw.split()),validate=True)
    except (ValueError,TypeError):raise eq.Blocked('BASELINE_PROVIDER_ENCODING') from None
    eq.require(len(c)==size,'BASELINE_PROVIDER_SIZE');return bridge.check_cipher(c,blob,digest)


class RestoreAdapter:
    def __init__(self, offline):self.offline=offline;self.container=None;self.name=None;self.token=None;self.started=False
    def start(self):
        o=self.offline
        ctx=o._docker(['context','inspect','--format','{{.Endpoints.docker.Host}}'],timeout=15)
        eq.require(ctx.returncode==0 and ctx.stdout.strip().startswith(b'unix://'),'BASELINE_DOCKER_CONTEXT')
        eq.require(o._docker(['info','--format','{{.ServerVersion}}'],timeout=15).returncode==0 and o._docker(['image','inspect',o.IMAGE],timeout=15).returncode==0,'BASELINE_DOCKER_IMAGE')
        self.token=secrets.token_hex(16);self.name='jw-baseline-'+self.token
        # Unique name permits cleanup even if docker output/transport fails.
        self.started=True
        r=o._docker(['run','--rm','--pull','never','-d','--name',self.name,'--label','jw.baseline.run='+self.token,'--network','none','--publish-all=false','--tmpfs','/var/lib/postgresql/data:rw,size=1073741824','--tmpfs','/var/run/postgresql:rw,size=16777216','-e','POSTGRES_HOST_AUTH_METHOD=trust',o.IMAGE],timeout=45)
        eq.require(r.returncode==0,'BASELINE_CONTAINER_START');self.container=r.stdout.decode('ascii','strict').strip()
        eq.require(eq.valid_hex(self.container),'BASELINE_CONTAINER_ID')
        for _ in range(60):
            if o._final_pg17_ready(self.container):break
            time.sleep(.5)
        else:raise eq.Blocked('BASELINE_PG17_NOT_READY')
        v=o._exec(self.container,['postgres','--version'],timeout=15)
        eq.require(v.returncode==0 and re.search(rb'PostgreSQL\)\s+17\.',v.stdout),'BASELINE_PG17_VERSION')
    def restore(self,p,i):
        if self.container is None:self.start()
        observed=[]
        def collect(c,db):
            eq.require(c==self.container and db=='jw_p1_offline_'+str(i) and not observed,'BASELINE_CALLBACK_TARGET')
            observed.append(cat.probe(self.offline._exec,c,db))
        r=self.offline._restore_one(self.container,p,i,catalog_probe=collect)
        eq.require(len(observed)==1,'BASELINE_CALLBACK_MISSING');return r,observed[0]
    def cleanup(self):
        if not self.started:return 'PASS'
        # Never remove by an unverified container ID; uniquely generated name only.
        try:
            probe=self.offline._docker(['inspect','--format','{{.Id}} {{index .Config.Labels "jw.baseline.run"}}',self.name],timeout=15)
            parts=probe.stdout.decode('ascii','strict').strip().split()
            if probe.returncode or len(parts)!=2 or not eq.valid_hex(parts[0]) or parts[1]!=self.token or (self.container is not None and eq.valid_hex(self.container) and parts[0]!=self.container):return 'BLOCKED'
            r=self.offline._docker(['rm','-f',parts[0]],timeout=30)
        except Exception:return 'BLOCKED'
        return 'PASS' if r.returncode==0 else 'BLOCKED'


def write_candidate(path,raw):
    # Output directory is existing 0700 owner-private; no overwrite or symlink.
    parent=path.parent; st=parent.lstat()
    eq.require(stat.S_ISDIR(st.st_mode) and st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o700,'BASELINE_OUTPUT_DIR')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    eq.require(private_read(path)==raw,'BASELINE_OUTPUT_READBACK')
    fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for field in ('source','receipt','output'):p.add_argument('--'+field,type=Path,required=True)
    for field in ('source-pin','receipt-pin','old-vault','new-vault','old-scope','new-scope'):p.add_argument('--'+field,required=True)
    for field in ('old-key-fd','new-key-fd'):p.add_argument('--'+field,type=int,required=True)
    args=p.parse_args(argv)
    try:
        os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE,(0,0));sanitize_environment()
        old_raw=private_read(args.source);receipt_raw=private_read(args.receipt)
        source=bridge.parse_source(old_raw,pin=args.source_pin,vault=args.old_vault,scope=args.old_scope)
        # Exact mapping pin is supplied separately; provider bytes are independently
        # checked again in bridge.build, not trusted merely from this receipt.
        d=bridge.parse_pinned(receipt_raw,args.receipt_pin);eq.require(type(d) is dict and type(d.get('archives')) is list,'BASELINE_RECEIPT')
        pairs={r['blob_sha1']:r['cipher_sha256'] for r in d['archives']}
        bridge.parse_receipt(receipt_raw,pin=args.receipt_pin,source=source,new_scope=args.new_scope,new_provider=pairs)
        meta=api(REPO);eq.require(meta.get('private') is True and meta.get('archived') is False,'BASELINE_VAULT_PRIVATE')
        ref=api(REPO+'/git/ref/heads/main');eq.require(ref.get('object',{}).get('sha')==args.new_vault,'BASELINE_VAULT_HEAD')
        ot,nt=tree(args.old_vault),tree(args.new_vault)
        k1,k2=keys_from_pipes(args.old_key_fd,args.new_key_fd)
        from scripts import p1_owner_offline_restore_v223 as offline
        adapter=RestoreAdapter(offline)
        raw,r=bridge.build(source_raw=old_raw,source_pin=args.source_pin,old_vault=args.old_vault,old_scope=args.old_scope,receipt_raw=receipt_raw,receipt_pin=args.receipt_pin,new_vault=args.new_vault,new_scope=args.new_scope,old_tree=ot,new_tree=nt,new_provider=pairs,old_key=k1,new_key=k2,fetch_old=fetch,fetch_new=fetch,restore_old=adapter.restore,cleanup=adapter.cleanup)
        k1=k2=None
        ref=api(REPO+'/git/ref/heads/main');eq.require(ref.get('object',{}).get('sha')==args.new_vault,'BASELINE_VAULT_HEAD_CHANGED')
        write_candidate(args.output,raw);print(json.dumps(r,sort_keys=True,separators=(',',':')));return 0
    except (Exception,KeyboardInterrupt) as e:
        code=str(e) if isinstance(e,eq.Blocked) and re.fullmatch('[A-Z_]{3,100}',str(e)) else 'BASELINE_FAIL_CLOSED'
        print(json.dumps({'blocker':code,'overall':'BLOCKED','reference_approval':'NOT_APPROVED'}));return 1

if __name__=='__main__':sys.exit(main())
