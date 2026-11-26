"""Local-only, non-activating re-encryption of the 11 approved PG archives.
No network or database calls. Plaintext only in memory, never written to disk.
Requires reviewed jw_key_escrow_v223.py alongside this program.
"""
import argparse, base64, hashlib, hmac, json, os, re, resource, secrets, stat, struct, sys
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import jw_key_escrow_v223 as escrow

MAGIC = b'JWPGBK2\n'
LEGACY = b'JWPGBK1\n'
MAX = 32 * 1024 * 1024
CHUNK = 1 << 20
PIN = '7b87c985452ee4d3a00049971380414ef436646516fa9d745ef878e267188147'
VAULT = '65d2d4b98badd8231d65bf8553cb434a4a5141f9'

def sha(raw): return hashlib.sha256(raw).hexdigest()
def git_id(raw): return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def require(ok, code):
    if not ok: raise ValueError(code)
def scope(ids): return sha(('JW-WORM-OWNER-SCOPE-V1\n'+'\n'.join(sorted(ids))+'\n').encode())
def manifest(doc, pin=PIN, vault=VAULT):
    require(isinstance(doc,dict) and doc.get('vault_commit_sha1')==vault, 'VAULT_PIN')
    rows=doc.get('archives'); require(isinstance(rows,list) and len(rows)==11, 'MANIFEST_COUNT')
    out={}
    for x in rows:
        require(isinstance(x,dict),'MANIFEST_ENTRY')
        i=x.get('blob_sha1',''); s=x.get('cipher_sha256','')
        require(isinstance(i,str) and re.fullmatch('[0-9a-f]{40}',i) and isinstance(s,str) and re.fullmatch('[0-9a-f]{64}',s) and i not in out,'MANIFEST_ENTRY')
        out[i]=s
    require(hmac.compare_digest(scope(out),pin),'SCOPE_PIN')
    return out

def private_read(path,limit=MAX):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        a=os.fstat(f.fileno()); require(stat.S_ISREG(a.st_mode) and stat.S_IMODE(a.st_mode)==0o600 and a.st_uid==os.getuid() and 0<a.st_size<=limit,'PRIVATE_FILE')
        raw=f.read(limit+1); b=os.fstat(f.fileno()); require(len(raw)==a.st_size and (a.st_ino,a.st_dev,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_ino,b.st_dev,b.st_size,b.st_mtime_ns,b.st_ctime_ns),'FILE_CHANGED')
        return raw

def scan(root, expected):
    escrow.private_dir(root); out={}; files=0
    for base,dirs,names in os.walk(root,followlinks=False):
        p=Path(base); require(len(p.relative_to(root).parts)<=2,'SOURCE_DEPTH'); escrow.private_dir(p)
        for d in dirs: escrow.private_dir(p/d)
        for name in names:
            if not name.endswith('.jwpgbk'): continue
            files+=1; require(files<=11,'SOURCE_COUNT')
            raw=private_read(p/name); i=git_id(raw)
            require(i in expected and i not in out and hmac.compare_digest(sha(raw),expected[i]),'SOURCE_HASH')
            out[i]=raw
    require(set(out)==set(expected),'SOURCE_COUNT'); return out

def nonce(prefix,i): return prefix+struct.pack('>I' if len(prefix)==8 else '>Q',i)
def aad(m,i,final): return m+struct.pack('>QB',i,int(final))
def decrypt(raw,key):
    m=raw[:8]; require(m in (MAGIC,LEGACY),'HEADER'); n=8 if m==MAGIC else 4
    prefix=raw[8:8+n]; pos=8+n; i=0; plain=bytearray(); aes=AESGCM(key)
    try:
        while pos<len(raw):
            require(len(raw)-pos>=4,'TRUNCATED'); length=struct.unpack('>I',raw[pos:pos+4])[0]; pos+=4
            require(16<=length<=CHUNK+16 and pos+length<=len(raw),'RECORD_SIZE')
            end=pos+length; plain.extend(aes.decrypt(nonce(prefix,i),raw[pos:end],aad(m,i,end==len(raw))))
            require(len(plain)<=MAX,'PLAIN_LIMIT'); pos=end; i+=1
        require(i>0 and plain.startswith(b'PGDMP'),'NOT_PG_CUSTOM_ARCHIVE'); return plain
    except BaseException:
        plain.clear(); raise

def encrypt(plain,key,prefix):
    require(len(prefix)==8 and 0<len(plain)<=MAX,'ENCRYPT_INPUT')
    aes=AESGCM(key); out=bytearray(MAGIC+prefix)
    for i,pos in enumerate(range(0,len(plain),CHUNK)):
        chunk=bytes(plain[pos:pos+CHUNK]); b=aes.encrypt(nonce(prefix,i),chunk,aad(MAGIC,i,pos+len(chunk)==len(plain)))
        out.extend(struct.pack('>I',len(b))); out.extend(b)
    require(len(out)<=MAX,'CIPHER_LIMIT'); return bytes(out)

def prepare(sources,old,new):
    require(len(old)==len(new)==32 and not hmac.compare_digest(old,new),'KEY_NOT_DISTINCT')
    require(len(sources)==11,'SOURCE_COUNT'); out={}; prefixes=set()
    for i,raw in sorted(sources.items()):
        p=decrypt(raw,old)
        try:
            prefix=secrets.token_bytes(8); require(prefix not in prefixes,'NONCE_COLLISION'); prefixes.add(prefix)
            cipher=encrypt(p,new,prefix); check=decrypt(cipher,new)
            try: require(hmac.compare_digest(p,check),'PLAINTEXT_MISMATCH')
            finally: check.clear()
            try: wrong=decrypt(cipher,old)
            except InvalidTag: pass
            else: wrong.clear(); raise ValueError('OLD_KEY_STILL_WORKS')
            out[i]=(cipher,sha(p))
        finally: p.clear()
    require(len({git_id(c) for c,_ in out.values()})==11,'OUTPUT_DUPLICATE'); return out

def write_new(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f: f.write(raw); f.flush(); os.fsync(f.fileno())

def publish_local(target,outputs,new):
    require(len(outputs)==11,'OUTPUT_COUNT'); target.mkdir(mode=0o700,exist_ok=False); escrow.private_dir(target)
    rows=[]
    for src,(raw,digest) in sorted(outputs.items()):
        i=git_id(raw); path=target/(i+'.jwpgbk'); write_new(path,raw)
        got=private_read(path); require(got==raw,'OUTPUT_READBACK')
        p=decrypt(got,new)
        try: require(hmac.compare_digest(sha(p),digest),'OUTPUT_AUTH')
        finally: p.clear()
        rows.append({'source_blob_sha1':src,'blob_sha1':i,'cipher_sha256':sha(raw)})
    receipt={'stage':'complete','verified':11,'activated':False,'remote_writes':False,'archives':rows,'new_scope_sha256':scope([r['blob_sha1'] for r in rows])}
    write_new(target/'receipt.json',(json.dumps(receipt,sort_keys=True)+'\n').encode()); fd=os.open(target,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); os.fsync(fd); os.close(fd)
    return receipt

def main():
    os.umask(0o077); resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    p=argparse.ArgumentParser(); p.add_argument('--manifest',required=True,type=Path); p.add_argument('--envelope-sha256',required=True); args=p.parse_args()
    home=Path.home(); target=home/'.jw-rekey-candidate-20261124'; require(not os.path.lexists(target),'OUTPUT_EXISTS')
    expected=manifest(json.loads(args.manifest.read_bytes())); sources=scan(home/'.local/share/jw-v223-restore/backups',expected)
    envelope=home/'.jw-key-escrow-20261124'/'candidate-key.jwescrow'; escrow.private_dir(envelope.parent); raw=escrow.read_private(envelope)
    require(re.fullmatch('[0-9a-f]{64}',args.envelope_sha256) and hmac.compare_digest(sha(raw),args.envelope_sha256),'ENVELOPE_PIN')
    old=base64.urlsafe_b64decode(os.environ['JW_PG_BACKUP_KEY']); require(len(old)==32,'OLD_KEY_FORMAT')
    new=escrow.unseal(raw,escrow.masked('Escrow passphrase: '))
    outputs=prepare(sources,old,new); receipt=publish_local(target,outputs,new)
    print('REKEY_LOCAL_CANDIDATE_PASS verified=11 activated=false remote_writes=false')
    print('NEW_SCOPE_SHA256='+receipt['new_scope_sha256']); print('RECEIPT_PATH='+str(target/'receipt.json'))

if __name__=='__main__':
    try: main()
    except (Exception,KeyboardInterrupt) as e:
        msg=str(e); safe=msg if type(e) is ValueError and re.fullmatch('[A-Z_]{3,80}',msg) else type(e).__name__
        print('BLOCKED: '+safe,file=sys.stderr); sys.exit(1)
