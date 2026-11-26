"""Owner-side archived-state reference builder; no DB source, network or disk I/O.

Only old archive restores may supply baseline observations. Both ciphertexts
must authenticate and decrypt to the same PG custom archive. Never give old
keys to the independent recovery site. Output is an UNAPPROVED candidate for
V4, not a backup-time signature or evidence of ACL/owner equivalence.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import struct
from scripts import jw_independent_equivalence_v223 as eq
from scripts import jw_independent_catalog_v223 as cat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

MAX_CIPHER = 32 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
MAX_PLAIN = 32 * 1024 * 1024
MAX_CHUNK = 1 << 20
MAGIC = b'JWPGBK2\n'
LEGACY = b'JWPGBK1\n'


def sha(raw): return hashlib.sha256(raw).hexdigest()
def git_blob(raw): return hashlib.sha1(b'blob '+str(len(raw)).encode('ascii')+b'\0'+raw).hexdigest()
def req(ok, code): eq.require(ok, code)


def parse_pinned(raw, pin):
    req(type(raw) is bytes and 0 < len(raw) <= eq.MAX_JSON, 'BRIDGE_DOCUMENT_SIZE')
    req(eq.valid_hex(pin) and hmac.compare_digest(sha(raw), pin), 'BRIDGE_DOCUMENT_PIN')
    try:
        return json.loads(raw.decode('ascii'), object_pairs_hook=eq.no_duplicates, parse_constant=eq.reject_constant)
    except eq.Blocked: raise
    except (ValueError, UnicodeError, RecursionError): raise eq.Blocked('BRIDGE_DOCUMENT_JSON') from None


def parse_source(raw, *, pin, vault, scope):
    d=parse_pinned(raw,pin)
    req(eq.valid_hex(vault,eq.GIT) and eq.valid_hex(scope),'BRIDGE_SOURCE_SCOPE')
    req(type(d) is dict and set(d)=={'vault_commit_sha1','archives'} and d['vault_commit_sha1']==vault,'BRIDGE_SOURCE_VAULT')
    rows=d['archives']; req(type(rows) is list and len(rows)==eq.COUNT,'BRIDGE_SOURCE_COUNT')
    out={}
    for r in rows:
        req(type(r) is dict and set(r)=={'blob_sha1','cipher_sha256'},'BRIDGE_SOURCE_ROW')
        b,s=r['blob_sha1'],r['cipher_sha256']
        req(eq.valid_hex(b,eq.GIT) and eq.valid_hex(s) and b not in out,'BRIDGE_SOURCE_ID')
        out[b]=s
    req(len(set(out.values()))==eq.COUNT and hmac.compare_digest(eq.owner_scope(out),scope),'BRIDGE_SOURCE_SCOPE')
    return out


def parse_receipt(raw, *, pin, source, new_scope, new_provider):
    d=parse_pinned(raw,pin)
    fields={'stage','verified','activated','remote_writes','archives','new_scope_sha256'}
    req(type(d) is dict and set(d)==fields,'BRIDGE_RECEIPT_FIELDS')
    req(d['stage']=='complete' and type(d['verified']) is int and d['verified']==eq.COUNT and d['activated'] is False and d['remote_writes'] is False,'BRIDGE_RECEIPT_STATE')
    req(eq.valid_hex(new_scope) and d['new_scope_sha256']==new_scope,'BRIDGE_NEW_SCOPE')
    rows=d['archives']; req(type(rows) is list and len(rows)==eq.COUNT,'BRIDGE_MAPPING_COUNT')
    out={}; seen=set(); digests=set()
    for r in rows:
        req(type(r) is dict and set(r)=={'source_blob_sha1','blob_sha1','cipher_sha256'},'BRIDGE_MAPPING_FIELDS')
        old,new,s=r['source_blob_sha1'],r['blob_sha1'],r['cipher_sha256']
        req(eq.valid_hex(old,eq.GIT) and old in source and old not in out,'BRIDGE_OLD_ID')
        req(eq.valid_hex(new,eq.GIT) and new not in seen and new not in source,'BRIDGE_NEW_ID')
        req(eq.valid_hex(s) and s not in digests and s not in source.values(),'BRIDGE_NEW_DIGEST')
        out[old]=(new,s); seen.add(new); digests.add(s)
    req(set(out)==set(source) and hmac.compare_digest(eq.owner_scope(seen),new_scope),'BRIDGE_MAPPING_SCOPE')
    req(type(new_provider) is dict and new_provider=={b:s for b,s in out.values()},'BRIDGE_PROVIDER_SET')
    return out


def check_cipher(raw, blob, digest):
    req(type(raw) is bytes and 24<len(raw)<=MAX_CIPHER,'BRIDGE_CIPHER_SIZE')
    req(hmac.compare_digest(git_blob(raw),blob) and hmac.compare_digest(sha(raw),digest),'BRIDGE_CIPHER_HASH')
    return raw


def decrypt(raw,key):
    req(type(key) is bytes and len(key)==32,'BRIDGE_KEY_FORMAT')
    m=raw[:8]; req(m in (MAGIC,LEGACY),'BRIDGE_HEADER')
    n=8 if m==MAGIC else 4; prefix=raw[8:8+n]; pos=8+n; i=0; plain=bytearray(); aes=AESGCM(key)
    try:
        while pos<len(raw):
            req(i < (2**32 if n==8 else 2**64) and len(raw)-pos>=4,'BRIDGE_RECORD')
            size=struct.unpack_from('>I',raw,pos)[0]; pos+=4
            req(16<=size<=MAX_CHUNK+16 and pos+size<=len(raw),'BRIDGE_RECORD')
            end=pos+size
            nonce=prefix+struct.pack('>I' if n==8 else '>Q',i)
            try: part=aes.decrypt(nonce,raw[pos:end],m+struct.pack('>QB',i,int(end==len(raw))))
            except InvalidTag: raise eq.Blocked('BRIDGE_AEAD_FAILED') from None
            req(len(plain)+len(part)<=MAX_PLAIN,'BRIDGE_PLAIN_SIZE'); plain.extend(part); pos=end; i+=1
        req(i>0 and plain.startswith(b'PGDMP'),'BRIDGE_NOT_PGDMP')
        return plain
    except BaseException:
        plain[:] = b'\0'*len(plain); plain.clear(); raise


def wipe(p):
    if p is not None: p[:] = b'\0'*len(p); p.clear()


def checkpoint(restored, observed, blob, cipher):
    req(type(restored) in (tuple,list) and len(restored)==8,'BRIDGE_RESTORE_SHAPE')
    status,tables,_,legacy,rows,constraint,_,metadata=restored
    req(status=='LOCAL_DISPOSABLE_RESTORED' and eq.valid_hex(legacy),'BRIDGE_RESTORE_STATUS')
    req(type(metadata) in (tuple,list) and len(metadata)==9,'BRIDGE_RESTORE_METADATA')
    row={'git_blob_sha1':blob,'cipher_sha256':cipher,'table_count':tables,'row_count':rows,
         'constraint_sha256':constraint,'row_manifest_c_sha256':metadata[7],
         'table_names_c_sha256':metadata[5],'empty_table_names_c_sha256':metadata[6],
         'populated_tables':metadata[2]}
    eq.Archive.parse(row)
    req(type(observed) is dict and all(type(v) in (list,tuple) for v in observed.values()),'BRIDGE_CATALOG_SHAPE')
    sections={k:list(v) for k,v in observed.items()}; cat.parse_catalog(sections)
    return row,{'git_blob_sha1':blob,'cipher_sha256':cipher,'sections':sections}


def build(*, source_raw, source_pin, old_vault, old_scope, receipt_raw, receipt_pin,
          new_vault, new_scope, old_tree, new_tree, new_provider, old_key, new_key,
          fetch_old, fetch_new, restore_old, cleanup):
    """Trusted owner adapters only: fetch pinned bytes, restore OLD plaintext into
    isolated PG17, and return actual cleanup status. No stdout/log side effects.
    The caller must use real isolation/cleanup; callback tests are synthetic.
    """
    req(eq.valid_hex(new_vault,eq.GIT) and new_vault!=old_vault,'BRIDGE_NEW_VAULT')
    req(type(old_key) is bytes and type(new_key) is bytes and len(old_key)==len(new_key)==32 and not hmac.compare_digest(old_key,new_key),'BRIDGE_DISTINCT_KEYS')
    source=parse_source(source_raw,pin=source_pin,vault=old_vault,scope=old_scope)
    mapping=parse_receipt(receipt_raw,pin=receipt_pin,source=source,new_scope=new_scope,new_provider=new_provider)
    req(type(old_tree) is dict and type(new_tree) is dict and len(old_tree)<=80 and len(new_tree)<=80,'BRIDGE_TREE_SHAPE')
    req(all(type(k) is str and eq.valid_hex(v,eq.GIT) for t in (old_tree,new_tree) for k,v in t.items()),'BRIDGE_TREE_ENTRY')
    req(set(source)<=set(old_tree.values()) and all(new_tree.get(k)==v for k,v in old_tree.items()),'BRIDGE_ORIGINAL_TREE_CHANGED')
    extra={k:v for k,v in new_tree.items() if k not in old_tree}
    req(len(extra)==eq.COUNT and set(extra.values())==set(new_provider) and not (set(old_tree.values())&set(extra.values())),'BRIDGE_NEW_TREE_SCOPE')
    req(all(k.endswith('/'+v+'.jwpgbk') for k,v in extra.items()),'BRIDGE_NEW_TREE_PATH')
    data=[]; catalogs=[]; total=0; cleanup_status=None
    try:
        for i,(old,old_sha) in enumerate(sorted(source.items())):
            new,new_sha=mapping[old]
            a=check_cipher(fetch_old(old,old_sha),old,old_sha)
            b=check_cipher(fetch_new(new,new_sha),new,new_sha)
            total+=len(a)+len(b); req(total<=MAX_TOTAL,'BRIDGE_TOTAL_BUDGET')
            p=q=None
            try:
                p=decrypt(a,old_key); q=decrypt(b,new_key)
                req(hmac.compare_digest(p,q),'BRIDGE_PLAINTEXT_MISMATCH')
                wipe(q); q=None
                # New ciphertext is never the source of the historical baseline.
                restored,observed=restore_old(p,i)
                row,catrow=checkpoint(restored,observed,new,new_sha)
                data.append(row); catalogs.append(catrow)
            finally: wipe(q); wipe(p)
    finally:
        cleanup_status=cleanup()
    req(cleanup_status=='PASS','BRIDGE_CLEANUP_FAILED')
    req(len(data)==eq.COUNT,'BRIDGE_INCOMPLETE')
    doc={'format':cat.FORMAT,'algorithm':cat.ALGORITHM,
         'data_reference':{'format':eq.FORMAT,'algorithm':eq.ALGORITHM,'vault_commit_sha1':new_vault,'archives':data},
         'catalog_archives':catalogs}
    raw=eq.canonical(doc); pin=sha(raw)
    # Self-validation is NOT independent approval. Owner must approve pin separately.
    cat.load_reference(raw,expected_reference_sha256=pin,expected_vault=new_vault,
                       expected_scope=new_scope,provider_pairs=list(new_provider.items()))
    return raw, {'candidate_sha256':pin,'old_archives_restored':len(data),'plaintext_pairs_equal':len(data),
                 'cleanup':'PASS','reference_approval':'NOT_APPROVED','historical_source_signature':'NOT_ATTESTED',
                 'original_owner_acl_equivalence':'NOT_ATTESTED','independent_recovery':'NOT_RUN','overall':'BLOCKED'}
