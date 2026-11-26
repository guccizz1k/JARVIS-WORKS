"""Local candidate: independent archived-state comparison, no I/O or secrets.

The approved reference is a historical, per-ciphertext normalized restore
baseline, not the current source DB.  A matching result is deliberately not an
ACL/owner or independent-custody acceptance. Existing restore uses --no-acl
and --no-owner, and the existing row digest is not collision-proof.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import re
from dataclasses import dataclass

FORMAT = 'JW-PG17-NORMALIZED-RESTORE-REFERENCE-V1'
ALGORITHM = 'JW-P1-ROW-MD5-SUM-C-SORTED-V1'
COUNT = 11
TABLES = 65
MAX_ROWS = 5_000_000
MAX_JSON = 32_768
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
GIT = re.compile(r'[0-9a-f]{40}\Z', re.ASCII)
FIELDS = frozenset(('cipher_sha256','git_blob_sha1','table_count','row_count',
                    'constraint_sha256','row_manifest_c_sha256','table_names_c_sha256',
                    'empty_table_names_c_sha256','populated_tables'))
ROOT_FIELDS = frozenset(('format','algorithm','vault_commit_sha1','archives'))

class Blocked(ValueError):
    pass

def require(ok, code):
    if not ok:
        raise Blocked(code)

def valid_hex(v, pattern=HEX):
    return type(v) is str and pattern.fullmatch(v) is not None

def no_duplicates(pairs):
    result = {}
    for k,v in pairs:
        require(k not in result,'REFERENCE_DUPLICATE_JSON_KEY')
        result[k] = v
    return result

def reject_constant(_):
    raise Blocked('REFERENCE_NONFINITE_JSON')

def canonical(doc):
    return json.dumps(doc,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')

def owner_scope(blob_ids):
    return hashlib.sha256(('JW-WORM-OWNER-SCOPE-V1\n'+'\n'.join(sorted(blob_ids))+'\n').encode('ascii')).hexdigest()

@dataclass(frozen=True)
class Archive:
    cipher_sha256: str
    git_blob_sha1: str
    table_count: int
    row_count: int
    constraint_sha256: str
    row_manifest_c_sha256: str
    table_names_c_sha256: str
    empty_table_names_c_sha256: str
    populated_tables: int

    @classmethod
    def parse(cls, row):
        require(type(row) is dict and set(row)==FIELDS,'REFERENCE_ARCHIVE_FIELDS')
        for name in ('cipher_sha256','constraint_sha256','row_manifest_c_sha256',
                     'table_names_c_sha256','empty_table_names_c_sha256'):
            require(valid_hex(row[name]),'REFERENCE_DIGEST_INVALID')
        require(valid_hex(row['git_blob_sha1'],GIT),'REFERENCE_BLOB_INVALID')
        require(type(row['table_count']) is int and row['table_count']==TABLES,'REFERENCE_TABLE_COUNT')
        require(type(row['row_count']) is int and 0<=row['row_count']<=MAX_ROWS,'REFERENCE_ROW_COUNT')
        require(type(row['populated_tables']) is int and 0<=row['populated_tables']<=min(TABLES,row['row_count']),'REFERENCE_POPULATED_COUNT')
        require((row['row_count']==0)==(row['populated_tables']==0),'REFERENCE_POPULATED_COUNT')
        return cls(**row)

def load_reference(raw, *, expected_reference_sha256, expected_vault, expected_scope, provider_pairs):
    """Require caller-supplied *independently approved* reference hash and scope.

    Hash pin verifies bytes, not signer identity. Do not compute the pin from the
    untrusted reference in the same execution and call that independent approval.
    """
    require(type(raw) is bytes and 0<len(raw)<=MAX_JSON,'REFERENCE_SIZE')
    require(valid_hex(expected_reference_sha256),'REFERENCE_APPROVAL_PIN_REQUIRED')
    require(valid_hex(expected_vault,GIT),'REFERENCE_VAULT_PIN_REQUIRED')
    require(valid_hex(expected_scope),'REFERENCE_OWNER_SCOPE_REQUIRED')
    require(hmac.compare_digest(hashlib.sha256(raw).hexdigest(),expected_reference_sha256),'REFERENCE_PIN_MISMATCH')
    try:
        doc=json.loads(raw.decode('ascii'),object_pairs_hook=no_duplicates,parse_constant=reject_constant)
    except (UnicodeError,json.JSONDecodeError,RecursionError,ValueError) as e:
        if isinstance(e,Blocked): raise
        raise Blocked('REFERENCE_JSON_INVALID') from None
    require(type(doc) is dict and set(doc)==ROOT_FIELDS,'REFERENCE_ROOT_FIELDS')
    require(doc['format']==FORMAT and doc['algorithm']==ALGORITHM,'REFERENCE_ALGORITHM_MISMATCH')
    require(doc['vault_commit_sha1']==expected_vault,'REFERENCE_VAULT_MISMATCH')
    require(type(doc['archives']) is list and len(doc['archives'])==COUNT,'REFERENCE_ARCHIVE_COUNT')
    rows=tuple(Archive.parse(row) for row in doc['archives'])
    require(len({r.git_blob_sha1 for r in rows})==COUNT and len({r.cipher_sha256 for r in rows})==COUNT,'REFERENCE_DUPLICATE_ARCHIVE')
    require(hmac.compare_digest(owner_scope(r.git_blob_sha1 for r in rows),expected_scope),'REFERENCE_SCOPE_MISMATCH')
    require(type(provider_pairs) in (list,tuple) and len(provider_pairs)==COUNT,'PROVIDER_ARCHIVE_COUNT')
    require(all(type(p) in (list,tuple) and len(p)==2 and valid_hex(p[0],GIT) and valid_hex(p[1]) for p in provider_pairs),'PROVIDER_PAIR_INVALID')
    require({(r.git_blob_sha1,r.cipher_sha256) for r in rows}=={tuple(p) for p in provider_pairs},'REFERENCE_PROVIDER_MISMATCH')
    return rows

class Equivalence:
    """One-use per-archive comparison; any failure poisons the whole run."""
    def __init__(self, rows):
        rows=tuple(rows)
        require(len(rows)==COUNT and all(type(r) is Archive for r in rows),'REFERENCE_NOT_VALIDATED')
        require(len({r.git_blob_sha1 for r in rows})==COUNT and len({r.cipher_sha256 for r in rows})==COUNT,'REFERENCE_DUPLICATE_ARCHIVE')
        for r in rows: Archive.parse(vars(r))
        self._rows={r.git_blob_sha1:r for r in rows}
        self._done=set()
        self._failed=False

    def compare(self, blob, cipher_sha, restored):
        """Consume actual `_restore_one()` tuple, never synthetic status alone."""
        try:
            require(not self._failed,'RUN_ALREADY_FAILED')
            require(valid_hex(blob,GIT) and blob in self._rows and blob not in self._done,'ARCHIVE_UNKNOWN_OR_REPLAYED')
            r=self._rows[blob]
            require(valid_hex(cipher_sha) and hmac.compare_digest(cipher_sha,r.cipher_sha256),'ARCHIVE_CIPHERTEXT_MISMATCH')
            require(type(restored) in (tuple,list) and len(restored)==8,'RESTORE_RESULT_SHAPE')
            status,tables,_,legacy,rows,constraint,_,metadata=restored
            require(status=='LOCAL_DISPOSABLE_RESTORED','RESTORE_STATUS_FAILED')
            require(type(tables) is int and tables==r.table_count,'TABLE_COUNT_MISMATCH')
            require(type(rows) is int and rows==r.row_count,'ROW_COUNT_MISMATCH')
            require(valid_hex(legacy),'LEGACY_ROW_MANIFEST_INVALID')
            require(type(metadata) in (list,tuple) and len(metadata)==9,'RESTORE_METADATA_MISSING')
            require(type(metadata[2]) is int and metadata[2]==r.populated_tables,'POPULATED_TABLES_MISMATCH')
            for actual,expected,code in ((constraint,r.constraint_sha256,'CONSTRAINT_MISMATCH'),
                    (metadata[5],r.table_names_c_sha256,'TABLE_NAMES_MISMATCH'),
                    (metadata[6],r.empty_table_names_c_sha256,'EMPTY_TABLE_NAMES_MISMATCH'),
                    (metadata[7],r.row_manifest_c_sha256,'ROW_MANIFEST_MISMATCH')):
                require(valid_hex(actual) and hmac.compare_digest(actual,expected),code)
            self._done.add(blob)
        except BaseException:
            self._failed=True
            raise

    def receipt(self, *, cleanup):
        complete=not self._failed and len(self._done)==COUNT and cleanup=='PASS'
        return {'normalized_archive_comparison':'PASS_11_ARCHIVE_CHECKPOINTS' if complete else 'BLOCKED',
                'matched_archives':len(self._done),
                'cleanup_pass':cleanup=='PASS',
                'row_digest_collision_proof':False,
                'full_schema_equivalence':'NOT_RUN',
                'rls_policy_equivalence':'NOT_RUN',
                'original_owner_acl_equivalence':'NOT_RUN_RESTORE_STRIPS_OWNER_ACL',
                'independent_key_custody':'NOT_ATTESTED',
                'overall':'BLOCKED'}

def read_reference_pipe(env, *, timeout=10.0):
    import os
    import select
    import stat
    import time
    try:
        fd=int(env.get('JW_PG_RESTORE_REFERENCE_FD',''))
        other=[int(env.get(n,'')) for n in ('JW_PG_CLEANROOM_KEY_FD','JW_PG_CLEANROOM_MANIFEST_FD')]
        require(3<=fd<=1048576 and fd not in other,'REFERENCE_PIPE_ALIAS_OR_INVALID')
        st=os.fstat(fd)
        require(stat.S_ISFIFO(st.st_mode),'REFERENCE_NOT_PIPE')
        for other_fd in other:
            ost=os.fstat(other_fd)
            require((st.st_dev,st.st_ino)!=(ost.st_dev,ost.st_ino),'REFERENCE_PIPE_ALIAS_OR_INVALID')
        data=bytearray(); deadline=time.monotonic()+timeout
        while True:
            remain=deadline-time.monotonic()
            require(remain>0 and bool(select.select([fd],[],[],remain)[0]),'REFERENCE_PIPE_TIMEOUT')
            chunk=os.read(fd, min(8192,MAX_JSON+1-len(data)))
            if not chunk:break
            data.extend(chunk)
            require(len(data)<=MAX_JSON,'REFERENCE_SIZE')
        require(bool(data),'REFERENCE_SIZE')
        return bytes(data)
    except (OSError,TypeError,ValueError) as exc:
        if isinstance(exc,Blocked):raise
        raise Blocked('REFERENCE_PIPE_INVALID') from None
