"""Exact original source guard for optional pre-drop catalog callback."""
import ast
import hashlib
from pathlib import Path
import sys
EXPECTED='79beb07dabbd59190a355dd6dba3bb9a44f6c79e'
TARGET=Path('scripts/p1_owner_offline_restore_v223.py')
ANCHORS=(
('schema_salt: str | None = None) -> tuple[str, int, str | None, str | None, int | None, str | None, tuple[int, str, str] | None, tuple[str, str, int, str, str] | None]:',
 'schema_salt: str | None = None, *, catalog_probe=None) -> tuple[str, int, str | None, str | None, int | None, str | None, tuple[int, str, str] | None, tuple[str, str, int, str, str] | None]:'),
('            schema_probe = _schema_delta_probe(container, db, schema_salt) if schema_salt else None\n            return "LOCAL_DISPOSABLE_RESTORED",',
 '            schema_probe = _schema_delta_probe(container, db, schema_salt) if schema_salt else None\n            if catalog_probe is not None:\n                catalog_probe(container, db)\n            return "LOCAL_DISPOSABLE_RESTORED",'))
def transform(text):
    for old,new in ANCHORS:
        if text.count(old)!=1: raise ValueError('OFFLINE_HOOK_ANCHOR_NOT_UNIQUE')
        text=text.replace(old,new,1)
    ast.parse(text); return text

def check(raw):
    if hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()!=EXPECTED:
        raise ValueError('OFFLINE_HOOK_SOURCE_BLOB_MISMATCH')
    return transform(raw.decode('utf-8'))

if __name__=='__main__':
    # Check only; no changes to any checkout. Review hook before applying.
    p=Path(sys.argv[1])/TARGET
    check(p.read_bytes()); print('OFFLINE_HOOK_PINNED_CHECK_PASS_NO_WRITES')
