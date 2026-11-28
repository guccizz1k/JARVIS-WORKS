"""Exact-blob fix for Wave7 PR205. Never updates a remote or changes the input."""
import hashlib
from pathlib import Path
import sys

EXPECTED = '954cc9a12dd7db10db26cc183b7539af7fe86475'
GLOBAL = 'from scripts.naruv_native_write_review_ci import NativeWrite\n'
FIXTURE = "def pg():\n    # Existing bootstrap insists on a fresh, localhost PG17 CI service.\n"


def blob(raw):
    return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()


def transform(text):
    if text.count(GLOBAL) != 1 or text.count(FIXTURE) != 1:
        raise ValueError('WAVE7_COLLECTION_ANCHOR_MISMATCH')
    text = text.replace(GLOBAL, '', 1)
    text = text.replace(FIXTURE, FIXTURE+'    # Local import avoids pytest collecting the imported unittest.TestCase.\n    from scripts.naruv_native_write_review_ci import NativeWrite\n', 1)
    compile(text, 'test_integrated.py', 'exec')
    return text


def build(source, destination):
    raw = Path(source).read_bytes()
    if blob(raw) != EXPECTED:
        raise ValueError('WAVE7_TEST_SOURCE_BLOB_MISMATCH')
    corrected = transform(raw.decode('utf-8'))
    with Path(destination).open('x', encoding='utf-8', newline='') as f:
        f.write(corrected)

if __name__ == '__main__':
    build(*sys.argv[1:])
