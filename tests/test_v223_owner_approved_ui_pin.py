from pathlib import Path
import hashlib
import re

ROOT=Path(__file__).resolve().parents[1]
APPROVED=ROOT/'app'/'static'/'approved_v223_owner_original.html'
SHA256='953c1b00cead79173c0c7a9c40319344e510bec9f6a1f646f30e0a147356076d'
GIT_BLOB='a1712541b46167c21e9779d41bb198745df2ffc0'

def test_approved_ui_original_exact_bytes():
    raw=APPROVED.read_bytes()
    assert len(raw)==229028
    assert hashlib.sha256(raw).hexdigest()==SHA256
    assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==GIT_BLOB

def test_preserved_visual_and_local_only_boundary():
    html=APPROVED.read_text('utf8')
    assert '#d4ff3a' in html
    assert html.count('<script>')==1 and html.count('boot();')==1
    assert 'jw3.db' in html
    assert 'indexedDB' in html
    assert 'function registerCompany' in html
    assert 'function login' in html
    # Pin checks source, not server integration. This is a documented blocker.
    assert not re.search(r'fetch\s*\(', html)
