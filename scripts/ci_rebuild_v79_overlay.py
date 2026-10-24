"""Reconstruct a V7.9 installer fixture using ONLY Git-tracked V8.9 inputs.

The immutable V8.9 baseline is not altered; the generated overlay lives in the
parent of the checkout and is verified by pinned SHA-256 hashes.
"""
from pathlib import Path
import hashlib
import json

root = Path.cwd()
base = {
 "app/deployment_safety_v78.py":"fd80b7c5289f0a903423b75b0ab4996ec11ee569480f5a5fb9c7d2fa76735570",
 "app/main.py":"e4584787c8ee97a417656e62297507caa7d618f4146398342dabc23c8a6ab25f",
 "app/pg_rls_full_review_v78.py":"7b58e3b3cfce6eb57138e7a979668d11a4237ea6e53303ac69a4f432c535fdc7",
 "pytest.ini":"3e96466ab8e521eaceb9521fec97b47d456b002fc8000aabf13c4f44fccbd1e6",
 "scripts/release_audit_v78.py":"2c76ec5fd2b3aa66acdcf15279f6232c1be4b5de5f09e7c0a566bded95ca6082",
}
payload = {
 "app/pg_rls_gate_v79.py":"92c885644da98420f3846e1d42e8b2a93034b0c769d79255496441858d2299b6",
 "scripts/check_pg_rls_v79.py":"01057d510a23e16d3cf39da0b582e2075c7eb50c2a665b283a0f1994b04369ee",
 "tests/browser_webkit_v79.py":"bfec1d45c5b6c544bbea74830b7bd69d9e5bf131e158341db89283f0a29bb4fa",
 "tests/test_pg_rls_gate_v79.py":"4a8f3879c1e862d1e9bfcb346ad536d0e535e4cf571e0bcd053d0ca8fc5fe589",
}

def sha(data):
    return hashlib.sha256(data).hexdigest()

for name, expected in base.items():
    if sha((root / name).read_bytes()) != expected:
        raise RuntimeError("V8.9 baseline file changed: " + name)

fixture = root.parent / 'overlay'
fixture.mkdir(exist_ok=True)
for name, expected in payload.items():
    data = (root / name).read_bytes()
    if name == 'scripts/check_pg_rls_v79.py':
        data = data.replace(b'c.oid FROM pg_class c',b'c.oid::integer FROM pg_class c').replace(
            b"('jw_app',f'public.\\\"{name}\\\"',grant)", b"('jw_app',oid,grant)")
    if sha(data) != expected:
        raise RuntimeError("Untrusted overlay reconstruction: " + name)
    target = fixture / 'payload' / name
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_bytes(data)
(fixture/'BASE_SHA256.json').write_text(json.dumps(base,indent=2)+'\n')
(fixture/'PAYLOAD_SHA256.json').write_text(json.dumps(payload,indent=2)+'\n')
print("PASS: 5 baseline and 4 overlay SHA-256 verifications")
