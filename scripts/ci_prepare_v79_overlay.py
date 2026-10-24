"""Reconstruct the V7.9 *test-only* overlay from reviewed, pinned Git blobs.

Why: historical tests/test_installer_v79.py expects ROOT.parent/overlay, but
the independently archived overlay was not committed to the V8.9 Git tree.
This CI fixture is an equivalent installer-behavior fixture assembled from
reviewed V8.9 tracked files; it is NOT the byte-identical original archived
overlay (one CLI script evolved). Never report archive-fixture identity.

Fail closed on unexpected source SHA, existing overlay, or path traversal.
Never execute or install the overlay into the app.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil

BASE = {
    "app/main.py": "e4584787c8ee97a417656e62297507caa7d618f4146398342dabc23c8a6ab25f",
    "app/pg_rls_full_review_v78.py": "7b58e3b3cfce6eb57138e7a979668d11a4237ea6e53303ac69a4f432c535fdc7",
    "scripts/release_audit_v78.py": "2c76ec5fd2b3aa66acdcf15279f6232c1be4b5de5f09e7c0a566bded95ca6082",
    "pytest.ini": "3e96466ab8e521eaceb9521fec97b47d456b002fc8000aabf13c4f44fccbd1e6",
    "app/deployment_safety_v78.py": "fd80b7c5289f0a903423b75b0ab4996ec11ee569480f5a5fb9c7d2fa76735570",
}
PAYLOAD = {
    "app/pg_rls_gate_v79.py": "92c885644da98420f3846e1d42e8b2a93034b0c769d79255496441858d2299b6",
    "scripts/check_pg_rls_v79.py": "e824c477413cfd92d08e7b3163efe49ca54d2a8773d9a4593b5756d58c725180",
    "tests/browser_webkit_v79.py": "bfec1d45c5b6c544bbea74830b7bd69d9e5bf131e158341db89283f0a29bb4fa",
    "tests/test_pg_rls_gate_v79.py": "4a8f3879c1e862d1e9bfcb346ad536d0e535e4cf571e0bcd053d0ca8fc5fe589",
}

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main() -> None:
    root = Path(__file__).resolve().parents[1]
    if not (root / ".git").is_dir():
        raise SystemExit("BLOCKED: tracked Git checkout required")
    overlay = root.parent / "overlay"
    if overlay.exists() or overlay.is_symlink():
        raise SystemExit("BLOCKED: parent overlay exists; refusing to replace")
    for name, expected in {**BASE, **PAYLOAD}.items():
        source = root / name
        if not source.is_file() or source.is_symlink() or digest(source) != expected:
            raise SystemExit(f"BLOCKED: pinned source digest mismatch: {name}")
    overlay.mkdir(mode=0o700)
    (overlay / "payload").mkdir()
    for name in PAYLOAD:
        dest = overlay / "payload" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / name, dest)
    for filename, manifest in (("BASE_SHA256.json", BASE), ("PAYLOAD_SHA256.json", PAYLOAD)):
        (overlay / filename).write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    for name, expected in PAYLOAD.items():
        if digest(overlay / "payload" / name) != expected:
            raise SystemExit(f"BLOCKED: copied fixture failed hash validation: {name}")
    print("PASS: test-only overlay reproduced from nine pinned reviewed Git blobs")
    print("NOTE: original archived V7.9 overlay has a different check_pg_rls_v79.py payload")

if __name__ == "__main__":
    main()
