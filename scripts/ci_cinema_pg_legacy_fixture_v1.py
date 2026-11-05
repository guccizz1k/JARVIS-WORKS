#!/usr/bin/env python3
"""Reconstruct a pinned V7.9 synthetic installer fixture for *CI tests only*.

Historical V7.0/V7.8 were not equivalent to modern app/main.py. Their old
installer tests need authentic immutable sources, not line subtraction from
modern main. This script does NOT edit source, test assertions, existing
files, secrets, schemas, or any deployment. No network and no runtime DB.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PARENT = ROOT.parent
ARCHIVED_MAIN = ROOT / "v78_addon/payload/app/main.py"
CURRENT_MAIN_SHA = "91deef5315aca3edfe5b24145f5a7a79b7cc9de038eac27b91c7cf95cb95e345"
HISTORICAL_MAIN_SHA = "e4584787c8ee97a417656e62297507caa7d618f4146398342dabc23c8a6ab25f"
EXPECTED_BASE_COUNT = 5
EXPECTED_PAYLOAD_COUNT = 4


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def manifest_variables(source: Path) -> tuple[dict[str, str], dict[str, str]]:
    """Parse constants, never execute or import arbitrary historic bootstrap."""
    assignments = {}
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for lhs in node.targets:
                if isinstance(lhs, ast.Name) and lhs.id in ("base", "payload"):
                    assignments[lhs.id] = ast.literal_eval(node.value)
    base, payload = assignments["base"], assignments["payload"]
    if not isinstance(base, dict) or len(base) != EXPECTED_BASE_COUNT:
        raise ValueError("Unexpected historic base manifest")
    if not isinstance(payload, dict) or len(payload) != EXPECTED_PAYLOAD_COUNT:
        raise ValueError("Unexpected historic payload manifest")
    for mapping in (base, payload):
        for path, sha in mapping.items():
            if (not isinstance(path, str) or not path.startswith(("app/", "scripts/", "tests/", "pytest.ini"))
                    or ".." in Path(path).parts or Path(path).is_absolute()
                    or not isinstance(sha, str) or len(sha) != 64
                    or any(c not in "0123456789abcdef" for c in sha)):
                raise ValueError("Untrusted historical manifest entry")
    return base, payload


def build() -> dict:
    if os.environ.get("CI") != "true":
        raise RuntimeError("This fixture generator is restricted to ephemeral GitHub Actions CI")
    if os.environ.get("JW_ENV", "").lower() in ("production", "prod"):
        raise RuntimeError("Production fixture creation forbidden")
    if ROOT.is_symlink() or ARCHIVED_MAIN.is_symlink():
        raise RuntimeError("Untrusted source symlink")
    if digest((ROOT / "app/main.py").read_bytes()) != CURRENT_MAIN_SHA:
        raise RuntimeError("Current CINEMA main.py changed")
    if digest(ARCHIVED_MAIN.read_bytes()) != HISTORICAL_MAIN_SHA:
        raise RuntimeError("Historical V7.8 main.py not independently pinned")

    base, payload = manifest_variables(ROOT / "scripts/ci_rebuild_v79_overlay.py")
    if base.get("app/main.py") != HISTORICAL_MAIN_SHA:
        raise RuntimeError("Original V7.9 installer baseline differs")
    verified_base = {}
    for name, want in base.items():
        path = ARCHIVED_MAIN if name == "app/main.py" else ROOT / name
        if path.is_symlink():
            raise RuntimeError("Base fixture has symlink: " + name)
        have = digest(path.read_bytes())
        if have != want:
            raise RuntimeError("Historical baseline hash mismatch: " + name)
        verified_base[name] = have

    # Reconstruct using the two exact transformations already documented in
    # the historic scripts/ci_rebuild_v79_overlay.py, never weaken checksums.
    verified_payload = {}
    prepared = {}
    for name, want in payload.items():
        path = ROOT / name
        if path.is_symlink():
            raise RuntimeError("Payload fixture has symlink: " + name)
        data = path.read_bytes()
        if name == "scripts/check_pg_rls_v79.py":
            data = data.replace(
                b"c.oid FROM pg_class c", b"c.oid::integer FROM pg_class c"
            ).replace(
                b"""('jw_app',f'public."{name}"',grant)""",
                b"('jw_app',oid,grant)",
            )
        if digest(data) != want:
            raise RuntimeError("Untrusted V7.9 overlay payload: " + name)
        prepared[name] = data
        verified_payload[name] = want

    destination = PARENT / "jw_v79_overlay"
    if destination.exists() or destination.is_symlink():
        raise RuntimeError("Refusing to overwrite an existing overlay")
    with tempfile.TemporaryDirectory(prefix=".jw-v79-ci-", dir=PARENT) as tdir:
        tmp = Path(tdir)
        for name, data in prepared.items():
            target = tmp / "payload" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        (tmp / "BASE_SHA256.json").write_text(
            json.dumps(base, indent=2) + "\n", encoding="utf-8"
        )
        (tmp / "PAYLOAD_SHA256.json").write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8"
        )
        if destination.exists() or destination.is_symlink():
            raise RuntimeError("Concurrent overlay detected")
        # Copytree into an adjacent new destination; files are synthetic only.
        shutil.copytree(tmp, destination, symlinks=False)

    for name, want in prepared.items():
        assert digest((destination / "payload" / name).read_bytes()) == payload[name]
    return {"status": "PASS", "overlay_files": len(prepared),
            "historical_baseline_sha256": verified_base,
            "payload_sha256": verified_payload,
            "current_main_protected": True, "fixture_only": True}


if __name__ == "__main__":
    print(json.dumps(build(), ensure_ascii=False, sort_keys=True))
