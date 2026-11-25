"""Fail-closed source integrity for exact GitHub PR #61 review baseline.

This is NOT a third-party notarization and cannot authorize release by itself.
It prevents an isolated local mirror test run from silently claiming SHA equality.
"""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "scripts/review/v149_git_source_fidelity.json"
QUERY = ROOT / "scripts/review/v149_live_pg_role_negative_readonly.sql"


def _git_blob_sha1(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def test_protected_review_source_matches_pinned_remote_blobs():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["schema"] == "jw-review-verified-source-v149"
    assert manifest["source_head_sha"] == "bc77323c7b93fc004fa1f23ccfdc063db3355e14"
    protected = manifest["sha1_git_blob"]
    assert len(protected) == 9
    for name, expected in protected.items():
        path = ROOT / name
        assert path.resolve().is_relative_to(ROOT.resolve())
        assert re.fullmatch("[a-f0-9]{40}", expected)
        assert path.is_file(), f"Missing protected source: {name}"
        assert _git_blob_sha1(path.read_bytes()) == expected, (
            f"STALE_LOCAL_MIRROR: {name} is not the protected remote source; "
            "do not claim GitHub SHA-specific test success"
        )


def test_live_postgres_probe_readonly_rollback_and_fail_closed():
    sql = QUERY.read_text(encoding="utf-8")
    no_comments = re.sub(r"--[^\n]*", "", sql)
    assert "BEGIN READ ONLY;" in no_comments
    assert "SET LOCAL ROLE jw_app_dev;" in no_comments
    assert "ROLLBACK;" in no_comments
    assert "FAIL_V149_UNAUTHENTICATED_ROLE_ACCESS" in no_comments
    assert "PASS_V149_READONLY_NO_SESSION_ROLE_NEGATIVE_AND_CATALOG" in no_comments
    for forbidden in (
        "COMMIT;", "INSERT INTO ", "UPDATE jw_dev.", "DELETE FROM ", "DROP TABLE",
        "ALTER TABLE", "GRANT ", "REVOKE ", "TRUNCATE ", "CREATE ROLE",
    ):
        assert forbidden not in no_comments
