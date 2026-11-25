"""Unit tests for the containment guard's pure classification logic.

No FastAPI/psycopg import: runs anywhere pytest runs.
"""
import importlib.util
import re
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "ci_cinema_pg_guard", Path(__file__).resolve().parents[1] / "scripts" / "ci_cinema_pg_guard.py")
guard = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(guard)


@pytest.mark.parametrize("path,status", [
    ("app/pg_cinema_trade_v1.py", "A"),
    ("app/pg_cinema_trade_v1.py", "?"),
    ("app/cinema_bridge_v3.js", "A"),
    ("tests/test_cinema_pg_engine.py", "A"),
    ("scripts/ci_cinema_pg_guard.py", "A"),
    ("scripts/review/cinema_pg_write_engine.sql", "A"),
    (".github/workflows/jw-cinema-pg-gates.yml", "A"),
    ("docs/review/cinema-pg-report.md", "A"),
    ("app/pg_review_integrated_v202.py", "M"),
    ("app/cinema_entry_v1.py", "M"),
])
def test_allowed(path, status):
    assert guard.classify_path(path, status)[0]


@pytest.mark.parametrize("path,status", [
    ("app/main.py", "M"),
    ("app/static/cinema/JARVIS_WORKS_CINEMA.html", "M"),
    ("app/static/anything.css", "A"),
    ("app/cinema_bridge_v1.js", "M"),
    ("app/cinema_bridge_v2.js", "M"),
    ("app/pg_messenger_bridge_v90.py", "M"),
    ("app/pg_quote_api_v92.py", "M"),
    ("app/pg_cinema_sub/dir.py", "A"),            # no subdirectories
    ("app/pg_cinema_x.py.bak", "A"),
    ("tests/test_pg_quote_api_v92.py", "M"),
    ("tests/test_cinema_pg_x.py", "D"),
    ("scripts/review/v170_dev_review_draft_schema.sql", "M"),
    ("db/review/ci_v92_quote_ephemeral.sql", "M"),
    (".github/workflows/jw-v92-quote.yml", "M"),
    ("requirements.txt", "M"),
    ("app/pg_review_integrated_v202.py", "D"),    # whitelisted existing: modify only
    ("app/cinema_entry_v1.py", "A"),
    ("docs/review/other.md", "A"),
])
def test_denied(path, status):
    assert not guard.classify_path(path, status)[0]


def test_skip_marker_regex_catches_common_forms():
    # Samples are assembled at runtime so this file itself never contains a
    # literal marker (the guard scans new test files for exactly those).
    mark = "pytest" + ".mark."
    samples = ("@" + mark + "skip", "@" + mark + "skipif(x)", "pytest" + ".skip('x')",
               "@" + mark + "xfail", "self." + "skip" + "Test('x')", "@unittest" + ".skip('x')")
    for line in samples:
        assert guard.SKIP_MARKERS.search(line), line
    assert not guard.SKIP_MARKERS.search("def test_skipping_none():")


def test_protected_hashes_are_forty_hex():
    for value in list(guard.PROTECTED_BLOBS.values()) + list(guard.PROTECTED_TREES.values()) + [guard.BASELINE]:
        assert re.fullmatch(r"[0-9a-f]{40}", value)


def test_historic_fixup_files_must_remain_immutable():
    # Exact files and exact blob IDs: repair historical fixture provenance,
    # not permission to tamper with past installer/security assertions.
    import subprocess
    root=Path(__file__).resolve().parents[1]
    assert set(guard.APPROVED_LEGACY_TEST_BLOBS)=={
        "tests/test_installer_v75.py",
        "tests/test_installer_v79.py",
        "tests/test_pg_auth_v85.py",
    }
    for path, expected in guard.APPROVED_LEGACY_TEST_BLOBS.items():
        assert guard.classify_path(path, "M")[0]
        assert not guard.classify_path(path, "A")[0]
        assert not guard.classify_path(path, "D")[0]
        assert not guard.classify_path(path, "R")[0]
        actual=subprocess.check_output(["git", "hash-object", "--", path], cwd=root,text=True).strip()
        assert actual==expected, (path,expected,actual)
