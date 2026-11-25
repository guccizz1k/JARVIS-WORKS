"""Regression: database schema-fingerprint metadata is the ONLY new immutable-baseline exception.

The protected application, migration, security, and other DB files remain blocked.
"""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/jw-j1-j6-unified-acceptance.yml"

EXPECTED = {
    ":!db/review/ci_v92_quote_ephemeral.sql",
    ":!db/review/v99_live_tenant_row_read_rollback.sql",
    ":!db/review/v99_live_customer_withcheck_rollback.sql",
    ":!db/review/v108_source_schema_fingerprints.json",
}

def test_database_immutable_allowlist_exact_and_no_wildcards():
    import shlex
    text = WORKFLOW.read_text(encoding="utf-8")
    lines = [line.strip() for line in text.splitlines()
             if "git diff --exit-code efc7dbab8fed5f7291bde1512da5f11566dd9e4e HEAD -- db/" in line]
    assert len(lines) == 1
    tokens = shlex.split(lines[0])
    assert tokens[:7] == [
        "git", "diff", "--exit-code",
        "efc7dbab8fed5f7291bde1512da5f11566dd9e4e",
        "HEAD", "--", "db/",
    ]
    assert set(tokens[7:]) == EXPECTED
    assert all("*" not in x for x in tokens[7:])

def _git(path, *args, check=True):
    return subprocess.run(["git", *args], cwd=path, text=True,
                          capture_output=True, check=check)

def test_exact_git_pathspec_allows_only_approved_file(tmp_path):
    import shlex
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "ci@example.invalid")
    _git(tmp_path, "config", "user.name", "Regression Fixture")
    review = tmp_path / "db/review"
    review.mkdir(parents=True)
    allowed = review / "v108_source_schema_fingerprints.json"
    forbidden = tmp_path / "db/review/unapproved_metadata.json"
    protected = tmp_path / "db/schema.sql"
    for f in (allowed, forbidden, protected):
        f.write_text("base\n", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    text = WORKFLOW.read_text(encoding="utf-8")
    line = next(line.strip() for line in text.splitlines()
                if "git diff --exit-code efc7dbab8fed5f7291bde1512da5f11566dd9e4e HEAD -- db/" in line)
    excluded = [x for x in __import__("shlex").split(line) if x.startswith(":!")]
    command = ["diff", "--exit-code", "HEAD", "--", "db/", *excluded]
    allowed.write_text("reviewed\n", encoding="utf-8")
    assert _git(tmp_path, *command, check=False).returncode == 0
    forbidden.write_text("unreviewed\n", encoding="utf-8")
    assert _git(tmp_path, *command, check=False).returncode == 1
    forbidden.write_text("base\n", encoding="utf-8")
    protected.write_text("unreviewed\n", encoding="utf-8")
    assert _git(tmp_path, *command, check=False).returncode == 1
