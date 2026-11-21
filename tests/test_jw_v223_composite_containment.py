import subprocess

import pytest

from scripts import jw_v223_composite_containment as guard
from scripts import jw_v223_pg17_required as pg17


@pytest.mark.parametrize("path", [
    "app/static/cinematic_v222.css",
    ".github/workflows/jw-v223-full-python-review-20261114.yml",
    "scripts/jw_v223_approval.py",
    "docs/review/unexplained.txt",
    "docs/review/quoted\npath.txt",
])
def test_rejects_unauthorized_committed_path(tmp_path, path):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(tmp_path), *args], text=True).strip()

    git("init", "-q")
    git("config", "user.name", "Test")
    git("config", "user.email", "test@example.invalid")
    target = tmp_path / path
    target.parent.mkdir(parents=True)
    target.write_text("reviewed\n")
    git("add", "--", path)
    git("commit", "-qm", "reviewed")
    reviewed = guard.tree(tmp_path, git("rev-parse", "HEAD"))
    target.write_text("unexpected\n")
    git("add", "--", path)
    git("commit", "-qm", "unexpected")
    with pytest.raises(ValueError, match="unreviewed tree") as error:
        guard.require_same_tree(reviewed, guard.tree(tmp_path, "HEAD"))
    assert repr(path) in str(error.value)


@pytest.mark.parametrize("case", [
    "",
    '<testcase classname="tests.test_v36_pg17_engine_e2e" name="test_real_pg17_engine"><skipped/></testcase>',
    '<testcase classname="tests.test_v36_pg17_engine_e2e" name="test_real_pg17_engine"><failure/></testcase>',
    '<testcase classname="other" name="test_real_pg17_engine"/>',
])
def test_pg17_gate_rejects_missing_skipped_or_failed_case(tmp_path, case):
    report = tmp_path / "pg17.xml"
    report.write_text(f"<testsuites><testsuite>{case}</testsuite></testsuites>")
    with pytest.raises(ValueError, match="mandatory PG17"):
        pg17.require_pass(report)


def test_pg17_gate_accepts_exact_passing_case(tmp_path):
    report = tmp_path / "pg17.xml"
    report.write_text(
        '<testsuites><testsuite><testcase classname="tests.test_v36_pg17_engine_e2e" '
        'name="test_real_pg17_engine"/></testsuite></testsuites>'
    )
    pg17.require_pass(report)


def test_rejects_untracked_path(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "unexpected").touch()
    with pytest.raises(ValueError, match="untracked paths"):
        guard.require_clean(tmp_path)


def test_rejects_unexplained_inventory_category():
    document = {
        "baseline": guard.BASELINE,
        "source": guard.IMPORTED,
        "paths": [["test.txt", "A", "100644", "a" * 40, "unexplained", False]],
    }
    with pytest.raises(ValueError, match="unexplained inventory entry"):
        guard.require_inventory({}, {"test.txt": ("100644", "a" * 40)}, document)
