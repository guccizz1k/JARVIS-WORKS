"""Static guard for the P1/P2 PostgreSQL 17 gate: the pinned baseline check names must be recorded under EXACTLY those names on
every server-version branch. Regression for S4M.00z, which the PG17 branch recorded under a different name, so a PG17 run
would have failed the fixed-name verification even though every individual check passed.
No database is needed; the harness is only parsed, never executed."""
from __future__ import annotations
import ast
import re
from pathlib import Path

SRC = (Path(__file__).resolve().parents[1] / "scripts/ci_cinema_pg_p1_p2_pg17_suite.py").read_text(encoding="utf-8")
TREE = ast.parse(SRC)


def _baseline() -> tuple[str, ...]:
    for n in ast.walk(TREE):
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "BASELINE_CHECKS" for t in n.targets):
            return tuple(ast.literal_eval(n.value))
    raise AssertionError("BASELINE_CHECKS not found")


def _rec_names(nodes) -> list[str]:
    out = []
    for top in nodes:
        for n in ast.walk(top):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "rec" and n.args:
                a = n.args[0]
                out.append(a.value if isinstance(a, ast.Constant) and isinstance(a.value, str) else "<dynamic>")
    return out


def _major_branches():
    """Every `if MAJOR ... :` statement that has an else branch."""
    res = []
    for n in ast.walk(TREE):
        if isinstance(n, ast.If) and n.orelse and "MAJOR" in ast.unparse(n.test):
            res.append(n)
    return res


def test_baseline_has_96_unique_names_and_the_z_check_keeps_its_pinned_name():
    b = _baseline()
    assert len(b) == 96 and len(set(b)) == 96
    assert "S4M.00z_original_file_requires_pg17" in b


def test_every_record_call_in_a_version_branch_uses_the_same_names_on_both_sides():
    for n in _major_branches():
        a, b = _rec_names(n.body), _rec_names(n.orelse)
        if a or b:
            assert sorted(a) == sorted(b), f"line {n.lineno}: PG16 branch records {a}, PG17 branch records {b}"


def test_the_removed_pg17_only_check_name_never_returns():
    assert not re.search(r'rec\(\s*["\']S4M\.00z_original_file_passes', SRC)


def test_z_check_is_recorded_once_and_both_version_expectations_are_kept():
    names = _rec_names([TREE])
    assert names.count("S4M.00z_original_file_requires_pg17") == 1
    assert '"requires PostgreSQL 17" in p.stderr' in SRC                                   # PG16 expectation
    assert '"requires PostgreSQL 17" not in p.stderr and "non-empty ledger" in p.stderr' in SRC   # PG17 expectation


def test_every_literal_baseline_name_is_recorded_somewhere_in_the_harness():
    recorded = set(_rec_names([TREE]))
    missing = [n for n in _baseline() if n not in recorded and n not in SRC]
    assert not missing, missing
