"""Unit tests for the engine SQL gate's verdict (no database). Regression: a test that silently disappeared from the SQL test script
left the gate green with 221/221 because only per-gate minimums were checked. The exact expected inventory is now part of the verdict."""
from __future__ import annotations

import ast
import runpy
from pathlib import Path

import pytest

GATE = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/ci_cinema_pg_sql_gate.py"))
EXPECTED = GATE["EXPECTED_RESULT_NAMES"]
verdict = GATE["gate_verdict"]


def green():
    return [{"name": n, "result": "PASS", "detail": ""} for n in EXPECTED]


def test_expected_inventory_is_exact_and_unique():
    assert len(EXPECTED) == 222 == len(set(EXPECTED))
    assert {n.split(".")[0] for n in EXPECTED} == {"G1", "G2", "G3", "G5"}


def test_complete_green_run_passes():
    assert verdict(green())["overall"] == "PASS"


@pytest.mark.parametrize("mutate", [
    lambda r: r[:-1],                                                     # one test silently missing (the reproduced defect)
    lambda r: [x for x in r if x["name"] != "G3.03_payment_replay_posts_once"],
    lambda r: r + [r[0]],                                                 # duplicate
    lambda r: r[1:] + [{"name": "G3.99_renamed", "result": "PASS", "detail": ""}],   # renamed / unexpected
    lambda r: [{**r[0], "result": "FAIL"}] + r[1:],                       # a failure
    lambda r: [{**r[0], "result": "SKIP"}] + r[1:],                       # anything but PASS
    lambda r: [],                                                         # nothing ran
])
def test_incomplete_or_failed_runs_fail(mutate):
    assert verdict(mutate(green()))["overall"] == "FAIL"


def test_gate_verdict_is_not_shadowed_inside_the_gate():
    """Regression: main() once had a loop variable `verdict` that shadowed the verdict function, so the real run crashed while this
    unit test still passed. No assignment, argument or loop target may reuse the function's name."""
    tree = ast.parse((Path(__file__).resolve().parents[1] / "scripts/ci_cinema_pg_sql_gate.py").read_text(encoding="utf-8"))
    clashes = [n.lineno for n in ast.walk(tree)
               if (isinstance(n, ast.Name) and n.id == "gate_verdict" and isinstance(n.ctx, ast.Store))
               or (isinstance(n, ast.arg) and n.arg == "gate_verdict")]
    defs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "gate_verdict"]
    assert len(defs) == 1 and not clashes, clashes
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "gate_verdict"]
    assert len(calls) == 1, "main() must take its verdict from gate_verdict()"
