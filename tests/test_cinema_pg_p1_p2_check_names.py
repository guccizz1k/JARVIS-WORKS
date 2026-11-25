"""Static + unit guard for the P1/P2 PostgreSQL 17 gate's check inventory. No database; the harness is parsed, never executed.

Why this file exists
* S4M.00z was once recorded under a different name on the PG17 branch only: a PG17 run would have failed the fixed-name check
  although every individual check passed.
* The first version of this guard accepted a pinned name when the string merely appeared ANYWHERE in the source - and every pinned
  name appears in the pinned list itself, so a check whose rec() call had been deleted still passed.

What is verified here
1. Every rec() call site is enumerated from the AST. f-string names inside `for` loops are expanded from the literal loop iterables
   (module-level tuples such as LEDGER are resolved), so dynamic names are checked exactly, not by pattern. Anything that cannot be
   resolved fails the test (it must be made explicit), and a rec() inside a data-dependent branch, a while loop, an except handler or
   a nested function fails too.
2. The enumerated multiset must equal the pinned list (BASELINE_CHECKS + NEW_CHECKS) exactly: a name that is only listed, a recording
   path that was removed, a duplicate, a rename, an extra check -> FAIL. Names in comments/strings/function names do not count.
3. Branches on the server version (MAJOR / SVN / ALLOW_PG16) must record exactly the same names on both sides (an `if` without `else`
   counts as recording nothing on the other side).
4. The 96 baseline names and the 82 new names are pinned by SHA-256 so editing a name in BOTH places is still detected.
5. rec() and verify_results() are extracted from the harness and unit-tested: a FAIL can never become PASS, a non-boolean verdict is
   refused, and the final verdict rejects missing / unexpected / duplicate / failed / odd-status results.
The executed (runtime) names are verified by the harness itself against the same pinned list at the end of every real run."""
from __future__ import annotations

import ast
import hashlib
import itertools
import re
from collections import Counter
from pathlib import Path

import pytest

HARNESS = Path(__file__).resolve().parents[1] / "scripts/ci_cinema_pg_p1_p2_pg17_suite.py"
SRC = HARNESS.read_text(encoding="utf-8")
TREE = ast.parse(SRC)
VERSION_NAMES = {"MAJOR", "SVN", "ALLOW_PG16"}
# sha256("\n".join(names)) - change only together with a reviewed change of the check inventory
BASELINE_SHA256 = "3acf6c50c4b44eb427b45060ec229009ae0c0aec098a328407e824d547a4469a"   # = the 96 names the original 61af35a gate recorded
NEW_SHA256 = "32a98de1a65964f8e63284176309a547b5b331ff3982cd8f78f1df92563bfa62"


class Unresolvable(Exception):
    pass


def _module_tuple(name: str) -> tuple:
    for n in TREE.body:
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name:
            try:
                return tuple(ast.literal_eval(n.value))
            except ValueError as e:
                raise Unresolvable(f"{name} is not a literal tuple") from e
    raise Unresolvable(f"module-level literal {name} not found")


BASELINE = _module_tuple("BASELINE_CHECKS")
NEW = _module_tuple("NEW_CHECKS")
PINNED = BASELINE + NEW


def _values(node: ast.AST) -> list:
    if isinstance(node, (ast.Tuple, ast.List)):
        return list(ast.literal_eval(node))
    if isinstance(node, ast.Name):
        return list(_module_tuple(node.id))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("enumerate", "range"):
        args = [_values(a) if not isinstance(a, ast.Constant) else a.value for a in node.args]
        return list(enumerate(*args)) if node.func.id == "enumerate" else list(range(*args))
    raise Unresolvable(f"loop iterable at line {getattr(node, 'lineno', '?')}: {ast.unparse(node)}")


def _bind(target: ast.AST, value, env: dict) -> None:
    if isinstance(target, ast.Name):
        env[target.id] = value
    elif isinstance(target, (ast.Tuple, ast.List)):
        if len(target.elts) != len(value):
            raise Unresolvable(f"cannot unpack at line {target.lineno}")
        for t, v in zip(target.elts, value):
            _bind(t, v, env)
    else:
        raise Unresolvable(f"loop target at line {target.lineno}")


def _name(expr: ast.AST, env: dict) -> str:
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return expr.value
    if isinstance(expr, ast.JoinedStr):
        out = []
        for part in expr.values:
            if isinstance(part, ast.Constant):
                out.append(part.value)
            elif isinstance(part, ast.FormattedValue) and isinstance(part.value, ast.Name) and part.value.id in env \
                    and part.conversion == -1 and part.format_spec is None:
                out.append(str(env[part.value.id]))
            else:
                raise Unresolvable(f"dynamic check name at line {expr.lineno}: {ast.unparse(expr)}")
        return "".join(out)
    raise Unresolvable(f"check name at line {getattr(expr, 'lineno', '?')} is not a string literal / f-string: {ast.unparse(expr)}")


def _rec_calls(node: ast.AST):
    """rec(...) calls inside one simple statement (nested defs / lambdas are handled by the caller)."""
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "rec":
            yield n


def _contains_rec(nodes) -> bool:
    return any(True for n in nodes for _ in _rec_calls(n))


def _mentions_version(test: ast.AST) -> bool:
    return any(isinstance(n, ast.Name) and n.id in VERSION_NAMES for n in ast.walk(test))


def enumerate_checks(stmts=None, envs=None, problems=None) -> list[str]:
    """Statically expand every rec() call site into the exact list of check names it records."""
    stmts = TREE.body if stmts is None else stmts
    envs = [{}] if envs is None else envs
    problems = [] if problems is None else problems
    out: list[str] = []
    for s in stmts:
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            if s.name != "rec" and _contains_rec(s.body):
                problems.append(f"rec() inside function {s.name} (line {s.lineno}) cannot be enumerated")
            continue
        if isinstance(s, ast.For):
            vals = _values(s.iter) if _contains_rec(s.body) else []
            new_envs = []
            for env, v in itertools.product(envs, vals):
                e = dict(env); _bind(s.target, v, e); new_envs.append(e)
            out += enumerate_checks(s.body, new_envs, problems)
            out += enumerate_checks(s.orelse, envs, problems)
        elif isinstance(s, ast.If):
            a = enumerate_checks(s.body, envs, problems)
            b = enumerate_checks(s.orelse, envs, problems)
            if _mentions_version(s.test):
                if Counter(a) != Counter(b):
                    problems.append(f"line {s.lineno}: version branch records {sorted(a)} vs {sorted(b)}")
                out += a
            elif a or b:
                problems.append(f"line {s.lineno}: rec() inside a data-dependent branch ({ast.unparse(s.test)[:60]})")
        elif isinstance(s, ast.Try):
            out += enumerate_checks(s.body, envs, problems)
            for h in s.handlers:
                if _contains_rec(h.body):
                    problems.append(f"line {h.lineno}: rec() inside an except handler")
            out += enumerate_checks(s.orelse, envs, problems)
            out += enumerate_checks(s.finalbody, envs, problems)
        elif isinstance(s, (ast.While, ast.With, ast.AsyncWith, ast.AsyncFor, ast.Match)):
            if _contains_rec([s]):
                problems.append(f"line {s.lineno}: rec() inside {type(s).__name__} cannot be enumerated")
        else:
            for c in _rec_calls(s):
                if not c.args:
                    problems.append(f"line {c.lineno}: rec() without a name"); continue
                for env in envs:
                    out.append(_name(c.args[0], env))
            if isinstance(s, (ast.Expr, ast.Assign)) and any(isinstance(n, ast.IfExp) and _contains_rec([n]) for n in ast.walk(s)):
                problems.append(f"line {s.lineno}: rec() inside a conditional expression")
    return out


def _enumerated():
    problems: list[str] = []
    names = enumerate_checks(problems=problems)
    return names, problems


# ---------------------------------------------------------------- inventory

def test_pinned_lists_are_intact_unique_and_hash_pinned():
    assert len(BASELINE) == 96 and len(NEW) == 82 and len(set(PINNED)) == len(PINNED) == 178
    assert hashlib.sha256("\n".join(BASELINE).encode()).hexdigest() == BASELINE_SHA256, "a baseline check name was changed"
    assert hashlib.sha256("\n".join(NEW).encode()).hexdigest() == NEW_SHA256, "a new check name was changed/added/removed"
    assert "S4M.00z_original_file_requires_pg17" in BASELINE


def test_every_rec_call_site_is_statically_enumerable():
    names, problems = _enumerated()
    assert not problems, problems
    assert names, "no rec() call found"


def test_recorded_names_equal_the_pinned_list_exactly():
    """Replaces the former vacuous `n in SRC` test: the RECORDING PATHS, not the source text, must produce every pinned name once."""
    names, _ = _enumerated()
    got, want = Counter(names), Counter(PINNED)
    only_listed = sorted(set(want) - set(got))
    not_listed = sorted(set(got) - set(want))
    dup = sorted(n for n, c in got.items() if c > 1)
    assert not only_listed, f"pinned but never recorded: {only_listed}"
    assert not not_listed, f"recorded but not pinned (new or renamed): {not_listed}"
    assert not dup, f"recorded more than once: {dup}"
    assert len(names) == len(PINNED)


def test_version_branches_record_identical_names():
    branches = [n for n in ast.walk(TREE) if isinstance(n, ast.If) and _mentions_version(n.test)]
    assert branches, "expected at least the S4M.00z version branch"
    for n in branches:
        p: list[str] = []
        a = enumerate_checks(n.body, [{}], p); b = enumerate_checks(n.orelse, [{}], p)
        assert Counter(a) == Counter(b), f"line {n.lineno}: PG16 side {a} / PG17 side {b}"


def test_the_removed_pg17_only_check_name_never_returns():
    assert not re.search(r'rec\(\s*["\']S4M\.00z_original_file_passes', SRC)


def test_z_check_is_recorded_once_and_both_version_expectations_are_kept():
    names, _ = _enumerated()
    assert names.count("S4M.00z_original_file_requires_pg17") == 1
    assert '"requires PostgreSQL 17" in p.stderr' in SRC                                       # PG16 expectation
    assert '"requires PostgreSQL 17" not in p.stderr and "non-empty ledger" in p.stderr' in SRC   # PG17 expectation


# ---------------------------------------------------------------- the enumerator itself must catch the defects it exists for

def _enumerate_source(src: str):
    global TREE
    saved = TREE
    try:
        TREE = ast.parse(src)
        p: list[str] = []
        return enumerate_checks(problems=p), p
    finally:
        TREE = saved


@pytest.mark.parametrize("src,expect", [
    ("rec('A', True)\nif MAJOR != 17:\n    rec('B', True)\nelse:\n    rec('C', True)\n", "version branch"),
    ("if MAJOR == 17:\n    rec('PG17_ONLY', True)\n", "version branch"),
    ("if x:\n    rec('A', True)\n", "data-dependent"),
    ("for t in some_runtime_list():\n    rec(f'A_{t}', True)\n", None),
    ("def f():\n    rec('A', True)\n", "inside function"),
    ("try:\n    pass\nexcept Exception:\n    rec('A', True)\n", "except handler"),
])
def test_enumerator_flags_unsafe_recording_shapes(src, expect):
    if expect is None:
        with pytest.raises(Unresolvable):
            _enumerate_source(src)
    else:
        _, problems = _enumerate_source(src)
        assert any(expect in p for p in problems), problems


def test_enumerator_expands_loops_exactly():
    names, problems = _enumerate_source("L = ('a', 'b')\nfor i, t in enumerate(L):\n    for r in ('x', 'y'):\n        rec(f'C_{t}_{r}', True)\n")
    assert not problems and names == ["C_a_x", "C_a_y", "C_b_x", "C_b_y"]


def test_a_name_that_only_exists_in_comments_or_the_list_does_not_count():
    names, _ = _enumerate_source("# rec('GHOST', True)\nX = ('GHOST',)\ndef rec_GHOST(): pass\ns = \"rec('GHOST', True)\"\n")
    assert names == []


# ---------------------------------------------------------------- rec() / verify_results() unit tests (extracted, not executed harness)

def _load_verdict_functions():
    keep = []
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name in ("rec", "verify_results"):
            keep.append(n)
        elif isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name) and n.targets[0].id in (
                "BASELINE_CHECKS", "NEW_CHECKS", "ALL_CHECKS", "EXPECTED_NEW_CHECKS", "EXPECTED_CHECKS"):
            keep.append(n)
    assert {getattr(n, "name", None) for n in keep} >= {"rec", "verify_results"}
    ns: dict = {"R": [], "print": lambda *a, **k: None}
    exec(compile(ast.Module(body=keep, type_ignores=[]), str(HARNESS), "exec"), ns)
    return ns


def _green(ns):
    return [(n, "PASS", "") for n in ns["ALL_CHECKS"]]


def test_rec_records_fail_as_fail_and_pass_as_pass():
    ns = _load_verdict_functions()
    ns["rec"]("X1", False); ns["rec"]("X2", True)
    assert ns["R"] == [("X1", "FAIL", ""), ("X2", "PASS", "")]


@pytest.mark.parametrize("verdict", ["f", "t", 1, 0, None, [], ["x"], "PASS"])
def test_rec_refuses_non_boolean_verdicts(verdict):
    ns = _load_verdict_functions()
    with pytest.raises(SystemExit):
        ns["rec"]("X", verdict)
    assert ns["R"] == []


def test_rec_refuses_duplicate_names():
    ns = _load_verdict_functions()
    ns["rec"]("X", True)
    with pytest.raises(SystemExit):
        ns["rec"]("X", True)


def test_verify_accepts_only_the_complete_green_inventory():
    ns = _load_verdict_functions()
    assert ns["verify_results"](_green(ns)) == []


@pytest.mark.parametrize("mutate,word", [
    (lambda r: r[:-1], "missing"),                                            # one pinned check did not run
    (lambda r: r[1:] + [("S4X.renamed_check", "PASS", "")], "unexpected"),    # renamed
    (lambda r: r + [r[0]], "duplicate"),                                      # duplicated
    (lambda r: [(r[0][0], "FAIL", "")] + r[1:], "failed"),                    # a failure
    (lambda r: [(r[0][0], "SKIP", "")] + r[1:], "non PASS/FAIL"),             # a skip is never a pass
    (lambda r: [], "missing"),                                                # nothing ran
])
def test_verify_rejects_incomplete_or_failed_runs(mutate, word):
    ns = _load_verdict_functions()
    problems = ns["verify_results"](mutate(_green(ns)))
    assert problems and any(word in p for p in problems), problems
