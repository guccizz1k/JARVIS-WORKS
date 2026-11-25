"""Static contract for the CI definitions of the CINEMA PG gates. Text-based on purpose (the containment job installs only pytest,
so PyYAML is not assumed). It guards the ways a red gate could still produce a green workflow:
* the PG17 candidate gate not being triggered by a change to a file it loads at run time;
* a failing gate masked by a pipe without pipefail, `|| true`, `continue-on-error`, or a step-level `if:`;
* the supplemental PG16 switch or a non-17 server image sneaking into the PG17 job;
* new pure tests not being part of the fast containment job."""
from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WF_P1P2 = ROOT / ".github/workflows/jw-cinema-pg-p1-p2-pg17.yml"
WF_GATES = ROOT / ".github/workflows/jw-cinema-pg-gates.yml"
HARNESS = ROOT / "scripts/ci_cinema_pg_p1_p2_pg17_suite.py"
SQL_GATE = ROOT / "scripts/ci_cinema_pg_sql_gate.py"
GATE_SCRIPTS = re.compile(r"scripts/ci_cinema_pg_[a-z0-9_]+\.py|-m pytest")


def _steps(text: str) -> list[str]:
    """Split a workflow into its step blocks. Steps in these hand-written files are list items indented by exactly 6 spaces
    (`      - uses:/name:/run:`); a block runs until the next item at that indentation or a less indented key."""
    blocks, cur = [], None
    for line in text.splitlines():
        if re.match(r"^ {6}- ", line):
            if cur is not None: blocks.append("\n".join(cur))
            cur = [line]
        elif cur is not None and line.strip() and not line.startswith(" " * 7) and not line.lstrip().startswith("#"):
            blocks.append("\n".join(cur)); cur = None
        elif cur is not None:
            cur.append(line)
    if cur is not None: blocks.append("\n".join(cur))
    return [b for b in blocks if re.match(r"^ {6}- (uses|name|run):", b)]


def _trigger_paths(text: str) -> set[str]:
    m = re.search(r"^\s+paths:\s*\n((?:\s+(?:-\s+\S+|#.*)\s*\n)+)", text, re.M)
    assert m, "PG17 workflow has no push paths filter"
    return set(re.findall(r"-\s+(\S+)", m.group(1)))


def _harness_runtime_files() -> set[str]:
    """Repository files the harness reads while running (literal paths, REVIEW / '<file>', runpy targets and the SQL gate's BASE_FILES)."""
    tree = ast.parse(HARNESS.read_text(encoding="utf-8"))
    files = {"scripts/ci_cinema_pg_p1_p2_pg17_suite.py", ".github/workflows/jw-cinema-pg-p1-p2-pg17.yml"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and re.fullmatch(r"(scripts|db)/[\w./-]+\.(sql|py)", n.value):
            files.add(n.value)
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Div) and isinstance(n.left, ast.Name) and n.left.id == "REVIEW" \
                and isinstance(n.right, ast.Constant):
            files.add("scripts/review/" + n.right.value)
    gate = ast.parse(SQL_GATE.read_text(encoding="utf-8"))
    for n in gate.body:
        if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "BASE_FILES":
            files |= set(ast.literal_eval(n.value))
    return files


def test_harness_runtime_dependencies_were_found():
    deps = _harness_runtime_files()
    for must in ("scripts/ci_cinema_pg_sql_gate.py", "scripts/review/cinema_pg_write_engine.sql",
                 "scripts/review/cinema_pg_s4_dev_migration.sql", "scripts/review/cinema_pg_s4_dev_rollback.sql",
                 "scripts/review/cinema_pg_p2_login_role.sql", "scripts/review/cinema_pg_p2_login_role_rollback.sql",
                 "db/review/ci_v90_ephemeral_pg_schema.sql"):
        assert must in deps, must
    for f in deps:
        assert (ROOT / f).is_file(), f"dependency {f} does not exist"


def test_pg17_gate_is_triggered_by_every_file_it_loads():
    missing = sorted(_harness_runtime_files() - _trigger_paths(WF_P1P2.read_text(encoding="utf-8")))
    assert not missing, f"a change to these files would NOT re-run the PG17 candidate gate: {missing}"


def _assert_no_masking(path: Path):
    text = path.read_text(encoding="utf-8")
    assert "continue-on-error" not in text, f"{path.name}: continue-on-error"
    assert not re.search(r"\|\|\s*(true|:|exit 0)\b|;\s*true\s*$", text, re.M), f"{path.name}: failure masked with || true"
    for step in _steps(text):
        m = re.search(r"^\s+if:\s*(.+)$", step, re.M)
        if m:
            assert m.group(1).strip() == "always()" and "upload-artifact" in step, f"{path.name}: conditional step\n{step}"
        run = step.split("run:", 1)[1] if "run:" in step else ""
        run = re.sub(r"^\s*[|>][-+]?[ \t]*\n", "", run)          # the YAML block-scalar indicator is not a shell pipe
        if GATE_SCRIPTS.search(run) and re.search(r"\|\s*tee\b|\|(?!\|)\s*\w", run):
            assert re.search(r"set -[a-z]*o pipefail|set -euo pipefail|set -o pipefail", run), \
                f"{path.name}: gate output piped without pipefail (the pipe's exit code would hide a failure)\n{step}"


def test_pg17_workflow_cannot_mask_a_failing_gate():
    _assert_no_masking(WF_P1P2)


def test_gates_workflow_cannot_mask_a_failing_gate():
    _assert_no_masking(WF_GATES)


def test_pg17_job_runs_only_real_postgresql_17_and_never_the_pg16_switch():
    text = WF_P1P2.read_text(encoding="utf-8")
    assert re.findall(r"image:\s*(\S+)", text) == ["postgres:17"]
    assert "--allow-pg16-local" not in text
    assert re.search(r"python3 -I scripts/ci_cinema_pg_p1_p2_pg17_suite\.py --report \S+", text)
    assert re.search(r'test "\$v" -ge 170000 && test "\$v" -lt 180000', text)


def test_new_pure_tests_run_in_the_fast_containment_job():
    text = WF_GATES.read_text(encoding="utf-8")
    pure = next(s for s in _steps(text) if "--junitxml=jw-cinema-pg-static.xml" in s)
    for t in ("tests/test_cinema_pg_history_classifier.py", "tests/test_cinema_pg_p1_p2_check_names.py",
              "tests/test_cinema_pg_ci_workflow_contract.py", "tests/test_cinema_pg_sql_gate_verdict.py"):
        assert t in pure, f"{t} is not part of the pure-test CI step"


# ---- the contract itself must catch what it is for (negative controls on synthetic text)

def _tmp(tmp_path, text):
    p = tmp_path / "wf.yml"; p.write_text(text); return p


def test_contract_rejects_pipe_without_pipefail(tmp_path):
    wf = "jobs:\n  j:\n    steps:\n      - name: x\n        run: |\n          python3 -I scripts/ci_cinema_pg_p1_p2_pg17_suite.py 2>&1 | tee log\n"
    try:
        _assert_no_masking(_tmp(tmp_path, wf)); raised = False
    except AssertionError:
        raised = True
    assert raised


def test_contract_rejects_or_true_and_continue_on_error(tmp_path):
    for wf in ("jobs:\n  j:\n    steps:\n      - run: python3 -I scripts/ci_cinema_pg_sql_gate.py || true\n",
               "jobs:\n  j:\n    steps:\n      - run: python3 -I scripts/ci_cinema_pg_sql_gate.py\n        continue-on-error: true\n",
               "jobs:\n  j:\n    steps:\n      - run: python3 -I scripts/ci_cinema_pg_sql_gate.py\n        if: false\n"):
        try:
            _assert_no_masking(_tmp(tmp_path, wf)); raised = False
        except AssertionError:
            raised = True
        assert raised, wf


def test_contract_accepts_pipefail(tmp_path):
    wf = "jobs:\n  j:\n    steps:\n      - name: x\n        run: |\n          set -euo pipefail\n          python3 -I scripts/ci_cinema_pg_p1_p2_pg17_suite.py 2>&1 | tee log\n"
    _assert_no_masking(_tmp(tmp_path, wf))
