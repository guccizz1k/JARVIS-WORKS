"""Fail closed on Semgrep rule errors, missed injected vulnerabilities or app findings.

Runs fully locally with project-owned rules and telemetry disabled.
Do not silently exclude production source or treat a clean scan as full security proof.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "security/semgrep/jw-security.yml"
FIXTURES = ROOT / "security/semgrep/fixtures"
EXPECTED = {
    "jw-python-dangerous-eval",
    "jw-python-shell-true",
    "jw-python-insecure-pickle",
    "jw-python-requests-tls-bypass",
}

def scan(*paths: Path) -> dict:
    cmd = ["semgrep", "scan", "--config", str(CONFIG), "--metrics", "off",
           "--json", "--no-git-ignore", *map(str, paths)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=150,
                          cwd=ROOT, env={**os.environ, "SEMGREP_SEND_METRICS": "off"})
    if proc.returncode != 0:
        raise RuntimeError(f"Semgrep scan process failed: exit={proc.returncode}; "
                           f"stderr={proc.stderr[-1100:]}")
    try:
        result = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Semgrep did not return valid JSON") from exc
    if result.get("errors"):
        raise AssertionError("Semgrep parser/configuration errors: " + str(result["errors"])[:900])
    return result

def main() -> int:
    insecure = scan(FIXTURES / "insecure_example.py")
    ids = {entry["check_id"].split(".")[-1] for entry in insecure["results"]}
    if ids != EXPECTED:
        raise AssertionError(f"Detection contract mismatch: missing {sorted(EXPECTED-ids)}, "
                             f"unexpected {sorted(ids-EXPECTED)}")
    safe = scan(FIXTURES / "safe_example.py")
    if safe["results"]:
        raise AssertionError("Semgrep false-positive fixture did not pass")
    actual = scan(ROOT / "app", ROOT / "scripts")
    findings = actual["results"]
    output = ROOT / "artifacts/semgrep"
    output.mkdir(parents=True, exist_ok=True)
    (output / "result.json").write_text(json.dumps(actual, ensure_ascii=False, indent=2))
    print(f"PASS: 4/4 injected security patterns detected; safe fixture clear. "
          f"App/scripts findings={len(findings)}", flush=True)
    for finding in findings[:20]:
        print(f"SECURITY_FINDING {finding['check_id']} "
              f"{finding['path']}:{finding['start']['line']}", flush=True)
    if findings:
        raise AssertionError("Security rule violations detected; fix or explicitly review")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
