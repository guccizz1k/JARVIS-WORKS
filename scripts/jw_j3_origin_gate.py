"""J3 strict GitHub provenance gate, separate from the honest FORMAT-only gate.

This gate proves that the referenced GitHub commits and successful workflow runs
exist in the expected repository and match the *exact* source SHA. It cannot
prove that a CI job actually tested every business claim in a report.
Never treat it as production-release authorization.

Usage: python -m scripts.jw_j3_origin_gate --check evidence.json
Network: GitHub REST read-only; GITHUB_TOKEN optional for private repositories.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from scripts.jw_evidence_gate import GATES, validate

REPO = "guccizz1k/JARVIS-WORKS"
RUN_URL = re.compile(
    r"https://github[.]com/guccizz1k/JARVIS-WORKS/actions/runs/([1-9][0-9]*)"
)
HEX40 = re.compile(r"[0-9a-f]{40}")


def github_json(path: str) -> dict[str, Any]:
    """Only query our fixed GitHub API repository; never follow a report URL."""
    if not re.fullmatch(r"(?:commits/[0-9a-f]{40}|actions/runs/[1-9][0-9]*)", path):
        raise ValueError("unexpected GitHub API path")
    url = f"https://api.github.com/repos/{REPO}/{path}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "JARVIS-WORKS-J3-readonly-evidence",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    req = Request(url, headers=headers, method="GET")
    with urlopen(req, timeout=12) as response:
        data = json.load(response)
    if not isinstance(data, dict):
        raise ValueError("GitHub API returned a non-object")
    return data


def verify_report(
    report: Any,
    fetch: Callable[[str], dict[str, Any]] = github_json,
) -> list[str]:
    """Fail closed on false CI provenance or incomplete five-gate acceptance."""
    errors = validate(report)
    if errors:
        return errors
    if report["release"]["status"] != "REVIEW_CANDIDATE":
        errors.append("strict proof requires REVIEW_CANDIDATE; release is still not authorized")
    if not all(report["gates"][gate]["status"] == "PASS" for gate in GATES):
        errors.append("strict proof requires five PASS gates")
    results = report["test_results"]
    if results["failed"] or results["skipped"] or results["passed"] < 1:
        errors.append("strict proof requires positive test count and no failures/skips")
    if report["rollback"]["tested"] is not True:
        errors.append("strict proof requires a declared tested rollback")
    if errors:
        return errors

    urls = {results["run_ref"]}
    for gate in GATES:
        for item in report["gates"][gate]["evidence"]:
            # Reject claims which are not backed by GitHub CI run provenance.
            if item["kind"] != "ci":
                errors.append(f"{gate}: unsupported evidence kind in strict proof")
            else:
                urls.add(item["ref"])
    for url in urls:
        if not isinstance(url, str) or not RUN_URL.fullmatch(url):
            errors.append("noncanonical GitHub Actions run URL")
    if errors:
        return errors

    source, baseline = report["source_commit"], report["baseline_commit"]
    if not HEX40.fullmatch(source) or not HEX40.fullmatch(baseline):
        return ["noncanonical Git SHA"]
    for label, sha in (("source", source), ("baseline", baseline)):
        try:
            obj = fetch(f"commits/{sha}")
            if not isinstance(obj, dict) or obj.get("sha") != sha:
                errors.append(f"{label} commit is not authenticated by GitHub")
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, KeyError) as exc:
            errors.append(f"{label} commit lookup unavailable: {type(exc).__name__}")
    if errors:
        return errors

    for url in sorted(urls):
        run_id = RUN_URL.fullmatch(url).group(1)
        try:
            obj = fetch(f"actions/runs/{run_id}")
            repo = obj.get("repository")
            if not isinstance(repo, dict) or repo.get("full_name") != REPO:
                errors.append(f"run {run_id}: wrong repository")
            if str(obj.get("id")) != run_id:
                errors.append(f"run {run_id}: GitHub ID mismatch")
            if obj.get("head_sha") != source:
                errors.append(f"run {run_id}: SHA differs from report source")
            if obj.get("status") != "completed" or obj.get("conclusion") != "success":
                errors.append(f"run {run_id}: not completed successfully")
            if obj.get("html_url") != url:
                errors.append(f"run {run_id}: noncanonical GitHub response URL")
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, KeyError, AttributeError) as exc:
            errors.append(f"run {run_id}: lookup unavailable: {type(exc).__name__}")
    return errors



def verify_run_provenance(
    source: str,
    baseline: str,
    run_url: str,
    workflow_path: str,
    fetch: Callable[[str], dict[str, Any]] | None = None,
) -> list[str]:
    """Read-only proof of *one CI origin*, not business-case acceptance.

    This is deliberately useful for BLOCKED release reports: unlike a five-PASS
    declaration it does not manufacture fictitious gate completions.
    """
    if fetch is None:
        fetch = github_json  # Resolve at call time so isolated tests can inject a fetcher.
    if (not isinstance(source, str) or not HEX40.fullmatch(source)
            or not isinstance(baseline, str) or not HEX40.fullmatch(baseline)
            or not isinstance(run_url, str) or not RUN_URL.fullmatch(run_url)
            or not isinstance(workflow_path, str)
            or not re.fullmatch(r"\.github/workflows/[a-zA-Z0-9_.-]+\.ya?ml", workflow_path)):
        return ["noncanonical source, baseline, run URL, or workflow path"]
    errors: list[str] = []
    for label, sha in (("source", source), ("baseline", baseline)):
        try:
            obj = fetch(f"commits/{sha}")
            if not isinstance(obj, dict) or obj.get("sha") != sha:
                errors.append(f"{label}: commit mismatch or absent")
        except Exception as exc:
            errors.append(f"{label}: lookup unavailable ({type(exc).__name__})")
    if errors:
        return errors
    run_id = RUN_URL.fullmatch(run_url).group(1)
    try:
        run = fetch(f"actions/runs/{run_id}")
        if not isinstance(run, dict):
            return ["run: unexpected API result type"]
        repo = run.get("repository")
        expected = {
            "id": int(run_id),
            "head_sha": source,
            "status": "completed",
            "conclusion": "success",
            "html_url": run_url,
            "path": workflow_path,
        }
        if not isinstance(repo, dict) or repo.get("full_name") != REPO:
            errors.append("run: repository mismatch")
        for field, value in expected.items():
            if type(run.get(field)) is not type(value) or run.get(field) != value:
                errors.append(f"run: {field} mismatch")
        if run.get("event") not in ("push", "pull_request"):
            errors.append("run: event outside approved review triggers")
    except Exception as exc:
        errors.append(f"run: lookup unavailable ({type(exc).__name__})")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", type=Path, help="full review-candidate declaration")
    mode.add_argument("--verify-run", help="existing GitHub CI run URL (origin only)")
    parser.add_argument("--source", help="exact SHA for --verify-run")
    parser.add_argument("--baseline", help="exact baseline SHA for --verify-run")
    parser.add_argument("--workflow-path", help="expected workflow YAML for --verify-run")
    args = parser.parse_args()
    if args.verify_run:
        if not all((args.source, args.baseline, args.workflow_path)):
            parser.error("--verify-run requires --source, --baseline, --workflow-path")
        issues = verify_run_provenance(args.source, args.baseline, args.verify_run,
                                       args.workflow_path)
    else:
        if any((args.source, args.baseline, args.workflow_path)):
            parser.error("--source, --baseline and --workflow-path only apply to --verify-run")
        try:
            report = json.loads(args.check.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError) as exc:
            print(f"BLOCKED: evidence unreadable ({type(exc).__name__})")
            return 1
        issues = verify_report(report)
    for issue in issues:
        print("FAIL/BLOCKED: " + issue)
    if issues:
        return 1
    print("PASS: GitHub run origin/commit/workflow verified ONLY; no business assertions "
          "or independent reviewer verified; release NOT authorized")
    return 0

if __name__ == "__main__":
    sys.exit(main())
