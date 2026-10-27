"""Read-only Codebase Memory & Paperclip evidence adapters for J TEAM.

No imports of vendor SDKs, network, subprocess, installations, heartbeats,
filesystem mutations, or writes to J5. All artifact content is untrusted.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
from collections import Counter, deque
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "agents/team/jarvis_v1/code_context_workboard.json"
SCHEMA = "jw-jteam-code-context-workboard-v1"
ROLES = ("deputy", "deputy_manager", "manager", "director", "jarvis_lead")
HEX_SHA = re.compile(r"^[a-f0-9]{40}$")
ITEM_ID = re.compile(r"^JT-[0-9]{3,6}$")
SECRET = re.compile(
    r"(?i)(?:OPENAI_API_KEY|GITHUB_TOKEN|DATABASE_URL|"
    r"github_pat_|ghp_[A-Za-z0-9]{8,}|sk-[A-Za-z0-9_-]{12,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"(?:password|api[_ -]?key|비밀번호|secret[_ -]?key)\s*[:=])"
)
RESTRICTED = (".env", ".pem", ".key", ".p12", ".pfx", "secrets",
              "credentials", "private-key", "private_key", ".git/")
CODE_TERMS = ("코드", "함수", "파일", "의존성", "수정", "버그", "테스트", "리팩터",
              "변경 영향", "영향 범위", "call graph", "impact", "regression",
              "refactor", "debug", "mcp")
BOARD_TERMS = ("j team", "jteam", "에이전트", "업무 배정", "업무 현황",
               "진행 상황", "진행상황", "승인 대기", "작업 현황", "작업상태",
               "작업 상태", "대시보드", "역할", "태스크",
               "paperclip", "workboard", "agent status")
STATUS = ("todo", "in_progress", "in_review", "blocked", "done")
ALL_KEYS = frozenset(("sha", "indexed_sha", "files", "changed", "edges", "related_tests"))
GRAPH_KEYS = frozenset(("src", "dst"))
BOARD_KEYS = frozenset(("team_id", "sha", "items"))
ITEM_KEYS = frozenset(("id", "owner", "status", "j5_checkpoint_id", "approved"))


def _contract_expected() -> dict:
    return {
        "schema": SCHEMA, "harness": [f"J{x}" for x in range(1, 7)],
        "authority": "J5_IS_SOURCE_OF_TRUTH", "execution": "OFFLINE_REVIEW_ONLY",
        "required_order": list(ROLES),
        "tools": [
            {"id": "codebase-memory-mcp",
             "source": "https://github.com/DeusData/codebase-memory-mcp",
             "usage": "LOCAL_GRAPH_EXPORT_ONLY",
             "risk": "INSTALLER_CAN_WRITE_AGENT_CONFIG_AND_START_DAEMON", "license": "MIT"},
            {"id": "paperclip", "source": "https://github.com/paperclipai/paperclip",
             "usage": "READ_ONLY_TASK_SNAPSHOT_ONLY",
             "risk": "HEARTBEAT_CAN_EXECUTE_AGENTS_AND_SPEND", "license": "MIT"},
            {"id": "trail-code", "source": "https://github.com/trailhq/Trail-Code",
             "usage": "COMPARISON_CANDIDATE_NOT_INSTALLED",
             "risk": "INSTALLER_CAN_INSTALL_HOOKS", "license": "VERIFY_PINNED_RELEASE"},
        ],
        "no_auto_install": True, "no_heartbeats": True,
        "no_external_auth": True, "no_public_port": True,
        "no_paid_api": True, "no_remote_code_upload": True,
        "no_job_status_mutation": True, "no_j5_state_replacement": True,
        "no_main_merge": True, "no_prod_deploy": True,
        "no_production_data": True, "budget_actions_extra_usd": 5,
        "budget_api_krw": 50000,
        "evidence": "EXACT_SHA_SYNTHETIC_FIXTURES_NOT_REAL_VENDOR_PROOF"
    }


def read_contract(path: Path = CONTRACT) -> dict:
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384:
        raise ValueError("UNSAFE_CONTEXT_CONTRACT")
    data = json.loads(path.read_text(encoding="utf-8"))
    if type(data) is not dict or data != _contract_expected():
        raise ValueError("CONTEXT_POLICY_TAMPERED")
    return data


def _sha(value):
    if type(value) is not str or HEX_SHA.fullmatch(value) is None:
        raise ValueError("INVALID_SHA")
    return value


def _path(value):
    if type(value) is not str or not 1 <= len(value) <= 240:
        raise ValueError("INVALID_PATH")
    if SECRET.search(value) or "\\" in value or "//" in value:
        raise PermissionError("UNSAFE_PATH")
    if value.startswith("/") or value.startswith("~") or ":" in value:
        raise PermissionError("UNSAFE_PATH")
    p = PurePosixPath(value)
    if any(piece in ("", ".", "..") for piece in value.split("/")):
        raise PermissionError("PATH_TRAVERSAL")
    if any(value.casefold().endswith(x) or x in value.casefold() for x in RESTRICTED):
        raise PermissionError("PROTECTED_PATH")
    return str(p)


def _path_list(value, max_entries=2000):
    if type(value) is not list or len(value) > max_entries:
        raise ValueError("INVALID_PATH_SET")
    clean = [_path(p) for p in value]
    if len(clean) != len(set(clean)):
        raise ValueError("DUPLICATE_PATH")
    return clean


def analyze_code_graph(export: dict) -> dict:
    """Analyze a bounded graph export, never assert an installed MCP server."""
    read_contract()
    if type(export) is not dict or set(export) != ALL_KEYS:
        raise ValueError("INVALID_GRAPH_EXPORT_FIELDS")
    source_sha, index_sha = _sha(export["sha"]), _sha(export["indexed_sha"])
    files = set(_path_list(export["files"]))
    changed = _path_list(export["changed"], 100)
    tests = set(_path_list(export["related_tests"], 1000))
    edges = export["edges"]
    if (type(edges) is not list or len(edges) > 10000
            or any(type(x) is not dict or set(x) != GRAPH_KEYS for x in edges)):
        raise ValueError("INVALID_GRAPH_EDGES")
    reverse = {}
    for edge in edges:
        src, dst = _path(edge["src"]), _path(edge["dst"])
        if src not in files or dst not in files:
            raise ValueError("GRAPH_EDGE_OUTSIDE_INDEX")
        reverse.setdefault(dst, set()).add(src)
    missing = sorted(set(changed).difference(files))
    if tests.difference(files):
        raise ValueError("GRAPH_TEST_OUTSIDE_INDEX")
    fresh = source_sha == index_sha
    seen = set(changed) & files
    # Traverse all reachable indexed nodes. A fixed depth would silently miss
    # long dependency chains and create a false sense of impact coverage.
    queue = deque(seen)
    while queue:
        path = queue.popleft()
        for dependent in sorted(reverse.get(path, ())):
            if dependent not in seen:
                seen.add(dependent)
                queue.append(dependent)
    related = sorted(t for t in seen if t in tests)
    digest = hashlib.sha256(json.dumps({
        "sha": source_sha, "changed": sorted(changed),
        "impacted": sorted(seen)}, sort_keys=True).encode()).hexdigest()
    return {
        "status": "GRAPH_EXPORT_REVIEW" if fresh and not missing else "BLOCKED",
        "fresh_index": fresh, "changed_count": len(changed),
        "indexed_count": len(files),
        "missing_indexed_paths": missing,
        "impact_candidate_paths": sorted(seen),
        "related_test_candidates": related,
        "full_regression_required": True,
        "evidence_digest": digest,
        "vendor_binary_executed": False, "actual_mcp_connection": "NOT_RUN",
        "source_verified": "NOT_ATTESTED",
        "release": "BLOCKED",
    }


def project_paperclip_board(snapshot: dict) -> dict:
    """Project read-only synthetic/approved export, never write J5 or Paperclip."""
    read_contract()
    if type(snapshot) is not dict or set(snapshot) != BOARD_KEYS:
        raise ValueError("INVALID_BOARD_EXPORT_FIELDS")
    _sha(snapshot["sha"])
    if snapshot["team_id"] != "jarvis-works-one-team":
        raise PermissionError("FOREIGN_TEAM_BLOCKED")
    items = snapshot["items"]
    if type(items) is not list or len(items) > 500:
        raise ValueError("INVALID_TASK_SET")
    counts, ids, checkpoint_ids = Counter(), set(), set()
    for row in items:
        if type(row) is not dict or set(row) != ITEM_KEYS:
            raise ValueError("INVALID_TASK_FIELDS")
        task_id = row["id"]
        if (type(task_id) is not str or ITEM_ID.fullmatch(task_id) is None
                or task_id in ids):
            raise ValueError("INVALID_OR_DUPLICATE_TASK")
        ids.add(task_id)
        if row["owner"] not in ROLES or row["status"] not in STATUS:
            raise ValueError("INVALID_ROLE_OR_STATUS")
        if type(row["approved"]) is not bool:
            raise ValueError("INVALID_APPROVAL_VALUE")
        cp = row["j5_checkpoint_id"]
        if cp is not None:
            if (type(cp) is not str or re.fullmatch(r"^j5-[a-z0-9-]{3,80}$", cp) is None
                    or cp in checkpoint_ids):
                raise ValueError("INVALID_OR_DUPLICATE_J5_CHECKPOINT")
            checkpoint_ids.add(cp)
        if row["status"] == "done" and not row["approved"]:
            raise PermissionError("UNAPPROVED_DONE_CLAIM")
        counts[row["status"]] += 1
    return {
        "status": "LOCAL_BOARD_PROJECTION_ONLY",
        "items_count": len(items), "state_counts": dict(sorted(counts.items())),
        "assigned_roles": sorted({x["owner"] for x in items}),
        "checkpoint_links": len(checkpoint_ids),
        "J5_authority": "UNCHANGED", "write_ops": 0,
        "heartbeats_invoked": 0, "vendor_api_calls": 0,
        "spend_measured": "NOT_MEASURED",
        "actual_paperclip_connection": "NOT_RUN",
        "release": "BLOCKED",
    }


def advise(task: str, *, domain: str | None = None) -> dict:
    """Choose review workflow only when relevant; do not launch a process."""
    read_contract()
    if type(task) is not str or not 1 <= len(task.strip()) <= 5000:
        raise ValueError("INVALID_WORK_ORDER")
    if SECRET.search(task) or "\x00" in task:
        raise PermissionError("SECRET_IN_WORK_ORDER")
    if domain is not None and domain not in ("software", "social_media", "business",
                                            "research", "everyday"):
        raise ValueError("INVALID_DOMAIN")
    lowered = task.casefold()
    tools = []
    if domain == "software" and any(x in lowered for x in CODE_TERMS):
        tools.append({"id": "codebase-memory-mcp", "status": "OPTIONAL_PILOT",
                      "method": "LOCAL_GRAPH_EXPORT_ONLY",
                      "requires": "SYNTHETIC_SAMPLE_AND_EXACT_SHA"})
    if any(x in lowered for x in BOARD_TERMS) and domain != "social_media":
        tools.append({"id": "paperclip", "status": "OPTIONAL_PILOT",
                      "method": "READ_ONLY_TASK_SNAPSHOT_ONLY",
                      "requires": "J5_RECONCILIATION_AND_NO_HEARTBEATS"})
    return {
        "status": "ROUTING_ONLY",
        "task_sha256": hashlib.sha256(task.strip().encode()).hexdigest(),
        "candidates": tools,
        "alternative": "trail-code" if any(x["id"] == "codebase-memory-mcp"
                                         for x in tools) else None,
        "comparison": "NOT_MEASURED",
        "external_runtime_executed": False,
        "configuration_written": False, "system_of_record": "J5",
        "model_calls": 0, "cost_usd": 0, "release": "BLOCKED",
    }


def role_instructions(role: str) -> str:
    if role not in ROLES:
        raise ValueError("INVALID_ROLE")
    read_contract()
    if role == "manager":
        focus = "Use local Codebase Memory graph exports to locate dependency risks; compare Trail-Code only after independent test."
    elif role == "director":
        focus = "Review stale/missing graph nodes, unlinked tests, tenant isolation, cost-unit mismatches, and negative controls."
    elif role == "jarvis_lead":
        focus = "Paperclip is read-only board candidate; J5 owns durable state and user controls all deploy/merge/spend approvals."
    elif role == "deputy":
        focus = "Research provenance and pinned upstream changes; do not trust vendor benchmarks as measured improvement."
    else:
        focus = "Propose a usable owner-only task dashboard without operating agent heartbeats or modifying roles."
    return ("OPTIONAL_CODE_CONTEXT_WORKBOARD_V134: All external runtimes NOT_RUN; "
            "J1-J6 plus J5 state remains authoritative, original "
            "roles unmodified. " + focus)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--task")
    parser.add_argument("--domain", choices=("software", "social_media",
                                             "business", "research", "everyday"))
    args = parser.parse_args(argv)
    if args.check == bool(args.task):
        parser.error("choose --check or --task")
    try:
        value = ({"status": "OFFLINE_CONTEXT_POLICY_PASS",
                  "external_runtime": "NOT_RUN", "release": "BLOCKED"}
                 if args.check and read_contract()
                 else advise(args.task, domain=args.domain))
    except (OSError, ValueError, PermissionError):
        print(json.dumps({"status": "BLOCKED", "error": "UNSAFE_CONTEXT_REQUEST"}))
        return 3
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
