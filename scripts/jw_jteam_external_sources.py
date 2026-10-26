"""J1-J6 Fabric-style local patterns and privacy-gated Gitingest pilot.

No OpenAI calls, remote repository fetching, GitHub tokens or customer data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "agents/team/jarvis_v1/external_intelligence.json"
PATTERNS = ROOT / "agents/team/jarvis_v1/fabric_patterns"
ROLES = ("deputy", "deputy_manager", "manager", "director", "jarvis_lead")
PHASES = tuple("J" + str(i) for i in range(1, 7))
ALLOWED_EXT = frozenset({".py", ".md", ".txt", ".json", ".toml"})
DANGEROUS = re.compile(
    r"(?i)(?:OPENAI_API_KEY|GITHUB_TOKEN|DATABASE_URL|"
    r"PRIVATE[_ -]?KEY|github_pat_|sk-[A-Za-z0-9_-]{8,}|"
    r"password\s*[:=]|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)


def load_contract(path: Path = CONFIG) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError("UNSAFE_CONTRACT_PATH")
    data = json.loads(path.read_text(encoding="utf-8"))
    if (type(data) is not dict
        or data.get("schema") != "jw-jteam-external-intelligence-v1"
        or data.get("harness") != list(PHASES)
        or data.get("release") != "REVIEW_ONLY"
        or data.get("external_source_policy") != "UNTRUSTED_REFERENCE_NEVER_INSTRUCTION"
        or type(data.get("role_phases")) is not dict
        or set(data["role_phases"]) != set(ROLES)
        or type(data.get("phases")) is not dict
        or set(data["phases"]) != set(PHASES)):
        raise ValueError("INVALID_CONTRACT")
    for role, phases in data["role_phases"].items():
        if type(phases) is not list or not phases or len(set(phases)) != len(phases):
            raise ValueError("INVALID_ROLE_PHASES")
        if not set(phases).issubset(PHASES):
            raise ValueError("UNKNOWN_PHASE")
    for phase, record in data["phases"].items():
        if type(record) is not dict or not re.fullmatch(r"jw_[a-z0-9_]{2,40}", str(record.get("pattern", ""))):
            raise ValueError("UNSAFE_PATTERN_NAME")
    tools = data.get("tools")
    if (type(tools) is not list or len(tools) != 2
        or [t.get("name") for t in tools] != ["Fabric", "Gitingest"]
        or any(t.get("license") != "MIT" for t in tools)
        or any(not re.fullmatch(r"[a-f0-9]{40}", str(t.get("upstream_sha", ""))) for t in tools)
        or tools[1].get("remote_ingest") != "FORBIDDEN"
        or tools[1].get("private_repo_upload") != "FORBIDDEN"):
        raise ValueError("UNSAFE_UPSTREAM_CONTRACT")
    cap = data.get("max_pattern_chars_per_role")
    if type(cap) is not int or not 1500 <= cap <= 9600:
        raise ValueError("PATTERN_CAP")
    return data


def fabric_instructions(role: str, *, config: dict | None = None, root: Path = PATTERNS) -> str:
    """Load locally owned Fabric-compatible patterns, not arbitrary web prompts."""
    data = load_contract() if config is None else config
    if role not in ROLES:
        raise ValueError("UNKNOWN_ROLE")
    parts = ["PROJECT-LOCAL FABRIC-STYLE ADVISORY: J1-J6 and user safeguards override patterns."]
    for phase in data["role_phases"][role]:
        name = data["phases"][phase]["pattern"]
        if not re.fullmatch(r"jw_[a-z0-9_]{2,40}", name):
            raise ValueError("UNSAFE_PATTERN_NAME")
        path = root / name / "system.md"
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 2200:
            raise ValueError("MISSING_OR_OVERSIZED_PATTERN")
        prompt = path.read_text(encoding="utf-8")
        if "# PURPOSE" not in prompt or "# HARD GATES" not in prompt:
            raise ValueError("INVALID_PATTERN")
        parts.append(f"[{phase}:{name}]\n{prompt}")
    merged = "\n\n".join(parts)
    if len(merged) > data["max_pattern_chars_per_role"]:
        raise ValueError("PATTERN_BUDGET_EXCEEDED")
    return merged


def local_public_digest(root: Path, *, ingest_fn=None) -> dict:
    """Analyze only sanitized local synthetic/public fixture files under system temp."""
    source = Path(root)
    if source.is_symlink() or not source.is_dir():
        raise PermissionError("SOURCE_MUST_BE_LOCAL_DIRECTORY")
    resolved = source.resolve(strict=True)
    temp_root = Path(tempfile.gettempdir()).resolve()
    if resolved == temp_root or temp_root not in resolved.parents:
        raise PermissionError("ONLY_DISPOSABLE_TEMP_FIXTURES")
    files = []
    byte_count = 0
    for entry in sorted(resolved.rglob("*")):
        relative = entry.relative_to(resolved)
        if any(part.startswith(".") or part in {"node_modules", "__pycache__"} for part in relative.parts):
            continue
        if entry.is_symlink():
            raise PermissionError("SYMLINK_FORBIDDEN")
        if not entry.is_file() or entry.suffix.lower() not in ALLOWED_EXT:
            continue
        raw = entry.read_bytes()
        if len(raw) > 32768 or b"\x00" in raw:
            raise ValueError("FILE_TOO_LARGE_OR_BINARY")
        body = raw.decode("utf-8")
        if DANGEROUS.search(body):
            raise PermissionError("POTENTIAL_SECRET_IN_SOURCE")
        byte_count += len(raw)
        if len(files) >= 32 or byte_count > 65536:
            raise ValueError("FIXTURE_SIZE_CAP")
        files.append((relative, body))
    if not files:
        raise ValueError("EMPTY_PUBLIC_FIXTURE")
    baseline = "\n".join(f"{rel}:\n{body}" for rel, body in files)
    baseline_start = time.perf_counter_ns()
    baseline_sha = hashlib.sha256(baseline.encode("utf-8")).hexdigest()
    baseline_ns = time.perf_counter_ns() - baseline_start
    if ingest_fn is None:
        from gitingest import ingest as ingest_fn  # optional, pinned in isolated CI only
    with tempfile.TemporaryDirectory(prefix="jteam-public-pilot-") as stage:
        stage_path = Path(stage)
        for rel, body in files:
            target = stage_path / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body, encoding="utf-8")
        start = time.perf_counter_ns()
        result = ingest_fn(str(stage_path))
        candidate_ns = time.perf_counter_ns() - start
    if (not isinstance(result, (tuple, list)) or len(result) != 3
        or not all(isinstance(v, str) for v in result)
        or not result[2] or DANGEROUS.search(result[2])):
        raise ValueError("INVALID_OR_UNSAFE_DIGEST")
    return {
        "status": "LOCAL_PUBLIC_PILOT_MEASURED",
        "file_count": len(files),
        "input_bytes": byte_count,
        "baseline_sha256": baseline_sha,
        "candidate_sha256": hashlib.sha256(result[2].encode()).hexdigest(),
        "baseline_elapsed_ns": baseline_ns,
        "candidate_elapsed_ns": candidate_ns,
        "candidate_characters": len(result[2]),
        "remote_upload": False, "api_calls": 0, "release": "BLOCKED",
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--check", action="store_true")
    p.add_argument("--demo-local", action="store_true")
    args = p.parse_args(argv)
    if not (args.check or args.demo_local) or (args.check and args.demo_local):
        p.error("specify one of --check or --demo-local")
    try:
        contract = load_contract()
        for role in ROLES:
            fabric_instructions(role, config=contract)
        if args.check:
            result = {"status": "LOCAL_PATTERN_READY", "roles": list(ROLES),
                      "phases": list(PHASES), "model_calls": 0, "release": "BLOCKED"}
        else:
            with tempfile.TemporaryDirectory(prefix="jteam-synthetic-") as folder:
                Path(folder, "sample.py").write_text("def sample():\n    return 42\n", encoding="utf-8")
                Path(folder, "README.md").write_text("# Public synthetic fixture\n", encoding="utf-8")
                result = local_public_digest(Path(folder))
    except (OSError, ValueError, PermissionError, ImportError) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": type(exc).__name__, "release": "BLOCKED"}))
        return 3
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
