"""Private, no-HTTP J team CLI: durable role receipts and guarded model worker.

Default is dry-run. Paid calls require an operator-approved private environment,
a separately verified provider billing guard, and explicit --execute.
This code cannot itself prove the provider imposes a hard billing cap.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime
from zoneinfo import ZoneInfo

from scripts.jw_jteam_durable_dispatch import ROLES, dispatch, setup as setup_jobs
from scripts.jw_jteam_integrated_gate import (
    setup as setup_budget, reserve, mark_uncertain,
)
from scripts.jw_jteam_openai_runner import require_permission, request_one

PROJECT = Path(__file__).resolve().parents[1]
CREDENTIAL_HINT = re.compile(
    r"(?i)(?:sk-[A-Za-z0-9_-]{8,}|github_pat_|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"OPENAI_API_KEY\s*[:=]|password\s*[:=])"
)


def validated_db_path(db_path: Path) -> Path:
    candidate = Path(db_path).expanduser().absolute()
    if candidate.suffix != ".sqlite3":
        raise ValueError("PRIVATE_DATABASE_EXTENSION_REQUIRED")
    if candidate.is_symlink() or candidate.parent.is_symlink():
        raise PermissionError("SYMLINK_DATABASE_FORBIDDEN")
    if candidate == PROJECT or PROJECT in candidate.parents:
        raise PermissionError("DATABASE_INSIDE_GITHUB_WORKTREE_FORBIDDEN")
    if candidate.exists() and not candidate.is_file():
        raise PermissionError("DATABASE_MUST_BE_REGULAR_FILE")
    return candidate


def run_private(
    db_path: Path, job_id: str, task: str, *, execute: bool = False,
    env: dict | None = None, provider=None, budget_krw: int = 5000,
    reserve_per_role_krw: int = 1000, max_output_tokens: int = 350,
) -> dict:
    settings = os.environ if env is None else env
    if not execute:
        return {
            "status": "DRY_RUN", "runtime": "PRIVATE_CLI_NO_LISTENER",
            "actual_model_calls": 0, "release": "BLOCKED",
            "required": [
                "OPENAI_API_KEY", "JTEAM_MODEL",
                "JTEAM_PAID_API_APPROVED=YES", "JTEAM_PROVIDER_BUDGET_ENFORCED=YES",
                "JTEAM_OPERATOR_PRIVATE_APPROVAL_ID",
            ],
        }
    if type(task) is not str or not 1 <= len(task) <= 8000:
        raise ValueError("INVALID_TASK_LENGTH")
    if CREDENTIAL_HINT.search(task):
        raise PermissionError("CREDENTIAL_LIKE_INPUT_FORBIDDEN")
    if not isinstance(job_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", job_id):
        raise ValueError("INVALID_JOB_ID")
    if (type(reserve_per_role_krw) is not int or reserve_per_role_krw < 1
        or type(budget_krw) is not int or not 5 <= budget_krw <= 50000
        or reserve_per_role_krw * 5 > budget_krw):
        raise ValueError("INVALID_RESERVATION_POLICY")
    args = SimpleNamespace(
        execute=True, max_calls=5, max_output_tokens=max_output_tokens,
        budget_krw=budget_krw,
    )
    require_permission(args, settings)
    if not isinstance(settings.get("JTEAM_OPERATOR_PRIVATE_APPROVAL_ID"), str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{8,80}", settings["JTEAM_OPERATOR_PRIVATE_APPROVAL_ID"]
    ):
        raise PermissionError("MISSING_PRIVATE_OPERATOR_APPROVAL")
    path = validated_db_path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # No network listener, no Github writes, no automatic tool execution.
    call = request_one if provider is None else provider
    with sqlite3.connect(path, timeout=1.0) as db:
        if os.name == "posix":
            path.chmod(0o600)
        setup_jobs(db)
        setup_budget(db)
        scope = settings.get("JTEAM_BUDGET_SCOPE", datetime.now(ZoneInfo("Asia/Seoul")).strftime("%Y-%m"))
        if not re.fullmatch(r"[0-9]{4}-[0-9]{2}", scope):
            raise ValueError("BUDGET_SCOPE_INVALID")

        def worker(role: str, work: str) -> dict:
            request_id = f"{job_id}:{role}"
            state = reserve(db, scope, request_id, reserve_per_role_krw, cap=budget_krw)
            if state != "RESERVED":
                raise PermissionError("UNRECONCILED_BUDGET_RESERVATION")
            # Mark uncertain BEFORE network I/O. A timeout must never free budget.
            mark_uncertain(db, request_id)
            result = call(
                role, work, [], settings["JTEAM_MODEL"],
                settings["OPENAI_API_KEY"], max_output_tokens,
            )
            if type(result) is not dict or result.get("role") != role:
                raise ValueError("INVALID_MODEL_ROLE_RESPONSE")
            response_id = result.get("response_id")
            if (result.get("status") != "completed" or type(response_id) is not str
                or not 1 <= len(response_id) <= 256):
                raise ValueError("INCOMPLETE_PROVIDER_RESPONSE")
            usage = result.get("usage")
            if type(usage) is not dict:
                raise ValueError("UNATTESTED_PROVIDER_USAGE")
            tokens_in = usage.get("input_tokens")
            tokens_out = usage.get("output_tokens")
            if any(type(n) is not int or n < 0 for n in (tokens_in, tokens_out)):
                raise ValueError("INVALID_PROVIDER_USAGE")
            # Store only provider reference, usage and output hash; never persist
            # raw prompts, responses, API keys, customer files or business text.
            output_digest = hashlib.sha256(
                json.dumps(result.get("output", []), sort_keys=True, ensure_ascii=False).encode("utf-8")
            ).hexdigest()
            return {
                "receipt_id": response_id, "input_tokens": tokens_in,
                "output_tokens": tokens_out, "model": str(result.get("model", ""))[:100],
                "response_sha256": output_digest,
            }

        completed = dispatch(db, job_id, task, worker=worker)
        return {
            "status": "REVIEW_REQUIRED",
            "job_id": job_id, "runtime": "PRIVATE_CLI_NO_LISTENER",
            "role_receipts": completed["role_receipts"],
            "independent_review": "NOT_ATTESTED",
            "cost": "PROVIDER_BILLING_INDEPENDENT_CHECK_REQUIRED",
            "release": "BLOCKED",
        }


def main(argv=None, env=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, default=Path.home() / ".local/share/jteam/private.sqlite3")
    parser.add_argument("--job-id", default="offline-demo")
    parser.add_argument("--task", default="Review a synthetic code review example")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--budget-krw", type=int, default=5000)
    parser.add_argument("--reserve-per-role-krw", type=int, default=1000)
    parser.add_argument("--max-output-tokens", type=int, default=350)
    args = parser.parse_args(argv)
    try:
        output = run_private(
            args.db, args.job_id, args.task, execute=args.execute,
            env=env, budget_krw=args.budget_krw,
            reserve_per_role_krw=args.reserve_per_role_krw,
            max_output_tokens=args.max_output_tokens,
        )
    except (ValueError, PermissionError, sqlite3.Error, OSError, TimeoutError) as exc:
        # Deliberately avoid printing exception contents, to prevent secret leaks.
        output = {
            "status": "BLOCKED", "reason": type(exc).__name__,
            "actual_model_calls": "NOT_ATTESTED", "release": "BLOCKED",
        }
    print(json.dumps(output, ensure_ascii=False, sort_keys=True))
    return 0 if output["status"] in ("DRY_RUN", "REVIEW_REQUIRED") else 3


if __name__ == "__main__":
    sys.exit(main())
