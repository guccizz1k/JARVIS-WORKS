"""Render private J team candidate: one ephemeral offline smoke run; NO listener.

Never call OpenAI, any database server, GitHub, or external URL. Private cron
deployment smoke only. No persistent evidence outside Render service logs.
"""
from __future__ import annotations
import json
import os
import sqlite3
import tempfile
from pathlib import Path

from scripts.jw_jteam_private_cli import run_private

ROLES = ("deputy", "deputy_manager", "manager", "director", "jarvis_lead")


def main(env=None) -> dict:
    current = os.environ if env is None else env
    # Refuse operation if actual paid dispatch is configured in this process.
    if (current.get("OPENAI_API_KEY") or
        current.get("JTEAM_PAID_API_APPROVED") == "YES" or
        current.get("JTEAM_PROVIDER_BUDGET_ENFORCED") == "YES"):
        raise PermissionError("CLOUD_SMOKE_MUST_NOT_HAVE_PAID_DISPATCH_SECRETS")
    role_calls = []
    def simulated_provider(role, task, context, model, key, cap):
        role_calls.append(role)
        return {"role": role, "status": "completed",
                "response_id": "offline-fixture-" + role,
                "model": model, "usage": {"input_tokens": 0, "output_tokens": 0},
                "output": [{"type": "text", "text": "offline-synthetic-only"}]}
    mock_env = {
        "OPENAI_API_KEY": "offline-fixture-not-a-provider-key",
        "JTEAM_MODEL": "OFFLINE_LOCAL_STUB",
        "JTEAM_PAID_API_APPROVED": "YES",
        "JTEAM_PROVIDER_BUDGET_ENFORCED": "YES",
        "JTEAM_OPERATOR_PRIVATE_APPROVAL_ID": "offline-fixture-only",
        "JTEAM_BUDGET_SCOPE": "2026-10",
    }
    with tempfile.TemporaryDirectory(prefix="jteam-render-private-") as temp:
        state_path = Path(temp) / "private.sqlite3"
        result = run_private(
            state_path, "render-offline-1", "synthetic-private-worker-check",
            execute=True, env=mock_env, provider=simulated_provider,
        )
        with sqlite3.connect(state_path) as db:
            completed = db.execute(
                "SELECT COUNT(*) FROM steps WHERE status='COMPLETE'"
            ).fetchone()[0]
            receipts = db.execute(
                "SELECT COUNT(DISTINCT receipt) FROM steps"
            ).fetchone()[0]
            reserved = db.execute("SELECT reserved_krw FROM budget").fetchone()[0]
    if (result["status"] != "REVIEW_REQUIRED" or
        completed != 5 or receipts != 5 or reserved != 5000 or
        role_calls != list(ROLES)):
        raise AssertionError("LOCAL_PRIVATE_ROLE_ACCEPTANCE_FAILED")
    return {"status": "PASS", "scope": "OFFLINE_RENDER_PRIVATE_CRON",
            "roles_simulated": 5, "responses_real": 0,
            "provider_calls": 0, "listener": False,
            "persistence": "EPHEMERAL_ONLY",
            "independent_review": "NOT_ATTESTED",
            "release": "BLOCKED"}


if __name__ == "__main__":
    print(json.dumps(main(), sort_keys=True))
