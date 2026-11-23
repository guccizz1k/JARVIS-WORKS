"""Operator-only, fail-closed Render hosted synthetic trade E2E.

Reuses the EXACT existing document-to-settlement acceptance function, without
duplicating or modifying the approved V22.3 app, test or customer data logic.
This module never runs as a GitHub Actions job and NEVER deploys Render.

The operator must first independently inspect Render's current LIVE deploy
SHA, verify the disposable SQLite+Basic runtime guard and explicitly approve
creating synthetic rows in the existing public *review-only* service.
No external database, provider backup, key, tenant credentials or real user
documents may be used. The runner cannot independently attest Render metadata.
"""
from __future__ import annotations

import json
import os
import re
import sys

HOST = "https://jw-v223-qa-pinned-20261122.onrender.com"
SERVICE = "srv-dc1b24eq1p3s73fng070"
ARM = "OWNER_APPROVES_HOSTED_SYNTHETIC_TRADE_WRITES_ON_VERIFIED_SHA"
SHA = re.compile(r"[0-9a-f]{40}\Z")
DENIED_SECRET_KEYS = (
    "DATABASE_URL", "JW_PG_STAGE_DSN", "JW_PG_SOURCE_DSN",
    "JW_PG_TARGET_ADMIN_DSN", "SUPABASE_SERVICE_ROLE_KEY",
    "JW_PG_BACKUP_KEY", "JW_PG_BACKUP_RO_PASSWORD",
)


def preflight(env=None):
    """Pure, credential-value-free decision, no DNS/network/DB operations."""
    env = os.environ if env is None else env
    if env.get("JW_HOSTED_E2E_ACK") != ARM:
        return "BLOCKED", "HOSTED_MUTATION_NOT_APPROVED"
    if (env.get("JW_ENV") != "review"
        or env.get("JW_NO_EXTERNAL_DATABASE") != "1"
        or env.get("JW_HOSTED_ORIGIN") != HOST
        or env.get("JW_HOSTED_SERVICE_ID") != SERVICE):
        return "BLOCKED", "HOSTED_ISOLATION_OR_ORIGIN_MISMATCH"
    if any(env.get(k) for k in DENIED_SECRET_KEYS):
        return "BLOCKED", "SOURCE_OR_PRODUCTION_CREDENTIAL_PRESENT"
    current = env.get("JW_HOSTED_CANDIDATE_SHA", "")
    deployed = env.get("JW_HOSTED_RENDER_LIVE_SHA", "")
    if (not SHA.fullmatch(current) or not SHA.fullmatch(deployed)
        or current != deployed or current == "16b06a8da738de1129382cafc10e2b4b5004c424"):
        return "BLOCKED", "EXACT_LIVE_DEPLOY_SHA_NOT_ATTESTED"
    # On Render require provider-owned runtime identity, not user-declared SHA
    # alone. Operator must independently verify the external deploy metadata.
    if env.get("RENDER") == "true" and (
        env.get("RENDER_SERVICE_ID") != SERVICE
        or env.get("RENDER_EXTERNAL_URL") != HOST
        or env.get("RENDER_GIT_BRANCH") != "review/jw-v223-render-qa-pinned-20261122"
        or env.get("RENDER_GIT_COMMIT") != current
    ):
        return "BLOCKED", "RENDER_RUNTIME_IDENTITY_MISMATCH"
    if env.get("JW_HOSTED_RENDER_DEPLOY_STATUS") != "live":
        return "BLOCKED", "RENDER_LIVE_DEPLOY_STATUS_NOT_ATTESTED"
    user = env.get("JW_HOSTED_BASIC_USER", "")
    password = env.get("JW_HOSTED_BASIC_PASSWORD", "")
    if (not re.fullmatch(r"[A-Za-z0-9_-]{4,40}", user)
        or not 24 <= len(password) <= 256
        or password == "Demo!2026secure"):
        return "BLOCKED", "SCOPED_REVIEW_BASIC_AUTH_UNAVAILABLE"
    return "READY", "HOSTED_PRECHECK_ASSERTED_METADATA_ONLY"


def run(env=None):
    env = os.environ if env is None else env
    status, code = preflight(env)
    if status != "READY":
        return {"hosted_trade_e2e": "NOT_RUN", "reason": code,
                "release_ready": False}
    last_requests = []
    try:
        import httpx
        # Import is intentionally delayed until all write authorization checks
        # pass. Existing tests are the sole source of business acceptance logic.
        from tests.test_v223_document_to_settlement_e2e import (
            test_imported_document_full_trade_chain_and_negative_boundaries,
        )
        def observe(response):
            # Synthetic API route + HTTP status only, not a cookie, header,
            # response body, customer text, payment reference, or full URL.
            route = re.sub(r"/[0-9a-f]{32}(?=/|$)", "/:id",
                           response.request.url.path)
            if not route.startswith("/api/"):
                route = "/"
            last_requests.append({
                "method": response.request.method,
                "route": route[:100],
                "status": response.status_code,
            })
            del last_requests[:-5]

        with httpx.Client(
            base_url=HOST,
            auth=httpx.BasicAuth(
                env["JW_HOSTED_BASIC_USER"],
                env["JW_HOSTED_BASIC_PASSWORD"]),
            verify=True, trust_env=False, follow_redirects=False,
            timeout=httpx.Timeout(30.0, connect=15.0),
            event_hooks={"response": [observe]},
        ) as client:
            health = client.get("/api/health")
            if health.status_code != 200:
                raise RuntimeError("HOSTED_READINESS_NOT_VERIFIED")
            # Valid perimeter Basic auth is not a business-app login.
            anonymous = client.get("/api/me")
            if anonymous.status_code != 401:
                raise RuntimeError("HOSTED_ANONYMOUS_SESSION_NOT_DENIED")
            # Existing acceptance already enforces source -> invoice -> payment
            # lineage, full JSON server readbacks, tenant, CSRF, replay and CAS.
            test_imported_document_full_trade_chain_and_negative_boundaries(
                client)
        return {"hosted_trade_e2e":"PASS_SYNTHETIC_BUSINESS_FLOW",
                "sha_attestation":"EXTERNAL_RENDER_METADATA_REQUIRED",
                "backend":"SYNTHETIC_SQLITE_ONLY",
                "last_requests":last_requests,
                "release_ready":False}
    except Exception:
        # NEVER print HTTP response bodies, Basic credentials, cookie, SQL,
        # traceback or payload. A test failure can contain sensitive context.
        return {"hosted_trade_e2e":"FAIL_OR_BLOCKED",
                "reason":"HOSTED_E2E_FAIL_CLOSED_REVIEW_ONLY",
                "last_requests":last_requests,
                "release_ready":False}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv not in (["diagnose"], ["run"]):
        return 2
    if argv == ["diagnose"]:
        status, code = preflight()
        result = {"hosted_trade_e2e":"NOT_RUN",
                  "status":status, "reason":code, "release_ready":False}
    else:
        result = run()
    print(json.dumps(result,sort_keys=True,separators=(",",":")))
    return 0 if result.get("hosted_trade_e2e")=="PASS_SYNTHETIC_BUSINESS_FLOW" else 1


if __name__ == "__main__":
    raise SystemExit(main())
