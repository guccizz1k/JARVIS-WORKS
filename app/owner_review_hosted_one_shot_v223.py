"""Render-resident one-shot synthetic QA; no secret export, no public endpoint.

Reuses existing HTTPS transactional acceptance, with Render-provided identity
attestation, explicit operator opt-in, disposable SQLite, and server-local
preexisting Basic credentials. The only output is a bounded log receipt.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path

from .owner_review_public_qa_guard_v223 import (
    PublicQAGateError, check_public_qa_runtime,
)
from scripts import ci_v223_render_hosted_e2e as harness

LOG = logging.getLogger("jarvis.hosted.review")
ENV_SHA = "JW_HOSTED_EXPECTED_SHA"
BRANCH = "review/jw-v223-render-qa-pinned-20261122"


def preflight(env=None):
    env = os.environ if env is None else env
    if env.get("JW_HOSTED_E2E_ACK") != harness.ARM:
        return None, "DISABLED_NO_OPERATOR_ACK"
    if (env.get("RENDER") != "true"
        or env.get("RENDER_SERVICE_ID") != harness.SERVICE
        or env.get("RENDER_EXTERNAL_URL") != harness.HOST
        or env.get("RENDER_GIT_BRANCH") != BRANCH):
        return None, "BLOCKED_WRONG_RENDER_SERVICE"
    expected = env.get(ENV_SHA, "")
    if (not harness.SHA.fullmatch(expected)
        or env.get("RENDER_GIT_COMMIT") != expected):
        return None, "BLOCKED_UNATTESTED_DEPLOY_SHA"
    try:
        if check_public_qa_runtime(env) is not True:
            return None, "BLOCKED_PUBLIC_QA_DISABLED"
    except PublicQAGateError:
        return None, "BLOCKED_PUBLIC_QA_ISOLATION"
    # Do not materialize or print credential values outside the Render process.
    scoped = dict(env)
    scoped.update({
        "JW_HOSTED_ORIGIN": harness.HOST,
        "JW_HOSTED_SERVICE_ID": harness.SERVICE,
        "JW_HOSTED_CANDIDATE_SHA": expected,
        "JW_HOSTED_RENDER_LIVE_SHA": expected,
        "JW_HOSTED_RENDER_DEPLOY_STATUS": "live",
        "JW_HOSTED_BASIC_USER": env["JW_REVIEW_BASIC_USER"],
        "JW_HOSTED_BASIC_PASSWORD": env["JW_REVIEW_BASIC_PASSWORD"],
    })
    status, code = harness.preflight(scoped)
    if status != "READY":
        return None, code
    return scoped, "READY_SCOPED_RENDER_CREDENTIALS"


async def execute_once(env=None, *, sleeping=4):
    env = os.environ if env is None else env
    scoped, code = preflight(env)
    if scoped is None:
        receipt = {"status":"NOT_RUN", "reason":code, "release_ready":False}
    else:
        # Same instance cannot rerun on startup or concurrent task scheduling.
        # A later clean deployment has a new disposable instance/DB.
        lock = Path("/tmp/jw-v223-hosted-e2e-" + scoped[ENV_SHA][:12] + ".lock")
        try:
            fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        except FileExistsError:
            receipt = {"status":"NOT_RUN", "reason":"ALREADY_ATTEMPTED_ON_INSTANCE",
                       "release_ready":False}
        except OSError:
            receipt = {"status":"NOT_RUN", "reason":"ONE_SHOT_LOCK_UNAVAILABLE",
                       "release_ready":False}
        else:
            await asyncio.sleep(sleeping)
            # Run blocking TLS client in a separate thread. The ASGI application
            # remains responsive and its own TLS/middleware is exercised.
            receipt = await asyncio.to_thread(harness.run, scoped)
    # Fixed, bounded JSON result. Do not expose secrets, HTTP bodies or stack.
    LOG.warning("JW_HOSTED_RENDER_RESIDENT_E2E=%s",
                json.dumps(receipt, ensure_ascii=True, sort_keys=True))
    return receipt


def schedule():
    if os.environ.get("JW_HOSTED_E2E_ACK") != harness.ARM:
        return None
    return asyncio.create_task(execute_once())
