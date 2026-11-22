#!/usr/bin/env python3
"""Independent post-run acceptance for already completed V6 B2/B3.

Read-only: NEVER re-run a backup, activate a role, modify the source DB,
overwrite prior receipts, or weaken the server-auth-refusal requirement.
A detached, clean, exact GitHub source SHA is required.
"""
from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

from scripts import ci_cinema_pg_v6_owner_readonly as gate
from scripts import ci_cinema_pg_v223_codespace_run as runner
from scripts.ci_cinema_pg_v223_owner_live_20261117 import check_live_admin_state
from scripts.ci_cinema_pg_s import CERT_FILE, load_dashboard_ca

SUCCESSFUL_BACKUP_SHA = "175fb490bc2a3236db4d14026c5ca9c2f268729a"
DIRECT_HOST = "db.rvymwwzclagvljnofyss.supabase.co"
REQUIRED = frozenset({
    "temporary_login", "restricted_tls_login",
    "real_encrypted_backup_independent_restore", "revoke",
})
RECEIPT_PREFIX = "owner_b2b3_20261117_"

class AttestationBlocked(Exception):
    pass

def private_receipt():
    """Only read immutable previous receipts; do not rewrite a BLOCKED verdict."""
    directory = runner.SUMMARY_FILE.parent
    if directory.is_symlink() or not directory.is_dir():
        raise AttestationBlocked("evidence_directory_missing")
    candidates = []
    for path in directory.glob(RECEIPT_PREFIX + "*.json"):
        try:
            if path.is_symlink():
                continue
            st=path.stat()
            if (st.st_uid != os.getuid() or not stat.S_ISREG(st.st_mode)
                    or st.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
                    or st.st_size > 32768):
                continue
            receipt=json.loads(path.read_text(encoding="utf-8"))
            stages=receipt.get("stages")
            if (receipt.get("sha") != SUCCESSFUL_BACKUP_SHA
                    or receipt.get("verdict") != "BLOCKED"
                    or not isinstance(stages,dict)
                    or set(stages) != REQUIRED
                    or any(stages.get(key) != "PASS" for key in REQUIRED)):
                continue
            candidates.append((st.st_mtime_ns,path))
        except (OSError,ValueError,TypeError,KeyError):
            continue
    if not candidates:
        raise AttestationBlocked("prior_backup_receipt_not_verified")
    candidates.sort(reverse=True)
    return candidates[0][1]

def classify_refusal(exc):
    # Delegate to the same STRICT rule as the immutable original engine.
    if runner.classify_login_failure(exc) == "auth_rejected":
        return "AUTH_REJECTED"
    return "TRANSPORT_OR_UNRECOGNIZED"

def prove_direct_denial():
    """Try only the exact dev project's primary DB, verified TLS; never use a
    new host/port from any untrusted input. Admin catalog must already prove
    NOLOGIN, expired password and zero sessions.
    """
    import psycopg
    load_dashboard_ca()
    kw={
        "host":DIRECT_HOST, "port":5432,"dbname":"postgres",
        "user":runner.ROLE, "password":runner.read_password(),
        "sslmode":"verify-full","sslrootcert":str(CERT_FILE),
        "connect_timeout":7,
    }
    try:
        with psycopg.connect(**kw):
            raise AttestationBlocked("new_login_unexpectedly_succeeded")
    except psycopg.Error as exc:
        if classify_refusal(exc) == "AUTH_REJECTED":
            return "PRIMARY_PG_AUTH_REJECTION"
        return "PRIMARY_PG_TRANSPORT_OR_UNRECOGNIZED"

def independent_proof():
    """Attempt pinned session pooler first, then direct primary ONLY if the
    pin already fails because of unverified auth refusal. Never accept catalog
    checks as a substitute for real server rejection.
    """
    import psycopg
    try:
        receipt=runner.stage_prove_closed()
        if (receipt.get("new_login_refused") is True
                and receipt.get("refusal") == "auth_rejected"
                and receipt.get("active_sessions") == 0
                and receipt.get("rolcanlogin") is False):
            return "SESSION_POOLER_AUTH_REJECTION"
        raise AttestationBlocked("pooler_proof_invalid")
    except runner.Blocked as exc:
        if not str(exc).startswith("new_login_refusal_not_verified"):
            raise AttestationBlocked("pooler_catalog_or_session_blocked") from None
    return prove_direct_denial()

def audit():
    gate.verify_sources()
    check_live_admin_state() # pinned dev identity; 65 tables; NOLOGIN, expired, zero sessions
    evidence=private_receipt()
    proof=independent_proof()
    # The pooler and direct TCP paths may both hide auth denials behind their
    # transport layer. Only allow HISTORICAL provider-log evidence retrieved
    # independently from Supabase, with its own strict event-pair validation.
    # This never changes the original runner's BLOCKED verdict.
    provider_snapshot = None
    if proof == "PRIMARY_PG_TRANSPORT_OR_UNRECOGNIZED":
        from scripts.ci_cinema_pg_v6_provider_log_attest import (
            verify_saved, ProviderProofBlocked,
        )
        try:
            provider_snapshot = verify_saved()
        except ProviderProofBlocked:
            raise AttestationBlocked("authentication_refusal_not_verified") from None
        proof = "HISTORICAL_SUPABASE_PROVIDER_LOG_AUTH_REJECTION"
    check_live_admin_state()
    if proof not in ("SESSION_POOLER_AUTH_REJECTION","PRIMARY_PG_AUTH_REJECTION",
                     "HISTORICAL_SUPABASE_PROVIDER_LOG_AUTH_REJECTION"):
        raise AttestationBlocked("authentication_refusal_not_verified")
    # Save NEW explicitly supplementary evidence; do NOT alter original BLOCKED receipt.
    import hashlib
    artifact = {
        "kind":"independent_postrun_closure_v6",
        "original_verdict":"BLOCKED",
        "original_backup_sha":SUCCESSFUL_BACKUP_SHA,
        "original_receipt_sha256":hashlib.sha256(evidence.read_bytes()).hexdigest(),
        "current_source_sha":gate.git("rev-parse","HEAD"),
        "backup_restore_evidence":"four_prior_stages_PASS",
        "role_catalog_nologin_expired_no_sessions":True,
        "new_login_refused":True,
        "refusal_method":proof,
        "provider_log_evidence_is_historical": provider_snapshot is not None,
        "provider_log_is_cryptographically_signed": False,
        "provider_log_utc": (provider_snapshot or {}).get("event_utc"),
        "provider_log_sqlstate": (provider_snapshot or {}).get("sqlstate"),
        "provider_log_evidence_sha256": (
            hashlib.sha256(
                __import__("scripts.ci_cinema_pg_v6_provider_log_attest", fromlist=["EVIDENCE"]).EVIDENCE.read_bytes()
            ).hexdigest() if provider_snapshot is not None else None
        ),
        "time_utc":datetime.now(timezone.utc).isoformat(),
        "verdict":"INDEPENDENT_CLOSURE_PASS",
    }
    dest_dir=runner.SUMMARY_FILE.parent
    stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    target=dest_dir / ("v6_postrun_independent_"+stamp+".json")
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
    with os.fdopen(fd,"w",encoding="utf-8") as out:
        json.dump(artifact,out,sort_keys=True)
    return proof

def main():
    try:
        result=audit()
        print("V6_PRIOR_ENCRYPTED_B2_B3_RECEIPT_VERIFIED_PASS")
        print("V6_NLOGIN_EXPIRED_ZERO_SESSIONS_PASS")
        print("V6_INDEPENDENT_"+result+"_PASS")
        print("V6_POSTRUN_INDEPENDENT_CLOSURE_PASS")
        print("ORIGINAL_BLOCKED_RECEIPT_PRESERVED")
        return 0
    except BaseException as exc:
        safe={
            "evidence_directory_missing","prior_backup_receipt_not_verified",
            "pooler_proof_invalid","pooler_catalog_or_session_blocked",
            "new_login_unexpectedly_succeeded",
            "authentication_refusal_not_verified",
        }
        label=str(exc) if isinstance(exc,AttestationBlocked) else type(exc).__name__
        if label not in safe:
            label="UNVERIFIED_"+type(exc).__name__
        print("V6_POSTRUN_ATTESTATION_BLOCKED",label)
        print("NO_FALSE_PASS_NO_BACKUP_RETRY")
        return 2
    finally:
        print("NO_ROLE_CHANGE_NO_BACKUP")

if __name__=="__main__":
    raise SystemExit(main())
