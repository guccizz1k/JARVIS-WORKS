"""Read-only, secret-free classification of the last owner's B2/B3 run.

No DB, subprocess, network, secrets or role changes. Output only fixed labels.
The private files remain on the owner's machine.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

HOME = Path.home() / ".local/share/jw-v223-restore"
SUMMARY = HOME / "last_run_summary.json"
ERROR = HOME / "last_backup_error.log"
STAGES = ("target_ready", "renew", "live_login", "backup_restore_compare", "revoke", "prove_closed")
SAFE_CODES = (
    "BLOCKED_V223_", "FAIL_V223_", "BLOCKED_", "FAIL_",
)
CAUSE_PATTERNS = (
    ("SOURCE_AUTH", ("password authentication failed", "authentication failed", "permission denied for schema", "permission denied for table")),
    ("SOURCE_CONNECTIVITY", ("could not translate host name", "connection refused", "connection timed out", "network is unreachable")),
    ("SOURCE_TLS", ("certificate verify failed", "certificate verify", "ssl error", "tls handshake")),
    ("SOURCE_IDENTITY", ("source identity", "project ref", "fingerprint", "source_is_real_dev_db")),
    ("TARGET_RESTORE", ("pg_restore:", "restore target", "target_proven_ephemeral")),
    ("DUMP_FAILURE", ("pg_dump:", "dump failed")),
    ("ENCRYPTION", ("aes", "decrypt", "invalidtag", "encryption")),
    ("SIGNATURE_COMPARE", ("signature_mismatches", "signature mismatch", "snapshot_consistent")),
    ("TIMEOUT", ("timed out", "timeout")),
)

def safe_read(path: Path, limit: int = 200_000) -> str:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""

def diagnose(summary_text: str, error_text: str) -> list[str]:
    lines = []
    try:
        obj = json.loads(summary_text)
        if not isinstance(obj, dict):
            raise ValueError
    except (ValueError, TypeError):
        return ["DIAG SUMMARY_UNAVAILABLE"]
    stages = obj.get("stages", {})
    if not isinstance(stages, dict):
        stages = {}
    for name in STAGES:
        entry = stages.get(name, {})
        state = entry.get("status", "NOT_RUN") if isinstance(entry, dict) else "NOT_RUN"
        if state not in ("PASS", "BLOCKED", "FAIL", "NOT_RUN"):
            state = "UNKNOWN"
        lines.append("DIAG " + name.upper() + "_" + state)
    backup = stages.get("backup_restore_compare", {})
    reason = backup.get("reason", "") if isinstance(backup, dict) else ""
    if not isinstance(reason, str):
        reason = ""
    combined = (reason + "\n" + error_text).lower()
    # Classify only engine stderr for root cause; the summary can mention identity generically.\n    found = [code for code, words in CAUSE_PATTERNS if any(word in error_text.lower() for word in words)]
    lines.append("DIAG BACKUP_CAUSE_" + (found[0] if found else "UNKNOWN"))
    # The runner already records only the names of failed identity checks.
    # Extract names from its allowlist, never arbitrary error text or DSNs.
    identity_names = ("host", "port", "project_ref", "dbname", "role", "server_major", "schema_fingerprint")
    if "BLOCKED_V223_SOURCE_IDENTITY_NOT_VERIFIED:" in combined.upper():
        tail = combined.upper().split("BLOCKED_V223_SOURCE_IDENTITY_NOT_VERIFIED:", 1)[1]
        token = re.match(r"[a-z_,]+", tail.lower())
        failed = set(token.group(0).split(",")) if token else set()
        for name in identity_names:
            if name in failed:
                lines.append("DIAG IDENTITY_CHECK_" + name.upper() + "_FAILED")
    elif "source identity" in error_text.lower() or "source_identity" in error_text.lower():
        lines.append("DIAG IDENTITY_CHECK_UNSPECIFIED")
    # An unknown identity error must never be presented as an established fingerprint mismatch.

    code_match = re.search(r"(?<![a-z0-9_])(?:BLOCKED_V223_|FAIL_V223_)[A-Z0-9_]{3,80}", error_text + "\\n" + reason)
    if code_match:
        lines.append("DIAG ENGINE_CODE_" + code_match.group(0))
    proof = stages.get("prove_closed", {})
    proof_reason = proof.get("reason", "") if isinstance(proof, dict) else ""
    if not isinstance(proof_reason, str):
        proof_reason = ""
    if "new_login_refusal_not_verified" in proof_reason:
        lines.append("DIAG CLOSE_CAUSE_AUTH_REFUSAL_NOT_PROVEN")
    elif "role not closed" in proof_reason:
        lines.append("DIAG CLOSE_CAUSE_ROLE_STATE")
    elif proof.get("status") == "PASS" if isinstance(proof, dict) else False:
        lines.append("DIAG CLOSE_CAUSE_NONE")
    else:
        lines.append("DIAG CLOSE_CAUSE_UNKNOWN")
    return lines

def main() -> int:
    print("DIAG ERROR_LOG_" + ("AVAILABLE" if safe_read(ERROR) else "UNAVAILABLE"))\n    for line in diagnose(safe_read(SUMMARY), safe_read(ERROR)):
        print(line)
    print("DIAG READ_ONLY_NO_DB_CONTACT")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
