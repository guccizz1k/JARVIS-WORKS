"""Offline-only historical ciphertext format and prior-run evidence inventory.

This inventory never connects to any DB/network, creates no plaintext files,
changes no source archive, and does not report historical backup/restore PASS.
Only bounded, private local data are read. No paths, hashes, secrets or row data
are emitted. A locally recorded PASS is just a historical claim, not a proof.
"""
from __future__ import annotations

import base64
import json
import os
import re
import stat
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from scripts import pg_backup_v223 as backup
from scripts import p1_owner_one_shot_v223 as one

MAX_RECEIPT_BYTES = 65536
MAX_ERROR_LOG_BYTES = 16384


def _owner_private_bytes(path: Path, limit: int) -> bytes | None:
    """Open no-follow, owner-only 0600, bounded; return no data to CLI."""
    try:
        if path.is_symlink():
            return None
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as fh:
            st = os.fstat(fh.fileno())
            if not (stat.S_ISREG(st.st_mode)
                    and stat.S_IMODE(st.st_mode) == 0o600
                    and st.st_size <= limit
                    and (not hasattr(os, "getuid") or st.st_uid == os.getuid())):
                return None
            data = fh.read(limit + 1)
            return data if len(data) <= limit else None
    except (OSError, ValueError):
        return None


def _single_chunk_postgres_magic(path: Path, key: bytes) -> str:
    """Authenticate only first GCM chunk in memory. Whole-file auth is
    checked separately by one.inspect_local_candidates(). No plaintext copy.
    This is format screening, NOT a complete pg_restore verification.
    """
    if not one._private_cipher_file(path) or len(key) != 32:
        return "NOT_CONFIRMED"
    try:
        with open(path, "rb", opener=lambda p, f: os.open(p, f | getattr(os, "O_NOFOLLOW", 0))) as fh:
            magic = fh.read(len(backup.MAGIC))
            if magic not in (backup.MAGIC, backup.MAGIC_LEGACY):
                return "NOT_POSTGRES_CUSTOM"
            n = 8 if magic == backup.MAGIC else 4
            prefix = fh.read(n)
            length_raw = fh.read(4)
            if len(prefix) != n or len(length_raw) != 4:
                return "NOT_CONFIRMED"
            length = struct.unpack(">I", length_raw)[0]
            if not 16 <= length <= backup.MAX_CHUNK_CIPHERTEXT:
                return "NOT_CONFIRMED"
            blob = fh.read(length)
            next_byte = fh.read(1)
            if len(blob) != length:
                return "NOT_CONFIRMED"
            final = not next_byte
            clear = AESGCM(key).decrypt(backup._nonce(prefix, 0), blob,
                                        backup._aad(0, final, magic))
            if not clear.startswith(b"PGDMP"):
                return "NOT_POSTGRES_CUSTOM"
            # PostgreSQL custom archive major is 1; reject arbitrary data that
            # starts with the five-byte marker but has no plausible version.
            if len(clear) < 7 or clear[5] != 1 or not 0 <= clear[6] <= 99:
                return "NOT_POSTGRES_CUSTOM"
            return "AUTHENTICATED_PGDMP_HEADER_ONLY"
    except (OSError, InvalidTag, ValueError, backup.BackupError):
        return "NOT_CONFIRMED"


def _owner_history_status() -> dict[str, str]:
    """Only finite labels from previously held owner-only private records."""
    result = {
        "historical_owner_receipt": "UNAVAILABLE",
        "historical_owner_b2b3_stage": "NOT_CONFIRMED",
        "historical_error_log": "UNAVAILABLE",
        "historical_reported_signature_mismatch": "NOT_CONFIRMED",
        "historical_reported_tables_65": "NOT_CONFIRMED",
    }
    root = one._owner_backup_dir().parent
    if not one._private_directory(root):
        return result
    receipt = one._candidate_owner_receipt()
    if receipt:
        raw = _owner_private_bytes(Path(receipt), MAX_RECEIPT_BYTES)
        if raw is not None:
            try:
                data = json.loads(raw)
                if isinstance(data, dict):
                    v = data.get("verdict")
                    result["historical_owner_receipt"] = (
                        "REPORTED_BLOCKED_NOT_PROOF" if v == "BLOCKED"
                        else "REPORTED_PASS_NOT_PROOF" if v == "PASS"
                        else "PRESENT_STATUS_UNVERIFIED")
                    stage = data.get("stages", {})
                    if isinstance(stage, dict):
                        b2 = stage.get("real_encrypted_backup_independent_restore")
                        if b2 is None:
                            b2 = stage.get("backup_restore_compare")
                        if b2 == "PASS" or (isinstance(b2, dict) and b2.get("status") == "PASS"):
                            result["historical_owner_b2b3_stage"] = "REPORTED_PASS_NOT_PROOF"
                        elif b2 is not None:
                            result["historical_owner_b2b3_stage"] = "REPORTED_NOT_PASS"
            except (ValueError, UnicodeError, TypeError):
                result["historical_owner_receipt"] = "INVALID_UNTRUSTED_RECORD"
    raw_error = _owner_private_bytes(root / "last_backup_error.log", MAX_ERROR_LOG_BYTES)
    if raw_error is None:
        return result
    result["historical_error_log"] = "PRESENT_UNTRUSTED_PRIOR_RUN"
    # This was saved as a last 2k-character stdout tail. Parse strictly
    # bounded evidence hints; do not infer unseen source identity.
    try:
        s = raw_error.decode("utf-8", "replace")[-MAX_ERROR_LOG_BYTES:]
        if "--- stdout (tail) ---" not in s:
            return result
        s = s.split("--- stdout (tail) ---", 1)[1].split("--- stderr (tail) ---", 1)[0]
        if re.search(r'"signature_mismatches"\s*:\s*\[', s):
            result["historical_reported_signature_mismatch"] = "LIST_PRESENT_NOT_INDEPENDENTLY_VERIFIED"
        t = re.search(r'"tables"\s*:\s*(\d{1,5})\b', s)
        if t:
            result["historical_reported_tables_65"] = (
                "REPORTED_65_NOT_INDEPENDENTLY_VERIFIED"
                if t.group(1) == "65" else "REPORTED_OTHER_COUNT")
    except (ValueError, TypeError):
        pass
    return result


def generate_inventory() -> dict[str, object]:
    """No writes and no network; even 11 successful keys cannot prove source."""
    archives, discovery = one.discover_owner_archive()
    result: dict[str, object] = {
        "inventory_execution": "PASS",
        "archive_discovery": discovery,
        "private_archive_count": len(archives),
        "aes_gcm_full_archive_authenticated": 0,
        "postgres_custom_header_authenticated": 0,
        "not_postgres_custom_header_count": 0,
        "header_unconfirmed_count": 0,
        "independent_archive_receipt_verified": False,
        "actual_65_table_restore": "NOT_RUN",
        "remote_storage_attested": False,
        "overall": "BLOCKED",
    }
    result.update(_owner_history_status())
    key_text = os.environ.get("JW_PG_BACKUP_KEY", "")
    if not archives or not key_text:
        result["crypto_probe"] = "NO_ARCHIVES_OR_KEY"
        return result
    try:
        key = backup.load_key(key_text)
    except backup.BackupError:
        result["crypto_probe"] = "INVALID_KEY"
        return result
    audited, _ = one.inspect_local_candidates(archives, "", key_text)
    result["aes_gcm_full_archive_authenticated"] = audited["key_authenticated_candidate_count"]
    result["crypto_probe"] = audited["candidate_key_authentication"]
    # Bound header probes by the same original 16-candidate scan limit.
    if len(archives) > 16:
        result["crypto_probe"] = "MORE_THAN_16_CANDIDATES"
        return result
    # Only probe header for individual candidates within the original size
    # limits. A header-only check does not replace complete authentication.
    for path in archives:
        try:
            if path.lstat().st_size > one.MAX_AUTH_CANDIDATE_BYTES:
                result["header_unconfirmed_count"] += 1
                continue
            label = _single_chunk_postgres_magic(path, key)
        except OSError:
            label = "NOT_CONFIRMED"
        if label == "AUTHENTICATED_PGDMP_HEADER_ONLY":
            result["postgres_custom_header_authenticated"] += 1
        elif label == "NOT_POSTGRES_CUSTOM":
            result["not_postgres_custom_header_count"] += 1
        else:
            result["header_unconfirmed_count"] += 1
    return result


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args != ["inventory"]:
        print("USAGE: python -m scripts.p1_owner_archive_inventory_v223 inventory", file=sys.stderr)
        return 2
    try:
        report = generate_inventory()
    except Exception:
        print('{"inventory_execution":"BLOCKED","overall":"BLOCKED","reason":"SAFE_INVENTORY_ERROR"}')
        return 1
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0  # Diagnostic PASS only, NEVER historical backup/restore PASS.


if __name__ == "__main__":
    raise SystemExit(main())
