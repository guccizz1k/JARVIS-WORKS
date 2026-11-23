"""Owner-local historical archive TOC and mismatch-category analysis.

No network, no DB access, no plaintext disk artifacts, no remote upload.
PG17 pg_restore --list receives AES-GCM-authenticated bytes on stdin. Its
untrusted stdout/stderr are NEVER copied to console; only aggregate counts.
In-memory TOC validity and untrusted historic error logs are NOT source parity.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from scripts import pg_backup_v223 as backup
from scripts import p1_owner_one_shot_v223 as one
from scripts import p1_owner_archive_inventory_v223 as previous

MAX_PLAIN_BYTES = 32 * 1024 * 1024
MAX_TOTAL_PLAIN_BYTES = 160 * 1024 * 1024
MAX_TOC_OUTPUT_BYTES = 4 * 1024 * 1024
CATEGORIES = ("tables", "policies", "functions", "triggers",
              "indexes", "constraints", "acl", "rows", "schema")
TABLE_PATTERN = re.compile(rb"^\d+;\s+\d+\s+\d+\s+TABLE\s+jw_dev\s+", re.M)
PGDMP_PATTERN = re.compile(rb"^PGDMP\x01")


def authenticated_plain_in_memory(path: Path, limit: int = MAX_PLAIN_BYTES) -> bytearray:
    """Bounded owner-only in-memory AES-256-GCM V1/V2 decryption.

    Never selects an archive by name, never returns any plaintext to callers
    except the local trusted pg_restore parser, never writes a plaintext file.
    """
    path = Path(path)
    if not one._private_cipher_file(path):
        raise backup.BackupError("BLOCKED_UNSAFE_ARCHIVE")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    out = bytearray()
    try:
        with os.fdopen(fd, "rb") as fh:
            s = os.fstat(fh.fileno())
            if not (stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode) == 0o600
                    and (not hasattr(os, "getuid") or s.st_uid == os.getuid())):
                raise backup.BackupError("BLOCKED_UNSAFE_ARCHIVE")
            if s.st_size > limit + (limit // backup.CHUNK + 2) * 32 + 32:
                raise backup.BackupError("BLOCKED_ARCHIVE_SIZE_LIMIT")
            magic = fh.read(len(backup.MAGIC))
            if magic not in (backup.MAGIC, backup.MAGIC_LEGACY):
                raise backup.BackupError("BLOCKED_ARCHIVE_FORMAT")
            prefix_len = 8 if magic == backup.MAGIC else 4
            prefix = fh.read(prefix_len)
            if len(prefix) != prefix_len:
                raise backup.BackupError("BLOCKED_ARCHIVE_TRUNCATED")
            key = backup.load_key()
            aes = AESGCM(key)
            index = 0
            while True:
                raw = fh.read(4)
                if len(raw) != 4:
                    raise backup.BackupError("BLOCKED_ARCHIVE_TRUNCATED")
                n = struct.unpack(">I", raw)[0]
                if not 16 <= n <= backup.MAX_CHUNK_CIPHERTEXT:
                    raise backup.BackupError("BLOCKED_ARCHIVE_BAD_LENGTH")
                blob = fh.read(n)
                if len(blob) != n:
                    raise backup.BackupError("BLOCKED_ARCHIVE_TRUNCATED")
                peek = fh.read(1)
                final = not peek
                if peek:
                    fh.seek(-1, os.SEEK_CUR)
                try:
                    data = aes.decrypt(backup._nonce(prefix, index), blob,
                                       backup._aad(index, final, magic))
                except InvalidTag:
                    raise backup.BackupError("BLOCKED_ARCHIVE_AUTH_FAILURE") from None
                if len(out) + len(data) > limit:
                    raise backup.BackupError("BLOCKED_ARCHIVE_SIZE_LIMIT")
                out.extend(data)
                if final:
                    break
                index += 1
            if not PGDMP_PATTERN.match(out):
                raise backup.BackupError("BLOCKED_ARCHIVE_NOT_PGDMP")
            return out
    except BaseException:
        out.clear()
        raise


def pg17_toc_counts(plain: bytearray) -> tuple[str, int]:
    """List archive TOC using PG17 binary; no connection flags or DB env."""
    binary = shutil.which("pg_restore")
    if not binary:
        return "PG17_RESTORE_BINARY_MISSING", 0
    try:
        major = backup.tool_major(binary)
    except (backup.BackupError, OSError, subprocess.SubprocessError):
        return "PG17_BINARY_VERSION_UNKNOWN", 0
    if major != 17:
        return "PG17_BINARY_VERSION_NOT_17", 0
    try:
        done = subprocess.run(
            [binary, "--list"], input=bytes(plain), capture_output=True,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C",
                 "LC_ALL": "C"}, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return "PG17_TOC_TOOL_FAILED", 0
    if done.returncode or len(done.stdout) > MAX_TOC_OUTPUT_BYTES:
        return "PG17_TOC_PARSE_FAILED", 0
    entries = TABLE_PATTERN.findall(done.stdout)
    return "PG17_TOC_PARSED_NOT_RESTORED", len(entries)


def historic_log_mismatch_categories() -> dict[str, object]:
    """ONLY if complete JSON list exists in the bounded historical stdout tail."""
    result: dict[str, object] = {
        "historical_signature_list": "UNAVAILABLE",
        "historical_mismatch_categories": [],
        "historical_mismatch_total_reported": None,
        "historic_log_independent_proof": False,
    }
    root = one._owner_backup_dir().parent
    if not one._private_directory(root):
        return result
    raw = previous._owner_private_bytes(root / "last_backup_error.log", 16384)
    if raw is None:
        return result
    try:
        text = raw.decode("utf-8", "replace")
        head = text.split("--- stdout (tail) ---", 1)
        if len(head) < 2:
            result["historical_signature_list"] = "NO_SAVED_STDOUT"
            return result
        portion = head[1].split("--- stderr (tail) ---", 1)[0][-2300:]
        match = re.search(r'"signature_mismatches"\s*:\s*', portion)
        if not match:
            result["historical_signature_list"] = "NOT_IN_SAVED_TAIL"
            return result
        try:
            values, _ = json.JSONDecoder().raw_decode(portion[match.end():].lstrip())
        except (ValueError, TypeError):
            result["historical_signature_list"] = "TRUNCATED_OR_INVALID_JSON"
            return result
        if not isinstance(values, list) or len(values) > 5000:
            result["historical_signature_list"] = "INVALID_LIST_FORMAT"
            return result
        if not all(isinstance(x, str) and len(x) < 256 for x in values):
            result["historical_signature_list"] = "INVALID_LIST_FORMAT"
            return result
        result["historical_signature_list"] = ("REPORTED_EMPTY_NOT_PROOF"
                                                if not values else "REPORTED_NONEMPTY_NOT_PROOF")
        result["historical_mismatch_total_reported"] = len(values)
        result["historical_mismatch_categories"] = [
            c.upper() for c in CATEGORIES
            if any(x.startswith(c + ":") for x in values)
        ]
        if values and not result["historical_mismatch_categories"]:
            result["historical_mismatch_categories"] = ["UNKNOWN"]
    except (OSError, TypeError, ValueError):
        result["historical_signature_list"] = "UNREADABLE"
    return result


def deep_inventory() -> dict[str, object]:
    """One bounded owner-local pass; no historical PASS upgraded by this scan."""
    report = previous.generate_inventory()
    report.update(historic_log_mismatch_categories())
    report.update({
        "pg17_toc_examined": 0, "pg17_toc_65_table_archives": 0,
        "pg17_toc_other_table_archives": 0, "pg17_toc_unavailable_or_failed": 0,
        "pg17_toc_skipped_budget": 0,
        "toc_checks_are_restores": False,
        "historic_independent_65_table_restore": "NOT_RUN",
        "overall": "BLOCKED",
    })
    archives, _ = one.discover_owner_archive()
    if not os.environ.get("JW_PG_BACKUP_KEY") or len(archives) > 16:
        report["toc_probe"] = "KEY_UNAVAILABLE_OR_TOO_MANY"
        return report
    binary = shutil.which("pg_restore")
    if not binary:
        report["toc_probe"] = "PG17_RESTORE_BINARY_MISSING"
        return report
    try:
        if backup.tool_major(binary) != 17:
            report["toc_probe"] = "PG17_BINARY_VERSION_NOT_17"
            return report
    except (backup.BackupError, OSError, subprocess.SubprocessError):
        report["toc_probe"] = "PG17_BINARY_VERSION_UNKNOWN"
        return report
    spent = 0
    for archive in archives:
        try:
            size = archive.lstat().st_size
            remaining = MAX_TOTAL_PLAIN_BYTES - spent
            if remaining <= 0 or size > MAX_PLAIN_BYTES + 1280:
                report["pg17_toc_skipped_budget"] += 1
                continue
            raw = authenticated_plain_in_memory(
                archive, min(MAX_PLAIN_BYTES, remaining))
            spent += len(raw)
            try:
                status, count = pg17_toc_counts(raw)
            finally:
                raw.clear()
            if status == "PG17_TOC_PARSED_NOT_RESTORED":
                report["pg17_toc_examined"] += 1
                if count == 65:
                    report["pg17_toc_65_table_archives"] += 1
                else:
                    report["pg17_toc_other_table_archives"] += 1
            else:
                report["pg17_toc_unavailable_or_failed"] += 1
        except (backup.BackupError, OSError, ValueError, TypeError):
            report["pg17_toc_unavailable_or_failed"] += 1
    report["toc_probe"] = "LOCAL_ONLY_NO_DB_CONNECTION"
    return report


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args != ["deep-inventory"]:
        print("USAGE: python -m scripts.p1_owner_archive_deep_v223 deep-inventory", file=sys.stderr)
        return 2
    try:
        report = deep_inventory()
    except Exception:
        print('{"overall":"BLOCKED","diagnostic":"UNEXPECTED_DEEP_INVENTORY_ERROR"}')
        return 1
    # No raw PG TOC, paths, hashes, SQL, credentials or historic log contents.
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0  # Diagnostic execution can PASS, historic parity still BLOCKED.


if __name__ == "__main__":
    raise SystemExit(main())
