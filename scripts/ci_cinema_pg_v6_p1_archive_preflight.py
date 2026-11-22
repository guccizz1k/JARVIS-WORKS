#!/usr/bin/env python3
"""V6 P1 read-only audit of the existing 2026-11-22 encrypted PG17 archive.

No raw backup, password or key is read into logs. No network upload or DB
access occurs. The comparison SHA-256 is pinned to the operator's actual
Codespaces terminal inventory and must be verified against file bytes.
"""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

ARCHIVE_NAME = "cb2e034b07.jwpgbk"
EXPECTED_SIZE = 484971
EXPECTED_SHA256 = "f9163c454d808700b069d3811d34f956f8d31fd11fccff66fe2ba5b740a79ad0"
BACKUP_BASE = Path.home() / ".local" / "share" / "jw-v223-restore" / "backups"
DESTINATION_REPO = "guccizz1k/jw-backup-vault-261111"
DESTINATION_PREFIX = "backups/2026-11-22"
SOURCE_SHA = "175fb490bc2a3236db4d14026c5ca9c2f268729a"

class P1Blocked(Exception):
    pass


def candidate_paths(base: Path = BACKUP_BASE) -> list[Path]:
    # Exact filename. Search only the known private backup directory layout.
    return sorted([base / ARCHIVE_NAME, *base.glob("jw_v223_*/" + ARCHIVE_NAME)])


def verify_existing_archive(base: Path = BACKUP_BASE) -> dict:
    from scripts.pg_backup_v223 import MAGIC

    if base.is_symlink() or not base.is_dir():
        raise P1Blocked("backup_directory_unavailable")
    owner = os.getuid()
    base_stat = base.stat()
    if base_stat.st_uid != owner or base_stat.st_mode & 0o077:
        raise P1Blocked("backup_directory_permissions")
    available = [p for p in candidate_paths(base) if p.exists() or p.is_symlink()]
    if len(available) != 1:
        raise P1Blocked("archive_count_or_location")
    p = available[0]
    if p.is_symlink() or p.parent.is_symlink() or not p.is_file():
        raise P1Blocked("archive_symlink_or_type")
    if p.parent != base:
        ps = p.parent.stat()
        if ps.st_uid != owner or ps.st_mode & 0o077:
            raise P1Blocked("archive_parent_permissions")
    s = p.lstat()
    if (not stat.S_ISREG(s.st_mode) or s.st_uid != owner
            or s.st_nlink != 1 or s.st_mode & 0o077):
        raise P1Blocked("archive_permissions")
    if s.st_size != EXPECTED_SIZE:
        raise P1Blocked("archive_byte_count_mismatch")
    digest = hashlib.sha256()
    blob = hashlib.sha1()
    blob.update(b"blob " + str(s.st_size).encode("ascii") + b"\0")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(p, flags)
    with os.fdopen(fd, "rb") as stream:
        current = os.fstat(stream.fileno())
        if (current.st_ino != s.st_ino or current.st_dev != s.st_dev
                or current.st_size != s.st_size):
            raise P1Blocked("archive_changed_during_open")
        if stream.read(len(MAGIC)) != MAGIC:
            raise P1Blocked("encrypted_header_mismatch")
        stream.seek(0)
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            blob.update(chunk)
        after = os.fstat(stream.fileno())
    if after.st_ino != s.st_ino or after.st_size != s.st_size:
        raise P1Blocked("archive_changed_during_hash")
    computed = digest.hexdigest()
    if computed != EXPECTED_SHA256:
        raise P1Blocked("archive_sha256_mismatch")
    return {
        "sha256": computed,
        "git_blob_sha1": blob.hexdigest(),
        "bytes": s.st_size,
        "archive_name": ARCHIVE_NAME,
        "source_sha": SOURCE_SHA,
        "destination_repo": DESTINATION_REPO,
        "destination_relative_path": DESTINATION_PREFIX + "/" + ARCHIVE_NAME,
        "upload_status": "NOT_RUN_APPROVAL_REQUIRED",
    }


def main() -> int:
    try:
        from scripts.ci_cinema_pg_v6_owner_readonly import verify_sources
        from scripts.ci_cinema_pg_v6_postrun_attest import private_receipt
        verify_sources()
        private_receipt()  # original PINNED source SHA, prior backup/restore stages PASS
        result = verify_existing_archive()
        print("P1_LOCAL_ENCRYPTED_ARCHIVE_MATCH_PASS")
        print("SOURCE_BACKUP_RECEIPT_LINK_PASS")
        for key in ("archive_name", "bytes", "sha256", "git_blob_sha1",
                    "destination_repo", "destination_relative_path", "upload_status"):
            print(key.upper(), result[key])
        return 0
    except BaseException as exc:
        safe = {
            "backup_directory_unavailable", "backup_directory_permissions",
            "archive_count_or_location", "archive_symlink_or_type",
            "archive_parent_permissions", "archive_permissions",
            "archive_byte_count_mismatch", "archive_changed_during_open",
            "encrypted_header_mismatch", "archive_changed_during_hash",
            "archive_sha256_mismatch",
        }
        reason = str(exc) if isinstance(exc, P1Blocked) else type(exc).__name__
        print("P1_ARCHIVE_PREFLIGHT_BLOCKED",
              reason if reason in safe else type(exc).__name__)
        return 2
    finally:
        print("NO_UPLOAD_NO_DECRYPT_NO_ROLE_OR_DB_CHANGE")


if __name__ == "__main__":
    raise SystemExit(main())
