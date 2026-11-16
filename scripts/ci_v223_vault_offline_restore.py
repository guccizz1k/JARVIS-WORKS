"""Owner-only offline restoration of EXISTING encrypted vault artifacts.

No source Postgres connection, role renewal, network I/O, or GitHub authentication.
Runs only against a separately provisioned, empty, marker-bound local PG17 target.
Success here verifies archived ciphertext and isolated restore, NOT live B2,
same-snapshot source parity, complete DR, or release readiness.

Required inside the owner's secured Codespace:
  JW_PG_EXISTING_ARCHIVE=/absolute/path/to/private/existing.jwpgbk
  JW_PG_BACKUP_KEY=<existing secret via Codespaces secret only>
  JW_PG_EXPECT_ARCHIVE_GIT_SHA=<verified private vault blob SHA via owner only>
  JW_PG_TARGET_ADMIN_DSN=<ephemeral localhost PG17 URL, never production>
  JW_PG_TARGET_EPHEMERAL_TOKEN=<existing target marker token>
  JW_PG_CI_ALLOW=ONLY_EPHEMERAL_LOCAL_DATABASE
Run: python -m scripts.ci_v223_vault_offline_restore

Do not place the archive, plaintext or key in the PUBLIC JARVIS-WORKS repo.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import sys
import tempfile
import time
from pathlib import Path

from scripts import pg_backup_v223 as pb

# The private vault's file names and blob hashes are never committed to
# this public repository. The expected Git blob ID must be independently
# obtained inside the owner's private environment.
MAX_CIPHER_SIZE = 100 * 1024 * 1024
ALLOWED_ARCHIVE_NAME = re.compile(r"^[A-Za-z0-9_-]{6,96}\.jwpgbk$")
GIT_BLOB_ID = re.compile(r"^[a-f0-9]{40}$")


def verify_vault_file(path: Path, expected_git_blob: str) -> bool:
    """Check private blob identity and framing without logging paths or filenames."""
    path = Path(path)
    if (not path.is_absolute() or not ALLOWED_ARCHIVE_NAME.fullmatch(path.name)
            or not GIT_BLOB_ID.fullmatch(expected_git_blob or "")):
        raise pb.BackupError("BLOCKED_V223_VAULT_ARCHIVE_NOT_ALLOWLISTED")
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise pb.BackupError("BLOCKED_V223_VAULT_ARCHIVE_NOT_REGULAR")
    if not 32 <= metadata.st_size <= MAX_CIPHER_SIZE:
        raise pb.BackupError("BLOCKED_V223_VAULT_ARCHIVE_SIZE")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        current = os.fstat(fd)
        if not stat.S_ISREG(current.st_mode) or current.st_ino != metadata.st_ino or current.st_dev != metadata.st_dev:
            raise pb.BackupError("BLOCKED_V223_VAULT_ARCHIVE_RACE")
        git = hashlib.sha1(b"blob " + str(current.st_size).encode("ascii") + b"\0")
        with os.fdopen(fd, "rb") as source:
            fd = -1
            if source.read(len(pb.MAGIC)) != pb.MAGIC:
                raise pb.BackupError("BLOCKED_V223_VAULT_BAD_MAGIC")
            source.seek(0)
            while chunk := source.read(1024 * 1024):
                git.update(chunk)
        if git.hexdigest() != expected_git_blob:
            raise pb.BackupError("BLOCKED_V223_VAULT_GIT_BLOB_MISMATCH")
        return True
    finally:
        if fd >= 0:
            os.close(fd)


def ephemeral_target_options(dsn: str, environ: dict | None = None) -> dict:
    env = os.environ if environ is None else environ
    if env.get("JW_PG_CI_ALLOW") != "ONLY_EPHEMERAL_LOCAL_DATABASE":
        raise pb.BackupError("BLOCKED_V223_TARGET_NOT_DECLARED_EPHEMERAL")
    parsed = pb.parse_dsn(dsn)
    if parsed["host"] not in ("127.0.0.1", "localhost", "::1") or parsed["dbname"] != "postgres":
        raise pb.BackupError("BLOCKED_V223_OFFLINE_TARGET_MUST_BE_LOCAL_POSTGRES")
    if len(env.get(pb.EPHEMERAL_TOKEN_ENV, "")) < 16:
        raise pb.BackupError("BLOCKED_V223_TARGET_TOKEN_NOT_SET")
    return parsed


def _negative_controls(cipher: Path, key: bytes, directory: Path) -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    outcomes = {}
    for kind in ("tamper", "truncation"):
        altered, decrypted = directory / (kind + ".jwpgbk"), directory / (kind + ".dump")
        pb.write_negative_cipher_copy(cipher, altered, kind)
        try:
            try:
                pb.decrypt_file(altered, decrypted, key)
            except pb.BackupError:
                outcomes[kind + "_rejected"] = True
            else:
                outcomes[kind + "_rejected"] = False
        finally:
            altered.unlink(missing_ok=True)
            decrypted.unlink(missing_ok=True)
    output = directory / "wrongkey.dump"
    try:
        pb.decrypt_file(cipher, output, AESGCM.generate_key(256))
    except pb.BackupError:
        outcomes["wrong_key_rejected"] = True
    else:
        outcomes["wrong_key_rejected"] = False
    finally:
        output.unlink(missing_ok=True)
    if not all(outcomes.values()):
        raise pb.BackupError("FAIL_V223_OFFLINE_NEGATIVE_CONTROL")
    return outcomes


def run(archive: Path, dsn: str, key: bytes, expected_git_blob: str) -> dict:
    import psycopg
    from psycopg import sql

    opts = ephemeral_target_options(dsn)
    pb.require_pg17_tools()
    verify_vault_file(archive, expected_git_blob)
    with psycopg.connect(dsn, autocommit=True) as target:
        pb.verify_ephemeral_target(target)  # Requires independently marked EMPTY disposable PG17.

    restore_db = "jw_v223_" + secrets.token_hex(5)
    created = False
    started = time.monotonic()
    # All plaintext files live only inside an OS-protected temporary directory.
    with tempfile.TemporaryDirectory(prefix="jw-v223-vault-restore-") as tmp:
        workspace = Path(tmp)
        clear = workspace / "recovered.dump"
        try:
            digest = pb.decrypt_file(archive, clear, key)  # AES-GCM per chunk, final framing checked.
            if clear.stat().st_size < 8:
                raise pb.BackupError("FAIL_V223_OFFLINE_DUMP_TOO_SMALL")
            with clear.open("rb") as stream:
                if stream.read(5) != b"PGDMP":
                    raise pb.BackupError("FAIL_V223_OFFLINE_NOT_CUSTOM_PGDUMP")
            pb.run_tool(["pg_restore", "--list", str(clear)], opts, 60)
            negative = _negative_controls(archive, key, workspace)
            with psycopg.connect(dsn, autocommit=True) as target:
                pb.verify_ephemeral_target(target)
                target.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(restore_db)))
                created = True
            # Skipping target-local ACL grants prevents trying to recreate any privileged
            # source principals. Therefore ACL parity is explicitly NOT verified.
            restore_opts = {**opts, "dbname": restore_db}
            pb.run_tool(["pg_restore", "--no-owner", "--no-privileges",
                "--exit-on-error", "--dbname", restore_db, str(clear)], restore_opts, 600)
            with psycopg.connect(pb.dsn_with_dbname(dsn, restore_db)) as readback:
                sig = pb.fetch_signature(readback, "jw_dev")
            if not sig["tables"]:
                raise pb.BackupError("FAIL_V223_OFFLINE_EMPTY_JW_DEV")
            tables = len(sig["tables"])
            rls = sum(1 for row in sig["tables"] if row[1] is True)
            force_rls = sum(1 for row in sig["tables"] if row[2] is True)
            return {
                "scope": "EXISTING_VAULT_AUTHENTICATED_OFFLINE_RESTORE",
                "vault_blob_identity_verified": True,
                "authenticated_ciphertext": True,
                "plaintext_sha256": digest,
                "target_proven_ephemeral": True,
                "restore_verified": True,
                "negative_controls": negative,
                "schema": "jw_dev",
                "tables": tables, "rls": rls, "force_rls": force_rls,
                "policies": len(sig["policies"]),
                "functions": len(sig["functions"]),
                "triggers": len(sig["triggers"]),
                "signature_sha256": pb.signature_digest(sig),
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "real_source_snapshot_parity": "NOT_VERIFIED",
                "source_database_contacted": False,
                "acl_parity": "NOT_VERIFIED",
                "b2_live_backup": "NOT_RUN",
                "b3_existing_archive_restore": "PASS",
                "release_gate": "BLOCKED",
            }
        finally:
            clear.unlink(missing_ok=True)
            if created:
                # This can only affect the independently marker-proven ephemeral target.
                with psycopg.connect(dsn, autocommit=True) as target:
                    target.execute(sql.SQL("DROP DATABASE IF EXISTS {}")
                                   .format(sql.Identifier(restore_db)))


def main() -> int:
    path = os.environ.get("JW_PG_EXISTING_ARCHIVE", "")
    dsn = os.environ.get("JW_PG_TARGET_ADMIN_DSN", "")
    expected = os.environ.get("JW_PG_EXPECT_ARCHIVE_GIT_SHA", "")
    try:
        if not path:
            raise pb.BackupError("BLOCKED_V223_EXISTING_VAULT_ARCHIVE_REQUIRED")
        if not dsn:
            raise pb.BackupError("BLOCKED_V223_EPHEMERAL_DSN_REQUIRED")
        key = pb.load_key()
        result = run(Path(path), dsn, key, expected)
    except pb.BackupError as error:
        # Stable bounded code only: never leak paths, DSNs, keys or PostgreSQL rows.
        print(str(error).split(":", 1)[0].split(" ", 1)[0], file=sys.stderr)
        return 2
    except Exception as error:
        print("BLOCKED_V223_OFFLINE_UNEXPECTED_" + type(error).__name__, file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
