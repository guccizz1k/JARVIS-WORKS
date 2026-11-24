"""Recover ONLY provider-downloaded private ciphertexts into networkless PG17.

Uses the already-approved owner Codespace and its existing in-memory AES-GCM
key, never transfers the key or plaintext to GitHub. Provider blobs are
retrieved at an EXACT pinned Git commit, checked with Git blob SHA1 + SHA256,
then independently fed to the existing offline PG17 restore engine from
0600 temporary encrypted copies. Original 11 backups are used only as
selection hashes; never as restore input. Failure causes cleanup and NO-GO.

This demonstrates remote-ciphertext recoverability with the EXISTING OWNER KEY;
it DOES NOT prove a separately escrowed recovery key, immutable retention,
historic signed provenance or safe production restore.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

from scripts import p1_owner_vault_upload_v223 as upload
from scripts import p1_owner_vault_readback_v223 as vault
from scripts import p1_owner_offline_restore_v223 as offline
from scripts import pg_backup_v223 as backup

ACK = "OWNER_APPROVES_PRIVATE_REMOTE_NETWORKLESS_RECOVERY"
PIN_ENV = "JW_PG_VAULT_EXPECTED_SHA"
LIMIT = 32 * 1024 * 1024
TOTAL = 128 * 1024 * 1024
SHA1 = re.compile(r"^[0-9a-f]{40}$")
MAGICS = (b"JWPGBK1\n", b"JWPGBK2\n")


class Blocked(vault.Blocked):
    pass


def _preflight() -> str:
    if os.environ.get("CODESPACES","").lower() != "true":
        return "OWNER_CODESPACE_REQUIRED"
    if os.environ.get("JW_PG_VAULT_READBACK_ACK") != vault.ACK:
        return "OWNER_PRIVATE_VAULT_READBACK_ACK_REQUIRED"
    if os.environ.get("JW_PG_REMOTE_RECOVERY_ACK") != ACK:
        return "OWNER_REMOTE_NETWORKLESS_RECOVERY_ACK_REQUIRED"
    if os.environ.get("JW_PG_OFFLINE_RESTORE_ACK") != offline.ACK:
        return "OWNER_EXISTING_OFFLINE_RESTORE_ACK_REQUIRED"
    if not SHA1.fullmatch(os.environ.get(PIN_ENV,"")):
        return "PINNED_PRIVATE_VAULT_SHA_REQUIRED"
    if offline._preflight() != "PASS":
        return "NETWORKLESS_PG17_PRECONDITIONS_NOT_MET"
    try:
        backup.load_key()
    except backup.BackupError:
        return "OWNER_EXISTING_AES_KEY_NOT_AVAILABLE"
    return "PASS"


def _cipher_from_provider(blob_id: str, expected_sha256: str) -> bytearray:
    """Provider bytes stay in memory until written ONLY to owner-private tmp."""
    if not SHA1.fullmatch(blob_id) or not re.fullmatch(r"[0-9a-f]{64}",expected_sha256):
        raise Blocked("REMOTE_ARCHIVE_IDENTIFIERS_INVALID")
    raw = vault._vault_api_json(
        "repos/guccizz1k/jw-backup-vault-261111/git/blobs/"+blob_id,
        max_bytes=2*LIMIT+8192, timeout=90)
    encoded = raw.get("content")
    size = raw.get("size")
    if (raw.get("sha") != blob_id or raw.get("encoding") != "base64"
            or not isinstance(encoded,str) or not isinstance(size,int)
            or isinstance(size,bool) or not 16<size<=LIMIT
            or len(encoded)>2*LIMIT):
        raise Blocked("REMOTE_CIPHERTEXT_PROVIDER_METADATA_INVALID")
    try:
        ciphertext = bytearray(base64.b64decode("".join(encoded.split()), validate=True))
    except (ValueError,binascii.Error):
        raise Blocked("REMOTE_CIPHERTEXT_PROVIDER_ENCODING_INVALID") from None
    try:
        if (len(ciphertext)!=size or ciphertext[:8] not in MAGICS
            or hashlib.sha1(b"blob "+str(size).encode("ascii")+b"\0"+ciphertext).hexdigest()!=blob_id
            or hashlib.sha256(ciphertext).hexdigest()!=expected_sha256):
            raise Blocked("REMOTE_CIPHERTEXT_HASH_OR_MAGIC_MISMATCH")
        return ciphertext
    except BaseException:
        ciphertext.clear()
        raise


def _write_private_cipher(root: Path, index: int, encrypted: bytearray) -> Path:
    if (stat.S_IMODE(root.stat().st_mode)!=0o700
        or root.is_symlink() or not 0<=index<11):
        raise Blocked("TEMP_CIPHERTEXT_DIRECTORY_UNSAFE")
    path = root / f"provider_only_{index:02d}.jwpgbk"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os,"O_NOFOLLOW",0)
    try:
        fd = os.open(path,flags,0o600)
        with os.fdopen(fd,"wb") as stream:
            stream.write(encrypted)
            stream.flush()
            os.fsync(stream.fileno())
        if (path.is_symlink() or stat.S_IMODE(path.stat().st_mode)!=0o600
                or path.stat().st_size!=len(encrypted)):
            raise Blocked("TEMP_CIPHERTEXT_FILE_UNSAFE")
        return path
    except OSError:
        raise Blocked("TEMP_CIPHERTEXT_WRITE_FAILED") from None


def recover() -> dict:
    result = {
        "remote_disaster_recovery": "BLOCKED",
        "provider_sha256_authenticated_download_count": 0,
        "remote_only_disposable_pg17_restore_count": 0,
        "remote_only_pg17_65_table_count": 0,
        "remote_only_pg17_failed_count": 0,
        "downloaded_temporary_ciphertexts_removed": "NOT_RUN",
        "networkless_disposable_container_removed": "NOT_RUN",
        "source_database_contacted": False,
        "original_owner_ciphertexts_used_as_restore_input": False,
        "independent_off_codespaces_key_escrow": "NOT_VERIFIED",
        "immutable_provider_retention": "NOT_VERIFIED",
        "historic_signed_source_provenance": "NOT_VERIFIED",
        "overall": "BLOCKED",
    }
    ready = _preflight()
    if ready!="PASS":
        result["blocker"]=ready
        return result
    try:
        local=upload.local_files()
        if len(local)!=11:
            raise Blocked("OWNER_ELEVEN_ORIGINAL_CIPHER_SELECTION_MISSING")
        pin=os.environ[PIN_ENV]
        previous=vault._vault_api_readback(
            {key:item[1] for key,item in local.items()},pin)
        if not (previous.get("remote_commit_pinned") is True
                and previous.get("readback_transport")=="GH_REST_BLOB_BASE64_VERIFIED"
                and previous.get("all_11_archives_offsite") is True
                and previous.get("remote_unique_full_sha256_matches")==11
                and previous.get("local_archives_not_offsite")==0):
            raise Blocked("REMOTE_ELEVEN_OWNER_BACKUPS_NOT_INDEPENDENTLY_VERIFIED")
        spent=0
        with tempfile.TemporaryDirectory(prefix="jw-remote-only-cipher-") as dirname:
            root=Path(dirname)
            temporary=[]
            for i,blob_id in enumerate(sorted(local)):
                original_sha256=local[blob_id][1]
                content=_cipher_from_provider(blob_id,original_sha256)
                try:
                    spent+=len(content)
                    if spent>TOTAL:
                        raise Blocked("REMOTE_CIPHER_DOWNLOAD_TOTAL_BUDGET_EXCEEDED")
                    temporary.append(_write_private_cipher(root,i,content))
                    result["provider_sha256_authenticated_download_count"]+=1
                finally:
                    content.clear()
            if len(temporary)!=11:
                raise Blocked("REMOTE_CIPHER_DOWNLOAD_INCOMPLETE")
            # Scoped override only within this Python process; DO NOT fall back
            # to owner originals for restoration. Always reinstate the exact
            # original discovery function, including after any exception.
            original_discover=offline.owner.discover_owner_archive
            try:
                offline.owner.discover_owner_archive=lambda:(tuple(temporary),"REMOTE_ONLY_VERIFIED")
                restored=offline.run_offline()
            finally:
                offline.owner.discover_owner_archive=original_discover
            result["remote_only_disposable_pg17_restore_count"]=restored.get(
                "offline_restored_archive_count",0)
            result["remote_only_pg17_65_table_count"]=restored.get(
                "offline_65_table_archive_count",0)
            result["remote_only_pg17_failed_count"]=restored.get(
                "offline_restore_failure_count",0)
            result["networkless_disposable_container_removed"]=restored.get(
                "container_removed","NOT_RUN")
            if not (restored.get("offline_restore_execution")=="PASS_LOCAL_ONLY"
                    and restored.get("offline_restored_archive_count")==11
                    and restored.get("offline_65_table_archive_count")==11
                    and restored.get("offline_restore_failure_count")==0
                    and restored.get("offline_restore_skipped_budget_count")==0
                    and restored.get("container_removed")=="PASS"):
                raise Blocked("REMOTE_ONLY_PG17_RESTORE_NOT_FULLY_VERIFIED")
        result["downloaded_temporary_ciphertexts_removed"]="PASS"
        result["remote_disaster_recovery"]="PASS_ELEVEN_PROVIDER_CIPHERS_NETWORKLESS_PG17_RESTORED"
        return result
    except (Blocked,backup.BackupError,OSError,ValueError) as exc:
        # Stable reason-code only. Provider, Docker, table and credential
        # diagnostics must never appear in CI/logs or user message.
        safe = str(exc)
        if not re.fullmatch(r"[A-Z_]{3,100}",safe):
            safe="REMOTE_ONLY_RECOVERY_FAIL_CLOSED"
        result["blocker"]=safe
        # Temp downloaded ciphertext is deleted by TemporaryDirectory even
        # on exception. Mark it as unknown without a completed exit proof.
        return result
    except Exception:
        result["blocker"]="REMOTE_ONLY_RECOVERY_FAIL_CLOSED"
        return result


def main(argv=None) -> int:
    args=sys.argv[1:] if argv is None else argv
    if args != ["recover-remote"]:
        print("USAGE: python -m scripts.p1_owner_remote_recovery_v223 recover-remote",
              file=sys.stderr)
        return 2
    r=recover()
    print(json.dumps(r,sort_keys=True,separators=(",",":")))
    return 0 if (
        r.get("remote_disaster_recovery")==
            "PASS_ELEVEN_PROVIDER_CIPHERS_NETWORKLESS_PG17_RESTORED"
        and r.get("downloaded_temporary_ciphertexts_removed")=="PASS"
        and r.get("networkless_disposable_container_removed")=="PASS"
    ) else 1


if __name__=="__main__":
    raise SystemExit(main())
