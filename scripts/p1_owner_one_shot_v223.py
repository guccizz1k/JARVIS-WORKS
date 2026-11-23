"""Owner-local, read-only one-shot P1/B2/B3 evidence preflight.

Does NOT connect to source DB, grant rights, upload any object, restore any
historical archive or claim offsite storage. It checks locally available
ciphertexts and independent expected hashes, and emits fixed status labels.

Every input is owner-supplied via environment; no automatic secret discovery.
Never run this module in a public action with real data.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

from scripts.pg_backup_v223 import BackupError, audit_encrypted_archive, load_key

SHA256_RE = re.compile(r"[a-f0-9]{64}\Z")


def _same_file_identity(a: Path, b: Path) -> bool:
    """Prevent treating same inode/hardlink as independent downloaded copies."""
    x, y = a.stat(), b.stat()
    return x.st_dev == y.st_dev and x.st_ino == y.st_ino


def _private_receipt_present(path_string: str) -> bool:
    """Only report existence/security of receipt metadata; not validity or contents."""
    if not path_string:
        return False
    path = Path(path_string)
    if path.is_symlink():
        return False
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return False
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or (stat.S_IMODE(st.st_mode) & 0o777) != 0o600:
            return False
        if hasattr(os, "getuid") and st.st_uid != os.getuid():
            return False
        return st.st_size <= 65536
    finally:
        os.close(fd)


def execute_one_shot(environ: dict[str, str] | None = None) -> dict[str, object]:
    """Single-pass local-only diagnostics. Never interpret mock/signed-looking
    receipts as independently verified external origin or real DB parity."""
    env = dict(os.environ if environ is None else environ)
    result: dict[str, object] = {
        "local_archive_auth": "BLOCKED",
        "retrieved_archive_auth": "BLOCKED",
        "private_receipt_metadata": "BLOCKED",
        "external_storage_origin": "NOT_VERIFIED",
        "historical_65_table_restore": "NOT_RUN",
        "render_live_e2e": "NOT_RUN",
        "overall": "BLOCKED",
    }
    original = env.get("JW_PG_ARCHIVE_PATH", "")
    expected = env.get("JW_PG_EXPECT_ARCHIVE_SHA256", "")
    if not original:
        result["blocker"] = "ARCHIVE_PATH_REQUIRED"
        return result
    if not SHA256_RE.fullmatch(expected):
        result["blocker"] = "INDEPENDENT_CIPHER_SHA256_REQUIRED"
        return result
    key_encoded = env.get("JW_PG_BACKUP_KEY", "")
    if not key_encoded:
        result["blocker"] = "BACKUP_KEY_REQUIRED_IN_OWNER_ENV"
        return result
    try:
        import base64
        key = base64.urlsafe_b64decode(key_encoded.encode("ascii"))
        if len(key) != 32:
            raise ValueError("bad-key-size")
    except (ValueError, UnicodeError):
        result["blocker"] = "BACKUP_KEY_INVALID"
        return result
    origin = Path(original)
    try:
        audit_encrypted_archive(
            origin, expected, key,
            env.get("JW_PG_EXPECT_PLAINTEXT_SHA256", ""),
        )
    except (BackupError, OSError, ValueError, TypeError):
        result["blocker"] = "LOCAL_CIPHERTEXT_NOT_AUTHENTICATED"
        return result
    result["local_archive_auth"] = "PASS"
    receipt = env.get("JW_PG_OWNER_RECEIPT_PATH", "")
    if _private_receipt_present(receipt):
        result["private_receipt_metadata"] = "PRESENT_NOT_INDEPENDENTLY_VERIFIED"

    downloaded = env.get("JW_PG_RETRIEVED_ARCHIVE_PATH", "")
    if not downloaded:
        result["blocker"] = "INDEPENDENTLY_RETRIEVED_CIPHERTEXT_REQUIRED"
        return result
    second = Path(downloaded)
    try:
        if _same_file_identity(origin, second):
            result["blocker"] = "RETRIEVED_COPY_IS_SAME_FILE"
            return result
        audit_encrypted_archive(
            second, expected, key,
            env.get("JW_PG_EXPECT_PLAINTEXT_SHA256", ""),
        )
    except (BackupError, OSError, ValueError, TypeError):
        result["blocker"] = "RETRIEVED_CIPHERTEXT_NOT_AUTHENTICATED"
        return result
    result["retrieved_archive_auth"] = "PASS"
    # Do not label a second local file as proven remote storage. A trusted
    # storage-provider object/retention proof is independently required.
    result["blocker"] = "EXTERNAL_STORAGE_ATTESTATION_AND_HISTORIC_RESTORE_REQUIRED"
    return result


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args != ["check"]:
        print("USAGE: python -m scripts.p1_owner_one_shot_v223 check", file=sys.stderr)
        return 2
    try:
        result = execute_one_shot()
    except Exception:
        # Never print untrusted exceptions; an exception may embed paths or keys.
        print('{"overall":"BLOCKED","blocker":"UNEXPECTED_PREFLIGHT_ERROR"}')
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["overall"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
