"""Owner-local, read-only one-shot P1/B2/B3 evidence preflight.

Does NOT connect to source DB, grant rights, upload any object, restore any
historical archive or claim offsite storage. It checks locally available
ciphertexts and independent expected hashes, and emits fixed status labels.

Only a fixed, owner-private historical BACKUP directory is inspected.
Secrets are never searched for or printed. No synthetic evidence is promoted
to historical/offsite acceptance. The "diagnose" action exits 0 when the
DIAGNOSTIC completed; this is not B2/B3 PASS.
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
    # This check is independent of archive/key selection. The old order
    # returned early for a missing SHA and misreported an existing private
    # receipt as NOT_DISCOVERED.
    receipt = env.get("JW_PG_OWNER_RECEIPT_PATH", "")
    if _private_receipt_present(receipt):
        result["private_receipt_metadata"] = "PRESENT_NOT_INDEPENDENTLY_VERIFIED"
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




def _owner_backup_dir() -> Path:
    """Historical 2026-11-17 owner runner's TMPDIR, NOT a general file search."""
    return Path.home() / ".local" / "share" / "jw-v223-restore" / "backups"


def _private_directory(path: Path) -> bool:
    try:
        st = path.lstat()
    except OSError:
        return False
    return (stat.S_ISDIR(st.st_mode)
            and stat.S_IMODE(st.st_mode) == 0o700
            and (not hasattr(os, "getuid") or st.st_uid == os.getuid()))


def _private_cipher_file(path: Path) -> bool:
    try:
        st = path.lstat()
    except OSError:
        return False
    return (stat.S_ISREG(st.st_mode)
            and stat.S_IMODE(st.st_mode) == 0o600
            and (not hasattr(os, "getuid") or st.st_uid == os.getuid()))


def discover_owner_archive() -> tuple[list[Path], str]:
    """Bounded two-level search of the EXACT historical private backup root.

    The old pg_backup_v223 used tempfile.mkdtemp(prefix='jw_v223_') while
    TMPDIR pointed to .local/share/jw-v223-restore/backups. Thus ciphertext
    is nested one level below BACKUP_DIR, not at its root.
    """
    root = _owner_backup_dir()
    if not _private_directory(root):
        return [], "PRIVATE_BACKUP_DIRECTORY_ABSENT_OR_UNSAFE"
    hits: list[Path] = []
    inspected = 0
    try:
        with os.scandir(root) as outer:
            for item in outer:
                inspected += 1
                if inspected > 256:
                    return [], "DISCOVERY_SCAN_LIMIT_EXCEEDED"
                if item.is_file(follow_symlinks=False) and item.name.endswith(".jwpgbk"):
                    file = root / item.name
                    if _private_cipher_file(file):
                        hits.append(file)
                elif (item.is_dir(follow_symlinks=False)
                      and item.name.startswith("jw_v223_")
                      and _private_directory(root / item.name)):
                    with os.scandir(root / item.name) as inner:
                        for child in inner:
                            inspected += 1
                            if inspected > 256:
                                return [], "DISCOVERY_SCAN_LIMIT_EXCEEDED"
                            if child.is_file(follow_symlinks=False) and child.name.endswith(".jwpgbk"):
                                file = root / item.name / child.name
                                if _private_cipher_file(file):
                                    hits.append(file)
                if len(hits) > 16:
                    return [], "MULTIPLE_ARCHIVES_MANUAL_SELECTION_REQUIRED"
    except OSError:
        return [], "OWNER_BACKUP_DIRECTORY_UNREADABLE"
    if not hits:
        return [], "NO_PRIVATE_CIPHERTEXT_FOUND"
    return hits, "FOUND_ONE" if len(hits) == 1 else "MULTIPLE_ARCHIVES"


def _candidate_owner_receipt() -> str:
    """Metadata presence ONLY. Never trust a receipt's contents as source proof."""
    root = _owner_backup_dir().parent
    if not _private_directory(root):
        return ""
    candidates = [root / "last_run_summary.json"]
    try:
        with os.scandir(root) as it:
            for i, x in enumerate(it):
                if i >= 256:
                    break
                if x.name.startswith("owner_b2b3_") and x.name.endswith(".json"):
                    candidates.append(root / x.name)
    except OSError:
        return ""
    for p in sorted(candidates, reverse=True):
        if _private_receipt_present(str(p)):
            return str(p)
    return ""




# Not an external receipt: probing self-derived local hashes may prove only
# AES-GCM authentication under the current owner's key. The origin of each
# archive and historic DB parity remain UNVERIFIED.
MAX_AUTH_CANDIDATE_BYTES = 128 * 1024 * 1024
MAX_AUTH_TOTAL_BYTES = 512 * 1024 * 1024


def _sha256_private_candidate(path: Path, max_bytes: int) -> tuple[str, int]:
    """Bounded, no-follow, same-owner 0600 read; no secret/path printing."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        st = os.fstat(stream.fileno())
        if not (stat.S_ISREG(st.st_mode)
                and stat.S_IMODE(st.st_mode) == 0o600
                and (not hasattr(os, "getuid") or st.st_uid == os.getuid())):
            raise BackupError("BLOCKED_V223_UNSAFE_ARCHIVE_METADATA")
        if st.st_size > max_bytes:
            raise BackupError("BLOCKED_V223_LOCAL_KEY_PROBE_SIZE_LIMIT")
        digest = hashlib.sha256()
        total = 0
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(chunk)
            if total > max_bytes:
                raise BackupError("BLOCKED_V223_LOCAL_KEY_PROBE_SIZE_LIMIT")
            digest.update(chunk)
        return digest.hexdigest(), total


def inspect_local_candidates(
    archives: list[Path], supplied_expected_sha: str, key_encoded: str
) -> tuple[dict[str, object], Path | None]:
    """Inspect at most 16 private candidates, without selecting on age/name.

    When no independently sourced hash exists, AES-GCM verification alone
    must NEVER promote a candidate to source-verified PASS.
    """
    result: dict[str, object] = {
        "candidate_key_authentication": "KEY_UNAVAILABLE",
        "key_authenticated_candidate_count": 0,
        "candidate_hash_match_count": 0,
        "candidate_probe_skipped_count": 0,
        "candidate_selection": "NOT_SELECTED",
        "candidate_origin_verified": False,
    }
    if not archives or len(archives) > 16:
        result["candidate_key_authentication"] = "NOT_SCANNED"
        return result, None
    key = None
    if key_encoded:
        try:
            key = load_key(key_encoded)
        except BackupError:
            result["candidate_key_authentication"] = "KEY_INVALID"
    matched: list[Path] = []
    examined = 0
    skipped = 0
    authenticated = 0
    for candidate in archives:
        try:
            # Stop before reading beyond the total budget, even if an entry is
            # unexpectedly large or grows while being examined.
            remaining = MAX_AUTH_TOTAL_BYTES - examined
            if remaining <= 0:
                skipped += 1
                continue
            fingerprint, size = _sha256_private_candidate(
                candidate, min(MAX_AUTH_CANDIDATE_BYTES, remaining))
            examined += size
            if SHA256_RE.fullmatch(supplied_expected_sha or "") and fingerprint == supplied_expected_sha:
                matched.append(candidate)
            if key is not None:
                # SELF-HASHED expected value is ONLY an implementation detail
                # of authenticated decryption. It is NOT independent SHA proof.
                audit_encrypted_archive(candidate, fingerprint, key)
                authenticated += 1
        except (BackupError, OSError, TypeError, ValueError):
            skipped += 1
    result["key_authenticated_candidate_count"] = authenticated
    result["candidate_hash_match_count"] = len(matched)
    result["candidate_probe_skipped_count"] = skipped
    if key is None:
        result["candidate_key_authentication"] = "KEY_INVALID" if key_encoded else "KEY_UNAVAILABLE"
    else:
        result["candidate_key_authentication"] = ("BOUNDED_OR_INVALID_CANDIDATES"
                                                  if skipped else "AES_GCM_KEY_ONLY_VERIFIED")
    if len(matched) == 1:
        result["candidate_selection"] = "ONE_MATCH_TO_SUPPLIED_SHA_NOT_REMOTE_ATTESTED"
        return result, matched[0]
    if len(matched) > 1:
        result["candidate_selection"] = "AMBIGUOUS_SAME_SHA"
    elif supplied_expected_sha:
        result["candidate_selection"] = "NO_SHA_MATCH"
    return result, None

def diagnose_one_shot(environ: dict[str, str] | None = None) -> dict[str, object]:
    """Run as many independent safety gates as possible, report ALL blockers.

    Exit code 0 means the diagnosis ran correctly, NEVER a fake restore PASS.
    No connection, crypto key discovery, backup creation or external transfer.
    """
    env = dict(os.environ if environ is None else environ)
    blockers: list[str] = []
    explicit = env.get("JW_PG_ARCHIVE_PATH", "")
    discovery = "EXPLICIT_PATH" if explicit else "NOT_ATTEMPTED"
    count = 0
    inspect_report: dict[str, object] | None = None
    if not explicit:
        archives, discovery = discover_owner_archive()
        count = len(archives)
        if len(archives) == 1:
            env["JW_PG_ARCHIVE_PATH"] = str(archives[0])
        elif len(archives) > 1:
            inspect_report, selected = inspect_local_candidates(
                archives,
                env.get("JW_PG_EXPECT_ARCHIVE_SHA256", ""),
                env.get("JW_PG_BACKUP_KEY", ""),
            )
            if selected is not None:
                env["JW_PG_ARCHIVE_PATH"] = str(selected)
                discovery = "ONE_MATCHED_SUPPLIED_SHA"
            else:
                blockers.append("MULTIPLE_ARCHIVES_NEED_TRUSTED_RECEIPT_SELECTION")
        else:
            blockers.append(discovery)
    if not env.get("JW_PG_EXPECT_ARCHIVE_SHA256", ""):
        blockers.append("INDEPENDENT_CIPHER_SHA256_REQUIRED")
    if not env.get("JW_PG_BACKUP_KEY", ""):
        blockers.append("BACKUP_KEY_REQUIRED_IN_OWNER_ENV")
    if not env.get("JW_PG_RETRIEVED_ARCHIVE_PATH", ""):
        blockers.append("INDEPENDENTLY_RETRIEVED_CIPHERTEXT_REQUIRED")
    if not env.get("JW_PG_OWNER_RECEIPT_PATH", ""):
        receipt = _candidate_owner_receipt()
        if receipt:
            env["JW_PG_OWNER_RECEIPT_PATH"] = receipt

    report = execute_one_shot(env)
    if inspect_report is not None:
        report.update(inspect_report)
        if inspect_report["candidate_key_authentication"] == "BOUNDED_OR_INVALID_CANDIDATES":
            blockers.append("CANDIDATE_PROBE_INCOMPLETE")
        if inspect_report["candidate_key_authentication"] == "KEY_INVALID":
            blockers.append("CANDIDATE_KEY_INVALID")
        if inspect_report["candidate_key_authentication"] == "AES_GCM_KEY_ONLY_VERIFIED":
            blockers.append("LOCAL_KEY_AUTHENTICATION_NOT_INDEPENDENT_PROVENANCE")
    primary = str(report.get("blocker") or "")
    # When no path was supplied, the older first-failure checker says only
    # ARCHIVE_PATH_REQUIRED. Report the actual bounded discovery result
    # instead; do not make the owner repeat the same manual path input.
    if (primary and not (primary == "ARCHIVE_PATH_REQUIRED"
                         and not env.get("JW_PG_ARCHIVE_PATH"))
            and primary not in blockers):
        blockers.insert(0, primary)
    if report.get("private_receipt_metadata") != "PRESENT_NOT_INDEPENDENTLY_VERIFIED":
        blockers.append("OWNER_PRIVATE_RECEIPT_NOT_DISCOVERED")
    blockers.extend((
        "OFFSITE_STORAGE_PROVIDER_ATTESTATION_NOT_VERIFIED",
        "HISTORICAL_65_TABLE_INDEPENDENT_RESTORE_NOT_VERIFIED",
        "RENDER_AUTHENTICATED_LIVE_E2E_NOT_RUN",
    ))
    # Stable, deduplicated, fixed-code labels; no paths, hashes, keys or rows.
    report["blockers"] = list(dict.fromkeys(blockers))
    report["blocker"] = report["blockers"][0] if report["blockers"] else "NO_BLOCKERS"
    report["diagnostic_execution"] = "PASS"
    report["archive_discovery"] = discovery
    report["discovered_private_archive_count"] = count
    report["overall"] = "BLOCKED"
    return report


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args not in (["check"], ["diagnose"]):
        print("USAGE: python -m scripts.p1_owner_one_shot_v223 [check|diagnose]", file=sys.stderr)
        return 2
    try:
        result = diagnose_one_shot() if args == ["diagnose"] else execute_one_shot()
    except Exception:
        # Never print untrusted exceptions; an exception may embed paths or keys.
        print('{"overall":"BLOCKED","blocker":"UNEXPECTED_PREFLIGHT_ERROR"}')
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if args == ["diagnose"] else (0 if result["overall"] == "PASS" else 1)


if __name__ == "__main__":
    raise SystemExit(main())
