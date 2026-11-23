"""Owner-only offline restore of encrypted historic archives in networkless PG17.

Requirements: an existing owner Codespace, a LOCAL Unix-socket Docker daemon,
an already cached postgres:17 image, the existing owner-held AES-GCM backup key,
and explicit owner consent. No source DB, PG credentials, volumes, host ports,
network, remote storage, or production infrastructure are accessed.

Plaintext is held in bounded Python memory and transient PostgreSQL data in
container tmpfs; no plaintext dump files are created on the host. Container
cleanup is mandatory. Source provenance/offsite retention remain BLOCKED.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

from scripts import p1_owner_one_shot_v223 as owner
from scripts import p1_owner_archive_deep_v223 as deep
from scripts import pg_backup_v223 as backup

ACK = "OWNER_APPROVES_NETWORKLESS_TEMP_PG17_RESTORE"
IMAGE = "postgres:17"
MAX_ARCHIVES = 16
MAX_SECONDS = 480
MAX_MISSING_ROLES = 16
ROLE_MISSING_RE = re.compile(rb'role "([A-Za-z_][A-Za-z0-9_]{0,62})" does not exist')
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


# Current source snapshot references are taken READ-ONLY from the connected DEV
# database by a separate reviewer. Never read source credentials in this tool.
REFERENCE_CONSTRAINT_ENV = "JW_PG_EXPECT_LIVE_CONSTRAINT_SHA256"
REFERENCE_ROW_ENV = "JW_PG_EXPECT_LIVE_ROW_MANIFEST_SHA256"
REFERENCE_TOTAL_ENV = "JW_PG_EXPECT_LIVE_ROWS"
FINGERPRINT_RE = re.compile(r"^[a-f0-9]{64}$")
MAX_SOURCE_TABLE_ROWS = 2_000_000
MAX_SOURCE_TOTAL_ROWS = 5_000_000

# This is the same deterministic per-table row digest algorithm used by the
# P1 engine (MD5 of row text, summed high/low 64-bit halves). The aggregate
# manifest itself uses SHA256; it is a checkpoint, NOT formal collision-proof
# equality, nor a historic snapshot signature. It never exports a row or name.
ROW_MANIFEST_SQL = """
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ;
CREATE TEMP TABLE jw_p1_digest (name text, n bigint, lo text, hi text) ON COMMIT DROP;
DO $jw$
DECLARE x record; n bigint; lo text; hi text; grand_total bigint := 0;
BEGIN
  FOR x IN SELECT c.relname FROM pg_class c JOIN pg_namespace ns
            ON ns.oid=c.relnamespace
           WHERE ns.nspname='jw_dev' AND c.relkind IN ('r','p')
           ORDER BY c.relname LOOP
    EXECUTE format('SELECT count(*) FROM (SELECT 1 FROM %I.%I LIMIT 2000001) x',
                   'jw_dev', x.relname) INTO n;
    IF n > 2000000 THEN RAISE EXCEPTION 'TOO_MANY_ROWS'; END IF;
    grand_total := grand_total + n;
    IF grand_total > 5000000 THEN RAISE EXCEPTION 'TOO_MANY_TOTAL_ROWS'; END IF;
    EXECUTE format(
      'SELECT count(*)::bigint, '
      || 'coalesce(sum((''x''||substr(h,1,16))::bit(64)::bigint::numeric),0)::text, '
      || 'coalesce(sum((''x''||substr(h,17,16))::bit(64)::bigint::numeric),0)::text '
      || 'FROM (SELECT md5(t::text) h FROM %I.%I t) z',
      'jw_dev', x.relname
    ) INTO n, lo, hi;
    INSERT INTO jw_p1_digest VALUES(x.relname,n,lo,hi);
  END LOOP;
END;
$jw$;
SELECT count(*)::int, coalesce(sum(n),0)::bigint,
  encode(sha256(convert_to(
   coalesce(string_agg(name||':'||n::text||':'||lo||':'||hi,E'\\n' ORDER BY name),''),
  'UTF8')),'hex')
FROM jw_p1_digest;
ROLLBACK;
"""


def _audit_restored_row_manifest(container: str, db: str) -> tuple[int, int, str] | None:
    """Read-only content digest on the disposable DB (temporary table only)."""
    done = _exec(container, ["psql", "-qAt", "-U", "postgres", "-d", db,
                            "-v", "ON_ERROR_STOP=1", "-c", ROW_MANIFEST_SQL],
                 timeout=100)
    if done.returncode:
        return None
    parts = done.stdout.decode("ascii", "ignore").strip().split("|")
    if len(parts) != 3:
        return None
    try:
        table_count, rows = int(parts[0]), int(parts[1])
    except ValueError:
        return None
    if not (0 <= table_count <= 100000
            and 0 <= rows <= MAX_SOURCE_TOTAL_ROWS
            and FINGERPRINT_RE.fullmatch(parts[2])):
        return None
    return table_count, rows, parts[2]


def _source_snapshot_reference() -> tuple[str, str, int | None] | None:
    """No source access here. Reject malformed owner-supplied aggregate hashes."""
    c = os.environ.get(REFERENCE_CONSTRAINT_ENV, "")
    r = os.environ.get(REFERENCE_ROW_ENV, "")
    total = os.environ.get(REFERENCE_TOTAL_ENV, "")
    if not (c or r or total):
        return None
    if not (FINGERPRINT_RE.fullmatch(c) and FINGERPRINT_RE.fullmatch(r)
            and total.isascii() and total.isdecimal() and 0 <= int(total) <= MAX_SOURCE_TOTAL_ROWS):
        raise backup.BackupError("BLOCKED_INVALID_READONLY_SOURCE_REFERENCE")
    return c, r, int(total)



def _docker(args: list[str], *, data: bytes | None = None,
            timeout: int = 30) -> subprocess.CompletedProcess:
    """Never emit untrusted Docker/pg_restore stdout or stderr."""
    return subprocess.run(["docker", *args], input=data, capture_output=True,
                          timeout=timeout, check=False)


def _preflight() -> str:
    if os.environ.get("CODESPACES", "").lower() != "true":
        return "OWNER_CODESPACE_REQUIRED"
    if os.environ.get("JW_PG_OFFLINE_RESTORE_ACK") != ACK:
        return "EXPLICIT_OWNER_OFFLINE_RESTORE_ACK_REQUIRED"
    if shutil.which("docker") is None:
        return "DOCKER_CLI_NOT_INSTALLED"
    host = os.environ.get("DOCKER_HOST", "")
    if host and not host.startswith("unix://"):
        return "REMOTE_DOCKER_DAEMON_REFUSED"
    if os.environ.get("DOCKER_TLS_VERIFY", ""):
        return "REMOTE_DOCKER_DAEMON_REFUSED"
    try:
        context = _docker(["context", "inspect", "--format", "{{.Endpoints.docker.Host}}"])
        if context.returncode or not context.stdout.strip().startswith(b"unix://"):
            return "DOCKER_CONTEXT_NOT_LOCAL_UNIX"
        if _docker(["info", "--format", "{{.ServerVersion}}"], timeout=20).returncode:
            return "DOCKER_DAEMON_UNAVAILABLE"
        if _docker(["image", "inspect", IMAGE], timeout=20).returncode:
            return "PG17_LOCAL_IMAGE_NOT_CACHED"
    except (OSError, subprocess.TimeoutExpired):
        return "DOCKER_DAEMON_UNAVAILABLE"
    return "PASS"


def _restore_reason(stderr: bytes) -> str:
    text = stderr[:65536].lower()
    if b"extension" in text and (b"not available" in text or b"could not open extension" in text):
        return "MISSING_EXTENSION_IN_DISPOSABLE_TARGET"
    if b"permission denied" in text:
        return "TARGET_PERMISSION_ERROR"
    if b"could not connect" in text or b"connection refused" in text:
        return "DISPOSABLE_TARGET_CONNECTION_ERROR"
    if b"constraint" in text and (b"violat" in text or b"fails" in text):
        return "RESTORED_DATA_CONSTRAINT_ERROR"
    if b"role" in text and b"does not exist" in text:
        return "MISSING_DISPOSABLE_TARGET_ROLE"
    return "RESTORE_FAILED_UNCLASSIFIED"


def _exec(container: str, command: list[str], *, data: bytes | None = None,
          timeout: int = 30) -> subprocess.CompletedProcess:
    # Never allocate a TTY in unattended CI / mobile Codespaces: docker
    # exec -t may fail or alter output on redirected stdio.
    prefix = ["exec", "-i", container] if data is not None else ["exec", container]
    return _docker([*prefix, *command], data=data, timeout=timeout)


def _restore_one(container: str, original: bytearray, index: int) -> tuple[str, int, str | None, str | None, int | None]:
    """Fresh disposable DB per archive. Auto-create NOLOGIN roles ONLY in
    this networkless throwaway cluster, only when pg_restore reports one.
    """
    db = "jw_p1_offline_" + str(index)
    added = set()
    for attempt in range(MAX_MISSING_ROLES + 1):
        created = _exec(container, ["createdb", "-U", "postgres", db])
        if created.returncode:
            return "CREATE_DISPOSABLE_DB_FAILED", 0, None, None, None
        try:
            done = _exec(container, [
                "pg_restore", "-U", "postgres", "--no-owner", "--no-acl",
                "--exit-on-error", "--dbname", db,
            ], data=bytes(original), timeout=100)
            if done.returncode:
                missing = ROLE_MISSING_RE.search(done.stderr[:65536])
                if missing and attempt < MAX_MISSING_ROLES:
                    role = missing.group(1).decode("ascii")
                    if role in added or role.lower().startswith("pg_"):
                        return "MISSING_DISPOSABLE_TARGET_ROLE", 0, None, None, None
                    added.add(role)
                    # ASCII-validated, quoted identifier; the target cluster is
                    # fresh, networkless, and destroyed at the end of the run.
                    made = _exec(container, [
                        "psql", "-U", "postgres", "-d", "postgres",
                        "-v", "ON_ERROR_STOP=1", "-c", 'CREATE ROLE "'+role+'" NOLOGIN',
                    ])
                    if made.returncode:
                        return "EPHEMERAL_ROLE_PROVISION_FAILED", 0, None, None, None
                    continue
                return _restore_reason(done.stderr), 0, None
            count_query = (
                "SELECT count(*) FROM pg_class c "
                "JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname='jw_dev' AND c.relkind IN ('r','p');"
            )
            checked = _exec(container, [
                "psql", "-U", "postgres", "-d", db, "-At",
                "-v", "ON_ERROR_STOP=1", "-c", count_query,
            ])
            if checked.returncode:
                return "POST_RESTORE_TABLE_COUNT_UNAVAILABLE", 0, None, None, None
            try:
                total = int(checked.stdout.strip())
            except (TypeError, ValueError):
                return "POST_RESTORE_TABLE_COUNT_INVALID", 0, None, None, None
            if not 0 <= total <= 100000:
                return "POST_RESTORE_TABLE_COUNT_INVALID", 0, None, None, None
            hash_query = (
                "SELECT md5(coalesce(string_agg(c.relname||'.'||k.conname||'='||"
                "pg_get_constraintdef(k.oid,true),E'\\n' ORDER BY c.relname,k.conname),'') ) "
                "FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid "
                "JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname='jw_dev';"
            )
            h = _exec(container, [
                "psql", "-U", "postgres", "-d", db, "-At",
                "-v", "ON_ERROR_STOP=1", "-c", hash_query,
            ])
            digest = h.stdout.decode("ascii", "ignore").strip() if h.returncode == 0 else ""
            if not re.fullmatch(r"[a-f0-9]{32}", digest):
                return "POST_RESTORE_CONSTRAINT_DIGEST_INVALID", 0, None, None, None
            rows = _audit_restored_row_manifest(container, db)
            if rows is None or rows[0] != total:
                return "POST_RESTORE_ROW_MANIFEST_UNAVAILABLE", 0, None, None, None
            return "LOCAL_DISPOSABLE_RESTORED", total, digest, rows[2], rows[1]
        finally:
            # Always discard this database before moving to the next archive.
            dropped = _exec(container, ["dropdb", "-U", "postgres", "--force", db])
            if dropped.returncode:
                raise backup.BackupError("BLOCKED_EPHEMERAL_DATABASE_CLEANUP_FAILED")
    return "MISSING_DISPOSABLE_TARGET_ROLE", 0, None, None, None


def run_offline() -> dict[str, object]:
    """One bounded pass over all private archives; always NO-GO for source parity."""
    result: dict[str, object] = {
        "offline_restore_execution": "BLOCKED",
        "offline_restored_archive_count": 0,
        "offline_65_table_archive_count": 0,
        "offline_other_table_archive_count": 0,
        "offline_restore_failure_count": 0,
        "offline_restore_skipped_budget_count": 0,
        "disposable_constraint_signature_groups": 0,
        "disposable_row_manifest_groups": 0,
        "current_source_reference_provided": False,
        "current_source_constraints_match_count": 0,
        "current_source_row_manifest_match_count": 0,
        "current_source_combined_match_count": 0,
        "current_source_row_total_match_count": 0,
        "current_source_snapshot_is_historic_attestation": False,
        "historic_real_source_identity_verified": False,
        "independent_live_source_signature_compared": False,
        "remote_storage_proven": False,
        "container_removed": "NOT_STARTED",
        "overall": "BLOCKED",
    }
    preflight = _preflight()
    if preflight != "PASS":
        result["blocker"] = preflight
        return result
    try:
        snapshot = _source_snapshot_reference()
    except backup.BackupError:
        result["blocker"] = "INVALID_READONLY_SOURCE_REFERENCE"
        return result
    result["current_source_reference_provided"] = snapshot is not None
    archives, discovery = owner.discover_owner_archive()
    result["archive_discovery"] = discovery
    result["private_archives_found"] = len(archives)
    if not archives or len(archives) > MAX_ARCHIVES:
        result["blocker"] = "ARCHIVE_COUNT_NOT_SAFELY_BOUNDED"
        return result
    try:
        backup.load_key()
    except backup.BackupError:
        result["blocker"] = "BACKUP_KEY_INVALID_OR_MISSING"
        return result
    name = "jw-p1-offline-" + secrets.token_hex(8)
    start = time.monotonic()
    container = None
    fingerprints = set()
    row_fingerprints = set()
    try:
        create = _docker([
            "run", "--rm", "--pull", "never", "-d",
            "--name", name, "--network", "none", "--publish-all=false",
            "--tmpfs", "/var/lib/postgresql/data:rw,size=1073741824",
            "--tmpfs", "/var/run/postgresql:rw,size=16777216",
            "-e", "POSTGRES_HOST_AUTH_METHOD=trust",
            IMAGE,
        ], timeout=45)
        if create.returncode:
            result["blocker"] = "NETWORKLESS_DISPOSABLE_PG17_START_FAILED"
            return result
        container = create.stdout.decode("ascii", "ignore").strip()
        if not SHA_RE.fullmatch(container):
            result["blocker"] = "DISPOSABLE_CONTAINER_ID_INVALID"
            return result
        for i in range(60):
            ready = _exec(container, ["pg_isready", "-U", "postgres", "-d", "postgres"])
            if ready.returncode == 0:
                break
            time.sleep(0.5)
        else:
            result["blocker"] = "DISPOSABLE_PG17_NOT_READY"
            return result
        vers = _exec(container, ["postgres", "--version"])
        if vers.returncode or not re.search(rb"PostgreSQL\)\s+17\.", vers.stdout):
            result["blocker"] = "DISPOSABLE_PG17_VERSION_INVALID"
            return result
        remaining = deep.MAX_TOTAL_PLAIN_BYTES
        failure_kinds = set()
        for index, path in enumerate(archives):
            if time.monotonic() - start > MAX_SECONDS:
                result["offline_restore_skipped_budget_count"] += len(archives) - index
                break
            try:
                plain = deep.authenticated_plain_in_memory(
                    path, limit=min(deep.MAX_PLAIN_BYTES, remaining))
            except (backup.BackupError, OSError, ValueError):
                result["offline_restore_failure_count"] += 1
                failure_kinds.add("CIPHERTEXT_AUTH_OR_SIZE_BLOCKED")
                continue
            try:
                remaining -= len(plain)
                status, count, fingerprint, row_manifest, row_total = _restore_one(container, plain, index)
                if status != "LOCAL_DISPOSABLE_RESTORED":
                    result["offline_restore_failure_count"] += 1
                    failure_kinds.add(status)
                else:
                    result["offline_restored_archive_count"] += 1
                    if count == 65:
                        result["offline_65_table_archive_count"] += 1
                    else:
                        result["offline_other_table_archive_count"] += 1
                    if fingerprint:
                        fingerprints.add(fingerprint)
                    if row_manifest:
                        row_fingerprints.add(row_manifest)
                    if snapshot is not None:
                        live_constraints, live_rows, live_total = snapshot
                        # See separate SHA256 constraints query below. The old
                        # 32-character MD5 grouping is retained for backwards
                        # compatibility; source comparison uses SHA256.
                        if row_manifest == live_rows:
                            result["current_source_row_manifest_match_count"] += 1
                        if row_total == live_total:
                            result["current_source_row_total_match_count"] += 1
            except (backup.BackupError, OSError, subprocess.SubprocessError):
                result["offline_restore_failure_count"] += 1
                failure_kinds.add("DISPOSABLE_RESTORE_OR_CLEANUP_ERROR")
                break
            finally:
                plain.clear()
        result["disposable_constraint_signature_groups"] = len(fingerprints)
        result["disposable_row_manifest_groups"] = len(row_fingerprints)
        result["failure_categories"] = sorted(failure_kinds)
        result["offline_restore_execution"] = (
            "PASS_LOCAL_ONLY" if result["offline_restored_archive_count"] == len(archives)
            and result["offline_restore_failure_count"] == 0
            and result["offline_restore_skipped_budget_count"] == 0
            else "BLOCKED_INCOMPLETE")
        return result
    except (OSError, subprocess.SubprocessError):
        result["blocker"] = "OFFLINE_DOCKER_PROCESS_FAILED"
        return result
    finally:
        if container and SHA_RE.fullmatch(container):
            try:
                removed = _docker(["rm", "-f", container], timeout=30)
                result["container_removed"] = "PASS" if removed.returncode == 0 else "BLOCKED_CLEANUP"
            except (OSError, subprocess.TimeoutExpired):
                result["container_removed"] = "BLOCKED_CLEANUP"
            if result["container_removed"] != "PASS":
                result["offline_restore_execution"] = "BLOCKED_CLEANUP"
        # No container ID/paths/keys/SQL/row data are returned.


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args != ["restore-offline"]:
        print("USAGE: python -m scripts.p1_owner_offline_restore_v223 restore-offline", file=sys.stderr)
        return 2
    try:
        report = run_offline()
    except Exception:
        print('{"offline_restore_execution":"BLOCKED","overall":"BLOCKED","blocker":"UNEXPECTED_SAFE_RESTORE_ERROR"}')
        return 1
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report.get("offline_restore_execution") == "PASS_LOCAL_ONLY" and report.get("container_removed") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
