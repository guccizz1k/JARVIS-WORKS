"""V22.3 PostgreSQL 17 backup -> authenticated encryption -> isolated restore -> signature diff.

Scope: tooling only. Nothing here runs automatically and nothing here writes to the
SOURCE database: the source is only read by ``pg_dump`` and by SELECT queries.
The restore target must be a disposable local PostgreSQL 17 that is NOT the source.

Output hygiene: this repository is public. Never print row data, DSNs or passwords.
``summary`` contains only aggregate counts, digests and timings.

Status honesty: a run that did not restore a real backup into a separate PG17 and
compare signatures is NOT a P0-1 PASS. See ``verdict``.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"JWPGBK1\n"
CHUNK = 1 << 20
MAX_CHUNK_CIPHERTEXT = CHUNK + 16
SCHEMA_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
MAX_SIGNATURE_ROWS = 5_000_000


class BackupError(RuntimeError):
    """Raised with a stable BLOCKED_/FAIL_ code as the message prefix."""


# ---------------------------------------------------------------- secrets hygiene
def redact(text: str, *secrets: str) -> str:
    out = text
    for secret in secrets:
        if secret and len(secret) >= 4:
            out = out.replace(secret, "[REDACTED]")
    return re.sub(r"(postgres(?:ql)?://[^:/\s]+:)[^@\s]+@", r"\1[REDACTED]@", out)


def load_key(value: str | None = None) -> bytes:
    value = os.environ.get("JW_PG_BACKUP_KEY", "") if value is None else value
    if not value:
        raise BackupError("BLOCKED_V223_BACKUP_KEY_REQUIRED")
    try:
        key = base64.urlsafe_b64decode(value.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise BackupError("BLOCKED_V223_BACKUP_KEY_INVALID") from exc
    if len(key) != 32:
        raise BackupError("BLOCKED_V223_BACKUP_KEY_MUST_BE_32_BYTES")
    return key


# ------------------------------------------------- chunked AES-256-GCM file format
def _nonce(prefix: bytes, counter: int) -> bytes:
    return prefix + struct.pack(">Q", counter)


def _aad(counter: int, final: bool) -> bytes:
    return MAGIC + struct.pack(">QB", counter, 1 if final else 0)


def _open_new(path: Path):
    if path.is_symlink() or path.exists():
        raise BackupError("BLOCKED_V223_OUTPUT_EXISTS_OR_SYMLINK")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    return os.fdopen(os.open(path, flags, 0o600), "wb")


def encrypt_file(src: Path, dst: Path, key: bytes) -> dict:
    """Encrypt ``src`` to ``dst``. The final chunk is authenticated as final, so
    truncation (even at a chunk boundary), reordering and tampering all fail."""
    aes = AESGCM(key)
    prefix = os.urandom(4)
    plain_hash, cipher_hash = hashlib.sha256(), hashlib.sha256()
    out = _open_new(Path(dst))
    try:
        with open(src, "rb") as fin, out:
            head = MAGIC + prefix
            out.write(head)
            cipher_hash.update(head)
            counter, current = 0, fin.read(CHUNK)
            while True:
                following = fin.read(CHUNK) if current else b""
                final = not following
                plain_hash.update(current)
                blob = aes.encrypt(_nonce(prefix, counter), current, _aad(counter, final))
                record = struct.pack(">I", len(blob)) + blob
                out.write(record)
                cipher_hash.update(record)
                if final:
                    break
                counter, current = counter + 1, following
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        Path(dst).unlink(missing_ok=True)
        raise
    return {"plain_sha256": plain_hash.hexdigest(), "cipher_sha256": cipher_hash.hexdigest(),
            "chunks": counter + 1}


def decrypt_file(src: Path, dst: Path, key: bytes) -> str:
    """Decrypt to ``dst`` and return the plaintext sha256. Any failure removes ``dst``."""
    aes = AESGCM(key)
    digest = hashlib.sha256()
    out = _open_new(Path(dst))
    try:
        with open(src, "rb") as fin, out:
            if fin.read(len(MAGIC)) != MAGIC:
                raise BackupError("BLOCKED_V223_BACKUP_BAD_HEADER")
            prefix = fin.read(4)
            if len(prefix) != 4:
                raise BackupError("BLOCKED_V223_BACKUP_TRUNCATED")
            counter = 0
            while True:
                raw_len = fin.read(4)
                if len(raw_len) != 4:
                    raise BackupError("BLOCKED_V223_BACKUP_TRUNCATED")
                (length,) = struct.unpack(">I", raw_len)
                if not 16 <= length <= MAX_CHUNK_CIPHERTEXT:
                    raise BackupError("BLOCKED_V223_BACKUP_BAD_CHUNK_LENGTH")
                blob = fin.read(length)
                if len(blob) != length:
                    raise BackupError("BLOCKED_V223_BACKUP_TRUNCATED")
                final = fin.read(1) == b""
                if not final:
                    fin.seek(-1, os.SEEK_CUR)
                try:
                    plain = aes.decrypt(_nonce(prefix, counter), blob, _aad(counter, final))
                except InvalidTag as exc:
                    raise BackupError("BLOCKED_V223_BACKUP_AUTH_FAILED") from exc
                digest.update(plain)
                out.write(plain)
                if final:
                    break
                counter += 1
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        Path(dst).unlink(missing_ok=True)
        raise
    return digest.hexdigest()


# ---------------------------------------------------------------------- DSN guards
def parse_dsn(dsn: str) -> dict:
    parts = urlsplit(dsn)
    if parts.scheme not in ("postgresql", "postgres") or not parts.hostname:
        raise BackupError("BLOCKED_V223_DSN_MUST_BE_POSTGRESQL_URL")
    query = {k: v[-1] for k, v in parse_qs(parts.query).items()}
    return {"host": parts.hostname.lower(), "port": str(parts.port or 5432),
            "user": unquote(parts.username or ""), "password": unquote(parts.password or ""),
            "dbname": unquote(parts.path.lstrip("/") or "postgres"),
            "sslmode": query.get("sslmode", ""), "sslrootcert": query.get("sslrootcert", "")}


def guard_source(dsn: str) -> dict:
    opts = parse_dsn(dsn)
    if opts["sslmode"] != "verify-full" or not opts["sslrootcert"]:
        raise BackupError("BLOCKED_V223_SOURCE_REQUIRES_VERIFY_FULL_AND_ROOT_CERT")
    return opts


def guard_target(target_dsn: str, source_dsn: str, environ: dict | None = None) -> dict:
    env = os.environ if environ is None else environ
    if env.get("JW_PG_CI_ALLOW") != "ONLY_EPHEMERAL_LOCAL_DATABASE":
        raise BackupError("BLOCKED_V223_TARGET_NOT_DECLARED_EPHEMERAL")
    target, source = parse_dsn(target_dsn), parse_dsn(source_dsn)
    if target["host"] not in ("localhost", "127.0.0.1", "::1"):
        raise BackupError("BLOCKED_V223_TARGET_MUST_BE_LOCAL")
    if (target["host"], target["port"], target["dbname"]) == (
            source["host"], source["port"], source["dbname"]):
        raise BackupError("BLOCKED_V223_TARGET_EQUALS_SOURCE")
    return target


def check_schema(schema: str) -> str:
    if not SCHEMA_RE.fullmatch(schema):
        raise BackupError("BLOCKED_V223_BAD_SCHEMA_NAME")
    return schema


def pg_env(opts: dict) -> dict:
    env = {**os.environ, "PGHOST": opts["host"], "PGPORT": opts["port"],
           "PGUSER": opts["user"], "PGPASSWORD": opts["password"], "PGDATABASE": opts["dbname"]}
    if opts.get("sslmode"):
        env["PGSSLMODE"] = opts["sslmode"]
    if opts.get("sslrootcert"):
        env["PGSSLROOTCERT"] = opts["sslrootcert"]
    return env


def tool_major(tool: str) -> int:
    out = subprocess.run([tool, "--version"], capture_output=True, text=True, timeout=15).stdout
    match = re.search(r"(\d+)(?:\.\d+)?", out.split(")")[-1])
    if not match:
        raise BackupError("BLOCKED_V223_TOOL_VERSION_UNKNOWN")
    return int(match.group(1))


def require_pg17_tools() -> None:
    for tool in ("pg_dump", "pg_restore"):
        if tool_major(tool) < 17:
            raise BackupError(f"BLOCKED_V223_{tool.upper()}_OLDER_THAN_17")


def run_tool(args: list[str], opts: dict, timeout: int) -> str:
    result = subprocess.run(args, env=pg_env(opts), capture_output=True, text=True,
                            timeout=timeout)
    if result.returncode != 0:
        detail = redact(result.stderr.strip()[-400:], opts["password"])
        raise BackupError(f"FAIL_V223_{Path(args[0]).name.upper()}_EXIT_{result.returncode}: {detail}")
    return result.stdout


# ------------------------------------------------------------- signature (via SQL)
SIGNATURE_QUERIES = {
    "tables": """SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
                 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                 WHERE n.nspname=%(s)s AND c.relkind IN ('r','p') ORDER BY 1""",
    "policies": """SELECT tablename||'.'||policyname, md5(concat_ws('|',cmd,permissive,roles::text,
                     coalesce(qual,''),coalesce(with_check,'')))
                   FROM pg_policies WHERE schemaname=%(s)s ORDER BY 1""",
    "functions": """SELECT p.oid::regprocedure::text, md5(pg_get_functiondef(p.oid))
                    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                    WHERE n.nspname=%(s)s AND p.prokind IN ('f','p') ORDER BY 1""",
    "triggers": """SELECT c.relname||'.'||t.tgname, md5(regexp_replace(pg_get_triggerdef(t.oid),
                     '\\s+',' ','g'))
                   FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
                   JOIN pg_namespace n ON n.oid=c.relnamespace
                   WHERE n.nspname=%(s)s AND NOT t.tgisinternal ORDER BY 1""",
    "indexes": """SELECT indexname, md5(indexdef) FROM pg_indexes WHERE schemaname=%(s)s ORDER BY 1""",
    "constraints": """SELECT c.relname||'.'||k.conname, md5(pg_get_constraintdef(k.oid))
                      FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid
                      JOIN pg_namespace n ON n.oid=c.relnamespace
                      WHERE n.nspname=%(s)s ORDER BY 1""",
    "acl": """SELECT c.relname, coalesce(c.relacl::text,'') FROM pg_class c
              JOIN pg_namespace n ON n.oid=c.relnamespace
              WHERE n.nspname=%(s)s AND c.relkind IN ('r','p','S','v') ORDER BY 1""",
}


def fetch_signature(connection, schema: str) -> dict:
    """``connection`` is an open psycopg connection. Only SELECTs are issued; row data
    is reduced to a per-table (count, md5-of-row-hashes) pair and never returned."""
    check_schema(schema)
    sig: dict = {"schema": schema}
    with connection.cursor() as cur:
        for name, query in SIGNATURE_QUERIES.items():
            cur.execute(query, {"s": schema})
            sig[name] = [list(row) for row in cur.fetchall()]
        cur.execute("SELECT coalesce(sum(n_live_tup),0) FROM pg_stat_user_tables "
                    "WHERE schemaname=%s", (schema,))
        if int(cur.fetchone()[0]) > MAX_SIGNATURE_ROWS:
            raise BackupError("BLOCKED_V223_TABLE_TOO_LARGE_FOR_ROW_DIGEST")
        rows = {}
        for table, _, _ in sig["tables"]:
            cur.execute(f'SELECT count(*), coalesce(md5(string_agg(md5(t::text),\'\' '
                        f'ORDER BY md5(t::text))),\'\') FROM "{schema}"."{table}" t')
            count, digest = cur.fetchone()
            rows[table] = [int(count), digest]
        sig["rows"] = rows
    return sig


def diff_signatures(source: dict, restored: dict) -> list[str]:
    """Return mismatch labels only (names, never values)."""
    problems = []
    for key in sorted(set(source) | set(restored)):
        if source.get(key) == restored.get(key):
            continue
        if isinstance(source.get(key), dict) and isinstance(restored.get(key), dict):
            names = sorted(k for k in set(source[key]) | set(restored[key])
                           if source[key].get(k) != restored[key].get(k))
            problems.extend(f"{key}:{name}" for name in names)
        elif isinstance(source.get(key), list) and isinstance(restored.get(key), list):
            a = {row[0]: row for row in source[key]}
            b = {row[0]: row for row in restored[key]}
            names = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
            problems.extend(f"{key}:{name}" for name in names)
        else:
            problems.append(key)
    return problems


def signature_digest(sig: dict) -> str:
    return hashlib.sha256(json.dumps(sig, sort_keys=True, default=str).encode()).hexdigest()


# ------------------------------------------------------------------------ pipeline
def verdict(summary: dict) -> str:
    """P0-1 is PASS only for a real source restored to a separate PG17 with 0 diffs and
    every negative test rejected. Anything else is stated as such, never PASS."""
    if not summary.get("source_is_real_dev_db"):
        return "NOT_P0_1_PASS: source was not the real development database"
    # A user-provided 'real_source' switch alone is never proof that a real
    # backup was restored. Require independent execution evidence as well.
    required_evidence = ("source_identity_verified", "snapshot_consistent",
                         "restore_verified", "decrypt_sha256_matches")
    if not all(summary.get(k) is True for k in required_evidence):
        return "PARTIAL: source, snapshot, decrypt or actual restore not verified"
    if summary.get("signature_mismatches") != []:
        return "FAIL: restored database differs from source"
    if not isinstance(summary.get("tables"), int) or summary["tables"] < 1:
        return "PARTIAL: no verified application tables"
    needed = ("tamper_rejected", "wrong_key_rejected", "truncation_rejected",
              "partial_dump_restore_rejected")
    if not all(summary.get(k) is True for k in needed):
        return "PARTIAL: a negative test did not run or did not reject"
    return "PASS"


def roles_in_acl(connection, schema: str) -> list[str]:
    """Roles referenced by ACLs/policies in ``schema``; created NOLOGIN on the target
    so ACLs and policies restore faithfully. Passwords/attributes are not copied."""
    check_schema(schema)
    with connection.cursor() as cur:
        cur.execute("""SELECT DISTINCT r.rolname FROM pg_roles r WHERE r.rolname !~ '^pg_' AND (
              EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace,
                      LATERAL aclexplode(coalesce(c.relacl,'{}'::aclitem[])) a
                      WHERE n.nspname=%(s)s AND (a.grantee=r.oid OR a.grantor=r.oid))
              OR EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname=%(s)s
                         AND r.rolname = ANY(p.roles))) ORDER BY 1""", {"s": schema})
        return [row[0] for row in cur.fetchall()]


def run(source_dsn: str, target_admin_dsn: str, schema: str = "jw_dev",
        workdir: Path | None = None, real_source: bool = False) -> dict:
    import psycopg  # lazy: unit tests of the pure logic do not need it
    from psycopg import sql

    check_schema(schema)
    src = guard_source(source_dsn) if real_source else parse_dsn(source_dsn)
    # Explicit source binding prevents arbitrary synthetic or third-party DSNs
    # from being relabeled as an approved real development DB.
    expected_host = os.environ.get("JW_PG_EXPECT_SOURCE_HOST", "")
    if real_source and (not expected_host or expected_host.lower() != src["host"]):
        raise BackupError("BLOCKED_V223_REAL_SOURCE_HOST_NOT_VERIFIED")
    tgt = guard_target(target_admin_dsn, source_dsn)
    key = load_key()
    require_pg17_tools()
    work = Path(workdir or tempfile.mkdtemp(prefix="jw_v223_"))
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    nonce = os.urandom(5).hex()
    restore_db = f"jw_v223_{nonce}"
    plain, enc, back = (work / f"{nonce}.dump", work / f"{nonce}.jwpgbk", work / f"{nonce}.back")
    summary: dict = {"source_is_real_dev_db": bool(real_source), "schema": schema,
                     "restore_db": restore_db, "timings_s": {}}
    t = time.monotonic
    created = False
    try:
        # PostgreSQL exported snapshot keeps source signatures and pg_dump
        # consistent under concurrent writes (the transaction stays open until
        # pg_dump exits). The read-only permission is enforced by PostgreSQL.
        with psycopg.connect(source_dsn, autocommit=True) as conn:
            conn.execute("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            snapshot = conn.execute("SELECT pg_export_snapshot()").fetchone()[0]
            summary["server_version"] = conn.execute("SHOW server_version").fetchone()[0]
            src_sig = fetch_signature(conn, schema)
            roles = roles_in_acl(conn, schema)
            t0 = t()
            run_tool(["pg_dump", "--format=custom", f"--schema={schema}", "--no-owner",
                      f"--snapshot={snapshot}", "--lock-wait-timeout=30s",
                      "--file", str(plain)], src, timeout=600)
            summary["timings_s"]["dump"] = round(t() - t0, 3)
            summary["snapshot_consistent"] = True
            summary["source_identity_verified"] = (not real_source or
                        bool(expected_host and src["host"] == expected_host.lower()))
        summary["encrypt"] = encrypt_file(plain, enc, key)
        summary["dump_bytes"] = plain.stat().st_size
        plain.unlink()
        # negative tests on the ENCRYPTED artifact (never on the only copy)
        data = bytearray(enc.read_bytes())
        for label, mutate in (("tamper_rejected", lambda d: d.__setitem__(len(d) // 2, d[len(d) // 2] ^ 1)),
                              ("truncation_rejected", lambda d: d.__delitem__(slice(-40, None)))):
            copy = bytearray(data)
            mutate(copy)
            bad = work / f"{nonce}.{label}"
            bad.write_bytes(bytes(copy))
            try:
                decrypt_file(bad, work / f"{nonce}.{label}.out", key)
                summary[label] = False
            except BackupError:
                summary[label] = True
            finally:
                bad.unlink(missing_ok=True)
        try:
            decrypt_file(enc, work / f"{nonce}.wrongkey", AESGCM.generate_key(256))
            summary["wrong_key_rejected"] = False
        except BackupError:
            summary["wrong_key_rejected"] = True
        t1 = t()
        summary["decrypt_sha256_matches"] = decrypt_file(enc, back, key) == summary["encrypt"]["plain_sha256"]
        if not summary["decrypt_sha256_matches"]:
            raise BackupError("FAIL_V223_BACKUP_DECRYPT_HASH_MISMATCH")
        run_tool(["pg_restore", "--list", str(back)], tgt, timeout=60)
        with psycopg.connect(target_admin_dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(restore_db)))
            created = True
        restore_opts = {**tgt, "dbname": restore_db}
        restore_dsn = target_admin_dsn.rsplit("/", 1)[0] + "/" + restore_db
        with psycopg.connect(restore_dsn, autocommit=True) as tconn:
            for role in roles:
                tconn.execute(sql.SQL("DO $$BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname={}) "
                                      "THEN CREATE ROLE {} NOLOGIN; END IF; END$$").format(
                                          sql.Literal(role), sql.Identifier(role)))
        run_tool(["pg_restore", "--no-owner", "--exit-on-error", "--dbname", restore_db, str(back)],
                 restore_opts, timeout=600)
        summary["timings_s"]["restore_rto"] = round(t() - t1, 3)
        with psycopg.connect(restore_dsn) as tconn:
            restored_sig = fetch_signature(tconn, schema)
        summary["signature_mismatches"] = diff_signatures(src_sig, restored_sig)
        summary["restore_verified"] = not summary["signature_mismatches"]
        summary["tables"] = len(src_sig["tables"])
        summary["signature_sha256"] = signature_digest(src_sig)
        # A truncated archive can still pass `pg_restore --list` because its
        # TOC can be intact. Demand a failed REAL restore into another isolated
        # disposable database; never use --list as a proxy for restore success.
        half = work / f"{nonce}.half"
        half.write_bytes(back.read_bytes()[: back.stat().st_size * 6 // 10])
        bad_restore_db = f"{restore_db}_truncated"
        with psycopg.connect(target_admin_dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(bad_restore_db)))
        try:
            try:
                run_tool(["pg_restore", "--no-owner", "--exit-on-error",
                          "--dbname", bad_restore_db, str(half)],
                         {**tgt, "dbname": bad_restore_db}, timeout=60)
                summary["partial_dump_restore_rejected"] = False
            except BackupError:
                summary["partial_dump_restore_rejected"] = True
        finally:
            with psycopg.connect(target_admin_dsn, autocommit=True) as admin:
                admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(
                              sql.Identifier(bad_restore_db)))
        summary["rpo_note"] = "snapshot backup: commits after pg_dump started are not included"
    finally:
        for path in (plain, back, work / f"{nonce}.half"):
            path.unlink(missing_ok=True)
        if created:
            with psycopg.connect(target_admin_dsn, autocommit=True) as admin:
                admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(restore_db)))
    summary["verdict"] = verdict(summary)
    return summary


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] != "run":
        print("usage: JW_PG_SOURCE_DSN=... JW_PG_TARGET_ADMIN_DSN=... JW_PG_BACKUP_KEY=... "
              "JW_PG_REAL_SOURCE=1 python -m scripts.pg_backup_v223 run", file=sys.stderr)
        return 2
    source, target = os.environ.get("JW_PG_SOURCE_DSN", ""), os.environ.get("JW_PG_TARGET_ADMIN_DSN", "")
    secrets = [parse_dsn(d)["password"] for d in (source, target) if d]
    try:
        summary = run(source, target, os.environ.get("JW_PG_SCHEMA", "jw_dev"),
                      real_source=os.environ.get("JW_PG_REAL_SOURCE") == "1")
    except BackupError as exc:
        print(redact(str(exc), *secrets), file=sys.stderr)
        return 1
    except Exception as exc:
        # Never print traceback or error strings from DB clients in public logs;
        # they may include unredacted credentials or customer data.
        print("FAIL_V223_UNEXPECTED_" + type(exc).__name__, file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
