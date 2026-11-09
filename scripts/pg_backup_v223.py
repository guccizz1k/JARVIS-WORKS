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
import shutil
import signal
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
MAX_TABLE_ROWS = 2_000_000          # exact per-table cap (not a planner estimate)
STATEMENT_TIMEOUT = "300s"          # applied to every signature query (transaction local)


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


def write_negative_cipher_copy(src: Path, dst: Path, kind: str) -> None:
    """Make a corrupt 0600 ciphertext copy without loading the entire file into RAM."""
    src, dst = Path(src), Path(dst)
    if kind not in ("tamper", "truncation"):
        raise BackupError("BLOCKED_V223_UNKNOWN_NEGATIVE_TEST")
    payload_offset = len(MAGIC) + 4 + 4
    size = src.stat().st_size
    if size <= payload_offset:
        raise BackupError("BLOCKED_V223_ENCRYPTED_ARTIFACT_TOO_SHORT")
    created = False
    try:
        with open(src, "rb") as original, _open_new(dst) as output:
            created = True
            shutil.copyfileobj(original, output, length=CHUNK)
            if kind == "tamper":
                original.seek(payload_offset)
                byte = original.read(1)
                if len(byte) != 1:
                    raise BackupError("BLOCKED_V223_ENCRYPTED_ARTIFACT_TOO_SHORT")
                output.seek(payload_offset)
                output.write(bytes([byte[0] ^ 1]))
            else:
                output.truncate(max(0, size - 40))
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        if created:
            dst.unlink(missing_ok=True)
        raise


def write_partial_restore_copy(src: Path, dst: Path) -> None:
    """Write a 60%-length damaged custom-format dump using bounded buffers."""
    src, dst = Path(src), Path(dst)
    remaining = src.stat().st_size * 6 // 10
    created = False
    try:
        with open(src, "rb") as original, _open_new(dst) as output:
            created = True
            while remaining > 0:
                block = original.read(min(CHUNK, remaining))
                if not block:
                    raise BackupError("BLOCKED_V223_PARTIAL_DUMP_SOURCE_TRUNCATED")
                output.write(block)
                remaining -= len(block)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        if created:
            dst.unlink(missing_ok=True)
        raise


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


def quote_pg_identifier(value: str) -> str:
    """Quote an identifier sourced from the PostgreSQL catalog, including embedded quotes."""
    if not isinstance(value, str) or not value or "\x00" in value:
        raise BackupError("BLOCKED_V223_INVALID_CATALOG_IDENTIFIER")
    return '"' + value.replace('"', '""') + '"'


def dsn_with_dbname(dsn: str, dbname: str) -> str:
    """Same DSN (scheme, credentials, host, query such as sslmode) with another database."""
    parts = urlsplit(dsn)
    from urllib.parse import quote, urlunsplit
    return urlunsplit((parts.scheme, parts.netloc, "/" + quote(dbname, safe=""),
                       parts.query, parts.fragment))


def pg_env(opts: dict) -> dict:
    env = {**os.environ, "PGHOST": opts["host"], "PGPORT": opts["port"],
           "PGUSER": opts["user"], "PGPASSWORD": opts["password"], "PGDATABASE": opts["dbname"]}
    if opts.get("sslmode"):
        env["PGSSLMODE"] = opts["sslmode"]
    if opts.get("sslrootcert"):
        env["PGSSLROOTCERT"] = opts["sslrootcert"]
    return env


TOOL_VERSION_RE = re.compile(r"^\S+ \(PostgreSQL\) (\d+)(?:\.\d+)*\b", re.ASCII)


def parse_tool_major(out: str) -> int | None:
    """``pg_dump (PostgreSQL) 17.11 (Debian 17.11-1.pgdg13+2)`` -> 17. The number right after
    ``(PostgreSQL)`` is the version; a distribution suffix in parentheses is ignored, never parsed."""
    match = TOOL_VERSION_RE.match((out or "").strip())
    return int(match.group(1)) if match else None


def tool_major(tool: str) -> int:
    out = subprocess.run([tool, "--version"], capture_output=True, text=True, timeout=15).stdout
    major = parse_tool_major(out)
    if major is None:
        raise BackupError("BLOCKED_V223_TOOL_VERSION_UNKNOWN")
    return major


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
    # NULL relacl means "owner default"; an explicit ACL equal to that default (left behind by
    # GRANT ... then REVOKE/DROP OWNED) is not dumped by pg_dump, so compare the EFFECTIVE ACL.
    "acl": """SELECT c.relname, coalesce(c.relacl, acldefault((CASE c.relkind WHEN 'S' THEN 's'
                     ELSE 'r' END)::"char", c.relowner))::text FROM pg_class c
              JOIN pg_namespace n ON n.oid=c.relnamespace
              WHERE n.nspname=%(s)s AND c.relkind IN ('r','p','S','v') ORDER BY 1""",
}


def _safe_label(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "?", str(name))[:40]


def fetch_signature(connection, schema: str) -> dict:
    """``connection`` is an open psycopg connection. Only SELECTs are issued; row data
    is reduced to a per-table (count, digest) pair and never returned.

    Row digests are streamed in constant memory: each row is hashed on the server and
    the 64-bit halves are summed (order independent, so no sort and no string_agg of
    the whole table). Sizes are bounded by EXACT counts, never by planner estimates,
    and every query runs under a transaction-local statement_timeout."""
    check_schema(schema)
    sig: dict = {"schema": schema}
    with connection.cursor() as cur:
        cur.execute("SELECT set_config('statement_timeout', %s, true)", (STATEMENT_TIMEOUT,))
        try:
            for name, query in SIGNATURE_QUERIES.items():
                cur.execute(query, {"s": schema})
                sig[name] = [list(row) for row in cur.fetchall()]
            tables = [row[0] for row in sig["tables"]]
            total = 0
            for table in tables:   # pass 1: bounded exact counts, no row hashing yet
                cur.execute(f"SELECT count(*) FROM (SELECT 1 FROM {quote_pg_identifier(schema)}."
                            f"{quote_pg_identifier(table)} LIMIT %s) s", (MAX_TABLE_ROWS + 1,))
                exact = int(cur.fetchone()[0])
                if exact > MAX_TABLE_ROWS:
                    raise BackupError("BLOCKED_V223_TABLE_OVER_ROW_CAP:" + _safe_label(table))
                total += exact
                if total > MAX_SIGNATURE_ROWS:
                    raise BackupError("BLOCKED_V223_TABLE_TOO_LARGE_FOR_ROW_DIGEST")
            rows = {}
            for table in tables:   # pass 2: streamed order-independent digest
                cur.execute(
                    "SELECT count(*), coalesce(sum(('x'||substr(h,1,16))::bit(64)::bigint::numeric),0)::text, "
                    "coalesce(sum(('x'||substr(h,17,16))::bit(64)::bigint::numeric),0)::text "
                    f"FROM (SELECT md5(t::text) AS h FROM {quote_pg_identifier(schema)}."
                    f"{quote_pg_identifier(table)} t) s")
                count, low, high = cur.fetchone()
                if int(count) > MAX_TABLE_ROWS:
                    raise BackupError("BLOCKED_V223_TABLE_OVER_ROW_CAP:" + _safe_label(table))
                rows[table] = [int(count), hashlib.md5(f"{count}:{low}:{high}".encode()).hexdigest()]
        except BackupError:
            raise
        except Exception as exc:
            if type(exc).__name__ == "QueryCanceled":
                raise BackupError("BLOCKED_V223_SIGNATURE_STATEMENT_TIMEOUT") from None
            raise
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


# --------------------------------------------------------- independent source identity
# A host name alone cannot prove which database was dumped (another database or role on the
# same host, or a restored copy elsewhere, would look similar). A real-source run therefore
# needs ALL of these to agree with expectations supplied out-of-band by the operator:
#   host, port, Supabase project ref (derived from the DSN), database name and role (both
#   from the DSN AND from the live session), server major >= 17, and a path-independent
#   fingerprint of the live schema shape. The expected fingerprint should be computed
#   through a different channel than the DSN (for example the Supabase management plane).
IDENTITY_ENV = {
    "host": "JW_PG_EXPECT_SOURCE_HOST", "port": "JW_PG_EXPECT_SOURCE_PORT",
    "project_ref": "JW_PG_EXPECT_PROJECT_REF", "dbname": "JW_PG_EXPECT_DBNAME",
    "role": "JW_PG_EXPECT_ROLE", "schema_fingerprint": "JW_PG_EXPECT_SCHEMA_FINGERPRINT",
}
IDENTITY_CHECKS = ("host", "port", "project_ref", "dbname", "role", "server_major",
                   "schema_fingerprint")
PROJECT_REF_RE = re.compile(r"[a-z]{20}")
IDENTITY_SQL = """
SELECT t.tables, t.force_rls, f.functions, g.triggers, t.tmd5, f.fmd5,
       md5(concat_ws('|', t.tables, t.force_rls, f.functions, g.triggers, t.tmd5, f.fmd5))
FROM (SELECT count(*) AS tables, count(*) FILTER (WHERE c.relforcerowsecurity) AS force_rls,
             md5(coalesce(string_agg(c.relname, ',' ORDER BY c.relname), '')) AS tmd5
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = %(s)s AND c.relkind IN ('r','p')) t,
     (SELECT count(*) AS functions,
             md5(coalesce(string_agg(p.proname || '/' || p.pronargs, ','
                 ORDER BY p.proname || '/' || p.pronargs), '')) AS fmd5
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = %(s)s AND p.prokind IN ('f','p')) f,
     (SELECT count(*) AS triggers FROM pg_trigger tg JOIN pg_class c ON c.oid = tg.tgrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = %(s)s AND NOT tg.tgisinternal) g
"""


def project_ref_from_dsn(opts: dict) -> str:
    """Direct host ``db.<ref>.supabase.co`` or pooler login ``<role>.<ref>``; else ''."""
    match = re.fullmatch(r"db\.([a-z]{20})\.supabase\.co", opts.get("host", ""))
    if not match:
        match = re.fullmatch(r"[^.]+\.([a-z]{20})", opts.get("user", ""))
    return match.group(1) if match else ""


def dsn_role(opts: dict) -> str:
    match = re.fullmatch(r"([^.]+)\.[a-z]{20}", opts.get("user", ""))
    return match.group(1) if match else opts.get("user", "")


def read_identity_expectations(environ: dict | None = None) -> dict:
    env = os.environ if environ is None else environ
    return {key: env.get(name, "").strip() for key, name in IDENTITY_ENV.items()}


def fetch_live_identity(connection, schema: str) -> dict:
    """SELECT-only facts about the live session; no names or row values are returned."""
    check_schema(schema)
    with connection.cursor() as cur:
        cur.execute("SELECT current_database(), current_user, "
                    "current_setting('server_version_num')::int / 10000")
        dbname, user, major = cur.fetchone()
        cur.execute(IDENTITY_SQL, {"s": schema})
        fingerprint = cur.fetchone()[-1]
    return {"dbname": dbname, "user": user, "major": int(major), "fingerprint": fingerprint}


def check_source_identity(opts: dict, live: dict, expected: dict) -> dict:
    """Return {check: bool}. An absent expectation or absent live fact is always False."""
    def same(a, b) -> bool:
        return bool(a) and bool(b) and a == b

    ref = project_ref_from_dsn(opts)
    want = {k: (expected.get(k) or "") for k in IDENTITY_ENV}
    return {
        "host": same(opts.get("host", ""), want["host"].lower()),
        "port": same(opts.get("port", ""), want["port"]),
        "project_ref": PROJECT_REF_RE.fullmatch(ref) is not None and same(ref, want["project_ref"]),
        "dbname": same(opts.get("dbname", ""), want["dbname"]) and same(live.get("dbname", ""), want["dbname"]),
        "role": same(dsn_role(opts), want["role"]) and same(live.get("user", ""), want["role"]),
        "server_major": isinstance(live.get("major"), int) and live["major"] >= 17,
        "schema_fingerprint": same(live.get("fingerprint", ""), want["schema_fingerprint"].lower()),
    }


def identity_failures(checks: dict) -> list[str]:
    return [name for name in IDENTITY_CHECKS if checks.get(name) is not True]


def identity_verified(checks: dict) -> bool:
    return set(checks) == set(IDENTITY_CHECKS) and not identity_failures(checks)


# ------------------------------------------------ F2: source role must be least privilege
# A matching role NAME proves nothing about its power. Before any table is scanned or
# dumped, the live session's attributes and privileges are read (SELECT only).
# BYPASSRLS is the one deliberate allowance: with FORCE ROW LEVEL SECURITY a dump or a
# row digest taken without it would silently see only some rows. It is allowed only when
# the schema actually has RLS tables, and everything that could WRITE stays forbidden.
PRIVILEGED_BUILTIN_ROLES = ("pg_write_all_data", "pg_execute_server_program",
                            "pg_read_server_files", "pg_write_server_files")
ROLE_FACT_KEYS = ("superuser", "createrole", "createdb", "replication", "bypassrls",
                  "same_session_user", "settable_other_roles", "privileged_builtin_member", "database_create",
                  "schema_usage", "schema_create", "tables", "tables_unreadable",
                  "tables_writable", "rls_tables", "sequences_writable")
ROLE_SQL = """
SELECT r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls,
       current_user = session_user,
       EXISTS (SELECT 1 FROM pg_roles r2 WHERE r2.rolname <> current_user
               AND pg_has_role(current_user, r2.oid, 'SET')),
       (SELECT coalesce(bool_or(pg_has_role(current_user, m, 'MEMBER')), false)
          FROM unnest(%(builtin)s::text[]) m),
       has_database_privilege(current_user, current_database(), 'CREATE'),
       has_schema_privilege(current_user, %(s)s, 'USAGE'),
       has_schema_privilege(current_user, %(s)s, 'CREATE'),
       t.tables, t.unreadable, t.writable, t.rls_tables, q.writable_seq
FROM pg_roles r,
     LATERAL (SELECT count(*) AS tables,
                     count(*) FILTER (WHERE NOT has_table_privilege(c.oid, 'SELECT')) AS unreadable,
                     count(*) FILTER (WHERE has_table_privilege(c.oid, 'INSERT')
                                         OR has_table_privilege(c.oid, 'UPDATE')
                                         OR has_table_privilege(c.oid, 'DELETE')
                                         OR has_table_privilege(c.oid, 'TRUNCATE')
                                         OR has_table_privilege(c.oid, 'REFERENCES')
                                         OR has_table_privilege(c.oid, 'TRIGGER')) AS writable,
                     count(*) FILTER (WHERE c.relrowsecurity) AS rls_tables
              FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = %(s)s AND c.relkind IN ('r','p')) t,
     LATERAL (SELECT count(*) FILTER (WHERE has_sequence_privilege(c.oid, 'UPDATE')) AS writable_seq
              FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = %(s)s AND c.relkind = 'S') q
WHERE r.rolname = current_user
"""


def fetch_role_facts(connection, schema: str) -> dict:
    check_schema(schema)
    with connection.cursor() as cur:
        cur.execute(ROLE_SQL, {"s": schema, "builtin": list(PRIVILEGED_BUILTIN_ROLES)})
        row = cur.fetchone()
    if row is None or len(row) != len(ROLE_FACT_KEYS):
        return {}
    return dict(zip(ROLE_FACT_KEYS, row))


def evaluate_source_privileges(facts: dict) -> list[str]:
    """Names of violated rules; empty means least privilege. Missing facts fail closed."""
    if set(facts) != set(ROLE_FACT_KEYS) or any(v is None for v in facts.values()):
        return ["facts_incomplete"]
    bad = []
    for key, name in (("superuser", "superuser"), ("createrole", "createrole"),
                      ("createdb", "createdb"), ("replication", "replication"),
                      ("privileged_builtin_member", "privileged_builtin_member"),
                      ("database_create", "database_create"), ("schema_create", "schema_create")):
        if facts[key] is not False:
            bad.append(name)
    if facts["same_session_user"] is not True:
        bad.append("role_switched")
    if facts["settable_other_roles"] is not False:
        bad.append("settable_other_roles")
    if facts["schema_usage"] is not True:
        bad.append("schema_no_usage")
    if not (isinstance(facts["tables"], int) and facts["tables"] >= 1):
        bad.append("no_tables_visible")
    for key, name in (("tables_unreadable", "tables_unreadable"), ("tables_writable", "tables_writable"),
                      ("sequences_writable", "sequences_writable")):
        if facts[key] != 0:
            bad.append(name)
    if isinstance(facts["rls_tables"], int) and facts["rls_tables"] > 0 and facts["bypassrls"] is not True:
        bad.append("rls_rows_not_fully_readable")
    return bad


# ------------------------------------------- F1: restore target must PROVE it is disposable
# ``localhost`` and an environment variable prove nothing (a tunnel or a forwarded port can
# point anywhere). The target cluster must carry a marker that the operator planted in the
# disposable cluster, bound to a secret token, AND look empty: no user database other than
# ``postgres``, the marker and our own leftovers, and no relations in ``postgres``.
EPHEMERAL_TOKEN_ENV = "JW_PG_TARGET_EPHEMERAL_TOKEN"
EPHEMERAL_MARKER_DB = "jw_ephemeral_marker"
EPHEMERAL_MARKER_PREFIX = "JW_EPHEMERAL_V1:"
LEFTOVER_DB_RE = re.compile(r"jw_v223_[0-9a-f]{10}(_truncated)?")
TARGET_SQL = """
SELECT current_database(), pg_is_in_recovery(),
       current_setting('server_version_num')::int / 10000,
       (SELECT array_agg(datname ORDER BY datname) FROM pg_database WHERE NOT datistemplate),
       (SELECT shobj_description(oid, 'pg_database') FROM pg_database WHERE datname = %(m)s),
       (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')
           AND n.nspname !~ '^pg_(temp|toast_temp)'
           AND c.relkind IN ('r','p','v','m','S','f'))
"""
TARGET_FACT_KEYS = ("dbname", "in_recovery", "major", "databases", "marker_comment", "user_relations")


def fetch_target_facts(connection) -> dict:
    with connection.cursor() as cur:
        cur.execute(TARGET_SQL, {"m": EPHEMERAL_MARKER_DB})
        row = cur.fetchone()
    return dict(zip(TARGET_FACT_KEYS, row)) if row and len(row) == len(TARGET_FACT_KEYS) else {}


def evaluate_target_facts(facts: dict, token: str, require_marker: bool = True) -> list[str]:
    """Names of failed proofs (never values). Empty list = target proven disposable."""
    import hmac
    if set(facts) != set(TARGET_FACT_KEYS):
        return ["facts_incomplete"]
    bad = []
    if len(token or "") < 16:
        bad.append("token_missing_or_short")
    if facts["dbname"] != "postgres":
        bad.append("admin_database_not_postgres")
    if facts["in_recovery"] is not False:
        bad.append("target_is_replica")
    if not isinstance(facts["major"], int) or facts["major"] < 17:
        bad.append("target_older_than_17")
    names = list(facts["databases"] or [])
    foreign = [n for n in names if n not in ("postgres", EPHEMERAL_MARKER_DB)
               and not LEFTOVER_DB_RE.fullmatch(n)]
    if foreign:
        bad.append("foreign_databases_present")
    if facts["user_relations"] != 0:
        bad.append("postgres_database_not_empty")
    if require_marker:
        want = EPHEMERAL_MARKER_PREFIX + (token or "")
        comment = facts["marker_comment"] or ""
        if EPHEMERAL_MARKER_DB not in names:
            bad.append("marker_missing")
        elif len(token or "") < 16 or not hmac.compare_digest(comment.encode(), want.encode()):
            bad.append("marker_token_mismatch")
    return bad


def verify_ephemeral_target(connection, token: str | None = None) -> None:
    token = os.environ.get(EPHEMERAL_TOKEN_ENV, "") if token is None else token
    failures = evaluate_target_facts(fetch_target_facts(connection), token)
    if failures:
        raise BackupError("BLOCKED_V223_TARGET_NOT_PROVEN_EPHEMERAL:" + ",".join(failures))


def provision_ephemeral_marker(admin_dsn: str, token: str) -> None:
    """For the operator of a disposable cluster (CI container setup). Refuses any cluster
    that already holds foreign databases or relations, so it cannot label a populated one."""
    import psycopg
    from psycopg import sql
    with psycopg.connect(admin_dsn, autocommit=True) as admin:
        failures = evaluate_target_facts(fetch_target_facts(admin), token, require_marker=False)
        if failures:
            raise BackupError("BLOCKED_V223_MARKER_REFUSED_CLUSTER_NOT_EMPTY:" + ",".join(failures))
        exists = admin.execute("SELECT 1 FROM pg_database WHERE datname=%s",
                               (EPHEMERAL_MARKER_DB,)).fetchone()
        if not exists:
            admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(EPHEMERAL_MARKER_DB)))
        admin.execute(sql.SQL("COMMENT ON DATABASE {} IS {}").format(
            sql.Identifier(EPHEMERAL_MARKER_DB), sql.Literal(EPHEMERAL_MARKER_PREFIX + token)))


# ------------------------------------------------------------------------ pipeline
def verdict(summary: dict) -> str:
    """P0-1 is PASS only for a real source restored to a separate PG17 with 0 diffs and
    every negative test rejected. Anything else is stated as such, never PASS."""
    if not summary.get("source_is_real_dev_db"):
        return "NOT_P0_1_PASS: source was not the real development database"
    # A user-provided 'real_source' switch alone is never proof that a real
    # backup was restored. Require independent execution evidence as well.
    required_evidence = ("source_identity_verified", "source_role_least_privilege",
                         "target_proven_ephemeral", "snapshot_consistent",
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
                      LATERAL aclexplode(c.relacl) a
                      WHERE n.nspname=%(s)s AND c.relacl IS NOT NULL
                        AND (a.grantee=r.oid OR a.grantor=r.oid))
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
    # F1: prove the restore target is a disposable cluster BEFORE connecting to the source
    # or issuing any CREATE/DROP on the target.
    with psycopg.connect(target_admin_dsn, autocommit=True) as probe:
        verify_ephemeral_target(probe)
    work = Path(workdir or tempfile.mkdtemp(prefix="jw_v223_"))
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    nonce = os.urandom(5).hex()
    restore_db = f"jw_v223_{nonce}"
    plain, enc, back = (work / f"{nonce}.dump", work / f"{nonce}.jwpgbk", work / f"{nonce}.back")
    summary: dict = {"source_is_real_dev_db": bool(real_source), "schema": schema,
                     "restore_db": restore_db, "timings_s": {},
                     "target_proven_ephemeral": True}
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
            identity_checks = None
            if real_source:
                # Verify identity BEFORE scanning full tables or dumping the source.
                identity_checks = check_source_identity(
                    src, fetch_live_identity(conn, schema), read_identity_expectations())
                summary["identity_checks"] = identity_checks
                if not identity_verified(identity_checks):
                    raise BackupError("BLOCKED_V223_SOURCE_IDENTITY_NOT_VERIFIED:"
                                      + ",".join(identity_failures(identity_checks)))
            role_failures = []
            if real_source:
                # F2: least privilege proof, still before any table scan or dump.
                role_failures = evaluate_source_privileges(fetch_role_facts(conn, schema))
                if role_failures:
                    raise BackupError("BLOCKED_V223_SOURCE_ROLE_NOT_LEAST_PRIVILEGE:"
                                      + ",".join(role_failures))
            summary["source_role_least_privilege"] = (not real_source) or not role_failures
            src_sig = fetch_signature(conn, schema)
            roles = roles_in_acl(conn, schema)
            t0 = t()
            run_tool(["pg_dump", "--format=custom", f"--schema={schema}", "--no-owner",
                      f"--snapshot={snapshot}", "--lock-wait-timeout=30s",
                      "--file", str(plain)], src, timeout=600)
            summary["timings_s"]["dump"] = round(t() - t0, 3)
            summary["snapshot_consistent"] = True
            summary["source_identity_verified"] = (not real_source or
                        identity_verified(identity_checks or {}))
        summary["encrypt"] = encrypt_file(plain, enc, key)
        summary["dump_bytes"] = plain.stat().st_size
        plain.unlink()
        # negative tests on the ENCRYPTED artifact (never on the only copy)
        for label, kind in (("tamper_rejected", "tamper"),
                            ("truncation_rejected", "truncation")):
            bad = work / f"{nonce}.{label}"
            write_negative_cipher_copy(enc, bad, kind)
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
        restore_dsn = dsn_with_dbname(target_admin_dsn, restore_db)
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
        write_partial_restore_copy(back, half)
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


def install_termination_handlers() -> None:
    """SIGTERM/SIGHUP must unwind through run()'s ``finally`` so a plaintext dump, the decrypted copy and the
    temporary restore database are removed; the default action ends the process without any cleanup.
    A second signal during that cleanup is ignored so the cleanup cannot be cut short."""
    def _handler(signum, _frame):
        for sig in (signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        raise BackupError("FAIL_V223_INTERRUPTED_BY_SIGNAL")
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, _handler)


def mark_target() -> int:
    """``mark-target``: plant the ephemeral marker in the disposable restore cluster."""
    target, token = os.environ.get("JW_PG_TARGET_ADMIN_DSN", ""), os.environ.get(EPHEMERAL_TOKEN_ENV, "")
    try:
        if len(token) < 16:
            raise BackupError("BLOCKED_V223_TOKEN_REQUIRED_MIN_16_CHARS")
        guard_target(target, os.environ.get("JW_PG_SOURCE_DSN", "postgresql://none@invalid.invalid/none"))
        provision_ephemeral_marker(target, token)
    except BackupError as exc:
        print(redact(str(exc), parse_dsn(target)["password"] if target else ""), file=sys.stderr)
        return 1
    except Exception as exc:
        print("FAIL_V223_UNEXPECTED_" + type(exc).__name__, file=sys.stderr)
        return 1
    print("OK_V223_TARGET_MARKED")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["mark-target"]:
        return mark_target()
    if len(argv) != 1 or argv[0] != "run":
        print("usage: JW_PG_SOURCE_DSN=... JW_PG_TARGET_ADMIN_DSN=... JW_PG_BACKUP_KEY=... "
              "JW_PG_TARGET_EPHEMERAL_TOKEN=... JW_PG_REAL_SOURCE=1 "
              "python -m scripts.pg_backup_v223 [mark-target|run]", file=sys.stderr)
        return 2
    source, target = os.environ.get("JW_PG_SOURCE_DSN", ""), os.environ.get("JW_PG_TARGET_ADMIN_DSN", "")
    secrets = [parse_dsn(d)["password"] for d in (source, target) if d]
    install_termination_handlers()
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
