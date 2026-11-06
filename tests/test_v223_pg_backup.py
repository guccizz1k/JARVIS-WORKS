"""V22.3 backup tooling: DB-free logic only. The PG17 dump/restore path is NOT covered
here; it needs the disposable PG17 CI job or a local Docker PG17 (see scripts/pg_backup_v223.py)."""
import base64
import os
import struct

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scripts import pg_backup_v223 as pb

SRC = "postgresql://postgres:s3cr3tpw@db.example.supabase.co:5432/postgres?sslmode=verify-full&sslrootcert=/ca.crt"
LOCAL = "postgresql://postgres:localpw@127.0.0.1:5432/postgres"


@pytest.fixture()
def key():
    return AESGCM.generate_key(256)


def make(tmp_path, size):
    src = tmp_path / "plain.bin"
    src.write_bytes(os.urandom(size))
    return src


@pytest.mark.parametrize("size", [0, 1, pb.CHUNK - 1, pb.CHUNK, pb.CHUNK + 1, 3 * pb.CHUNK])
def test_roundtrip_including_chunk_boundaries(tmp_path, key, size):
    src = make(tmp_path, size)
    meta = pb.encrypt_file(src, tmp_path / "e", key)
    assert pb.decrypt_file(tmp_path / "e", tmp_path / "d", key) == meta["plain_sha256"]
    assert (tmp_path / "d").read_bytes() == src.read_bytes()


def test_ciphertext_does_not_contain_plaintext(tmp_path, key):
    src = tmp_path / "p"
    src.write_bytes(b"PGDMP-recognisable-marker" * 1000)
    pb.encrypt_file(src, tmp_path / "e", key)
    assert b"recognisable-marker" not in (tmp_path / "e").read_bytes()


def test_wrong_key_rejected_and_output_removed(tmp_path, key):
    pb.encrypt_file(make(tmp_path, 5000), tmp_path / "e", key)
    with pytest.raises(pb.BackupError, match="AUTH_FAILED"):
        pb.decrypt_file(tmp_path / "e", tmp_path / "d", AESGCM.generate_key(256))
    assert not (tmp_path / "d").exists()


def test_bitflip_rejected(tmp_path, key):
    pb.encrypt_file(make(tmp_path, 5000), tmp_path / "e", key)
    data = bytearray((tmp_path / "e").read_bytes())
    data[len(data) // 2] ^= 1
    (tmp_path / "bad").write_bytes(bytes(data))
    with pytest.raises(pb.BackupError):
        pb.decrypt_file(tmp_path / "bad", tmp_path / "d", key)


def test_truncation_at_chunk_boundary_rejected(tmp_path, key):
    pb.encrypt_file(make(tmp_path, 2 * pb.CHUNK + 10), tmp_path / "e", key)
    raw = (tmp_path / "e").read_bytes()
    first_len = struct.unpack(">I", raw[12:16])[0]
    (tmp_path / "cut").write_bytes(raw[: 12 + 4 + first_len])  # only chunk 0 left
    with pytest.raises(pb.BackupError, match="AUTH_FAILED"):
        pb.decrypt_file(tmp_path / "cut", tmp_path / "d", key)


def test_chunk_reorder_rejected(tmp_path, key):
    pb.encrypt_file(make(tmp_path, 3 * pb.CHUNK), tmp_path / "e", key)
    raw = (tmp_path / "e").read_bytes()
    head, body = raw[:12], raw[12:]
    records, pos = [], 0
    while pos < len(body):
        n = struct.unpack(">I", body[pos:pos + 4])[0]
        records.append(body[pos:pos + 4 + n])
        pos += 4 + n
    records[0], records[1] = records[1], records[0]
    (tmp_path / "swap").write_bytes(head + b"".join(records))
    with pytest.raises(pb.BackupError):
        pb.decrypt_file(tmp_path / "swap", tmp_path / "d", key)


def test_bad_header_and_existing_output_and_symlink(tmp_path, key):
    (tmp_path / "junk").write_bytes(b"not a backup")
    with pytest.raises(pb.BackupError, match="BAD_HEADER"):
        pb.decrypt_file(tmp_path / "junk", tmp_path / "d", key)
    src = make(tmp_path, 10)
    (tmp_path / "exists").write_bytes(b"x")
    with pytest.raises(pb.BackupError, match="OUTPUT_EXISTS"):
        pb.encrypt_file(src, tmp_path / "exists", key)
    (tmp_path / "link").symlink_to(tmp_path / "plain.bin")
    with pytest.raises(pb.BackupError, match="OUTPUT_EXISTS_OR_SYMLINK"):
        pb.encrypt_file(src, tmp_path / "link", key)


def test_key_loading(monkeypatch):
    monkeypatch.delenv("JW_PG_BACKUP_KEY", raising=False)
    with pytest.raises(pb.BackupError, match="KEY_REQUIRED"):
        pb.load_key()
    with pytest.raises(pb.BackupError, match="32_BYTES"):
        pb.load_key(base64.urlsafe_b64encode(b"short").decode())
    good = base64.urlsafe_b64encode(os.urandom(32)).decode()
    assert len(pb.load_key(good)) == 32


def test_source_requires_verify_full_and_root_cert():
    assert pb.guard_source(SRC)["host"] == "db.example.supabase.co"
    for weak in ("postgresql://u:p@h/db", "postgresql://u:p@h/db?sslmode=require",
                 "postgresql://u:p@h/db?sslmode=verify-full"):
        with pytest.raises(pb.BackupError, match="VERIFY_FULL"):
            pb.guard_source(weak)
    with pytest.raises(pb.BackupError, match="POSTGRESQL_URL"):
        pb.guard_source("host=x dbname=y")


def test_target_must_be_declared_local_and_not_source():
    ok = {"JW_PG_CI_ALLOW": "ONLY_EPHEMERAL_LOCAL_DATABASE"}
    assert pb.guard_target(LOCAL, SRC, ok)["host"] == "127.0.0.1"
    with pytest.raises(pb.BackupError, match="NOT_DECLARED_EPHEMERAL"):
        pb.guard_target(LOCAL, SRC, {})
    with pytest.raises(pb.BackupError, match="MUST_BE_LOCAL"):
        pb.guard_target(SRC, SRC, ok)
    with pytest.raises(pb.BackupError, match="MUST_BE_LOCAL"):
        pb.guard_target("postgresql://u:p@db.other.example.com/postgres", SRC, ok)
    same = "postgresql://u:p@localhost:5432/postgres"
    with pytest.raises(pb.BackupError, match="TARGET_EQUALS_SOURCE"):
        pb.guard_target(same, same, ok)


def test_redact_hides_password_and_url_form():
    text = f"connection to {SRC} failed, password s3cr3tpw rejected"
    cleaned = pb.redact(text, "s3cr3tpw")
    assert "s3cr3tpw" not in cleaned


def test_schema_name_is_validated_against_injection():
    assert pb.check_schema("jw_dev") == "jw_dev"
    for bad in ('jw_dev"; DROP SCHEMA x;--', "Jw_Dev", "", "a" * 64):
        with pytest.raises(pb.BackupError, match="BAD_SCHEMA"):
            pb.check_schema(bad)


def _sig(**over):
    base = {"schema": "jw_dev", "tables": [["a", True, True], ["b", True, True]],
            "policies": [["a.p", "h1"]], "functions": [["f()", "h2"]], "triggers": [],
            "indexes": [], "constraints": [], "acl": [["a", "{x=r/y}"]],
            "rows": {"a": [3, "d1"], "b": [0, ""]}}
    base.update(over)
    return base


def test_diff_signatures_reports_names_not_values():
    assert pb.diff_signatures(_sig(), _sig()) == []
    changed = _sig(rows={"a": [2, "d9"], "b": [0, ""]})
    assert pb.diff_signatures(_sig(), changed) == ["rows:a"]
    missing_policy = _sig(policies=[])
    assert pb.diff_signatures(_sig(), missing_policy) == ["policies:a.p"]
    force_off = _sig(tables=[["a", True, False], ["b", True, True]])
    assert pb.diff_signatures(_sig(), force_off) == ["tables:a"]
    assert "d9" not in " ".join(pb.diff_signatures(_sig(), changed))


def test_verdict_never_passes_without_real_source_and_all_negative_tests():
    full = {"source_is_real_dev_db": True, "source_identity_verified": True,
            "snapshot_consistent": True, "restore_verified": True,
            "decrypt_sha256_matches": True, "tables": 2,
            "signature_mismatches": [], "tamper_rejected": True,
            "wrong_key_rejected": True, "truncation_rejected": True,
            "partial_dump_restore_rejected": True}
    assert pb.verdict(full) == "PASS"
    assert pb.verdict({**full, "source_is_real_dev_db": False}).startswith("NOT_P0_1_PASS")
    assert pb.verdict({**full, "signature_mismatches": ["rows:a"]}).startswith("FAIL")
    assert pb.verdict({**full, "tamper_rejected": False}).startswith("PARTIAL")
    assert pb.verdict({**full, "snapshot_consistent": False}).startswith("PARTIAL")
    assert pb.verdict({**full, "restore_verified": False}).startswith("PARTIAL")
    assert pb.verdict({**full, "decrypt_sha256_matches": False}).startswith("PARTIAL")
    assert pb.verdict({**full, "source_identity_verified": False}).startswith("PARTIAL")
    assert pb.verdict({**full, "tables": 0}).startswith("PARTIAL")
    missing = dict(full)
    del missing["wrong_key_rejected"]
    assert pb.verdict(missing).startswith("PARTIAL")


REF = "abcdefghijklmnopqrst"
OTHER_REF = "tsrqponmlkjihgfedcba"
FP = "0123456789abcdef0123456789abcdef"
DIRECT = (f"postgresql://reader:pw@db.{REF}.supabase.co:5432/postgres"
          "?sslmode=verify-full&sslrootcert=/ca.crt")
POOLER = (f"postgresql://reader.{REF}:pw@aws-0-region.pooler.supabase.com:5432/postgres"
          "?sslmode=verify-full&sslrootcert=/ca.crt")
EXPECT = {"host": f"db.{REF}.supabase.co", "port": "5432", "project_ref": REF,
          "dbname": "postgres", "role": "reader", "schema_fingerprint": FP}
LIVE = {"dbname": "postgres", "user": "reader", "major": 17, "fingerprint": FP}


def identity(dsn=DIRECT, live=None, expected=None):
    return pb.check_source_identity(pb.parse_dsn(dsn), {**LIVE, **(live or {})},
                                    {**EXPECT, **(expected or {})})


def test_project_ref_comes_from_direct_host_or_pooler_login_only():
    assert pb.project_ref_from_dsn(pb.parse_dsn(DIRECT)) == REF
    assert pb.project_ref_from_dsn(pb.parse_dsn(POOLER)) == REF
    assert pb.dsn_role(pb.parse_dsn(POOLER)) == "reader"
    assert pb.project_ref_from_dsn(pb.parse_dsn(LOCAL)) == ""
    assert pb.project_ref_from_dsn(pb.parse_dsn(
        f"postgresql://u:p@evil.example.com/{REF}")) == ""


def test_identity_all_checks_pass_for_matching_direct_and_pooler_sources():
    assert pb.identity_verified(identity())
    pooler_expect = {"host": "aws-0-region.pooler.supabase.com"}
    assert pb.identity_verified(identity(POOLER, expected=pooler_expect))


@pytest.mark.parametrize("kwargs,failed", [
    ({"live": {"dbname": "other_db"}}, "dbname"),          # same host, different database
    ({"expected": {"dbname": "other_db"}}, "dbname"),
    ({"live": {"user": "someone_else"}}, "role"),           # same host, different role
    ({"expected": {"role": "someone_else"}}, "role"),
    ({"expected": {"project_ref": OTHER_REF}}, "project_ref"),
    ({"expected": {"host": "db.other.supabase.co"}}, "host"),
    ({"expected": {"port": "6543"}}, "port"),
    ({"live": {"major": 16}}, "server_major"),
    ({"live": {"fingerprint": "f" * 32}}, "schema_fingerprint"),
])
def test_identity_single_mismatch_fails_exactly_that_check(kwargs, failed):
    checks = identity(**kwargs)
    assert pb.identity_failures(checks) == [failed]
    assert not pb.identity_verified(checks)


def test_identity_missing_expectation_or_live_fact_never_verifies():
    for key in pb.IDENTITY_ENV:
        assert not pb.identity_verified(identity(expected={key: ""})), key
    assert not pb.identity_verified(identity(live={"fingerprint": ""}))
    assert not pb.identity_verified(identity(live={"major": None}))
    partial = identity()
    del partial["port"]
    assert not pb.identity_verified(partial)
    assert not pb.identity_verified({})


def test_empty_expected_and_empty_actual_never_count_as_a_match():
    # Both sides blank (unset env + unreadable fact) must NOT verify; a naive a == b would.
    assert pb.identity_failures(identity(
        live={"fingerprint": ""}, expected={"schema_fingerprint": ""})) == ["schema_fingerprint"]
    no_user = "postgresql://db.%s.supabase.co/postgres?sslmode=verify-full&sslrootcert=/ca" % REF
    blank = pb.check_source_identity(
        pb.parse_dsn(no_user), {**LIVE, "user": ""}, {**EXPECT, "role": ""})
    assert "role" in pb.identity_failures(blank)
    assert pb.identity_failures(identity(live={"dbname": ""}, expected={"dbname": ""})) == ["dbname"]


def test_synthetic_local_database_cannot_be_relabelled_real_by_copying_its_own_values():
    own = {"host": "127.0.0.1", "port": "5432", "project_ref": "", "dbname": "postgres",
           "role": "postgres", "schema_fingerprint": FP}
    checks = pb.check_source_identity(pb.parse_dsn(LOCAL), {**LIVE, "user": "postgres"}, own)
    assert pb.identity_failures(checks) == ["project_ref"]
    assert not pb.identity_verified(checks)


def test_expectations_are_read_from_environment_and_stripped():
    env = {"JW_PG_EXPECT_SOURCE_HOST": " h ", "JW_PG_EXPECT_PROJECT_REF": REF}
    got = pb.read_identity_expectations(env)
    assert got["host"] == "h" and got["project_ref"] == REF and got["role"] == ""


def test_identity_sql_is_read_only_parameterised_and_schema_independent_of_literals():
    import re
    assert pb.IDENTITY_SQL.count("%(s)s") == 3 and "jw_dev" not in pb.IDENTITY_SQL
    tokens = set(re.findall(r"[A-Za-z_]+", pb.IDENTITY_SQL.upper()))
    forbidden = {"INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "GRANT",
                 "REVOKE", "TRUNCATE", "COPY", "DO", "CALL"}
    assert not tokens & forbidden, tokens & forbidden
    assert ";" not in pb.IDENTITY_SQL


def test_catalog_identifier_quotes_embedded_double_quote_and_sql_metacharacters():
    assert pb.quote_pg_identifier('normal') == '"normal"'
    assert pb.quote_pg_identifier('has"quote') == '"has""quote"'
    assert pb.quote_pg_identifier('x"; DROP TABLE jw_dev.audit_log; --') == (
        '"x""; DROP TABLE jw_dev.audit_log; --"')
    for bad in ('', 'bad\x00name'):
        with pytest.raises(pb.BackupError):
            pb.quote_pg_identifier(bad)


def test_invalid_real_source_fails_before_table_signature_or_pg_dump(monkeypatch, tmp_path):
    import sys
    import types

    trace = []

    class FakeCursorResult:
        def __init__(self, value):
            self.value = value
        def fetchone(self):
            return (self.value,)

    class FakeConnection:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def execute(self, sql):
            if 'pg_export_snapshot' in sql:
                return FakeCursorResult('fake-snapshot')
            if 'SHOW server_version' in sql:
                return FakeCursorResult('17.11')
            return FakeCursorResult(None)

    fake_psycopg = types.ModuleType('psycopg')
    fake_psycopg.connect = lambda *_args, **_kwargs: FakeConnection()
    fake_psycopg.sql = types.SimpleNamespace()
    monkeypatch.setitem(sys.modules, 'psycopg', fake_psycopg)
    monkeypatch.setattr(pb, 'require_pg17_tools', lambda: None)
    monkeypatch.setattr(pb, 'load_key', lambda: b'K' * 32)
    monkeypatch.setattr(pb, 'fetch_live_identity', lambda *_args: {
        'dbname': 'wrong', 'user': 'reader', 'major': 17,
        'fingerprint': 'not-expected',
    })
    monkeypatch.setattr(pb, 'fetch_signature', lambda *_args: trace.append('signature'))
    monkeypatch.setattr(pb, 'roles_in_acl', lambda *_args: trace.append('roles'))
    monkeypatch.setattr(pb, 'run_tool', lambda *_args, **_kwargs: trace.append('dump'))
    monkeypatch.setenv('JW_PG_CI_ALLOW', 'ONLY_EPHEMERAL_LOCAL_DATABASE')
    monkeypatch.setenv('JW_PG_EXPECT_SOURCE_HOST', f'db.{REF}.supabase.co')
    with pytest.raises(pb.BackupError, match='BLOCKED_V223_SOURCE_IDENTITY_NOT_VERIFIED'):
        pb.run(DIRECT, LOCAL, real_source=True, workdir=tmp_path)
    assert trace == []


def test_fetch_signature_uses_escaped_catalog_table_identifier():
    history = []

    class Cursor:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def execute(self, statement, params=None):
            history.append(str(statement))
        def fetchall(self):
            if 'FROM pg_class c JOIN pg_namespace' in history[-1] and "c.relkind IN ('r','p')" in history[-1]:
                return [('has"quote', False, False)]
            return []
        def fetchone(self):
            if 'pg_stat_user_tables' in history[-1]:
                return (0,)
            return (0, '')

    class Connection:
        def cursor(self):
            return Cursor()

    pb.fetch_signature(Connection(), 'jw_dev')
    assert any('FROM "jw_dev"."has""quote" t' in entry for entry in history)
    assert not any('FROM "jw_dev"."has"quote" t' in entry for entry in history)
