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
            "source_role_least_privilege": True, "target_proven_ephemeral": True,
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
    assert pb.verdict({**full, "source_role_least_privilege": False}).startswith("PARTIAL")
    assert pb.verdict({**full, "target_proven_ephemeral": False}).startswith("PARTIAL")
    for gone in ("source_role_least_privilege", "target_proven_ephemeral"):
        absent = dict(full)
        del absent[gone]
        assert pb.verdict(absent).startswith("PARTIAL")
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
    monkeypatch.setattr(pb, 'verify_ephemeral_target', lambda *_a, **_k: None)  # covered below
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


class SigCursor:
    """Scripted cursor: records every statement; behaviour chosen by the caller."""
    def __init__(self, history, tables, exact, raise_on=None):
        self.history, self.tables, self.exact, self.raise_on = history, tables, exact, raise_on
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def execute(self, statement, params=None):
        text = str(statement)
        self.history.append(text)
        if self.raise_on and self.raise_on in text:
            raise type("QueryCanceled", (Exception,), {})("canceling statement due to statement timeout")
    def fetchall(self):
        last = self.history[-1]
        if "FROM pg_class c JOIN pg_namespace" in last and "c.relkind IN ('r','p')" in last:
            return [(t, False, False) for t in self.tables]
        return []
    def fetchone(self):
        last = self.history[-1]
        if "bit(64)" in last:
            return (self.exact, "1", "2")
        return (self.exact,)


class SigConnection:
    def __init__(self, tables, exact=0, raise_on=None):
        self.history = []
        self._args = (tables, exact, raise_on)
    def cursor(self):
        return SigCursor(self.history, *self._args)


def test_fetch_signature_uses_escaped_catalog_table_identifier():
    conn = SigConnection(['has"quote'])
    pb.fetch_signature(conn, 'jw_dev')
    assert any('FROM "jw_dev"."has""quote" t' in entry for entry in conn.history)
    assert not any('FROM "jw_dev"."has"quote" t' in entry for entry in conn.history)


# ---------------------------------------------------------------- F5: bounded signature
def test_row_cap_uses_exact_counts_and_never_the_planner_estimate(monkeypatch):
    monkeypatch.setattr(pb, "MAX_TABLE_ROWS", 10)
    conn = SigConnection(["big_table"], exact=11)       # catalog statistics are not consulted
    with pytest.raises(pb.BackupError, match="BLOCKED_V223_TABLE_OVER_ROW_CAP:big_table"):
        pb.fetch_signature(conn, "jw_dev")
    assert not any("pg_stat" in h or "n_live_tup" in h for h in conn.history)
    assert not any("bit(64)" in h for h in conn.history), "no row hashing before the cap check"


def test_total_row_cap_is_checked_from_exact_counts_before_any_digest(monkeypatch):
    monkeypatch.setattr(pb, "MAX_TABLE_ROWS", 10)
    monkeypatch.setattr(pb, "MAX_SIGNATURE_ROWS", 5)
    conn = SigConnection(["a", "b", "c"], exact=3)      # 3 tables x 3 rows = 9 > 5
    with pytest.raises(pb.BackupError, match="BLOCKED_V223_TABLE_TOO_LARGE_FOR_ROW_DIGEST"):
        pb.fetch_signature(conn, "jw_dev")
    assert not any("bit(64)" in h for h in conn.history)


def test_row_digest_is_streamed_order_independent_and_timeboxed():
    conn = SigConnection(["t1"], exact=2)
    sig = pb.fetch_signature(conn, "jw_dev")
    assert "statement_timeout" in conn.history[0] and "set_config" in conn.history[0]
    digest_sql = [h for h in conn.history if "bit(64)" in h][0]
    assert "string_agg" not in digest_sql and "ORDER BY" not in digest_sql.upper()
    assert sig["rows"]["t1"][0] == 2 and len(sig["rows"]["t1"][1]) == 32
    assert "n_live_tup" not in "".join(conn.history)


def test_statement_timeout_is_reported_as_a_stable_blocked_code():
    conn = SigConnection(["t1"], exact=1, raise_on="bit(64)")
    with pytest.raises(pb.BackupError, match="BLOCKED_V223_SIGNATURE_STATEMENT_TIMEOUT"):
        pb.fetch_signature(conn, "jw_dev")


def test_row_cap_error_cannot_leak_an_attacker_shaped_table_name(monkeypatch):
    monkeypatch.setattr(pb, "MAX_TABLE_ROWS", 1)
    hostile = 'x"; DROP TABLE y;-- ' + "z" * 100
    with pytest.raises(pb.BackupError) as info:
        pb.fetch_signature(SigConnection([hostile], exact=2), "jw_dev")
    assert '"' not in str(info.value) and ";" not in str(info.value) and len(str(info.value)) < 120


# ------------------------------------------------- F2: source role must be least privilege
GOOD_ROLE = {"superuser": False, "createrole": False, "createdb": False, "replication": False,
             "bypassrls": True, "same_session_user": True, "settable_other_roles": False,
             "privileged_builtin_member": False,
             "database_create": False, "schema_usage": True, "schema_create": False,
             "tables": 62, "tables_unreadable": 0, "tables_writable": 0, "rls_tables": 61,
             "sequences_writable": 0}


def test_set_role_membership_escalation_is_denied():
    # A LOGIN role can have no effective INSERT permission while still being able
    # to SET ROLE to a writer through SET TRUE / INHERIT FALSE membership.
    # This must fail even when current_user == session_user before SET ROLE.
    candidate = {**GOOD_ROLE, "settable_other_roles": True}
    assert "settable_other_roles" in pb.evaluate_source_privileges(candidate)
    assert "pg_has_role(current_user, r2.oid, 'SET')" in pb.ROLE_SQL


def test_good_read_only_role_with_bypassrls_is_accepted_when_schema_has_rls():
    assert set(GOOD_ROLE) == set(pb.ROLE_FACT_KEYS)
    assert pb.evaluate_source_privileges(GOOD_ROLE) == []


@pytest.mark.parametrize("change,expected", [
    ({"superuser": True}, "superuser"),
    ({"createrole": True}, "createrole"),
    ({"createdb": True}, "createdb"),
    ({"replication": True}, "replication"),
    ({"privileged_builtin_member": True}, "privileged_builtin_member"),
    ({"database_create": True}, "database_create"),
    ({"schema_create": True}, "schema_create"),
    ({"same_session_user": False}, "role_switched"),
    ({"settable_other_roles": True}, "settable_other_roles"),
    ({"schema_usage": False}, "schema_no_usage"),
    ({"tables": 0}, "no_tables_visible"),
    ({"tables_unreadable": 1}, "tables_unreadable"),
    ({"tables_writable": 1}, "tables_writable"),
    ({"sequences_writable": 1}, "sequences_writable"),
    ({"bypassrls": False}, "rls_rows_not_fully_readable"),
])
def test_each_excess_privilege_is_reported_by_name(change, expected):
    assert expected in pb.evaluate_source_privileges({**GOOD_ROLE, **change})


def test_no_bypassrls_is_fine_only_when_the_schema_has_no_rls_tables():
    assert pb.evaluate_source_privileges({**GOOD_ROLE, "bypassrls": False, "rls_tables": 0}) == []


def test_postgres_style_superuser_is_rejected_even_if_name_matches_expectation():
    admin = {**GOOD_ROLE, "superuser": True, "createrole": True, "createdb": True,
             "tables_writable": 62, "schema_create": True, "database_create": True}
    assert {"superuser", "tables_writable", "schema_create"} <= set(pb.evaluate_source_privileges(admin))


@pytest.mark.parametrize("facts", [{}, {**GOOD_ROLE, "tables": None},
                                   {k: v for k, v in GOOD_ROLE.items() if k != "superuser"},
                                   {**GOOD_ROLE, "extra": True}])
def test_incomplete_or_unexpected_role_facts_fail_closed(facts):
    assert pb.evaluate_source_privileges(facts) == ["facts_incomplete"]


def test_role_sql_only_reads_catalogs_and_is_parameterised():
    sql = pb.ROLE_SQL.upper()
    for word in ("INSERT ", "UPDATE ", "DELETE ", "DROP ", "ALTER ", "CREATE TABLE", "GRANT ", "SET ROLE"):
        assert word not in sql.replace("'UPDATE'", "").replace("'INSERT'", "").replace("'DELETE'", "")
    assert "%(S)S" in sql and "CURRENT_USER" in sql and "pg_has_role".upper() in sql


def _real_source_env(monkeypatch):
    monkeypatch.setenv("JW_PG_CI_ALLOW", "ONLY_EPHEMERAL_LOCAL_DATABASE")
    for key, name in pb.IDENTITY_ENV.items():
        monkeypatch.setenv(name, {"host": f"db.{REF}.supabase.co", "port": "5432",
                                  "project_ref": REF, "dbname": "postgres", "role": "reader",
                                  "schema_fingerprint": FP}[key])


def _fake_psycopg(monkeypatch, connections):
    import sys
    import types

    class Conn:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def execute(self, sql, *a):
            class R:
                def fetchone(self_inner):
                    return ("fake-snapshot",) if "pg_export_snapshot" in sql else ("17.11",)
            return R()

    def connect(dsn, **kwargs):
        connections.append(dsn)
        return Conn()

    fake = types.ModuleType("psycopg")
    fake.connect = connect
    fake.sql = types.SimpleNamespace()
    monkeypatch.setitem(sys.modules, "psycopg", fake)


def test_privileged_source_role_blocks_before_signature_or_dump(monkeypatch, tmp_path):
    trace, connections = [], []
    _fake_psycopg(monkeypatch, connections)
    _real_source_env(monkeypatch)
    monkeypatch.setattr(pb, "require_pg17_tools", lambda: None)
    monkeypatch.setattr(pb, "verify_ephemeral_target", lambda *_a, **_k: None)
    monkeypatch.setattr(pb, "load_key", lambda: b"K" * 32)
    monkeypatch.setattr(pb, "fetch_live_identity", lambda *_a: {
        "dbname": "postgres", "user": "reader", "major": 17, "fingerprint": FP})
    monkeypatch.setattr(pb, "fetch_role_facts", lambda *_a: {**GOOD_ROLE, "superuser": True})
    monkeypatch.setattr(pb, "fetch_signature", lambda *_a: trace.append("signature"))
    monkeypatch.setattr(pb, "roles_in_acl", lambda *_a: trace.append("roles"))
    monkeypatch.setattr(pb, "run_tool", lambda *_a, **_k: trace.append("dump"))
    with pytest.raises(pb.BackupError, match="BLOCKED_V223_SOURCE_ROLE_NOT_LEAST_PRIVILEGE:superuser"):
        pb.run(DIRECT, LOCAL, real_source=True, workdir=tmp_path)
    assert trace == []


# --------------------------------------- F1: restore target must prove it is disposable
TOKEN = "t" * 32
GOOD_TARGET = {"dbname": "postgres", "in_recovery": False, "major": 17,
               "databases": ["jw_ephemeral_marker", "postgres"],
               "marker_comment": pb.EPHEMERAL_MARKER_PREFIX + TOKEN, "user_relations": 0}


def test_marked_empty_pg17_target_is_accepted_including_our_own_leftovers():
    assert pb.evaluate_target_facts(GOOD_TARGET, TOKEN) == []
    with_left = {**GOOD_TARGET, "databases": ["jw_ephemeral_marker", "jw_v223_0123456789", "postgres"]}
    assert pb.evaluate_target_facts(with_left, TOKEN) == []


@pytest.mark.parametrize("change,token,expected", [
    ({}, "", "token_missing_or_short"),
    ({}, "short", "token_missing_or_short"),
    ({}, "u" * 32, "marker_token_mismatch"),
    ({"marker_comment": None}, TOKEN, "marker_token_mismatch"),
    ({"marker_comment": pb.EPHEMERAL_MARKER_PREFIX + "x" * 32}, TOKEN, "marker_token_mismatch"),
    ({"databases": ["postgres"]}, TOKEN, "marker_missing"),
    ({"databases": ["jw_ephemeral_marker", "postgres", "customer_data"]}, TOKEN, "foreign_databases_present"),
    ({"databases": ["jw_ephemeral_marker", "postgres", "jw_v223_zz"]}, TOKEN, "foreign_databases_present"),
    ({"databases": ["jw_ephemeral_marker", "postgres", "jw_v223_0123456789_x"]}, TOKEN, "foreign_databases_present"),
    ({"user_relations": 3}, TOKEN, "postgres_database_not_empty"),
    ({"in_recovery": True}, TOKEN, "target_is_replica"),
    ({"major": 16}, TOKEN, "target_older_than_17"),
    ({"dbname": "template1"}, TOKEN, "admin_database_not_postgres"),
])
def test_unproven_target_is_rejected_by_name(change, token, expected):
    assert expected in pb.evaluate_target_facts({**GOOD_TARGET, **change}, token)


def test_localhost_plus_environment_variable_alone_is_no_longer_enough():
    # The original QA repro: only host + JW_PG_CI_ALLOW were checked.
    assert pb.guard_target(LOCAL, SRC, {"JW_PG_CI_ALLOW": "ONLY_EPHEMERAL_LOCAL_DATABASE"})["host"] == "127.0.0.1"
    forwarded_production = {**GOOD_TARGET, "marker_comment": None, "databases": ["postgres", "app_prod"],
                            "user_relations": 40}
    failures = pb.evaluate_target_facts(forwarded_production, TOKEN)
    assert {"marker_token_mismatch", "marker_missing", "foreign_databases_present",
            "postgres_database_not_empty"} & set(failures)


@pytest.mark.parametrize("facts", [{}, {k: v for k, v in GOOD_TARGET.items() if k != "major"}])
def test_incomplete_target_facts_fail_closed(facts):
    assert pb.evaluate_target_facts(facts, TOKEN) == ["facts_incomplete"]


def test_target_probe_failure_stops_before_any_source_connection_or_create(monkeypatch, tmp_path):
    connections, executed = [], []
    import sys
    import types

    class Cursor:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def execute(self, statement, params=None):
            executed.append(str(statement))
        def fetchone(self):
            return ("postgres", False, 17, ["postgres", "customer_data"], None, 12)

    class Probe:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def cursor(self):
            return Cursor()
        def execute(self, statement, *a):
            executed.append(str(statement))

    def connect(dsn, **kwargs):
        connections.append(dsn)
        return Probe()

    fake = types.ModuleType("psycopg")
    fake.connect = connect
    fake.sql = types.SimpleNamespace()
    monkeypatch.setitem(sys.modules, "psycopg", fake)
    monkeypatch.setattr(pb, "require_pg17_tools", lambda: None)
    monkeypatch.setattr(pb, "load_key", lambda: b"K" * 32)
    monkeypatch.setenv("JW_PG_CI_ALLOW", "ONLY_EPHEMERAL_LOCAL_DATABASE")
    monkeypatch.setenv(pb.EPHEMERAL_TOKEN_ENV, TOKEN)
    with pytest.raises(pb.BackupError, match="BLOCKED_V223_TARGET_NOT_PROVEN_EPHEMERAL") as info:
        pb.run(SRC.replace("db.example", f"db.{REF}"), LOCAL, real_source=False, workdir=tmp_path)
    assert "foreign_databases_present" in str(info.value)
    assert connections == [LOCAL], "the source database must not be contacted"
    assert not any(w in " ".join(executed).upper() for w in ("CREATE DATABASE", "DROP DATABASE", "CREATE ROLE"))


def test_token_comes_from_environment_not_from_the_dsn(monkeypatch):
    class Cursor:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def execute(self, statement, params=None):
            pass
        def fetchone(self):
            return tuple(GOOD_TARGET[k] for k in pb.TARGET_FACT_KEYS)

    class Conn:
        def cursor(self):
            return Cursor()

    monkeypatch.delenv(pb.EPHEMERAL_TOKEN_ENV, raising=False)
    with pytest.raises(pb.BackupError, match="token_missing_or_short"):
        pb.verify_ephemeral_target(Conn())
    monkeypatch.setenv(pb.EPHEMERAL_TOKEN_ENV, TOKEN)
    pb.verify_ephemeral_target(Conn())          # proven


def test_marker_provisioning_refuses_a_populated_cluster_without_creating_anything(monkeypatch):
    import sys
    import types
    executed = []

    class Cursor:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def execute(self, statement, params=None):
            executed.append(str(statement))
        def fetchone(self):
            return ("postgres", False, 17, ["postgres", "customer_data"], None, 9)

    class Admin:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def cursor(self):
            return Cursor()
        def execute(self, statement, *a):
            executed.append("DIRECT:" + str(statement))

    fake = types.ModuleType("psycopg")
    fake.connect = lambda *a, **k: Admin()
    fake.sql = types.SimpleNamespace()
    monkeypatch.setitem(sys.modules, "psycopg", fake)
    with pytest.raises(pb.BackupError, match="BLOCKED_V223_MARKER_REFUSED_CLUSTER_NOT_EMPTY"):
        pb.provision_ephemeral_marker(LOCAL, TOKEN)
    assert not any(e.startswith("DIRECT:") for e in executed)


def test_restore_dsn_keeps_credentials_and_query_when_switching_database():
    dsn = "postgresql://postgres:pw@127.0.0.1:5433/postgres?sslmode=disable&connect_timeout=5"
    assert pb.dsn_with_dbname(dsn, "jw_v223_abc") == \
        "postgresql://postgres:pw@127.0.0.1:5433/jw_v223_abc?sslmode=disable&connect_timeout=5"
    assert pb.dsn_with_dbname(LOCAL, "x").endswith("@127.0.0.1:5432/x")


def test_mark_target_command_needs_a_long_token_and_never_prints_the_password(monkeypatch, capsys):
    monkeypatch.setenv("JW_PG_TARGET_ADMIN_DSN", LOCAL)
    monkeypatch.setenv("JW_PG_CI_ALLOW", "ONLY_EPHEMERAL_LOCAL_DATABASE")
    monkeypatch.setenv(pb.EPHEMERAL_TOKEN_ENV, "short")
    assert pb.main(["mark-target"]) == 1
    err = capsys.readouterr().err
    assert "BLOCKED_V223_TOKEN_REQUIRED_MIN_16_CHARS" in err and "localpw" not in err
    assert pb.main(["nonsense"]) == 2


@pytest.mark.parametrize("odd", [1, "t", "true", "", 0])
def test_settable_other_roles_accepts_only_a_real_false(odd):
    # Anything that is not the boolean False (a driver returning 0 / 't' / '') fails closed.
    assert "settable_other_roles" in pb.evaluate_source_privileges({**GOOD_ROLE, "settable_other_roles": odd})


# F7: negative-test artifacts must be streamed; large real dumps must never be
# read into RAM just to flip one ciphertext byte or truncate a copy.
@pytest.mark.parametrize("size", [0, 1, pb.CHUNK + 5, 3 * pb.CHUNK + 53])
def test_negative_cipher_copies_are_private_and_fail_authentication(tmp_path, key, size):
    plaintext = make(tmp_path, size)
    enc = tmp_path / "enc"
    pb.encrypt_file(plaintext, enc, key)
    digest_before = __import__("hashlib").sha256(enc.read_bytes()).hexdigest()
    for kind in ("tamper", "truncation"):
        bad = tmp_path / kind
        pb.write_negative_cipher_copy(enc, bad, kind)
        assert bad.stat().st_mode & 0o777 == 0o600
        with pytest.raises(pb.BackupError):
            pb.decrypt_file(bad, tmp_path / f"{kind}.plain", key)
    assert __import__("hashlib").sha256(enc.read_bytes()).hexdigest() == digest_before


def test_negative_artifact_helpers_do_not_use_path_read_bytes(tmp_path, key, monkeypatch):
    src = make(tmp_path, 2 * pb.CHUNK + 37)
    enc, partial = tmp_path / "enc", tmp_path / "partial"
    pb.encrypt_file(src, enc, key)
    def no_read_bytes(self):
        raise AssertionError("negative-test helper attempted whole-file read_bytes")
    monkeypatch.setattr(pb.Path, "read_bytes", no_read_bytes)
    pb.write_negative_cipher_copy(enc, tmp_path / "tamper", "tamper")
    pb.write_negative_cipher_copy(enc, tmp_path / "cut", "truncation")
    pb.write_partial_restore_copy(src, partial)
    assert partial.stat().st_size == src.stat().st_size * 6 // 10
    assert partial.stat().st_mode & 0o777 == 0o600


def test_negative_artifact_fail_closed_no_unsafe_overwrite(tmp_path, key):
    src = make(tmp_path, 50)
    enc = tmp_path / "enc"
    pb.encrypt_file(src, enc, key)
    existing = tmp_path / "existing"
    existing.write_bytes(b"preserve")
    with pytest.raises(pb.BackupError, match="OUTPUT_EXISTS"):
        pb.write_negative_cipher_copy(enc, existing, "tamper")
    assert existing.read_bytes() == b"preserve"
    with pytest.raises(pb.BackupError, match="UNKNOWN_NEGATIVE_TEST"):
        pb.write_negative_cipher_copy(enc, tmp_path / "bad", "unknown")
    with pytest.raises(pb.BackupError, match="OUTPUT_EXISTS"):
        pb.write_partial_restore_copy(src, existing)
    assert existing.read_bytes() == b"preserve"


def test_sigterm_unwinds_instead_of_killing_the_process_without_cleanup():
    """SIGTERM must raise BackupError (so run()'s finally removes the plaintext dump) and ignore a second signal."""
    import signal
    old = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGHUP)}
    try:
        pb.install_termination_handlers()
        handler = signal.getsignal(signal.SIGTERM)
        assert callable(handler) and handler is not signal.SIG_DFL
        with pytest.raises(pb.BackupError, match="FAIL_V223_INTERRUPTED_BY_SIGNAL"):
            handler(signal.SIGTERM, None)
        assert signal.getsignal(signal.SIGTERM) == signal.SIG_IGN   # cleanup cannot be cut short
        assert signal.getsignal(signal.SIGHUP) == signal.SIG_IGN
    finally:
        for s, h in old.items():
            signal.signal(s, h)
