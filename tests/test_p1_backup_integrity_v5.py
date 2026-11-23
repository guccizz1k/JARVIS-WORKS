"""P1 V5 integrity regressions. Pure unit tests; no DB, secrets, or network."""
from __future__ import annotations

from collections import Counter
import hashlib
import inspect
import itertools
from pathlib import Path

import pytest

from scripts import pg_backup_v223 as p


def test_duplicate_loss_original_false_negative_regression():
    a = {"acl": [["t", "before"], ["t", "unchanged"]]}
    b = {"acl": [["t", "after"], ["t", "unchanged"]]}
    assert p.diff_signatures(a, b) == ["acl:t"]
    diag = p.diagnose_signature_mismatches(a, b)["acl"]
    assert diag["source_objects"] == 2
    assert diag["restored_objects"] == 2
    assert diag["different_definition_or_grants"] == 1


@pytest.mark.parametrize("category", ["acl", "constraints", "tables", "policies", "indexes"])
def test_duplicate_count_is_not_dropped(category):
    src = {category: [["a", "one"], ["a", "one"]]}
    dst = {category: [["a", "one"]]}
    assert p.diff_signatures(src, dst)
    assert p.signature_digest(p.canonical_signature(src)) != p.signature_digest(p.canonical_signature(dst))


def test_sql_result_reordering_does_not_change_canonical_digest():
    src = {"tables": [["b", True], ["a", False]], "acl": [["t", "A"], ["t", "B"]]}
    dst = {"tables": [["a", False], ["b", True]], "acl": [["t", "B"], ["t", "A"]]}
    assert p.diff_signatures(src, dst) == []
    assert p.signature_digest(p.canonical_signature(src)) == p.signature_digest(p.canonical_signature(dst))


def test_missing_dict_key_even_if_value_is_none():
    assert p.diff_signatures({"rows": {"t": None}}, {"rows": {}}) == ["rows:t"]
    assert p.diff_signatures({"rows": {}}, {"rows": {"t": None}}) == ["rows:t"]


def test_missing_top_level_key_is_rejected():
    assert p.diff_signatures({"rows": None}, {}) == ["rows"]


def test_duplicate_multiset_combinatorial_regression():
    alphabet = [("a", "x"), ("a", "y"), ("b", "x")]
    sequences = [list(seq) for n in range(4) for seq in itertools.product(alphabet, repeat=n)]
    for seq1 in sequences:
        for seq2 in sequences:
            a = {"acl": [list(row) for row in seq1]}
            b = {"acl": [list(row) for row in seq2]}
            changed = Counter(seq1) != Counter(seq2)
            assert bool(p.diff_signatures(a, b)) == changed
            d = p.diagnose_signature_mismatches(a, b)["acl"]
            assert bool(d["missing_in_restore"] or d["unexpected_in_restore"] or
                        d["different_definition_or_grants"]) == changed


@pytest.mark.parametrize("invalid_row", [None, [], "not-a-row", 1])
def test_bad_signature_rows_fail_closed(invalid_row):
    with pytest.raises(ValueError, match="INVALID_SIGNATURE_ROW"):
        p.diff_signatures({"acl": [invalid_row]}, {"acl": [invalid_row]})


def test_diagnostics_do_not_emit_acl_values():
    value = "sensitive-fixture-not-for-logs"
    a, b = {"acl": [["t", value]]}, {"acl": [["t", "changed"]]}
    assert value not in repr(p.diff_signatures(a, b))
    assert value not in repr(p.diagnose_signature_mismatches(a, b))


def test_ciphertext_file_hash_and_decrypt(tmp_path: Path):
    key = p.AESGCM.generate_key(bit_length=256)
    original = tmp_path / "plain"
    cipher = tmp_path / "cipher"
    restored = tmp_path / "restored"
    original.write_bytes(b"backup-test-only-" * 100)
    info = p.encrypt_file(original, cipher, key)
    assert info["plain_sha256"] == hashlib.sha256(original.read_bytes()).hexdigest()
    assert info["cipher_sha256"] == hashlib.sha256(cipher.read_bytes()).hexdigest()
    assert p.decrypt_file(cipher, restored, key) == info["plain_sha256"]
    assert restored.read_bytes() == original.read_bytes()


def test_ciphertext_tamper_and_truncation_are_rejected(tmp_path: Path):
    key = p.AESGCM.generate_key(bit_length=256)
    original = tmp_path / "plain"
    encrypted = tmp_path / "encrypted"
    original.write_bytes(b"secretless-fixture" * 100)
    p.encrypt_file(original, encrypted, key)
    for suffix, payload in [("tamper", bytearray(encrypted.read_bytes())),
                            ("short", bytearray(encrypted.read_bytes()[:-1]))]:
        if suffix == "tamper":
            payload[-6] ^= 1
        modified = tmp_path / suffix
        modified.write_bytes(payload)
        plaintext_out = tmp_path / (suffix + ".out")
        with pytest.raises(p.BackupError):
            p.decrypt_file(modified, plaintext_out, key)
        assert not plaintext_out.exists()


def test_ciphertext_wrong_key_rejected(tmp_path: Path):
    original = tmp_path / "plain"
    encrypted = tmp_path / "encrypted"
    original.write_bytes(b"fixture")
    key = p.AESGCM.generate_key(bit_length=256)
    p.encrypt_file(original, encrypted, key)
    out = tmp_path / "wrong"
    with pytest.raises(p.BackupError):
        p.decrypt_file(encrypted, out, p.AESGCM.generate_key(bit_length=256))
    assert not out.exists()


def _valid_mock_evidence():
    flags = ("source_identity_verified", "source_role_least_privilege",
             "target_proven_ephemeral", "snapshot_consistent",
             "restore_verified", "decrypt_sha256_matches",
             "signature_digest_matches", "archive_sha256_matches",
             "tamper_rejected", "wrong_key_rejected", "truncation_rejected",
             "partial_dump_restore_rejected")
    evidence = {key: True for key in flags}
    evidence.update(source_is_real_dev_db=True, signature_mismatches=[], tables=1)
    return evidence


def test_verdict_denies_missing_or_false_integrity_evidence():
    base = _valid_mock_evidence()
    assert p.verdict(base) == "PASS"  # Test-only synthetic evidence, no DB claim.
    for key in ("signature_digest_matches", "archive_sha256_matches",
                "restore_verified", "decrypt_sha256_matches"):
        for mode in ("missing", "false"):
            bad = base.copy()
            if mode == "missing":
                bad.pop(key)
            else:
                bad[key] = False
            assert p.verdict(bad) != "PASS"


def test_source_guard_blocks_nonreal_db_and_missing_tables():
    sample = _valid_mock_evidence()
    sample["source_is_real_dev_db"] = False
    assert p.verdict(sample) != "PASS"
    sample = _valid_mock_evidence()
    sample["tables"] = 0
    assert p.verdict(sample) != "PASS"


def test_real_run_source_contains_restored_hash_and_stream_guard():
    src = inspect.getsource(p.run)
    assert 'summary["archive_sha256_matches"]' in src
    assert 'summary["signature_digest_matches"]' in src
    assert 'summary["restore_verified"]' in src
    assert 'summary["signature_component_sha256"]' in src


@pytest.mark.parametrize("tool, status", [("pg_dump", 1), ("pg_restore", 2)])
def test_pg_tool_stderr_never_leaks(monkeypatch, tool, status):
    """A failed PostgreSQL utility must never copy arbitrary stderr into logs."""
    from types import SimpleNamespace
    opts = dict(host="127.0.0.1", port="55433", user="postgres",
                password="unpublished-fixture-password", dbname="postgres",
                sslmode="", sslrootcert="")
    sensitive = "CREATE FUNCTION secret AS 'private-row'; postgresql://u:password@db"
    def fake_run(*args, **kwargs):
        assert kwargs["capture_output"] is True
        return SimpleNamespace(returncode=status, stderr=sensitive, stdout="")
    monkeypatch.setattr(p.subprocess, "run", fake_run)
    with pytest.raises(p.BackupError) as exc:
        p.run_tool([tool, "--version"], opts, timeout=5)
    message = str(exc.value)
    assert message == f"FAIL_V223_{tool.upper()}_EXIT_{status}"
    for forbidden in ("private-row", "password", "CREATE FUNCTION", "postgresql://"):
        assert forbidden not in message


def test_pg_tool_success_returns_stdout_without_stderr(monkeypatch):
    from types import SimpleNamespace
    opts = dict(host="127.0.0.1", port="55433", user="postgres",
                password="synthetic-fixture", dbname="postgres",
                sslmode="", sslrootcert="")
    monkeypatch.setattr(
        p.subprocess, "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stderr="sensitive-stderr", stdout="good")
    )
    assert p.run_tool(["pg_dump", "--version"], opts, timeout=5) == "good"


@pytest.mark.parametrize("sensitive_name", [
    "JW_PG_BACKUP_KEY", "JW_PG_SOURCE_DSN", "JW_PG_TARGET_ADMIN_DSN",
    "JW_PG_TARGET_EPHEMERAL_TOKEN", "GH_TOKEN", "GITHUB_TOKEN",
    "AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY", "DATABASE_URL", "SECRET_KEY",
])
def test_pg_child_env_strips_sensitive_tokens(monkeypatch, sensitive_name):
    """PostgreSQL CLI processes must not inherit unrelated credentials."""
    monkeypatch.setenv(sensitive_name, "canary-do-not-inherit")
    opts = dict(host="127.0.0.1", port="55433", user="postgres",
                password="db-only-test-fixture", dbname="postgres",
                sslmode="verify-full", sslrootcert="/tmp/test-root-ca.pem")
    env = p.pg_env(opts)
    assert sensitive_name not in env
    assert "canary-do-not-inherit" not in repr(env)
    assert env["PGHOST"] == opts["host"]
    assert env["PGPORT"] == opts["port"]
    assert env["PGUSER"] == opts["user"]
    assert env["PGPASSWORD"] == opts["password"]
    assert env["PGDATABASE"] == opts["dbname"]
    assert env["PGSSLMODE"] == opts["sslmode"]
    assert env["PGSSLROOTCERT"] == opts["sslrootcert"]


def test_pg_child_env_preserves_path_without_inheriting_unused_pg_secrets(monkeypatch):
    monkeypatch.setenv("PATH", "/synthetic-bin:/usr/bin")
    monkeypatch.setenv("PGSERVICEFILE", "/tmp/sensitive-service.conf")
    monkeypatch.setenv("PGPASSFILE", "/tmp/sensitive-passfile")
    opts = dict(host="localhost", port="5432", user="u", password="synthetic",
                dbname="d", sslmode="", sslrootcert="")
    env = p.pg_env(opts)
    assert env["PATH"] == "/synthetic-bin:/usr/bin"
    assert "PGSERVICEFILE" not in env
    assert "PGPASSFILE" not in env
    assert "PGSSLMODE" not in env
    assert "PGSSLROOTCERT" not in env


def test_version_probe_does_not_inherit_credentials(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setenv("JW_PG_BACKUP_KEY", "canary-backup-key")
    monkeypatch.setenv("GITHUB_TOKEN", "canary-github-token")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "canary-cloud-secret")
    seen = []
    def fake_run(args, **kwargs):
        seen.append((args, kwargs))
        return SimpleNamespace(returncode=0, stderr="", stdout="pg_dump (PostgreSQL) 17.11")
    monkeypatch.setattr(p.subprocess, "run", fake_run)
    assert p.tool_major("pg_dump") == 17
    assert len(seen) == 1
    args, kwargs = seen[0]
    assert args == ["pg_dump", "--version"]
    for name in ("JW_PG_BACKUP_KEY", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY"):
        assert name not in kwargs["env"]
    assert "PGPASSWORD" not in kwargs["env"]
    assert "PATH" in kwargs["env"]


def test_pg_tool_env_allowlist_is_shared_with_version_probe(monkeypatch):
    """Keep a single source of truth for safe subprocess environment."""
    monkeypatch.setenv("JW_PG_SOURCE_DSN", "secret-dsn-canary")
    parent = p._pg_process_base_env()
    opts = dict(host="127.0.0.1", port="55433", user="postgres",
                password="synthetic-fixture", dbname="postgres",
                sslmode="", sslrootcert="")
    env = p.pg_env(opts)
    assert "JW_PG_SOURCE_DSN" not in parent
    assert "JW_PG_SOURCE_DSN" not in env
    assert all(env[name] == value for name, value in parent.items())


@pytest.mark.parametrize("malformed", [
    "not-a-url",
    "postgresql://[unclosed-ipv6",
    "postgresql://",
])
def test_safe_password_extraction_never_crashes(malformed):
    assert p._safe_dsn_password(malformed) == ""


def test_safe_password_extraction_retains_password_redaction():
    assert p._safe_dsn_password("postgresql://alice:safe-fixture@localhost/test") == "safe-fixture"


def test_malformed_dsn_never_leaks_traceback(monkeypatch, capsys):
    """Broken URL must flow to sanitized CLI errors, not print an exception traceback."""
    monkeypatch.setenv("JW_PG_SOURCE_DSN", "postgresql://[malformed-host")
    monkeypatch.setenv(
        "JW_PG_TARGET_ADMIN_DSN",
        "postgresql://u:target-fixture-secret@localhost:5432/postgres")
    monkeypatch.setattr(p, "install_termination_handlers", lambda: None)
    assert p.main(["run"]) == 1
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    assert "target-fixture-secret" not in captured.err
    assert "FAIL_V223_UNEXPECTED_ValueError" in captured.err


def test_mark_target_error_handling_survives_malformed_url(monkeypatch, capsys):
    """A malformed target must not crash its own error redaction handler."""
    monkeypatch.setenv("JW_PG_TARGET_ADMIN_DSN", "postgresql://[malformed-target")
    monkeypatch.setenv("JW_PG_TARGET_EPHEMERAL_TOKEN", "bad")
    assert p.mark_target() == 1
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    assert "BLOCKED_V223_TOKEN_REQUIRED_MIN_16_CHARS" in captured.err


@pytest.mark.parametrize("bad_dsn", [
    "postgresql://[missing-ipv6-bracket",
    "postgresql://",
    "bad-scheme://u:p@localhost/db",
])
def test_malformed_dsn_fails_before_optional_psycopg_import(monkeypatch, bad_dsn):
    """Isolation test: reject invalid connection strings even without psycopg installed."""
    import sys
    monkeypatch.setitem(sys.modules, "psycopg", None)
    with pytest.raises((p.BackupError, ValueError)):
        p.run(
            bad_dsn,
            "postgresql://u:fixture@127.0.0.1:55433/postgres",
            schema="jw_dev",
            real_source=False,
        )


def test_validation_precedes_psycopg_import_in_real_engine():
    src = inspect.getsource(p.run)
    validation = src.index("tgt = guard_target(target_admin_dsn, source_dsn)")
    driver = src.index("    import psycopg")
    assert validation < driver, "DB driver import must not preempt DSN validation"


# Batch security regressions: no production resources or credentials involved.
@pytest.mark.parametrize(("source", "target"), [
    ("postgresql://u:p@127.0.0.1:55432/postgres", "postgresql://u:p@localhost:55432/postgres"),
    ("postgresql://u:p@localhost:55432/postgres", "postgresql://u:p@127.0.0.1:55432/postgres"),
    ("postgresql://u:p@[::1]:55432/postgres", "postgresql://u:p@127.0.0.1:55432/postgres"),
])
def test_source_target_loopback_aliases_are_not_independent(source, target):
    with pytest.raises(p.BackupError, match="TARGET_EQUALS_SOURCE"):
        p.guard_target(target, source, {"JW_PG_CI_ALLOW": "ONLY_EPHEMERAL_LOCAL_DATABASE"})


def test_different_loopback_ports_remain_allowed():
    source = "postgresql://u:p@localhost:55432/postgres"
    target = "postgresql://u:p@127.0.0.1:55433/postgres"
    assert p.guard_target(target, source, {"JW_PG_CI_ALLOW": "ONLY_EPHEMERAL_LOCAL_DATABASE"})["port"] == "55433"


def test_new_workspace_is_private_0700(tmp_path: Path):
    folder = p.prepare_private_workdir(tmp_path / "new_private")
    assert folder.is_dir()
    assert folder.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o770, 0o777, 0o600])
def test_existing_nonprivate_workspaces_fail_closed(tmp_path: Path, mode):
    folder = tmp_path / "shared"
    folder.mkdir()
    folder.chmod(mode)
    with pytest.raises(p.BackupError, match="WORKDIR_NOT_PRIVATE_0700"):
        p.prepare_private_workdir(folder)


def test_symlinked_workspace_is_rejected(tmp_path: Path):
    actual = tmp_path / "actual"
    actual.mkdir(mode=0o700)
    link = tmp_path / "alias"
    link.symlink_to(actual, target_is_directory=True)
    with pytest.raises(p.BackupError, match="WORKDIR_SYMLINK"):
        p.prepare_private_workdir(link)


def _readonly_role_facts():
    facts = {key: False for key in p.ROLE_FACT_KEYS}
    facts.update(tables=1, tables_unreadable=0, tables_writable=0, rls_tables=1,
                 sequences_writable=0, schema_usage=True, same_session_user=True,
                 bypassrls=True)
    return facts


def test_valid_rls_source_role_still_passes():
    assert p.evaluate_source_privileges(_readonly_role_facts()) == []


@pytest.mark.parametrize(("key", "value", "failure"), [
    ("sequences_writable", 1, "sequences_writable"),
    ("tables_writable", 1, "tables_writable"),
    ("rls_tables", -1, "rls_table_count_invalid"),
    ("rls_tables", "1", "rls_table_count_invalid"),
    ("rls_tables", None, "facts_incomplete"),
    ("bypassrls", False, "rls_rows_not_fully_readable"),
])
def test_source_role_untrusted_or_write_capable_fails_closed(key, value, failure):
    facts = _readonly_role_facts()
    facts[key] = value
    assert failure in p.evaluate_source_privileges(facts)


def test_bypassrls_is_rejected_without_rls_tables():
    facts = _readonly_role_facts()
    facts["rls_tables"] = 0
    assert "bypassrls_without_rls" in p.evaluate_source_privileges(facts)


def test_source_privilege_catalog_includes_views_and_nextval():
    sql = p.ROLE_SQL
    assert "('r','p','v','m','f')" in sql
    assert "has_sequence_privilege(c.oid, 'USAGE')" in sql
    assert "has_sequence_privilege(c.oid, 'UPDATE')" in sql
