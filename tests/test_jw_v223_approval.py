"""Offline approval verification with ephemeral Ed25519 keys."""

import hashlib
import json
import multiprocessing
import os
import sqlite3
import subprocess
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import jw_v223_approval as approval
from scripts.approval_crypto import ApprovalError, canonical_payload, verify_ed25519


def encode(fields):
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("ascii")


def ledger_for(path):
    return path.parent.with_name(path.parent.name + "-ledger") / "consumption.sqlite"


def initialize_pair(path):
    ledger = ledger_for(path)
    ledger.parent.mkdir(mode=0o700, exist_ok=True)
    approval.initialize_challenge_store(path, ledger_db=ledger)


@pytest.fixture
def challenge_db(tmp_path):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    path = directory / "approvals.sqlite"
    initialize_pair(path)
    return path


@pytest.fixture
def bundle(monkeypatch, challenge_db):
    clock = {"wall": 1_800_000_000, "elapsed": 50}
    monkeypatch.setattr(approval, "time", lambda: clock["wall"])
    monkeypatch.setattr(approval, "monotonic", lambda: clock["elapsed"])
    key = Ed25519PrivateKey.generate()
    public_key = key.public_key().public_bytes_raw()
    policy = approval.OwnerPolicy(
        public_key, hashlib.sha256(public_key).hexdigest(),
        frozenset({"review", "inspect"}), owner_authorized=True,
    )
    request = {
        "manifest": b'{"artifact":"test-only"}',
        "git_tree": subprocess.check_output(
            ["git", "rev-parse", "HEAD^{tree}"], text=True,
            cwd=Path(__file__).resolve().parents[1],
        ).strip(),
        "scope": "review",
    }
    verifier = approval.ApprovalVerifier(policy, challenge_db=challenge_db, ledger_db=ledger_for(challenge_db))
    challenge = verifier.issue(**request)
    fields = {
        "domain": "jarvis-works/v22.3/approval/v1",
        "key_fingerprint": policy.fingerprint,
        "manifest_sha256": hashlib.sha256(request["manifest"]).hexdigest(),
        "git_tree": request["git_tree"],
        "scope": request["scope"],
        "challenge": challenge.nonce,
        "expires_at": challenge.expires_at,
    }
    return verifier, key, policy, request, fields, clock


def verify(bundle):
    verifier, key, _, request, fields, _ = bundle
    payload = encode(fields)
    verifier.verify(payload, key.sign(payload), **request)


def test_valid_approval_and_single_use(bundle):
    verify(bundle)
    with pytest.raises(ApprovalError, match="consumed challenge"):
        verify(bundle)


def test_concurrent_replay_accepts_exactly_once(bundle):
    def attempt(_):
        try:
            verify(bundle)
        except ApprovalError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=8) as executor:
        assert sum(executor.map(attempt, range(32))) == 1


def test_challenge_cannot_be_reused_in_different_store(bundle, tmp_path):
    _, key, policy, request, fields, clock = bundle
    other_dir = tmp_path / "other"
    other_dir.mkdir(mode=0o700)
    other_db = other_dir / "approvals.sqlite"
    initialize_pair(other_db)
    fresh = approval.ApprovalVerifier(policy, challenge_db=other_db, ledger_db=ledger_for(other_db))
    fresh.issue(**request)
    with pytest.raises(ApprovalError, match="unknown"):
        verify((fresh, key, policy, request, fields, clock))


@pytest.mark.parametrize("forgery", ["wrong-key", "altered", "truncated"])
def test_forged_signature_does_not_burn_challenge(bundle, forgery):
    verifier, key, _, request, fields, _ = bundle
    payload = encode(fields)
    signature = key.sign(payload)
    signature = {
        "wrong-key": Ed25519PrivateKey.generate().sign(payload),
        "altered": bytes([signature[0] ^ 1]) + signature[1:],
        "truncated": signature[:-1],
    }[forgery]
    with pytest.raises(ApprovalError, match="signature"):
        verifier.verify(payload, signature, **request)
    verify(bundle)


@pytest.mark.parametrize(("field", "value", "error"), [
    ("key_fingerprint", "0" * 64, "unknown key"),
    ("manifest_sha256", "0" * 64, "manifest SHA-256 mismatch"),
    ("git_tree", "a" * 40, "Git tree mismatch"),
    ("scope", "inspect", "scope mismatch"),
    ("scope", "deploy", "scope mismatch"),
    ("challenge", "a" * 64, "unknown"),
    ("challenge", 5, "invalid challenge"),
    ("expires_at", "1800000300", "invalid challenge"),
    ("domain", "other-project", "schema or domain"),
    ("extra", "value", "schema or domain"),
])
def test_signed_field_mismatch(bundle, field, value, error):
    bundle[4][field] = value
    with pytest.raises(ApprovalError, match=error):
        verify(bundle)


@pytest.mark.parametrize(("field", "value"), [
    ("manifest", b"changed"),
    ("git_tree", "a" * 40),
    ("scope", "inspect"),
])
def test_challenge_bound_to_request_even_if_resigned(bundle, field, value):
    _, _, _, request, fields, _ = bundle
    request[field] = value
    if field == "manifest":
        fields["manifest_sha256"] = hashlib.sha256(value).hexdigest()
    else:
        fields[field] = value
    with pytest.raises(ApprovalError, match="mismatched"):
        verify(bundle)


def test_existing_signature_cannot_cover_modified_payload(bundle):
    verifier, key, _, request, fields, _ = bundle
    signature = key.sign(encode(fields))
    fields["scope"] = "inspect"
    with pytest.raises(ApprovalError, match="invalid signature"):
        verifier.verify(encode(fields), signature, **request)
    fields["scope"] = "review"
    verify(bundle)


@pytest.mark.parametrize("case", ["absent", "denied", "truthy", "scope", "bad-pin"])
def test_missing_or_invalid_owner_policy_fails_closed(bundle, case):
    _, key, policy, request, fields, clock = bundle
    policy = {
        "absent": None,
        "denied": replace(policy, owner_authorized=False),
        "truthy": replace(policy, owner_authorized=1),
        "scope": replace(policy, scopes=frozenset({"inspect"})),
        "bad-pin": replace(policy, public_key=Ed25519PrivateKey.generate().public_key().public_bytes_raw()),
    }[case]
    verifier = approval.ApprovalVerifier(policy)
    with pytest.raises(ApprovalError):
        verify((verifier, key, policy, request, fields, clock))
    with pytest.raises(ApprovalError):
        verifier.issue(**request)


@pytest.mark.parametrize(("wall_delta", "elapsed_delta", "expiry_delta"), [
    (300, 300, 0), (301, 301, 0), (0, 0, 1), (0, 0, -300),
    (-1, 1, 0), (0, 300, 0), (10, 10, -290), (1, 10, -290),
])
def test_expiry_and_clock_boundaries(bundle, wall_delta, elapsed_delta, expiry_delta):
    fields, clock = bundle[4:]
    clock["wall"] += wall_delta
    clock["elapsed"] += elapsed_delta
    fields["expires_at"] += expiry_delta
    with pytest.raises(ApprovalError, match="expired"):
        verify(bundle)


def test_valid_shorter_expiry(bundle):
    bundle[4]["expires_at"] -= 1
    verify(bundle)


@pytest.mark.parametrize("payload", [
    b"", b" " * 4097, b"{", b"[]", b'{"a":true}', b'{"a":null}',
    b'{"a":NaN}', b'{"a":1.0}', b'{"a":{}}', b'{"a":[]}', b'{"a":-0}',
    b'{"a":"\\u0061"}', b'{"a":1,"a":1}', b'{"b":1,"a":2}', b'{"a": 1}',
    b'{"a":1}\n', b'{"a":"\\ud800"}', b'\xff', b"[" * 2000 + b"]" * 2000,
])
def test_noncanonical_payloads_fail_closed(payload):
    with pytest.raises(ApprovalError):
        canonical_payload(payload)


@pytest.mark.parametrize(("field", "value"), [
    ("manifest", b""), ("git_tree", "abc123"), ("git_tree", "A" * 40),
    ("git_tree", "0" * 40), ("scope", "*"), ("scope", "deploy"),
])
def test_invalid_trusted_request_cannot_issue(bundle, field, value):
    verifier, _, _, request, _, _ = bundle
    request[field] = value
    with pytest.raises(ApprovalError):
        verifier.issue(**request)


def test_independent_crypto_primitives():
    payload = b'{"a":1}'
    assert canonical_payload(payload) == {"a": 1}
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()
    signature = private_key.sign(payload)
    verify_ed25519(payload, signature, public_key, hashlib.sha256(public_key).hexdigest())
    with pytest.raises(ApprovalError, match="untrusted key"):
        verify_ed25519(payload, signature, public_key, "0" * 64)


def test_process_copy_cannot_issue_or_consume(bundle, monkeypatch):
    verifier, _, _, request, _, _ = bundle
    monkeypatch.setattr(approval, "getpid", lambda: -1)
    with pytest.raises(ApprovalError, match="different process"):
        verifier.issue(**request)
    with pytest.raises(ApprovalError, match="different process"):
        verify(bundle)


def test_missing_payload_field_is_denied(bundle):
    del bundle[4]["manifest_sha256"]
    with pytest.raises(ApprovalError, match="schema or domain"):
        verify(bundle)


def test_manifest_bytes_are_hashed_without_normalization(bundle):
    bundle[3]["manifest"] += b"\n"
    with pytest.raises(ApprovalError, match="manifest SHA-256 mismatch"):
        verify(bundle)


def _worker_verify(path, policy, request, payload, signature, ready, start, results):
    verifier = approval.ApprovalVerifier(policy, challenge_db=path, ledger_db=ledger_for(path))
    ready.put(None)
    if not start.wait(10):
        raise TimeoutError("worker start")
    try:
        verifier.verify(payload, signature, **request)
    except ApprovalError as exc:
        results.put(str(exc))
    else:
        results.put("accepted")


def run_workers(bundle, path, count):
    _, key, policy, request, fields, _ = bundle
    payload = encode(fields)
    signature = key.sign(payload)
    ctx = multiprocessing.get_context("fork")
    ready, results = ctx.Queue(), ctx.Queue()
    start = ctx.Event()
    workers = [
        ctx.Process(
            target=_worker_verify,
            args=(path, policy, request, payload, signature, ready, start, results),
        )
        for _ in range(count)
    ]
    for worker in workers:
        worker.start()
    try:
        for _ in workers:
            ready.get(timeout=10)
        start.set()
        outcomes = [results.get(timeout=10) for _ in workers]
        for worker in workers:
            worker.join(timeout=10)
            assert worker.exitcode == 0
        return outcomes
    finally:
        for worker in workers:
            if worker.is_alive():
                worker.terminate()
                worker.join()
        ready.close()
        results.close()


def test_pending_survives_worker_restart_but_consumed_challenge_does_not_replay(
    bundle, challenge_db,
):
    assert run_workers(bundle, challenge_db, 1) == ["accepted"]
    assert "consumed challenge" in run_workers(bundle, challenge_db, 1)[0]


def test_worker_process_race_accepts_exactly_once(bundle, challenge_db):
    outcomes = run_workers(bundle, challenge_db, 8)
    assert outcomes.count("accepted") == 1
    assert sum("consumed challenge" in outcome for outcome in outcomes) == 7


def test_failed_update_rolls_back_and_does_not_return_approval(bundle, challenge_db):
    with closing(sqlite3.connect(challenge_db)) as db:
        db.execute("""
            CREATE TRIGGER abort_consumption AFTER UPDATE ON approval_challenges
            BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END
        """)
    assert run_workers(bundle, challenge_db, 1) == ["challenge store unavailable"]
    with closing(sqlite3.connect(challenge_db)) as db:
        assert db.execute("SELECT consumed FROM approval_challenges").fetchone() == (0,)
        db.execute("DROP TRIGGER abort_consumption")
    assert run_workers(bundle, challenge_db, 1) == ["accepted"]
    assert "consumed challenge" in run_workers(bundle, challenge_db, 1)[0]


def test_expiry_and_scope_escalation_survive_worker_restart(bundle, challenge_db):
    original_request = dict(bundle[3])
    original_fields = dict(bundle[4])
    bundle[3]["scope"] = bundle[4]["scope"] = "inspect"
    assert "mismatched" in run_workers(bundle, challenge_db, 1)[0]
    bundle[3].update(original_request)
    bundle[4].update(original_fields)
    bundle[5]["elapsed"] += 301
    assert "expired" in run_workers(bundle, challenge_db, 1)[0]


def test_reboot_and_monotonic_rollback_invalidate_pending(bundle, monkeypatch):
    bundle[5]["elapsed"] -= 1
    with pytest.raises(ApprovalError, match="expired"):
        verify(bundle)
    bundle[5]["elapsed"] += 1
    monkeypatch.setattr(approval, "_boot_id", lambda: "other-boot")
    with pytest.raises(ApprovalError, match="expired"):
        verify(bundle)


def test_challenge_bound_to_issuing_owner_fingerprint(bundle, challenge_db):
    key = Ed25519PrivateKey.generate()
    public_key = key.public_key().public_bytes_raw()
    _, _, policy, request, fields, clock = bundle
    policy = replace(policy, public_key=public_key, fingerprint=hashlib.sha256(public_key).hexdigest())
    verifier = approval.ApprovalVerifier(policy, challenge_db=challenge_db, ledger_db=ledger_for(challenge_db))
    fields = {**fields, "key_fingerprint": policy.fingerprint}
    with pytest.raises(ApprovalError, match="mismatched"):
        verify((verifier, key, policy, request, fields, clock))


def test_consumed_nonce_cannot_be_reissued(bundle, monkeypatch):
    verify(bundle)
    monkeypatch.setattr(approval.secrets, "token_hex", lambda _: bundle[4]["challenge"])
    with pytest.raises(ApprovalError, match="store unavailable"):
        bundle[0].issue(**bundle[3])
    with pytest.raises(ApprovalError, match="consumed"):
        verify(bundle)


@pytest.mark.parametrize("condition", ["unconfigured", "missing", "symlink", "hardlink", "file-mode", "dir-mode", "corrupt"])
def test_unsafe_or_unavailable_store_denies_issue_and_verify(bundle, challenge_db, condition):
    _, key, policy, request, fields, clock = bundle
    path = challenge_db
    assert path.stat().st_mode & 0o777 == 0o600
    if condition == "unconfigured":
        path = None
    elif condition == "missing":
        path = path.with_name("missing.sqlite")
    elif condition == "symlink":
        path = path.with_name("link.sqlite")
        path.symlink_to(challenge_db)
    elif condition == "hardlink":
        path = path.with_name("link.sqlite")
        os.link(challenge_db, path)
    elif condition == "file-mode":
        path.chmod(0o644)
    elif condition == "dir-mode":
        path.parent.chmod(0o755)
    elif condition == "corrupt":
        path.write_bytes(b"not a database")
    verifier = approval.ApprovalVerifier(policy, challenge_db=path, ledger_db=ledger_for(challenge_db))
    with pytest.raises(ApprovalError, match="challenge store"):
        verifier.issue(**request)
    with pytest.raises(ApprovalError, match="challenge store"):
        verify((verifier, key, policy, request, fields, clock))
    if condition == "missing":
        assert not path.exists()


def test_reinitialization_refused_and_consumption_preserved(bundle, challenge_db):
    verify(bundle)
    with pytest.raises(ApprovalError, match="initialize"):
        approval.initialize_challenge_store(challenge_db, ledger_db=ledger_for(challenge_db))
    with pytest.raises(ApprovalError, match="consumed"):
        verify(bundle)


def test_failed_commit_does_not_return_approval(bundle, challenge_db, monkeypatch):
    connect = sqlite3.connect

    def short_timeout(*args, **kwargs):
        return connect(*args, timeout=0.05, **kwargs)

    monkeypatch.setattr(approval.sqlite3, "connect", short_timeout)
    with closing(connect(challenge_db)) as reader:
        reader.execute("BEGIN")
        assert reader.execute("SELECT consumed FROM approval_challenges").fetchone() == (0,)
        with pytest.raises(ApprovalError, match="store unavailable"):
            verify(bundle)
    with closing(connect(challenge_db)) as reader:
        assert reader.execute("SELECT consumed FROM approval_challenges").fetchone() == (0,)
    verify(bundle)
    with pytest.raises(ApprovalError, match="consumed"):
        verify(bundle)


def test_restoring_preconsumption_snapshot_blocks_all_challenges(bundle, challenge_db):
    untouched = bundle[0].issue(**bundle[3])
    stale = challenge_db.read_bytes()
    verify(bundle)
    challenge_db.write_bytes(stale)
    with pytest.raises(ApprovalError, match="checkpoint mismatch"):
        verify(bundle)
    bundle[4].update(challenge=untouched.nonce, expires_at=untouched.expires_at)
    with pytest.raises(ApprovalError, match="checkpoint mismatch"):
        verify(bundle)
    with pytest.raises(ApprovalError, match="checkpoint mismatch"):
        bundle[0].issue(**bundle[3])


def test_preissuance_snapshot_is_detected(bundle, challenge_db):
    stale = challenge_db.read_bytes()
    bundle[0].issue(**bundle[3])
    challenge_db.write_bytes(stale)
    with pytest.raises(ApprovalError, match="checkpoint mismatch"):
        verify(bundle)


@pytest.mark.parametrize("condition", ["omitted", "missing", "corrupt", "unpaired", "colocated"])
def test_invalid_or_unavailable_independent_ledger(bundle, challenge_db, condition):
    verifier, key, policy, request, fields, clock = bundle
    ledger = ledger_for(challenge_db)
    if condition == "omitted":
        ledger = None
    elif condition == "missing":
        ledger = ledger.with_name("missing.sqlite")
    elif condition == "corrupt":
        ledger.write_bytes(b"not sqlite")
    elif condition == "unpaired":
        other = challenge_db.with_name("unused")
        ledger = ledger.with_name("other.sqlite")
        different_dir = challenge_db.parent.with_name("unpaired")
        different_dir.mkdir(mode=0o700)
        approval.initialize_challenge_store(different_dir / other.name, ledger_db=ledger)
    else:
        ledger = challenge_db.with_name("colocated.sqlite")
    rejected = approval.ApprovalVerifier(policy, challenge_db=challenge_db, ledger_db=ledger)
    with pytest.raises(ApprovalError, match="consumption ledger"):
        verify((rejected, key, policy, request, fields, clock))
    with pytest.raises(ApprovalError, match="consumption ledger"):
        rejected.issue(**request)


def test_rollback_of_ledger_only_is_detected(bundle, challenge_db):
    ledger = ledger_for(challenge_db)
    stale = ledger.read_bytes()
    verify(bundle)
    ledger.write_bytes(stale)
    with pytest.raises(ApprovalError, match="checkpoint mismatch"):
        verify(bundle)


def test_ledger_commit_failure_quarantines_pair(bundle, challenge_db, monkeypatch):
    connect = sqlite3.connect

    def short_timeout(*args, **kwargs):
        return connect(*args, timeout=0.05, **kwargs)

    monkeypatch.setattr(approval.sqlite3, "connect", short_timeout)
    with closing(connect(ledger_for(challenge_db))) as reader:
        reader.execute("BEGIN")
        assert reader.execute("SELECT COUNT(*) FROM ledger_events").fetchone() == (1,)
        with pytest.raises(ApprovalError, match="consumption ledger unavailable"):
            verify(bundle)
    with pytest.raises(ApprovalError, match="checkpoint mismatch"):
        verify(bundle)


def _crash_between_commits(bundle, path):
    from contextlib import contextmanager

    transaction = approval._transaction

    @contextmanager
    def crash_after_local_commit(db_path, **kwargs):
        with transaction(db_path, **kwargs) as db:
            yield db
        if db_path == path:
            os._exit(71)

    approval._transaction = crash_after_local_commit
    _, key, policy, request, fields, _ = bundle
    verifier = approval.ApprovalVerifier(policy, challenge_db=path, ledger_db=ledger_for(path))
    payload = encode(fields)
    verifier.verify(payload, key.sign(payload), **request)


def test_crash_between_commits_prevents_replay(bundle, challenge_db):
    ctx = multiprocessing.get_context("fork")
    worker = ctx.Process(target=_crash_between_commits, args=(bundle, challenge_db))
    worker.start()
    worker.join(timeout=10)
    if worker.is_alive():
        worker.terminate()
        worker.join()
    assert worker.exitcode == 71
    assert "checkpoint mismatch" in run_workers(bundle, challenge_db, 1)[0]


def test_actual_candidate_git_tree_enforcement(bundle, monkeypatch):
    verifier, key, _, request, fields, _ = bundle
    repo = Path(__file__).resolve().parents[1]
    read_git = lambda ref: subprocess.check_output(["git", "rev-parse", ref], cwd=repo, text=True).strip()
    commit = read_git("HEAD")
    other_commit = read_git("HEAD^")
    assert read_git("HEAD^{tree}") != read_git("HEAD^^{tree}")
    challenge = verifier.issue_candidate(
        manifest=request["manifest"], repository=repo, commit=commit, scope=request["scope"],
    )
    fields.update(challenge=challenge.nonce, expires_at=challenge.expires_at)
    payload = encode(fields)
    signature = key.sign(payload)
    verify_options = dict(manifest=request["manifest"], repository=repo, scope=request["scope"])
    with pytest.raises(ApprovalError, match="Git tree mismatch"):
        verifier.verify_candidate(payload, signature, commit=other_commit, **verify_options)
    with pytest.raises(ApprovalError, match="candidate commit ID"):
        verifier.verify_candidate(payload, signature, commit="HEAD", **verify_options)
    with pytest.raises(ApprovalError, match="scope mismatch"):
        verifier.verify_candidate(payload, signature, commit=commit, **{**verify_options, "scope": "inspect"})
    monkeypatch.setenv("GIT_DIR", str(repo / "nonexistent"))
    verifier.verify_candidate(payload, signature, commit=commit, **verify_options)
    with pytest.raises(ApprovalError, match="consumed"):
        verifier.verify_candidate(payload, signature, commit=commit, **verify_options)
