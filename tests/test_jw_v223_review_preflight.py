"""Exact-tree approval integration over disposable, separately held stores."""

import hashlib
import json
import multiprocessing
import os
import sqlite3
import subprocess
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import jw_v223_approval as approval
from scripts.approval_crypto import ApprovalError
from scripts.jw_v223_review_preflight import ReviewOperation, ReviewPreflight


@pytest.fixture
def review(tmp_path):
    stores = []
    for label in ("state", "ledger"):
        directory = tmp_path / label
        directory.mkdir(mode=0o700)
        stores.append(directory / "review.sqlite")
    state, ledger = stores
    approval.initialize_challenge_store(state, ledger_db=ledger)
    repo = Path(__file__).resolve().parents[1]
    commit, tree = subprocess.check_output(
        ["git", "show", "-s", "--format=%H %T", "HEAD"], cwd=repo, text=True,
    ).split()
    manifest = b"synthetic exact operation\n"
    operation = ReviewOperation(repo, commit, "inspect", hashlib.sha256(manifest).hexdigest())
    signing_key = Ed25519PrivateKey.generate()
    key = signing_key.public_key().public_bytes_raw()
    fingerprint = hashlib.sha256(key).hexdigest()
    policy = approval.OwnerPolicy(key, fingerprint, frozenset({"inspect", "other"}), True)
    witness = tmp_path / "independently-held.sqlite"
    initial = approval.read_ledger_checkpoint(ledger)
    with closing(sqlite3.connect(witness)) as db, db:
        db.execute("CREATE TABLE witness (store TEXT, revision INTEGER, digest TEXT)")
        db.execute("INSERT INTO witness VALUES (?, ?, ?)", (
            initial.store_id, initial.revision, initial.events_sha256,
        ))

    def compare_and_advance(previous, current):
        with closing(sqlite3.connect(witness)) as db, db:
            updated = db.execute(
                """UPDATE witness SET revision = ?, digest = ?
                   WHERE store = ? AND revision = ? AND digest = ?""",
                (current.revision, current.events_sha256, previous.store_id,
                 previous.revision, previous.events_sha256),
            )
            return updated.rowcount == 1

    gate = ReviewPreflight(operation, policy, state, ledger, compare_and_advance)
    challenge = gate.issue(manifest, checkpoint=approval.read_ledger_checkpoint(ledger))
    fields = {
        "domain": "jarvis-works/v22.3/approval/v1",
        "key_fingerprint": fingerprint,
        "manifest_sha256": operation.manifest_sha256,
        "git_tree": tree,
        "scope": "inspect",
        "challenge": challenge.nonce,
        "expires_at": challenge.expires_at,
    }
    payload = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("ascii")
    checkpoint = approval.read_ledger_checkpoint(ledger)
    return gate, manifest, payload, signing_key.sign(payload), checkpoint


def authorize(review, *, checkpoint=None):
    gate, manifest, payload, signature, pinned = review
    gate.authorize(manifest, payload, signature, checkpoint=pinned if checkpoint is None else checkpoint)


def test_live_witness_detects_dual_restore_and_explicitly_models_stale_witness(review):
    gate = review[0]
    state, ledger = gate.challenge_db, gate.ledger_db
    stale_state, stale_ledger = state.read_bytes(), ledger.read_bytes()
    authorize(review)
    latest = approval.read_ledger_checkpoint(ledger)
    assert latest.revision == review[-1].revision + 1
    state.write_bytes(stale_state)
    ledger.write_bytes(stale_ledger)
    with pytest.raises(ApprovalError, match="independent .* checkpoint mismatch"):
        authorize(review, checkpoint=latest)
    # A coordinated rollback of the authority itself is outside this trust model.
    assert approval.read_ledger_checkpoint(ledger) == review[-1]
    assert latest != review[-1]
    with pytest.raises(ApprovalError, match="publication failed"):
        authorize(review)


def test_checkpoint_detects_divergent_history_at_same_revision(review):
    gate = review[0]
    with closing(sqlite3.connect(gate.ledger_db)) as db, db:
        db.execute("UPDATE ledger_events SET nonce = ?", ("f" * 64,))
    changed = approval.read_ledger_checkpoint(gate.ledger_db)
    assert changed.revision == review[-1].revision
    with pytest.raises(ApprovalError, match="independent .* checkpoint mismatch"):
        authorize(review)


def test_unavailable_ledger_keeps_pending_challenge_unconsumed(review):
    gate, manifest, _, _, checkpoint = review
    ledger = gate.ledger_db
    unavailable = ledger.with_suffix(".offline")
    ledger.rename(unavailable)
    with pytest.raises(ApprovalError, match="consumption ledger unavailable"):
        authorize(review)
    with pytest.raises(ApprovalError, match="consumption ledger unavailable"):
        gate.issue(manifest, checkpoint=checkpoint)
    unavailable.rename(ledger)
    authorize(review)
    with pytest.raises(ApprovalError, match="consumed"):
        authorize(review, checkpoint=approval.read_ledger_checkpoint(ledger))


def test_requires_independent_checkpoint_and_pinned_operation(review):
    gate, manifest, payload, signature, checkpoint = review
    with pytest.raises(ApprovalError, match="independent checkpoint"):
        gate.authorize(manifest, payload, signature, checkpoint=None)
    with pytest.raises(ApprovalError, match="manifest SHA-256"):
        gate.authorize(manifest + b" ", payload, signature, checkpoint=checkpoint)
    with pytest.raises(ApprovalError, match="missing owner"):
        replace(gate, owner_policy=None).authorize(manifest, payload, signature, checkpoint=checkpoint)
    with pytest.raises(ApprovalError, match="scope mismatch"):
        broadened = replace(gate, operation=replace(gate.operation, scope="other"))
        broadened.authorize(manifest, payload, signature, checkpoint=checkpoint)
    authorize(review)


def test_competing_authorizations_commit_once(review):
    def attempt(_):
        try:
            authorize(review)
        except ApprovalError as exc:
            assert "checkpoint mismatch" in str(exc)
            return 0
        return 1

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(attempt, range(8))) == 1


def crash_after_state_commit(review):
    transaction = approval._transaction

    @contextmanager
    def crash_at_boundary(path, **kwargs):
        with transaction(path, **kwargs) as db:
            yield db
        if path == review[0].challenge_db:
            os._exit(71)

    approval._transaction = crash_at_boundary
    authorize(review)


def test_crash_quarantines_pair_and_recovery_requires_fresh_identity(review, tmp_path):
    gate, manifest, payload, signature, checkpoint = review
    worker = multiprocessing.get_context("fork").Process(
        target=crash_after_state_commit, args=(review,),
    )
    worker.start()
    worker.join(timeout=10)
    if worker.is_alive():
        worker.terminate()
        worker.join()
    assert worker.exitcode == 71
    assert approval.read_ledger_checkpoint(gate.ledger_db) == checkpoint
    with pytest.raises(ApprovalError, match="checkpoint mismatch"):
        authorize(review)
    paths = []
    for name in ("replacement-state", "replacement-ledger"):
        folder = tmp_path / name
        folder.mkdir(mode=0o700)
        paths.append(folder / "review.sqlite")
    approval.initialize_challenge_store(paths[0], ledger_db=paths[1])
    fresh = replace(gate, challenge_db=paths[0], ledger_db=paths[1])
    with pytest.raises(ApprovalError, match="checkpoint mismatch"):
        fresh.authorize(manifest, payload, signature, checkpoint=checkpoint)
    fresh_checkpoint = approval.read_ledger_checkpoint(paths[1])
    with pytest.raises(ApprovalError, match="unknown, mismatched"):
        fresh.authorize(manifest, payload, signature, checkpoint=fresh_checkpoint)
    # A new trust root requires explicit enrollment by the outside custodian.
    with pytest.raises(ApprovalError, match="publication failed"):
        fresh.issue(manifest, checkpoint=fresh_checkpoint)


def test_nested_restore_paths_are_rejected(tmp_path):
    state = tmp_path / "state"
    ledger = state / "ledger"
    ledger.mkdir(parents=True, mode=0o700)
    state.chmod(0o700)
    with pytest.raises(ApprovalError, match="separate private directory"):
        approval.initialize_challenge_store(state / "state.sqlite", ledger_db=ledger / "ledger.sqlite")


def test_checkpoint_publication_failure_burns_approval_without_returning_success(review):
    gate, manifest, payload, signature, checkpoint = review

    def offline(previous, current):
        raise OSError("simulated independent authority outage")

    with pytest.raises(ApprovalError, match="authority unavailable"):
        replace(gate, publish_checkpoint=None).authorize(
            manifest, payload, signature, checkpoint=checkpoint,
        )
    with pytest.raises(ApprovalError, match="authority unavailable"):
        replace(gate, publish_checkpoint=offline).authorize(
            manifest, payload, signature, checkpoint=checkpoint,
        )
    with pytest.raises(ApprovalError, match="checkpoint mismatch"):
        authorize(review)
    with pytest.raises(ApprovalError, match="consumed"):
        authorize(review, checkpoint=approval.read_ledger_checkpoint(gate.ledger_db))
