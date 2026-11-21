"""Exercise the real approval boundary with a mocked operation."""

import json
import multiprocessing
import os
from dataclasses import replace
from unittest.mock import Mock

import pytest

from scripts import jw_v223_approval as approval
from scripts import jw_v223_privileged_entry as entry
from scripts.approval_crypto import ApprovalError
from tests.test_jw_v223_review_preflight import review  # noqa: F401


def run(review, execute, rollback, *, checkpoint=None):
    gate, manifest, payload, signature, pinned = review
    return entry.PrivilegedEntry(gate, execute, rollback).run(
        manifest, payload, signature, checkpoint=pinned if checkpoint is None else checkpoint,
    )


@pytest.mark.parametrize("denial", ["signature", "scope", "expiry", "checkpoint"])
def test_denials_never_dispatch(review, denial, monkeypatch):
    gate, manifest, payload, signature, checkpoint = review
    if denial == "signature":
        signature = bytes([signature[0] ^ 1]) + signature[1:]
    elif denial == "scope":
        gate = replace(gate, operation=replace(gate.operation, scope="other"))
    elif denial == "expiry":
        monkeypatch.setattr(approval, "time", lambda: json.loads(payload)["expires_at"])
    else:
        gate = replace(gate, publish_checkpoint=lambda *_: False)

    execute, rollback = Mock(), Mock()
    with pytest.raises(ApprovalError, match={
        "signature": "signature", "scope": "scope mismatch",
        "expiry": "expired", "checkpoint": "publication failed",
    }[denial]):
        run((gate, manifest, payload, signature, checkpoint), execute, rollback)
    execute.assert_not_called()
    rollback.assert_not_called()


def test_dispatch_requires_published_checkpoint_and_consumes_once(review):
    gate, manifest, _, _, before = review
    publisher = Mock(wraps=gate.publish_checkpoint)
    config = (replace(gate, publish_checkpoint=publisher), *review[1:])

    def dispatch(approved_manifest):
        assert approved_manifest == manifest
        publisher.assert_called_once()
        assert publisher.call_args.args[1].revision == before.revision + 1
        return "mock result"

    execute, rollback = Mock(side_effect=dispatch), Mock()
    assert run(config, execute, rollback) == "mock result"
    latest = approval.read_ledger_checkpoint(gate.ledger_db)
    with pytest.raises(ApprovalError, match="consumed"):
        run(config, execute, rollback, checkpoint=latest)
    execute.assert_called_once()
    rollback.assert_not_called()


def test_expiry_while_checkpoint_is_published_burns_approval(review, monkeypatch):
    gate, _, payload, _, _ = review

    def publish(previous, current):
        assert gate.publish_checkpoint(previous, current) is True
        monkeypatch.setattr(entry, "time", lambda: json.loads(payload)["expires_at"])
        return True

    execute, rollback = Mock(), Mock()
    with pytest.raises(ApprovalError, match="expired"):
        run((replace(gate, publish_checkpoint=publish), *review[1:]), execute, rollback)
    latest = approval.read_ledger_checkpoint(gate.ledger_db)
    with pytest.raises(ApprovalError, match="consumed"):
        run(review, execute, rollback, checkpoint=latest)
    execute.assert_not_called()
    rollback.assert_not_called()


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_partial_mock_execution_rolls_back_and_approval_stays_consumed(review, cleanup_fails):
    effects = []

    def execute(manifest):
        effects.append(manifest)
        raise ValueError("mock execution failure")

    def rollback(manifest):
        assert effects == [manifest]
        if cleanup_fails:
            raise OSError("mock rollback failure")
        effects.clear()

    if cleanup_fails:
        with pytest.raises(entry.RollbackFailed, match="reconciliation required") as error:
            run(review, execute, rollback)
        assert isinstance(error.value.__cause__, OSError)
        assert effects == [review[1]]
    else:
        with pytest.raises(ValueError, match="mock execution failure"):
            run(review, execute, rollback)
        assert effects == []

    latest = approval.read_ledger_checkpoint(review[0].ledger_db)
    with pytest.raises(ApprovalError, match="consumed"):
        run(review, execute, rollback, checkpoint=latest)


@pytest.mark.parametrize("at_dispatch", [False, True])
def test_hard_crash_requires_reconciliation_and_prevents_replay(review, tmp_path, at_dispatch):
    gate = review[0]
    effect = tmp_path / "mock-effect"

    def publish_then_crash(previous, current):
        assert gate.publish_checkpoint(previous, current) is True
        os._exit(72)

    config = review if at_dispatch else (
        replace(gate, publish_checkpoint=publish_then_crash), *review[1:],
    )

    def dispatch(manifest):
        assert at_dispatch
        with effect.open("wb") as file:
            file.write(manifest)
            file.flush()
            os.fsync(file.fileno())
        os._exit(73)

    worker = multiprocessing.get_context("fork").Process(
        target=run, args=(config, dispatch, Mock()),
    )
    worker.start()
    worker.join(timeout=10)
    if worker.is_alive():
        worker.terminate()
        worker.join()
    assert worker.exitcode == (73 if at_dispatch else 72)
    assert effect.exists() == at_dispatch
    latest = approval.read_ledger_checkpoint(gate.ledger_db)
    assert latest.revision == review[-1].revision + 1
    execute, rollback = Mock(), Mock()
    with pytest.raises(ApprovalError, match="consumed"):
        run(review, execute, rollback, checkpoint=latest)
    execute.assert_not_called()
    rollback.assert_not_called()

    # A separately controlled reconciliation removes the mock effect if present.
    if at_dispatch:
        assert effect.read_bytes() == review[1]
        effect.unlink()
    assert not effect.exists()


def test_restoring_both_local_stores_cannot_redispatch(review):
    gate = review[0]
    snapshots = {
        path: path.read_bytes() for path in (gate.challenge_db, gate.ledger_db)
    }
    execute, rollback = Mock(), Mock()
    run(review, execute, rollback)
    latest = approval.read_ledger_checkpoint(gate.ledger_db)
    for path, contents in snapshots.items():
        path.write_bytes(contents)

    with pytest.raises(ApprovalError, match="checkpoint mismatch"):
        run(review, execute, rollback, checkpoint=latest)
    with pytest.raises(ApprovalError, match="publication failed"):
        run(review, execute, rollback)
    execute.assert_called_once_with(review[1])
    rollback.assert_not_called()


@pytest.mark.parametrize("fail_after_write", [False, True])
def test_bound_filesystem_adapter(review, tmp_path, fail_after_write):
    """Dispatch and compensate a real effect in a disposable directory."""
    gate, manifest, _, _, before = review
    artifact = tmp_path / "approved-artifact"

    def execute(approved_manifest):
        assert approval.read_ledger_checkpoint(gate.ledger_db).revision == before.revision + 1
        with artifact.open("xb") as output:
            output.write(approved_manifest)
            output.flush()
            os.fsync(output.fileno())
        if fail_after_write:
            raise OSError("synthetic operation interrupted after write")
        return artifact

    def rollback(approved_manifest):
        assert artifact.read_bytes() == approved_manifest
        artifact.unlink()

    if fail_after_write:
        with pytest.raises(OSError, match="interrupted after write"):
            run(review, execute, rollback)
        assert not artifact.exists()
    else:
        assert run(review, execute, rollback) == artifact
        assert artifact.read_bytes() == manifest

    latest = approval.read_ledger_checkpoint(gate.ledger_db)
    with pytest.raises(ApprovalError, match="consumed"):
        run(review, execute, rollback, checkpoint=latest)
    assert artifact.exists() is (not fail_after_write)
