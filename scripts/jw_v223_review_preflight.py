"""Review-only approval boundary for an independently pinned operation."""

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from scripts.approval_crypto import ApprovalError
from scripts.jw_v223_approval import (
    ApprovalVerifier,
    Challenge,
    LedgerCheckpoint,
    OwnerPolicy,
)

_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class ReviewOperation:
    repository: Path
    commit: str
    scope: str
    manifest_sha256: str


@dataclass(frozen=True)
class ReviewPreflight:
    """Configuration comes from a trusted operator, outside request/restore inputs."""

    operation: ReviewOperation
    owner_policy: OwnerPolicy | None
    challenge_db: Path
    ledger_db: Path
    publish_checkpoint: Callable[[LedgerCheckpoint, LedgerCheckpoint], bool] | None = None

    def _verifier(self, manifest: bytes, checkpoint: LedgerCheckpoint | None) -> ApprovalVerifier:
        if (
            type(checkpoint) is not LedgerCheckpoint
            or type(checkpoint.store_id) is not str
            or not _SHA256.fullmatch(checkpoint.store_id)
            or type(checkpoint.revision) is not int
            or checkpoint.revision < 0
            or type(checkpoint.events_sha256) is not str
            or not _SHA256.fullmatch(checkpoint.events_sha256)
        ):
            raise ApprovalError("missing or invalid independent checkpoint")
        if not callable(self.publish_checkpoint):
            raise ApprovalError("independent checkpoint authority unavailable")
        if type(manifest) is not bytes or hashlib.sha256(manifest).hexdigest() != self.operation.manifest_sha256:
            raise ApprovalError("operation manifest SHA-256 mismatch")
        return ApprovalVerifier(
            self.owner_policy, challenge_db=self.challenge_db, ledger_db=self.ledger_db,
            expected_checkpoint=checkpoint,
        )

    def _publish(self, previous: LedgerCheckpoint, current: LedgerCheckpoint | None) -> None:
        if current is None or current.store_id != previous.store_id or current.revision != previous.revision + 1:
            raise ApprovalError("unexpected committed checkpoint")
        try:
            confirmed = self.publish_checkpoint(previous, current)
        except OSError as exc:
            raise ApprovalError("independent checkpoint authority unavailable") from exc
        if confirmed is not True:
            raise ApprovalError("independent checkpoint publication failed")

    def issue(self, manifest: bytes, *, checkpoint: LedgerCheckpoint | None) -> Challenge:
        verifier = self._verifier(manifest, checkpoint)
        challenge = verifier.issue_candidate(
            manifest=manifest, repository=self.operation.repository,
            commit=self.operation.commit, scope=self.operation.scope,
        )
        self._publish(checkpoint, verifier.committed_checkpoint)
        return challenge

    def authorize(
        self, manifest: bytes, payload: bytes, signature: bytes, *,
        checkpoint: LedgerCheckpoint | None,
    ) -> None:
        """Return only after a committed preflight approval. No operation is dispatched."""
        verifier = self._verifier(manifest, checkpoint)
        verifier.verify_candidate(
            payload, signature, manifest=manifest, repository=self.operation.repository,
            commit=self.operation.commit, scope=self.operation.scope,
        )
        self._publish(checkpoint, verifier.committed_checkpoint)
