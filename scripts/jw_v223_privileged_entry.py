"""Review candidate with injected execution and cleanup, exercised only with mocks."""

from collections.abc import Callable
from dataclasses import dataclass
from time import monotonic, time

from scripts.approval_crypto import ApprovalError, canonical_payload
from scripts.jw_v223_approval import LedgerCheckpoint
from scripts.jw_v223_review_preflight import ReviewPreflight


class RollbackFailed(RuntimeError):
    """The operation may have left effects that require reconciliation."""


@dataclass(frozen=True)
class PrivilegedEntry:
    """Bind a trusted, single-operation adapter to its independent approval policy."""

    preflight: ReviewPreflight
    execute: Callable[[bytes], object]
    rollback: Callable[[bytes], None]

    def run(
        self, manifest: bytes, payload: bytes, signature: bytes, *,
        checkpoint: LedgerCheckpoint | None,
    ) -> object:
        if not callable(self.execute) or not callable(self.rollback):
            raise ApprovalError("execution and rollback adapters are required")

        started = time()
        monotonic_start = monotonic()
        self.preflight.authorize(manifest, payload, signature, checkpoint=checkpoint)

        # Publication may have taken the approval past its signed deadline.
        deadline = canonical_payload(payload)["expires_at"]
        now = time()
        elapsed = monotonic() - monotonic_start
        if now < started or elapsed < 0 or max(now, started + elapsed) >= deadline:
            raise ApprovalError("approval expired before dispatch")

        try:
            return self.execute(manifest)
        except BaseException:
            # Consumption remains durable even when execution is rolled back.
            try:
                self.rollback(manifest)
            except BaseException as cleanup_error:
                raise RollbackFailed("operation rollback failed; reconciliation required") from cleanup_error
            raise
