"""Standalone V22.3 approval policy. No runtime configuration or activation.

The caller supplies trusted owner policy, exact manifest bytes, and the full Git
tree ID resolved from the candidate that would be used. Workers open the same
explicitly initialized database in an owner-private directory on a local disk.
The consumption ledger must live in a separate backup and restore domain.
The pair alone cannot detect a coordinated restore. Review preflight also
requires an independently retained ledger checkpoint. A failed partial commit
leaves the pair unavailable rather than returning an approval.
"""

import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import subprocess
from contextlib import closing, contextmanager
from dataclasses import dataclass
from os import getpid
from pathlib import Path
from time import monotonic, time

from scripts.approval_crypto import (
    ApprovalError,
    canonical_payload,
    pinned_ed25519_key,
    verify_ed25519,
)

_DOMAIN = "jarvis-works/v22.3/approval/v1"
_FIELDS = {
    "domain", "key_fingerprint", "manifest_sha256", "git_tree",
    "scope", "challenge", "expires_at",
}
_TREE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_SCOPE = re.compile(r"[a-z][a-z0-9_-]{0,63}")
_CHALLENGE_TTL_SECONDS = 300


_BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
_SCHEMA = """
CREATE TABLE approval_challenges (
    nonce TEXT PRIMARY KEY NOT NULL,
    fingerprint TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    git_tree TEXT NOT NULL,
    scope TEXT NOT NULL,
    boot_id TEXT NOT NULL,
    issued_at REAL NOT NULL,
    issued_monotonic REAL NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0 CHECK (consumed IN (0, 1))
) WITHOUT ROWID
"""


def _private_path(path: Path) -> Path:
    path = path.absolute()
    if path.parent.resolve(strict=True) != path.parent:
        raise ApprovalError("challenge store directory must be a real path")
    parent = path.parent.stat()
    if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
        raise ApprovalError("challenge store directory must be owner-private (0700)")
    return path


@contextmanager
def _transaction(path: Path | None, *, label: str = "challenge store"):
    if path is None:
        raise ApprovalError(f"missing {label}")
    try:
        path = _private_path(path)
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
        ):
            raise ApprovalError("challenge store must be an owner-private file (0600)")
        with closing(sqlite3.connect(path.as_uri() + "?mode=rw", uri=True)) as db:
            db.execute("PRAGMA trusted_schema = OFF")
            db.execute("PRAGMA synchronous = FULL")
            with db:
                db.execute("BEGIN IMMEDIATE")
                yield db
    except (OSError, sqlite3.Error) as exc:
        raise ApprovalError(f"{label} unavailable") from exc


def _create_private_file(path: Path) -> None:
    path = _private_path(path)
    os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600))


def _separate_paths(challenge_db: Path, ledger_db: Path) -> None:
    challenge_dir = challenge_db.absolute().parent
    ledger_dir = ledger_db.absolute().parent
    if challenge_dir.is_relative_to(ledger_dir) or ledger_dir.is_relative_to(challenge_dir):
        raise ApprovalError("consumption ledger requires a separate private directory")


def initialize_challenge_store(path: Path, *, ledger_db: Path) -> None:
    """Provision a fresh pair. Existing or missing members are never reset by workers."""
    _separate_paths(path, ledger_db)
    try:
        _create_private_file(path)
        _create_private_file(ledger_db)
        store_id = secrets.token_hex(32)
        with _transaction(ledger_db, label="consumption ledger") as ledger:
            ledger.execute("CREATE TABLE ledger_identity (store_id TEXT PRIMARY KEY NOT NULL)")
            ledger.execute("INSERT INTO ledger_identity VALUES (?)", (store_id,))
            ledger.execute("""
                CREATE TABLE ledger_events (
                    revision INTEGER PRIMARY KEY,
                    nonce TEXT NOT NULL,
                    event TEXT NOT NULL CHECK (event IN ('issue', 'consume')),
                    UNIQUE (nonce, event)
                )
            """)
            with _transaction(path) as db:
                db.execute(_SCHEMA)
                db.execute("""
                    CREATE TABLE store_checkpoint (
                        store_id TEXT PRIMARY KEY NOT NULL, revision INTEGER NOT NULL
                    )
                """)
                db.execute("INSERT INTO store_checkpoint VALUES (?, 0)", (store_id,))
    except OSError as exc:
        raise ApprovalError("cannot initialize challenge store") from exc


@dataclass(frozen=True)
class LedgerCheckpoint:
    store_id: str
    revision: int
    events_sha256: str


def _ledger_checkpoint(ledger: sqlite3.Connection, store_id: str, revision: int) -> LedgerCheckpoint:
    digest = hashlib.sha256()
    events = ledger.execute("SELECT revision, nonce, event FROM ledger_events ORDER BY revision")
    for expected_revision, row in enumerate(events, start=1):
        event_revision, nonce, event = row
        if (
            event_revision != expected_revision
            or type(nonce) is not str or not re.fullmatch(r"[0-9a-f]{64}", nonce)
            or event not in ("issue", "consume")
        ):
            raise ApprovalError("invalid consumption ledger history")
        digest.update(json.dumps(row, separators=(",", ":")).encode("ascii") + b"\n")
    return LedgerCheckpoint(store_id, revision, digest.hexdigest())


def read_ledger_checkpoint(ledger_path: Path) -> LedgerCheckpoint:
    """Observe the ledger for trusted custody outside the pair's restore boundary."""
    with _transaction(ledger_path, label="consumption ledger") as ledger:
        checkpoint = _ledger_identity(ledger)
        if len(checkpoint) != 1:
            raise ApprovalError("invalid consumption ledger identity")
        return _ledger_checkpoint(ledger, *checkpoint[0])


def _ledger_identity(ledger: sqlite3.Connection) -> list:
    return ledger.execute("""
        SELECT store_id, COALESCE((SELECT MAX(revision) FROM ledger_events), 0)
        FROM ledger_identity
    """).fetchall()


@dataclass
class _LedgerEvent:
    db: sqlite3.Connection
    checkpoint: LedgerCheckpoint | None = None


@contextmanager
def _record_event(
    path: Path | None, ledger_path: Path | None, event: str, nonce: str,
    expected_checkpoint: LedgerCheckpoint | None,
):
    if path is None:
        raise ApprovalError("missing challenge store")
    if ledger_path is None:
        raise ApprovalError("missing consumption ledger")
    _separate_paths(path, ledger_path)
    # The ledger lock serializes workers through both commits. If the process
    # dies after the local commit, its advanced checkpoint quarantines the pair.
    with _transaction(ledger_path, label="consumption ledger") as ledger:
        ledger_checkpoint = _ledger_identity(ledger)
        if expected_checkpoint is not None and (
            len(ledger_checkpoint) != 1
            or _ledger_checkpoint(ledger, *ledger_checkpoint[0]) != expected_checkpoint
        ):
            raise ApprovalError("independent consumption ledger checkpoint mismatch")
        with _transaction(path) as db:
            checkpoint = db.execute("SELECT store_id, revision FROM store_checkpoint").fetchall()
            if len(checkpoint) != 1 or checkpoint != ledger_checkpoint:
                raise ApprovalError("challenge store and consumption ledger checkpoint mismatch")
            pending = _LedgerEvent(db)
            yield pending
            store_id, previous_revision = checkpoint[0]
            revision = previous_revision + 1
            ledger.execute("INSERT INTO ledger_events VALUES (?, ?, ?)", (revision, nonce, event))
            db.execute("UPDATE store_checkpoint SET revision = ?", (revision,))
            if expected_checkpoint is not None:
                pending.checkpoint = _ledger_checkpoint(ledger, store_id, revision)


def candidate_git_tree(repository: Path, commit: str) -> str:
    """Resolve the tree of a trusted, full commit ID without Git replacement objects."""
    if type(commit) is not str or not _TREE.fullmatch(commit):
        raise ApprovalError("invalid candidate commit ID")
    git_env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    git_env["GIT_NO_LAZY_FETCH"] = "1"
    try:
        resolved = [
            subprocess.run(
                ["git", "--no-replace-objects", "-C", str(repository), "rev-parse",
                 "--verify", commit + suffix],
                capture_output=True, text=True, check=True, timeout=5, env=git_env,
            ).stdout.strip()
            for suffix in ("^{commit}", "^{tree}")
        ]
    except (OSError, subprocess.SubprocessError) as exc:
        raise ApprovalError("cannot resolve candidate Git tree") from exc
    if resolved[0] != commit or not _TREE.fullmatch(resolved[1]):
        raise ApprovalError("cannot resolve candidate Git tree")
    return resolved[1]


def _boot_id() -> str:
    value = _BOOT_ID_PATH.read_bytes().strip()
    if not re.fullmatch(rb"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value):
        raise ApprovalError("unknown boot identity")
    return value.decode("ascii")


@dataclass(frozen=True)
class OwnerPolicy:
    """Trusted configuration from the owner, independent of the signed payload."""

    public_key: bytes
    fingerprint: str
    scopes: frozenset[str]
    owner_authorized: bool


@dataclass(frozen=True)
class Challenge:
    nonce: str
    expires_at: int


@dataclass(frozen=True)
class _Request:
    manifest_sha256: str
    git_tree: str
    scope: str


class ApprovalVerifier:
    def __init__(
        self, policy: OwnerPolicy | None = None, *, challenge_db: Path | None = None,
        ledger_db: Path | None = None, expected_checkpoint: LedgerCheckpoint | None = None,
    ) -> None:
        self._policy = policy
        self._pid = getpid()
        self._challenge_db = challenge_db.absolute() if challenge_db is not None else None
        self._ledger_db = ledger_db.absolute() if ledger_db is not None else None
        self._expected_checkpoint = expected_checkpoint
        self.committed_checkpoint: LedgerCheckpoint | None = None

    def _authorized_policy(self, scope: str) -> OwnerPolicy:
        if getpid() != self._pid:
            raise ApprovalError("verifier belongs to a different process")
        policy = self._policy
        if not isinstance(policy, OwnerPolicy) or policy.owner_authorized is not True:
            raise ApprovalError("missing owner authorization")
        if type(scope) is not str or not _SCOPE.fullmatch(scope):
            raise ApprovalError("invalid scope")
        if type(policy.scopes) is not frozenset or scope not in policy.scopes:
            raise ApprovalError("scope is not authorized")
        return policy

    @staticmethod
    def _request(manifest: bytes, git_tree: str, scope: str) -> _Request:
        if type(manifest) is not bytes or not manifest:
            raise ApprovalError("missing or invalid manifest")
        if type(git_tree) is not str or not _TREE.fullmatch(git_tree) or not git_tree.strip("0"):
            raise ApprovalError("invalid Git tree ID")
        return _Request(hashlib.sha256(manifest).hexdigest(), git_tree, scope)

    def issue(self, *, manifest: bytes, git_tree: str, scope: str) -> Challenge:
        policy = self._authorized_policy(scope)
        pinned_ed25519_key(policy.public_key, policy.fingerprint)
        request = self._request(manifest, git_tree, scope)
        nonce = secrets.token_hex(32)
        with _record_event(
            self._challenge_db, self._ledger_db, "issue", nonce, self._expected_checkpoint,
        ) as event:
            db = event.db
            now = time()
            challenge = Challenge(nonce, int(now) + _CHALLENGE_TTL_SECONDS)
            db.execute(
                """INSERT INTO approval_challenges
                   (nonce, fingerprint, manifest_sha256, git_tree, scope, boot_id,
                    issued_at, issued_monotonic, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (challenge.nonce, policy.fingerprint, request.manifest_sha256,
                 request.git_tree, request.scope, _boot_id(), now, monotonic(),
                 challenge.expires_at),
            )
        self.committed_checkpoint = event.checkpoint
        return challenge

    def verify(
        self, payload: bytes, signature: bytes, *,
        manifest: bytes, git_tree: str, scope: str,
    ) -> None:
        """Raise ApprovalError on denial. Success consumes the challenge once."""
        policy = self._authorized_policy(scope)
        request = self._request(manifest, git_tree, scope)
        fields = canonical_payload(payload)
        if fields.keys() != _FIELDS or fields["domain"] != _DOMAIN:
            raise ApprovalError("invalid approval schema or domain")
        if fields["key_fingerprint"] != policy.fingerprint:
            raise ApprovalError("unknown key")
        verify_ed25519(payload, signature, policy.public_key, policy.fingerprint)
        if fields["manifest_sha256"] != request.manifest_sha256:
            raise ApprovalError("manifest SHA-256 mismatch")
        if fields["git_tree"] != request.git_tree:
            raise ApprovalError("Git tree mismatch")
        if fields["scope"] != request.scope:
            raise ApprovalError("scope mismatch")
        nonce, expires_at = fields["challenge"], fields["expires_at"]
        if type(nonce) is not str or type(expires_at) is not int:
            raise ApprovalError("invalid challenge or expiry")
        with _record_event(
            self._challenge_db, self._ledger_db, "consume", nonce, self._expected_checkpoint,
        ) as event:
            db = event.db
            pending = db.execute(
                """SELECT boot_id, issued_at, issued_monotonic, expires_at
                   FROM approval_challenges
                   WHERE nonce = ? AND fingerprint = ? AND manifest_sha256 = ?
                     AND git_tree = ? AND scope = ? AND consumed = 0""",
                (nonce, policy.fingerprint, request.manifest_sha256,
                 request.git_tree, request.scope),
            ).fetchone()
            if pending is None:
                raise ApprovalError("unknown, mismatched, or consumed challenge")
            boot_id, issued_at, issued_monotonic, challenge_expiry = pending
            now = time()
            elapsed = monotonic() - issued_monotonic
            effective_now = max(now, issued_at + elapsed)
            if (
                boot_id != _boot_id()
                or elapsed < 0
                or now < issued_at
                or not effective_now < expires_at <= challenge_expiry
            ):
                raise ApprovalError("invalid or expired approval")
            updated = db.execute(
                "UPDATE approval_challenges SET consumed = 1 WHERE nonce = ? AND consumed = 0",
                (nonce,),
            )
            if updated.rowcount != 1:
                raise ApprovalError("challenge consumption failed")
        self.committed_checkpoint = event.checkpoint

    def issue_candidate(self, *, manifest: bytes, repository: Path, commit: str, scope: str) -> Challenge:
        self._authorized_policy(scope)
        return self.issue(manifest=manifest, git_tree=candidate_git_tree(repository, commit), scope=scope)

    def verify_candidate(
        self, payload: bytes, signature: bytes, *, manifest: bytes,
        repository: Path, commit: str, scope: str,
    ) -> None:
        """Verify against the immutable Git artifact selected by the trusted caller."""
        self._authorized_policy(scope)
        self.verify(
            payload, signature, manifest=manifest,
            git_tree=candidate_git_tree(repository, commit), scope=scope,
        )
