"""Isolated approval/reservation lifecycle, never permission to import rows.

Single-process in-memory lab. Actor contexts must be supplied by a trusted
server in a future integration; they are not authentication tokens. No real
ERP I/O, database writes, durable idempotency, external AI, or deployment.
A RESERVED record is a terminal lab marker, not a completed import.
"""
from dataclasses import dataclass, replace
import re
import threading
import time

from app.erp_migration_mapping import MappingBlocked
from app.erp_migration_preflight import check_row_preflight

MAX_APPROVALS = 1000
MAX_TTL = 900
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")

def _need(ok, reason):
    if not ok:
        raise MappingBlocked(reason)

def _identity(value):
    _need(type(value) is str and _ID.fullmatch(value) is not None,
          "APPROVAL_IDENTITY")
    return value

@dataclass(frozen=True)
class ActorContext:
    organization_id: str
    actor_id: str
    permission_revision: str
    active: bool
    can_approve: bool
    can_reserve: bool

def _actor(actor, org, capability):
    _need(type(actor) is ActorContext, "APPROVAL_ACTOR_TYPE")
    for value in (actor.organization_id, actor.actor_id, actor.permission_revision):
        _identity(value)
    _need(actor.organization_id == org, "APPROVAL_SCOPE")
    _need(type(actor.active) is bool and type(actor.can_approve) is bool
          and type(actor.can_reserve) is bool, "APPROVAL_PERMISSION_TYPE")
    _need(actor.active is True and getattr(actor, capability) is True,
          "APPROVAL_PERMISSION_DENIED")
    return actor

def _contexts(approver, executor, org):
    _actor(approver,org,"can_approve")
    _actor(executor,org,"can_reserve")
    if approver.actor_id == executor.actor_id:
        _need(approver == executor, "APPROVAL_CONTEXT_INCONSISTENT")

def _recheck(previous, review, current):
    # A mutable caller-owned container must not change between validation
    # and reservation. Tuples and primitive validated cells only.
    _need(type(current.get("headers")) is tuple and type(current.get("rows")) is tuple
          and all(type(row) is tuple for row in current["rows"]),
          "APPROVAL_IMMUTABLE_INPUT_REQUIRED")
    return check_row_preflight(previous,review,**current)

@dataclass(frozen=True)
class Approval:
    approval_id: str
    organization_id: str
    source_id: str
    entity: str
    preflight_binding_sha256: str
    rows_sha256: str
    approver_id: str
    approver_revision: str
    executor_id: str
    executor_revision: str
    issued_at: int
    expires_at: int
    status: str = "APPROVED"
    reservation_id: str | None = None
    row_import_authorized: bool = False

class ApprovalLab:
    """Thread-safe local state machine with bounded capacity and no auto-reset."""

    def __init__(self, *, clock=None):
        self._clock = clock if clock is not None else lambda: int(time.time())
        self._lock = threading.RLock()
        self._last_time = 0
        self._records = {}
        self._content = {}
        self._reservations = set()

    def _now(self):
        now = self._clock()
        _need(type(now) is int and 0 < now <= 253402300799 - MAX_TTL,
              "APPROVAL_CLOCK_INVALID")
        _need(now >= self._last_time, "APPROVAL_CLOCK_ROLLBACK")
        self._last_time = now
        return now

    @staticmethod
    def _live(record, now):
        _need(record.status == "APPROVED", "APPROVAL_TERMINAL")
        _need(record.issued_at <= now < record.expires_at, "APPROVAL_EXPIRED")

    def issue(self, approval_id, previous, review, *, approver, executor,
              confirmed, ttl_seconds, **current):
        _identity(approval_id)
        _need(confirmed is True, "APPROVAL_EXPLICIT_CONFIRMATION_REQUIRED")
        _need(type(ttl_seconds) is int and 1 <= ttl_seconds <= MAX_TTL,
              "APPROVAL_TTL")
        with self._lock:
            p = _recheck(previous,review,current)
            _contexts(approver,executor,p.organization_id)
            now = self._now()
            key = (p.organization_id,approval_id)
            content = (p.organization_id,p.source_id,p.entity,p.rows_sha256)
            old = self._records.get(key)
            if old is not None:
                self._live(old,now)
                expected = Approval(approval_id,p.organization_id,p.source_id,p.entity,
                    p.binding_sha256,p.rows_sha256,approver.actor_id,approver.permission_revision,
                    executor.actor_id,executor.permission_revision,old.issued_at,old.expires_at)
                _need(old == expected and ttl_seconds == old.expires_at-old.issued_at,
                      "APPROVAL_ID_CONFLICT")
                return old  # exact repeat never renews expiry
            _need(content not in self._content, "APPROVAL_CONTENT_ALREADY_REGISTERED")
            _need(len(self._records)<MAX_APPROVALS, "APPROVAL_CAPACITY")
            record = Approval(approval_id,p.organization_id,p.source_id,p.entity,
                p.binding_sha256,p.rows_sha256,approver.actor_id,approver.permission_revision,
                executor.actor_id,executor.permission_revision,now,now+ttl_seconds)
            self._records[key] = record
            self._content[content] = key
            return record

    def reserve(self, approval_id, reservation_id, previous, review, *,
                approver, executor, **current):
        _identity(approval_id)
        _identity(reservation_id)
        with self._lock:
            p = _recheck(previous,review,current)
            _contexts(approver,executor,p.organization_id)
            now = self._now()
            key = (p.organization_id,approval_id)
            record = self._records.get(key)
            _need(record is not None,"APPROVAL_NOT_FOUND")
            self._live(record,now)
            _need((record.source_id,record.entity,record.preflight_binding_sha256,record.rows_sha256)
                  ==(p.source_id,p.entity,p.binding_sha256,p.rows_sha256),
                  "APPROVAL_BINDING_CHANGED")
            _need((record.approver_id,record.approver_revision,record.executor_id,record.executor_revision)
                  ==(approver.actor_id,approver.permission_revision,executor.actor_id,executor.permission_revision),
                  "APPROVAL_ACTOR_CHANGED")
            reservation_key = (p.organization_id,reservation_id)
            _need(reservation_key not in self._reservations,"APPROVAL_RESERVATION_ID_CONFLICT")
            reserved = replace(record,status="RESERVED",reservation_id=reservation_id)
            self._reservations.add(reservation_key)
            self._records[key] = reserved
            return reserved

    def revoke(self, approval_id, *, approver):
        _identity(approval_id)
        _need(type(approver) is ActorContext,"APPROVAL_ACTOR_TYPE")
        _actor(approver,approver.organization_id,"can_approve")
        with self._lock:
            now = self._now()
            key = (approver.organization_id,approval_id)
            record = self._records.get(key)
            _need(record is not None,"APPROVAL_NOT_FOUND")
            _need(record.approver_id == approver.actor_id,"APPROVAL_ACTOR_CHANGED")
            self._live(record,now)
            revoked = replace(record,status="REVOKED")
            self._records[key] = revoked
            return revoked
