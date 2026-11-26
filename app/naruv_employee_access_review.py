"""Isolated employee statement access policy primitive; no routes, real credentials,
session persistence, identity proofing, payroll release or production authorization.

All three records must come from trusted server stores inside a transaction.
This evaluator must never be fed client-supplied principal/entitlement records.
"""
from dataclasses import dataclass
import hashlib
import re
import secrets

ID=re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
HEX=re.compile(r"[a-f0-9]{64}")
TOKEN=re.compile(r"[A-Za-z0-9_-]{43}")
AUDIENCE="naruv-employee-statement-review-v1"
MAX_LIFETIME=300

class AccessDenied(ValueError):
    pass

def need(condition):
    if not condition:
        raise AccessDenied("EMPLOYEE_ACCESS_DENIED")

def ident(x):
    return type(x) is str and ID.fullmatch(x) is not None

def digest(x):
    return type(x) is str and HEX.fullmatch(x) is not None

def epoch(x):
    return type(x) is int and 0<=x<=2**63-1

@dataclass(frozen=True)
class EmployeeIdentity:
    tenant: str
    principal: str
    worker: str
    auth_epoch: int
    active: bool

@dataclass(frozen=True)
class StatementEntitlement:
    tenant: str
    worker: str
    receipt: str
    review_sha256: str
    render_sha256: str
    active: bool

@dataclass(frozen=True)
class EmployeeSession:
    audience: str
    tenant: str
    principal: str
    worker: str
    auth_epoch: int
    receipt: str
    review_sha256: str
    render_sha256: str
    token_sha256: str
    issued_at: int
    expires_at: int
    revoked: bool

def _check_records(identity, entitlement):
    need(type(identity) is EmployeeIdentity and type(entitlement) is StatementEntitlement)
    need(all(ident(v) for v in (identity.tenant,identity.principal,identity.worker,
        entitlement.tenant,entitlement.worker,entitlement.receipt)))
    need(identity.active is True and entitlement.active is True and epoch(identity.auth_epoch))
    need((identity.tenant,identity.worker)==(entitlement.tenant,entitlement.worker))
    need(digest(entitlement.review_sha256) and digest(entitlement.render_sha256))

def issue_synthetic_session(*,identity,entitlement,now,ttl=MAX_LIFETIME):
    """Only call after trusted identity authentication and entitlement approval.
    This primitive deliberately performs neither; do not expose it as an endpoint.
    """
    _check_records(identity,entitlement)
    need(epoch(now) and type(ttl) is int and 1<=ttl<=MAX_LIFETIME and epoch(now+ttl))
    token=secrets.token_urlsafe(32)
    need(TOKEN.fullmatch(token) is not None)
    row=EmployeeSession(AUDIENCE,identity.tenant,identity.principal,identity.worker,
        identity.auth_epoch,entitlement.receipt,entitlement.review_sha256,
        entitlement.render_sha256,hashlib.sha256(token.encode("ascii")).hexdigest(),now,now+ttl,False)
    return token,row

def review_employee_statement_access(*,token,session,identity,entitlement,now,
        requested_receipt,requested_review_sha256,requested_render_sha256):
    """Read-only decision against live identity and receipt; not a release grant."""
    _check_records(identity,entitlement)
    need(type(session) is EmployeeSession and type(token) is str and TOKEN.fullmatch(token) is not None)
    need(session.audience==AUDIENCE and session.revoked is False and digest(session.token_sha256)
        and epoch(now) and epoch(session.issued_at) and epoch(session.expires_at)
        and session.issued_at<=now<session.expires_at
        and 1<=session.expires_at-session.issued_at<=MAX_LIFETIME)
    need(epoch(session.auth_epoch) and (session.tenant,session.principal,session.worker,session.auth_epoch)==
        (identity.tenant,identity.principal,identity.worker,identity.auth_epoch))
    need(ident(requested_receipt) and digest(requested_review_sha256) and digest(requested_render_sha256))
    need((session.receipt,session.review_sha256,session.render_sha256)==
        (entitlement.receipt,entitlement.review_sha256,entitlement.render_sha256)==
        (requested_receipt,requested_review_sha256,requested_render_sha256))
    need(secrets.compare_digest(session.token_sha256,hashlib.sha256(token.encode("ascii")).hexdigest()))
    return {"status":"SYNTHETIC_EMPLOYEE_SCOPE_MATCH_ONLY","identity_proofing_verified":False,
        "session_store_verified":False,"delivery_authorized":False,"payment_authorized":False,
        "production_authorized":False,"statutory_validated":False}
