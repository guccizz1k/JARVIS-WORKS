"""Fail closed: this FastAPI runtime still writes SQLite, not PostgreSQL.

A test-only PostgreSQL shadow, RLS plan, or green pytest suite must never be
mistaken for an authorized migration or a production-ready storage adapter.
"""
from __future__ import annotations
import os

class DeploymentBlocked(RuntimeError):
    pass


def require_safe_runtime() -> None:
    if os.getenv('JW_ENV','').strip().lower() in {'production','prod'}:
        raise DeploymentBlocked(
            'PRODUCTION_BLOCKED: app uses SQLite; full PostgreSQL adapter, '
            'write-side tenant RLS, audited migration and operational approval missing'
        )
