"""Standalone, staging-only ASGI entrypoint: app.pg_dev_entry_v84:app.

Legacy app.main stays byte-for-byte unchanged for baseline installer integrity.
Without explicit stage opt-in, importing this entrypoint fails closed.
It does NOT migrate SQLite login, sessions or API routes to PostgreSQL.
"""
from .main import app
from .pg_api_v84 import register_stage_api

if not register_stage_api(app):
    raise RuntimeError('PostgreSQL stage app requires ISOLATED_DEV_READ_ONLY opt-in')
