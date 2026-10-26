"""Explicit dev-only entrypoint: uvicorn app.pg_dev_entry_v90:app (HTTPS)."""
from .pg_dev_entry_v85 import app
from .pg_v90_integrated_entry import register_v90_messenger

if not register_v90_messenger(app):
    raise RuntimeError('V9 messenger isolated staging disabled (fail closed)')
