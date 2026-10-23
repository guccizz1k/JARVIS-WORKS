"""V8.5 isolated ASGI stage. Existing production app/main.py untouched."""
from .pg_dev_entry_v84 import app
from .pg_auth_v85 import register_v85_auth

if not register_v85_auth(app):
    raise RuntimeError('PostgreSQL auth stage is disabled (fail closed)')
