"""V9.2 opt-in isolated PostgreSQL quote writer; production app unchanged."""
from .pg_dev_entry_v90 import app
from .pg_quote_api_v92 import register_v92_quote_api

if not register_v92_quote_api(app):
    raise RuntimeError("V9.2 PostgreSQL quote writer not explicitly enabled")
