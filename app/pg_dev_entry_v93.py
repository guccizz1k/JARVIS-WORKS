"""V9.3 staged PostgreSQL quote CRUD subset: writes V9.2 + read/list V9.3."""
from .pg_dev_entry_v92 import app
from .pg_quote_read_v93 import register_v93_quote_reader
if not register_v93_quote_reader(app):
    raise RuntimeError("V9.3 PG quote read-stage not enabled")
