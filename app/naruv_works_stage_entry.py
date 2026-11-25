"""Explicit disposable WORKS + PG stage + NARUV composition; never production.

Import this entrypoint only in an isolated process. Legacy app.main, UI files,
and existing stage entrypoints stay unchanged. No database connection on import.
"""
import os
from . import naruv_integrated_review as integrated
from . import pg_api_v84 as v84, pg_auth_v85 as v85, pg_v90_integrated_entry as v90
from . import pg_quote_api_v92 as v92, pg_quote_read_v93 as v93
FLAG="NARUV_WORKS_STAGE"
ACK="ISOLATED_SYNTHETIC_ONLY"

if (os.getenv(FLAG)!=ACK or not integrated._available(True,True)
    or not v84.stage_enabled() or not v85.auth_stage_enabled() or not v90.v90_enabled()
    or not v92.enabled() or os.getenv("JW_V112_PG_NOTIFY_ACK")):
    raise RuntimeError("NARUV_WORKS_STAGE_DISABLED")
v90._origins()
from .main import app
# Reserve the isolated NARUV namespace before FastAPI lazily includes the
# existing PG router nodes. The original legacy middleware wraps all routes.
if not integrated.register_integrated_review(app,include_drafts=True,include_hr=True):
    raise RuntimeError("NARUV_WORKS_STAGE_DISABLED")
for register in (v84.register_stage_api,v85.register_v85_auth,v90.register_v90_messenger,
                 v92.register_v92_quote_api,v93.register_v93_quote_reader):
    if not register(app):raise RuntimeError("NARUV_WORKS_STAGE_INCOMPLETE")
app.openapi_schema=None
