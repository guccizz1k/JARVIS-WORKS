"""Explicit, atomic composition of the isolated ERP routes; no legacy app mount."""
import os
import re
from fastapi import APIRouter
from . import (
    naruv_native_file_preview as preview, naruv_native_write_review as write,
    naruv_inventory_review as inventory, naruv_trade_review as trade,
    naruv_finance_review as finance, naruv_accounting_review as accounting,
    naruv_bundle_review as bundle, naruv_quote_bundle_review as quotes,
    naruv_production_review as production, naruv_valuation_review as valuation,
    pg_v90_integrated_entry as v90,
)

MODULES=(preview,write,inventory,trade,finance,accounting,bundle,quotes,production,valuation)
PREFIX=preview.PREFIX
FLAG="NARUV_INTEGRATED_REVIEW"
ACK="ISOLATED_SYNTHETIC_ONLY"

def enabled():
    return (os.getenv(FLAG)==ACK and os.getenv("JW_ENV","").lower() in ("dev","development","test")
        and os.getenv("JW_INSECURE_LOCAL_DEV")!="1" and all(m.enabled() for m in MODULES))

def route_key(route):
    path=getattr(route,"path",None)
    if not isinstance(path,str):return set()
    shape=re.sub(r"\{[^}:]+(?=[:}])","{parameter",path)
    methods=getattr(route,"methods",None) or {"WEBSOCKET"}
    return {(method,shape) for method in methods}

def create_integrated_router():
    if not enabled():raise RuntimeError("NARUV_INTEGRATION_DISABLED")
    v90._origins()
    combined=APIRouter()
    seen=set()
    for module in MODULES:
        router=module.create_router()
        for route in router.routes:
            keys=route_key(route)
            if not keys or not route.path.startswith(PREFIX+"/") or any(method!="POST" for method,_ in keys):
                raise RuntimeError("NARUV_INTEGRATION_ROUTE_SCOPE")
            if keys&seen:raise RuntimeError("NARUV_INTEGRATION_ROUTE_COLLISION")
            seen.update(keys)
        combined.include_router(router)
    if not seen:raise RuntimeError("NARUV_INTEGRATION_EMPTY")
    return combined

def register_integrated_review(app):
    """All-or-none opt-in, preserving existing route table on refusal."""
    if not enabled():return False
    combined=create_integrated_router()
    # Reserve the namespace; refuse partial/duplicate mounts, including route
    # variants using different parameter names.
    for route in app.routes:
        path=getattr(route,"path","")
        if path==PREFIX or path.startswith(PREFIX+"/"):
            raise RuntimeError("NARUV_INTEGRATION_NAMESPACE_OCCUPIED")
        if "{path:path}" in path or "{full_path:path}" in path:
            # An earlier catch-all could shadow the whole API.
            raise RuntimeError("NARUV_INTEGRATION_CATCH_ALL")
    app.include_router(combined)
    return True
