"""Explicit, atomic composition of the isolated ERP routes; no legacy app mount."""
import os
import re
from fastapi import APIRouter, Depends, HTTPException
from starlette.routing import Mount
from . import (
    naruv_native_file_preview as preview, naruv_native_write_review as write,
    naruv_inventory_review as inventory, naruv_trade_review as trade,
    naruv_finance_review as finance, naruv_accounting_review as accounting,
    naruv_bundle_review as bundle, naruv_quote_bundle_review as quotes,
    naruv_production_review as production, naruv_valuation_review as valuation,
    pg_v90_integrated_entry as v90, naruv_draft_review as drafts, naruv_hr_review as hr,
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

def require_integrated_gate():
    if not enabled():raise HTTPException(404,"NARUV_INTEGRATION_DISABLED")

def require_full_gate():
    require_integrated_gate()
    if not drafts.enabled():raise HTTPException(404,"NARUV_INTEGRATION_DISABLED")

def require_hr_gate():
    require_full_gate()
    if not hr.enabled():raise HTTPException(404,"NARUV_INTEGRATION_DISABLED")

def _available(include_drafts,include_hr):
    return enabled() and (not include_drafts or drafts.enabled()) and (not include_hr or (include_drafts and hr.enabled()))

def create_integrated_router(*,include_drafts=False,include_hr=False):
    if not _available(include_drafts,include_hr):
        raise RuntimeError("NARUV_INTEGRATION_DISABLED")
    v90._origins()
    gate=require_hr_gate if include_hr else (require_full_gate if include_drafts else require_integrated_gate)
    combined=APIRouter(dependencies=[Depends(gate)])
    seen=set()
    for module in MODULES+((drafts,) if include_drafts else ())+((hr,) if include_hr else ()):
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

def register_integrated_review(app,*,include_drafts=False,include_hr=False):
    """Explicit opt-in modes; original 29 and 31 route contracts preserved."""
    if not _available(include_drafts,include_hr):return False
    if getattr(app.state,"naruv_integrated_review_registered",False):
        raise RuntimeError("NARUV_INTEGRATION_NAMESPACE_OCCUPIED")
    combined=create_integrated_router(include_drafts=include_drafts,include_hr=include_hr)
    # Reserve the namespace; refuse partial/duplicate mounts, including route
    # variants using different parameter names.
    for route in app.routes:
        path=getattr(route,"path",None)
        # FastAPI >=0.137 may expose opaque lazily included router nodes.
        # Do not guess their effective routes or ignore potentially hidden
        # endpoints. The isolated composer refuses this unproven topology.
        if not isinstance(path,str):
            raise RuntimeError("NARUV_INTEGRATION_UNVERIFIED_ROUTE_TREE")
        if path==PREFIX or path.startswith(PREFIX+"/"):
            raise RuntimeError("NARUV_INTEGRATION_NAMESPACE_OCCUPIED")
        if isinstance(route,Mount) and (not path or PREFIX.startswith(path.rstrip("/")+"/")):
            raise RuntimeError("NARUV_INTEGRATION_NAMESPACE_OCCUPIED")
        if re.search(r"\{[^{}:]+:path\}",path):
            # An earlier catch-all could shadow the whole API.
            raise RuntimeError("NARUV_INTEGRATION_CATCH_ALL")
    app.include_router(combined)
    app.state.naruv_integrated_review_registered=True
    app.openapi_schema=None
    return True
