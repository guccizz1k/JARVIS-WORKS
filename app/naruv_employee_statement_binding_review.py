"""CI-only statement rendering bound to live PG17 employee session and entitlement.
No HTTP, real identity proof, delivery, payment, or document body returned.
Trusted record must originate from server-owned storage, never a request body.
"""
from dataclasses import dataclass
import hashlib
import hmac
from app import naruv_employee_session_store_review as store
from app.naruv_employee_access_review import need,ident,digest,AccessDenied
from app.naruv_kr_payroll_review import isolated_wage_statement_print_html

@dataclass(frozen=True)
class TrustedDraft:
    tenant: str
    worker: str
    receipt: str
    result: dict

def review_bound_statement(conn,*,trusted_tenant,trusted_principal,receipt,token,draft):
    store._guard(conn)
    need(type(draft) is TrustedDraft and all(ident(v) for v in (trusted_tenant,trusted_principal,receipt,draft.worker)))
    need((draft.tenant,draft.receipt)==(trusted_tenant,receipt))
    identity,entitlement=store._live(conn,trusted_tenant,trusted_principal,receipt)
    need(identity.worker==draft.worker and entitlement.active is True and identity.active is True)
    try:
        statement=draft.result["wage_statement_reference"]
        need(type(statement) is dict and statement["worker"]==draft.worker
             and digest(statement["review_sha256"]) and digest(entitlement.review_sha256)
             and hmac.compare_digest(statement["review_sha256"],entitlement.review_sha256))
        rendered=isolated_wage_statement_print_html(draft.result).encode("utf-8")
        need(0<len(rendered)<=1024*1024)
        rendered_hash=hashlib.sha256(rendered).hexdigest()
        need(digest(entitlement.render_sha256) and hmac.compare_digest(rendered_hash,entitlement.render_sha256))
    except (KeyError,TypeError,ValueError,AttributeError,OverflowError):
        raise AccessDenied("EMPLOYEE_ACCESS_DENIED") from None
    decision=store.access(conn,trusted_tenant=trusted_tenant,trusted_principal=trusted_principal,
                          receipt=receipt,review_sha256=statement["review_sha256"],
                          render_sha256=rendered_hash,token=token)
    need(decision["session_store_verified"] is True and decision["delivery_authorized"] is False)
    return dict(decision,status="CI_EMPLOYEE_RENDER_BINDING_MATCH_ONLY",render_binding_verified=True,
                render_sha256=rendered_hash,document_returned=False)
