"""Offline review-only evidence tests; no external authority or DB mutation."""
import hashlib
import hmac
import json
from copy import deepcopy

import pytest
from app.pg_invoice_preview_v145 import build_invoice_preview
from app.pg_delivery_evidence_gate_v147 import evaluate_delivery, DeliveryProofRejected

NOW = 1793371000
ORG = "a"*32
KEY_D = b"dispatch-local-test-only-credential-123456789"
KEY_R = b"recipient-local-test-only-credential-123456789"
ORDER = ("b"*32,"c"*32,"O-001","d"*32,"Company B","fulfilled","acknowledged","taxable","Items")
LINES = [("l1","Widgets",2,2000,0),("l2","Parts",1,3000,1)]
PREVIEW = build_invoice_preview(ORDER, LINES)
ISSUERS = {"dispatch":"approved-dispatch-attestor-v1","receipt":"approved-receipt-attestor-v1"}


def signed(purpose_kind, **mutations):
    payload = {"schema":"jw-delivery-evidence-v147", "purpose":purpose_kind,
               "issuer":ISSUERS[purpose_kind], "org_id":ORG, "order_id":ORDER[0],
               "source_sha256":PREVIEW["source_sha256"],
               "document_sha256":("f" if purpose_kind=="dispatch" else "e")*64,
               "items":[{"source_order_item_id":i[0],"delivered_quantity":i[2]} for i in LINES],
               "signer_id":("1" if purpose_kind=="dispatch" else "2")*32,
               "nonce":("3" if purpose_kind=="dispatch" else "4")*32,
               "issued_at":NOW-60 if purpose_kind=="dispatch" else NOW-30,
               "expires_at":NOW+200}
    payload.update(mutations)
    k = KEY_D if purpose_kind=="dispatch" else KEY_R
    signature = hmac.new(k,json.dumps(payload,sort_keys=True,separators=(",",":"),
               ensure_ascii=False).encode(),hashlib.sha256).hexdigest()
    return {**payload,"signature":signature}


def run(**changes):
    d=dict(invoice_preview=deepcopy(PREVIEW),org_id=ORG,dispatch_proof=signed("dispatch"),
           recipient_proof=signed("receipt"),dispatch_key=KEY_D,recipient_key=KEY_R,
           consumed_nonces=set(),now=NOW)
    d.update(changes)
    return evaluate_delivery(**d)


def invalid(**changes):
    with pytest.raises(DeliveryProofRejected):
        run(**changes)


def test_positive_is_review_only_and_deterministic():
    x=run()
    assert x.status=="EVIDENCE_VALIDATED_REVIEW_ONLY"
    assert x.evidence_sha256==run().evidence_sha256
    assert not x.physical_delivery_verified
    assert not x.invoice_posted and not x.payment_posted
    assert not x.persistent_receipt_recorded


@pytest.mark.parametrize("field,value",[
 ("org_id","f"*32),("order_id","e"*32),("source_sha256","0"*64),
 ("document_sha256","bad"),("issuer","attacker"),("purpose","receipt"),
 ("signer_id","oops"),("nonce","abc"),("issued_at",NOW+1),
 ("expires_at",NOW),("expires_at",NOW+90000),("schema","different"),
 ("items",[]),
 ("items",[{"source_order_item_id":"l1","delivered_quantity":1},{"source_order_item_id":"l2","delivered_quantity":1}]),
 ("items",[{"source_order_item_id":"l2","delivered_quantity":1},{"source_order_item_id":"l1","delivered_quantity":2}]),
 ("items",[{"source_order_item_id":"l1","delivered_quantity":True},{"source_order_item_id":"l2","delivered_quantity":1}]),
])
def test_invalid_dispatch_even_if_resigned(field,value):
    invalid(dispatch_proof=signed("dispatch",**{field:value}))


def test_witness_tampered_after_signature():
    p=signed("dispatch")
    p["document_sha256"]="a"*64
    invalid(dispatch_proof=p)


def test_duplicate_nonce_replay_blocked():
    invalid(consumed_nonces={"3"*32})


def test_same_signer_and_same_nonce_disallowed():
    invalid(recipient_proof=signed("receipt",signer_id="1"*32))
    invalid(recipient_proof=signed("receipt",nonce="3"*32))


def test_receipt_before_dispatch_disallowed():
    invalid(recipient_proof=signed("receipt",issued_at=NOW-70))


def test_wrong_issuer_keys_and_reused_keys():
    invalid(dispatch_key=KEY_R)
    invalid(recipient_key=KEY_D)
    invalid(recipient_key=KEY_D,dispatch_key=KEY_D)


@pytest.mark.parametrize("field,value",[
 ("source_sha256","0"*64),("physical_delivery_verified",True),
 ("invoice_posted",True),("payment_posted",True),("draft_only",False),
 ("order_id","wrong")
])
def test_client_spoofed_source_fails(field,value):
    forged=deepcopy(PREVIEW)
    forged[field]=value
    invalid(invoice_preview=forged)


def test_money_canonical_recompute_blocks_inflation():
    forged=deepcopy(PREVIEW)
    forged["items"][0]["quantity"]+=1
    invalid(invoice_preview=forged)
    forged=deepcopy(PREVIEW)
    forged["money"]["total"]+=1
    invalid(invoice_preview=forged)


@pytest.mark.parametrize("bad",[None,True,0,1.2])
def test_bad_clock_denied(bad):
    invalid(now=bad)


def test_no_public_routes_or_database_posting():
    import inspect
    from app import pg_delivery_evidence_gate_v147 as m
    source=inspect.getsource(m)
    assert "@router" not in source and "INSERT INTO" not in source
    assert "GRANT " not in source and "create_app" not in source


@pytest.mark.parametrize("bad",[None,[],{},[{"name":"bad"}],
 [{"source_order_item_id":"l1","name":"Widgets","quantity":0,"unit_price":2000,"position":0}]+PREVIEW["items"][1:]])
def test_corrupted_preview_items_fail_with_fixed_exception(bad):
    forged=deepcopy(PREVIEW)
    forged["items"]=bad
    invalid(invoice_preview=forged)


def test_missing_receipt_signature_denied():
    p=signed("receipt")
    p.pop("signature")
    invalid(recipient_proof=p)


def test_no_unknown_client_state_flags_allowed():
    forged=deepcopy(PREVIEW)
    forged["approved_by"]="attacker"
    invalid(invoice_preview=forged)
