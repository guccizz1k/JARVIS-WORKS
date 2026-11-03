"""V15.4 isolated FastAPI signed delivery review route; no real DB in these tests."""
from contextlib import contextmanager

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from psycopg import errors

from app import pg_delivery_review_api_v154 as api
from app.pg_delivery_evidence_gate_v147 import DeliveryProofRejected
from app.pg_delivery_review_reservation_v151 import PendingReviewRejected


HOST = "https://stage.invalid.test"
PATH = "/api/pg-stage/v154/orders/" + "a" * 32 + "/delivery-review"
PAIR = {"dispatch_proof": {"nonce": "1" * 32},
        "recipient_proof": {"nonce": "2" * 32}}


@pytest.fixture
def wired(monkeypatch):
    monkeypatch.setenv("JW_PG_DELIVERY_REVIEW_V154",
                       "ISOLATED_DEV_SIGNED_RECEIPT_REVIEW_ONLY")
    monkeypatch.setenv("JW_V154_ISSUER_INDEPENDENCE_ACK",
                       "EXTERNAL_ISSUER_KEYS_VERIFIED")
    monkeypatch.setenv("JW_V154_DISPATCH_VERIFY_KEY_HEX", "a" * 64)
    monkeypatch.setenv("JW_V154_RECEIPT_VERIFY_KEY_HEX", "b" * 64)
    monkeypatch.setenv("JW_ENV", "test")
    monkeypatch.delenv("JW_INSECURE_LOCAL_DEV", raising=False)
    monkeypatch.setattr(api.sessions, "v90_enabled", lambda: True)
    monkeypatch.setattr(api.quotes, "enabled", lambda: True)
    monkeypatch.setattr(api.sessions, "_session_hash", lambda _: "s" * 64)
    monkeypatch.setattr(api.quotes, "_origin_checked", lambda r:
        None if r.headers.get("origin") == HOST
        else (_ for _ in ()).throw(HTTPException(403, "Invalid Origin")))
    calls = []
    identity = ("jw_app_dev", "0" * 32, "a" * 32, "admin", "csrf-value", "Org")

    @contextmanager
    def cursor(_):
        calls.append("cursor")
        yield object(), identity

    monkeypatch.setattr(api.sessions, "_pg_validated_cursor", cursor)

    def reserve(_cur, **kwargs):
        calls.append("reserve")
        assert kwargs["validated_identity"] == identity
        assert kwargs["order_id"] == "a" * 32
        assert kwargs["independent_dispatch_key"] == bytes.fromhex("a" * 64)
        assert kwargs["independent_recipient_key"] == bytes.fromhex("b" * 64)
        assert kwargs["dispatch_proof"] is not None
        return "c" * 64

    monkeypatch.setattr(api, "reserve_delivery_review_v151", reserve)
    app = FastAPI()
    assert api.register_v154_delivery_review(app) is True
    return TestClient(app), calls, identity


def _post(client, **kwargs):
    headers = {"origin": HOST, "X-CSRF-Token": "csrf-value"}
    headers.update(kwargs.pop("headers", {}))
    return client.post(PATH, headers=headers, json=kwargs.pop("body", PAIR))


def test_endpoint_creates_only_pending_review(wired):
    client, calls, _ = wired
    response = _post(client)
    assert response.status_code == 201, response.text
    assert response.json() == {
        "order_id": "a" * 32,
        "evidence_sha256": "c" * 64,
        "status": "PENDING_HUMAN_REVIEW",
        "physical_delivery_verified": False,
        "invoice_posted": False,
        "payment_posted": False,
    }
    assert response.headers["cache-control"] == "no-store"
    assert calls == ["cursor", "reserve"]


@pytest.mark.parametrize("headers", [
    {"origin": "https://attacker.invalid.test"},
    {"origin": "http://stage.invalid.test"},
    {"X-CSRF-Token": ""},
    {"X-CSRF-Token": "incorrect"},
])
def test_origin_and_csrf_errors_do_not_reach_storage(wired, headers):
    client, calls, _ = wired
    assert _post(client, headers=headers).status_code == 403
    assert "reserve" not in calls


def test_missing_or_invalid_order_id_does_not_reach_storage(wired):
    client, calls, _ = wired
    path = "/api/pg-stage/v154/orders/not-a-valid-id/delivery-review"
    r = client.post(path, headers={"origin": HOST}, json=PAIR)
    assert r.status_code == 404
    assert not calls


def test_body_extra_fields_and_oversized_envelopes_fail_closed(wired):
    client, calls, _ = wired
    assert _post(client, body={**PAIR, "approved": True}).status_code == 422
    assert _post(client, body={
        "dispatch_proof": {"malicious": "x" * 18000},
        "recipient_proof": PAIR["recipient_proof"],
    }).status_code == 413
    assert not calls


@pytest.mark.parametrize("error,status", [
    (PendingReviewRejected("invalid"), 409),
    (DeliveryProofRejected("invalid"), 409),
    (errors.UniqueViolation("duplicate"), 409),
    (errors.ForeignKeyViolation("invalid foreign key"), 409),
    (errors.InsufficientPrivilege("deny"), 503),
    (errors.UndefinedTable("missing"), 503),
])
def test_storage_rejects_invalid_proofs_and_missing_schema(wired, monkeypatch,
                                                         error, status):
    client, _, _ = wired
    def reject(_cur, **_kwargs):
        raise error
    monkeypatch.setattr(api, "reserve_delivery_review_v151", reject)
    response = _post(client)
    assert response.status_code == status
    assert "secret" not in response.text.lower()


def test_member_role_blocked_before_reservation(wired, monkeypatch):
    client, calls, identity = wired
    @contextmanager
    def staff(_):
        yield object(), (*identity[:3], "member", *identity[4:])
    monkeypatch.setattr(api.sessions, "_pg_validated_cursor", staff)
    assert _post(client).status_code == 403
    assert "reserve" not in calls


def test_key_config_strict_and_independent(wired, monkeypatch):
    for dispatch, receipt in [
        ("", "b" * 64), ("a" * 65, "b" * 64),
        ("a" * 64, "a" * 64), ("a" * 64, "c" * 63),
    ]:
        monkeypatch.setenv("JW_V154_DISPATCH_VERIFY_KEY_HEX", dispatch)
        monkeypatch.setenv("JW_V154_RECEIPT_VERIFY_KEY_HEX", receipt)
        with pytest.raises(RuntimeError):
            api._issuer_keys()


def test_disabled_by_default_and_fails_closed_on_bad_opt_in(wired, monkeypatch):
    monkeypatch.delenv("JW_PG_DELIVERY_REVIEW_V154")
    app = FastAPI()
    assert not api.register_v154_delivery_review(app)
    assert not any("/v154/" in route.path for route in app.routes)
    monkeypatch.setenv("JW_PG_DELIVERY_REVIEW_V154", "TRUE")
    with pytest.raises(RuntimeError):
        api.register_v154_delivery_review(app)
    monkeypatch.setenv("JW_PG_DELIVERY_REVIEW_V154",
                       "ISOLATED_DEV_SIGNED_RECEIPT_REVIEW_ONLY")
    monkeypatch.delenv("JW_V154_ISSUER_INDEPENDENCE_ACK")
    with pytest.raises(RuntimeError):
        api.register_v154_delivery_review(app)


def test_insecure_and_prod_environments_cannot_enable(wired, monkeypatch):
    monkeypatch.setenv("JW_ENV", "production")
    assert not api.enabled()
    monkeypatch.setenv("JW_ENV", "test")
    monkeypatch.setenv("JW_INSECURE_LOCAL_DEV", "1")
    assert not api.enabled()
