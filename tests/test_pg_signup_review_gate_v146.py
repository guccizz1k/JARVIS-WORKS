"""Stage 2 fail-closed offline security regression; NO live registration."""
import hashlib
import hmac
import json
from dataclasses import replace

import pytest
from app.pg_signup_review_gate_v146 import EnrollmentIntent, ProofRejected, evaluate_signup

EMAIL_KEY = b"test-mail-key-not-for-production" * 2
BUSINESS_KEY = b"test-business-key-not-for-production" * 2
NOW = 1793400000
INTENT = EnrollmentIntent("a" * 32, "Example Co", "Owner@Example.Com", "123-45-67890")
ISSUERS = {"email_control": "approved-mail-verifier-v1", "business_control": "approved-business-verifier-v1"}


def proof(purpose, intent=INTENT, nonce=None, key=None, **changes):
    d = intent.canonical()
    payload = dict(schema="jw-onboarding-proof-v146", purpose=purpose,
                   request_id=d["request_id"], intent_sha256=intent.sha256(),
                   subject=d["email" if purpose == "email_control" else "business_number"],
                   issuer=ISSUERS[purpose], issued_at=NOW - 30,
                   expires_at=NOW + 120, nonce=nonce or ("b" if purpose == "email_control" else "c") * 32)
    payload.update(changes)
    key = key or (EMAIL_KEY if purpose == "email_control" else BUSINESS_KEY)
    payload["signature"] = hmac.new(key, json.dumps(payload, sort_keys=True,
                separators=(",", ":"), ensure_ascii=False).encode(), hashlib.sha256).hexdigest()
    return payload


def run(**kwargs):
    args = dict(intent=INTENT, email_proof=proof("email_control"),
                business_proof=proof("business_control"),
                email_issuer_key=EMAIL_KEY, business_issuer_key=BUSINESS_KEY,
                consumed_nonces=set(), account_exists=lambda _email, _business: False, now=NOW)
    args.update(kwargs)
    return evaluate_signup(**args)


def test_only_review_not_signup_or_password_reset():
    decision = run()
    assert decision.status == "REVIEW_READY"
    assert len(decision.intent_sha256) == 64
    assert not decision.account_created and not decision.enrollment_approved
    assert not decision.recovery_enabled


def test_normalization_never_changes_proof_subject_binding():
    assert INTENT.canonical()["email"] == "owner@example.com"
    assert INTENT.canonical()["business_number"] == "1234567890"
    assert INTENT.sha256() == replace(INTENT, email="owner@example.com", business_number="1234567890").sha256()


@pytest.mark.parametrize("field,value", [
    ("request_id", "bad"), ("request_id", "A"*32),
    ("company_name", ""), ("company_name", " Company "),
    ("email", "bad"), ("email", "a..b@example.com"),
    ("email", " test@example.com"), ("business_number", "1234"),
    ("business_number", "１２３４５６７８９０"),
])
def test_invalid_intent_rejected(field, value):
    with pytest.raises(ProofRejected):
        run(intent=replace(INTENT, **{field: value}))


@pytest.mark.parametrize("mutation", [
    {"subject": "other@example.com"}, {"purpose": "business_control"},
    {"issuer": "fake-issuer"}, {"issued_at": NOW + 1},
    {"expires_at": NOW}, {"expires_at": NOW + 901},
    {"nonce": "bad"}, {"intent_sha256": "f"*64},
    {"request_id": "f"*32}, {"schema": "fake"},
])
def test_re_signed_invalid_email_envelopes_rejected(mutation):
    candidate = proof("email_control")
    candidate.update(mutation)
    candidate.pop("signature")
    candidate["signature"] = hmac.new(EMAIL_KEY, json.dumps(candidate,
        sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(),
        hashlib.sha256).hexdigest()
    with pytest.raises(ProofRejected):
        run(email_proof=candidate)


def test_tampering_original_signature_rejected():
    forged = proof("email_control")
    forged["subject"] = "attacker@example.com"
    with pytest.raises(ProofRejected):
        run(email_proof=forged)


def test_wrong_key_rejected():
    with pytest.raises(ProofRejected):
        run(email_issuer_key=b"another-key"*4)


def test_key_separation_prevents_same_issuer_self_approval():
    with pytest.raises(ProofRejected):
        run(business_issuer_key=EMAIL_KEY)


@pytest.mark.parametrize("existing", [True, None, "unknown"])
def test_duplicate_or_unavailable_account_lookup_fails_closed(existing):
    with pytest.raises(ProofRejected):
        run(account_exists=lambda _e, _b: existing)


def test_replay_rejected_before_review():
    with pytest.raises(ProofRejected):
        run(consumed_nonces={"b"*32})


def test_cross_purpose_nonce_collision_rejected():
    with pytest.raises(ProofRejected):
        run(business_proof=proof("business_control", nonce="b"*32))


def test_receipt_for_different_company_rejected():
    other = replace(INTENT, company_name="Other Company")
    with pytest.raises(ProofRejected):
        run(email_proof=proof("email_control", intent=other))


def test_missing_or_unknown_fields_rejected():
    original = proof("business_control")
    original["debug"] = "yes"
    with pytest.raises(ProofRejected):
        run(business_proof=original)
    original.pop("debug")
    original.pop("issuer")
    with pytest.raises(ProofRejected):
        run(business_proof=original)


@pytest.mark.parametrize("bad_now", [True, -1, 1793400000.5])
def test_now_not_boolean_negative_or_float(bad_now):
    with pytest.raises(ProofRejected):
        run(now=bad_now)


def test_no_unsourced_success_or_live_route_registration():
    import inspect
    import app.pg_signup_review_gate_v146 as gate
    source = inspect.getsource(gate)
    for forbidden in ('@router.', 'register_stage_api(', 'INSERT INTO ', 'ALTER ROLE ', 'send_email('):
        assert forbidden not in source
