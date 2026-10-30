"""Real filesystem SQLite transaction model and concurrent duplicate requests."""
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import pytest

from app.pg_signup_review_gate_v146 import EnrollmentIntent, ReviewDecision
from scripts.review.v147_enrollment_atomic_model import (
    initialize_test_db, reserve_for_human_review, ReservationRejected)

BASE=EnrollmentIntent("a"*32,"Example Company","demo@example.com","1234567890")
A="b"*32
B="c"*32


def decision(intent=BASE):
    return ReviewDecision("REVIEW_READY",intent.sha256())


def data(path):
    with sqlite3.connect(str(path)) as db:
        return db.execute("SELECT count(*) FROM review_requests").fetchone()[0],db.execute("SELECT count(*) FROM used_nonces").fetchone()[0]


def test_review_reservation_not_account_creation(tmp_path):
    p=tmp_path/"review.sqlite"
    initialize_test_db(p)
    assert reserve_for_human_review(p,intent=BASE,decision=decision(),email_nonce=A,business_nonce=B)
    assert data(p)==(1,2)
    with sqlite3.connect(str(p)) as db:
        assert db.execute("SELECT status FROM review_requests").fetchone()==("PENDING_HUMAN_REVIEW",)


def test_atomic_repeated_request_replay_no_partial_rows(tmp_path):
    p=tmp_path/"review.sqlite"
    initialize_test_db(p)
    reserve_for_human_review(p,intent=BASE,decision=decision(),email_nonce=A,business_nonce=B)
    with pytest.raises(ReservationRejected):
        reserve_for_human_review(p,intent=BASE,decision=decision(),email_nonce=A,business_nonce=B)
    assert data(p)==(1,2)


def test_email_business_uniqueness_and_nonce_reuse(tmp_path):
    p=tmp_path/"review.sqlite"
    initialize_test_db(p)
    reserve_for_human_review(p,intent=BASE,decision=decision(),email_nonce=A,business_nonce=B)
    variants=[
        (replace(BASE,request_id="1"*32,business_number="9999999999"),"d"*32,"e"*32),
        (replace(BASE,request_id="2"*32,email="other@example.com"),"d"*32,"e"*32),
        (replace(BASE,request_id="3"*32,email="other@example.com",business_number="9999999999"),A,"e"*32),
        (replace(BASE,request_id="4"*32,email="third@example.com",business_number="9999999999"),"d"*32,B),
    ]
    for candidate,mail_nonce,biz_nonce in variants:
        with pytest.raises(ReservationRejected):
            reserve_for_human_review(p,intent=candidate,decision=decision(candidate),email_nonce=mail_nonce,business_nonce=biz_nonce)
        assert data(p)==(1,2)


@pytest.mark.parametrize("override",[{"status":"PASS"},{"account_created":True},
 {"enrollment_approved":True},{"recovery_enabled":True},{"intent_sha256":"f"*64}])
def test_not_eligible_without_review_only_proof(tmp_path,override):
    p=tmp_path/"review.sqlite"
    initialize_test_db(p)
    d=replace(decision(),**override)
    with pytest.raises(ReservationRejected):
        reserve_for_human_review(p,intent=BASE,decision=d,email_nonce=A,business_nonce=B)
    assert data(p)==(0,0)


def test_8_concurrent_same_enrollment_only_one_reserves(tmp_path):
    p=tmp_path/"review.sqlite"
    initialize_test_db(p)
    def attempt(_):
        try:
            return reserve_for_human_review(p,intent=BASE,decision=decision(),email_nonce=A,business_nonce=B)
        except ReservationRejected:
            return False
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes=list(pool.map(attempt,range(8)))
    assert outcomes.count(True)==1
    assert data(p)==(1,2)


def test_8_concurrent_unique_requests_with_same_business_only_one(tmp_path):
    p=tmp_path/"review.sqlite"
    initialize_test_db(p)
    def attempt(i):
        x=replace(BASE,request_id=f"{i+1:032x}",email=f"demo{i}@example.com")
        try:
            return reserve_for_human_review(p,intent=x,decision=decision(x),
                 email_nonce=f"{i+20:032x}",business_nonce=f"{i+30:032x}")
        except ReservationRejected:
            return False
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes=list(pool.map(attempt,range(8)))
    assert outcomes.count(True)==1
    assert data(p)==(1,2)
