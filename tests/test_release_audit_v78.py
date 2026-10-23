"""Local green tests must not override external release blockers."""
from scripts.release_audit_v78 import evaluate

def test_release_audit_is_fail_closed():
    actual=evaluate()
    assert actual['decision']=='BLOCKED'
    assert actual['postgres_live_attack_test']=='NOT_RUN'
    assert actual['representative_consent_customer_ocr']=='NOT_RUN'
    assert actual['physical_iphone_safari']=='NOT_RUN'
    assert actual['production_rehearsal']=='NOT_RUN'
    assert actual['remote_git_push']=='NOT_PERFORMED'
