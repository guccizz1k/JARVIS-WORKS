"""Network-free fail-closed, evidence and scope checks for V4.1 recovery."""
from pathlib import Path

import pytest

from scripts.test_postgres_recovery_v41 import check_persisted_row, run


def test_no_test_authorization_never_connects(monkeypatch):
    for name in ('JW_PG_LAB_V40', 'JW_PG_LAB_V41', 'JW_PG_ALLOW_TEST_WRITES'):
        monkeypatch.delenv(name, raising=False)
    assert run() == 2


@pytest.mark.parametrize('missing', [
    'JW_PG_LAB_V40', 'JW_PG_LAB_V41', 'JW_PG_ALLOW_TEST_WRITES',
])
def test_partial_authorization_never_connects(monkeypatch, missing):
    monkeypatch.setenv('JW_PG_LAB_V40', 'ONLY_DISPOSABLE_LAB')
    monkeypatch.setenv('JW_PG_LAB_V41', 'ONLY_DISPOSABLE_LAB')
    monkeypatch.setenv('JW_PG_ALLOW_TEST_WRITES', 'ONLY_EPHEMERAL_DATABASE')
    monkeypatch.delenv(missing)
    assert run() == 2


def test_durable_row_exact_identity():
    row=('committed', 9, 'nonce', 'tenant_a', 'body')
    check_persisted_row(rows=[row],request_id='nonce', sender_org='tenant_a',
                        content='body',expected_id='committed',expected_seq=9)


@pytest.mark.parametrize('rows,seq', [
    ([],9), ([('committed',9,'nonce','tenant_a','body')]*2,9),
    ([('forged',9,'nonce','tenant_a','body')],9),
    ([('committed',9,'nonce','tenant_b','body')],9),
    ([('committed',9,'nonce','tenant_a','wrong')],9),
    ([('committed',9,'nonce','tenant_a','body')],0),
    ([('committed',9,'nonce','tenant_a','body')],True),
])
def test_bad_persisted_row(rows, seq):
    def not_valid(rowset):
        return check_persisted_row(rows=rowset,request_id='nonce',sender_org='tenant_a',
                                   content='body',expected_id='committed',expected_seq=seq)
    with pytest.raises(AssertionError):
        not_valid(rows)


def test_lab_safety_boundaries():
    main = Path('app/main.py').read_text()
    gate = Path('scripts/test_postgres_recovery_v41.py').read_text()
    assert 'test_postgres_recovery_v41' not in main
    assert "'ONLY_EPHEMERAL_DATABASE'" in gate and 'JW_PG_LAB_V41' in gate
    assert 'create_lab_app(uri)' in gate and 'ExpectedRollback' in gate
    assert 'DROP DATABASE' not in gate and 'ALTER ROLE' not in gate
    assert 'production' in gate.lower()
