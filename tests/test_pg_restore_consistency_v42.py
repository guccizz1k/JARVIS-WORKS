"""Pure V4.2 logical mirror audit tests; never requires a running PG server."""
from pathlib import Path
import pytest

from app.pg_restore_consistency_v42 import RestoreMismatch, compare_mirror, evidence

M = [('msg1', 'chat_ab', 'tenant_a', 'ua', 'text', '주문 확인', 'nonce1', 1),
     ('msg2', 'chat_ab', 'tenant_b', 'ub', 'order', 'invoice', 'nonce2', 2)]
C = [('chat_ab', 2)]


def test_checkpoint_determinism_and_exact_reconciliation():
    proof = compare_mirror(M, C, list(reversed(M)), list(reversed(C)))
    assert proof['messages'] == 2 and proof['counters'] == 1 and len(proof['sha256']) == 64
    assert evidence(M, C) == proof


@pytest.mark.parametrize('changes', [
    [('msg1', 'chat_ab', 'tenant_a', 'ua', 'text', 'altered', 'nonce1', 1), M[1]],
    [M[0]],
    M + [('msg3', 'chat_ab', 'tenant_a', 'ua', 'text', 'new', 'nonce3', 3)],
])
def test_changed_missing_or_extra_messages_block_restore(changes):
    with pytest.raises(RestoreMismatch):
        compare_mirror(M, C, changes, C)


@pytest.mark.parametrize('bad', [
    [('chat_ab', 1)], [], [('chat_ab', 2), ('chat_ab', 2)], [('chat_ab', True)],
])
def test_missing_backward_duplicate_or_boolean_counter_rejected(bad):
    with pytest.raises(RestoreMismatch):
        compare_mirror(M, C, M, bad)


@pytest.mark.parametrize('bad', [
    [M[0], M[0]],
    [M[0], ('msg3', 'chat_ab', 'tenant_a', 'ua', 'text', 'other', 'nonce1', 3)],
    [M[0], ('msg3', 'chat_ab', 'tenant_b', 'ub', 'text', 'other', 'nonce3', 1)],
    [M[0][:-1] + (True,), M[1]],
    [('msg1', 'chat_ab', 'tenant_a', None, 'text', 'hello', 'nonce1', 1)],
])
def test_duplicate_identity_nonce_sequence_and_invalid_fields_rejected(bad):
    with pytest.raises(RestoreMismatch):
        evidence(bad, C)


def test_empty_or_unbounded_checkpoint_rejected():
    with pytest.raises(RestoreMismatch): evidence([], C)
    with pytest.raises(RestoreMismatch): evidence(M * 3000, C)
    with pytest.raises(RestoreMismatch): evidence([(M[0][0], M[0][1], M[0][2], M[0][3], M[0][4], 'x' * (5 * 1024 * 1024), M[0][6], M[0][7])], C)


def test_not_mounted_and_schema_has_no_production_ddl():
    main = Path('app/main.py').read_text()
    assert 'pg_restore_consistency_v42' not in main
    runner = Path('scripts/test_postgres_restore_v42.py').read_text()
    assert 'jw_restore_v42' in runner and 'ONLY_EPHEMERAL_DATABASE' in runner
    assert 'DROP DATABASE' not in runner
