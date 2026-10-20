"""V4.2: deterministic PostgreSQL logical-mirror recovery evidence (synthetic only).

This is NOT an OS/physical backup, disaster recovery, or production migrator.
Only validates bounded public messenger rows and row-locked sequence counters.
"""
from __future__ import annotations

from hashlib import sha256
import json

MAX_MESSAGES = 5000
MAX_BYTES = 4 * 1024 * 1024


class RestoreMismatch(ValueError):
    """Fail closed on missing, extra, modified, or inconsistent recovery evidence."""


def _strict_row(value, width):
    if not isinstance(value, (tuple, list)) or len(value) != width:
        raise RestoreMismatch('Unexpected logical mirror row shape')
    if any(isinstance(x, bool) or type(x) not in (str, int) for x in value):
        raise RestoreMismatch('Unexpected logical mirror field type')
    return tuple(value)


def evidence(messages, counters):
    """Validate exact row identities and return a canonical SHA256 checkpoint.

    Message fields: id, connection_id, sender_org, sender_user, kind, body,
    request_id, message_seq. Counter fields: connection_id, last_seq.
    This operates solely on trusted, bounded synthetic database readbacks.
    """
    if not isinstance(messages, (tuple, list)) or not isinstance(counters, (tuple, list)):
        raise RestoreMismatch('Invalid evidence collection')
    if not messages or len(messages) > MAX_MESSAGES or not counters:
        raise RestoreMismatch('Missing or excessive recovery evidence')
    msg = [_strict_row(v, 8) for v in messages]
    cnt = [_strict_row(v, 2) for v in counters]
    ids = set()
    nonces = set()
    sequences = set()
    max_seq = {}
    for mid, conn, org, actor, kind, body, nonce, seq in msg:
        if not all((mid, conn, org, actor, kind, nonce)) or not isinstance(body, str):
            raise RestoreMismatch('Invalid message identity')
        if type(seq) is not int or seq <= 0:
            raise RestoreMismatch('Invalid message sequence')
        if mid in ids or (org, nonce) in nonces or (conn, seq) in sequences:
            raise RestoreMismatch('Duplicate message identity, nonce, or sequence')
        ids.add(mid)
        nonces.add((org, nonce))
        sequences.add((conn, seq))
        max_seq[conn] = max(seq, max_seq.get(conn, 0))
    counter_map = {}
    for conn, last in cnt:
        if not conn or type(last) is not int or last < 1 or conn in counter_map:
            raise RestoreMismatch('Invalid or repeated counter')
        counter_map[conn] = last
    for conn, high in max_seq.items():
        if counter_map.get(conn, -1) < high:
            raise RestoreMismatch('Restored sequence counter went backwards')
    data = json.dumps({'messages': sorted(msg), 'counters': sorted(cnt)},
                      ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
    if len(data) > MAX_BYTES:
        raise RestoreMismatch('Evidence exceeds synthetic size guard')
    return {'messages': len(msg), 'counters': len(cnt), 'sha256': sha256(data).hexdigest()}


def compare_mirror(before_messages, before_counters, after_messages, after_counters):
    """Require exact logical evidence, not just matching counts or rows ids."""
    before = evidence(before_messages, before_counters)
    after = evidence(after_messages, after_counters)
    if before != after:
        raise RestoreMismatch('Mirror evidence differed from sealed checkpoint')
    return before
