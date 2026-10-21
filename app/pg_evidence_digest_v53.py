"""V5.3 disposable-lab-only immutable evidence-reference digest transport.

This is NOT a production-data migrator. It never transfers attachment bytes,
message bodies, edit bodies, session tokens, or receipts' freeform actor names.
It proves some immutable source evidence can be attributed to a signed actor
and mirrored as a tamper-evident metadata digest to a restricted PG ledger.
Mutable read positions and ambiguous message.body_changed deliberately block.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import re
import sqlite3

from app.pg_transition_outbox_v51 import OUTBOX, _authorize, OutboxRefused
from app.pg_outbox_relay_v52 import RelayRefused, _gate as _old_gate

LAB = "ONLY_DISPOSABLE_LAB"
STATE = "jw_evidence_checkpoint_v53"
MAX_BATCH = 32
SUPPORTED = frozenset({"message.insert", "attachment.insert", "edit.insert", "receipt.insert"})
REF_LIMIT = 128


@dataclass(frozen=True)
class Evidence:
    seq: int
    event_type: str
    ref: str
    org: str
    actor: str
    digest: str
    evidence_digest: str


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fingerprint(payload: dict) -> str:
    return _hash(json.dumps(payload, sort_keys=True, ensure_ascii=False,
                            separators=(",", ":")).encode("utf-8"))


def _one(c: sqlite3.Connection, sql: str, params: tuple):
    rows = c.execute(sql, params).fetchall()
    if len(rows) != 1:
        raise RelayRefused("Missing or nonunique immutable evidence")
    return rows[0]


def _source_integrity(c: sqlite3.Connection, kind: str, ref: str) -> tuple[str, str, str]:
    """Return (source tenant, signed actor, evidence SHA256); never actual payload."""
    if kind == "message.insert":
        org, actor, mid, thread = _one(c,
            "SELECT sender_org,sender_user,id,connection_id FROM messenger_messages WHERE id=?",
            (ref,))
        if not all(isinstance(v, str) and v for v in (org, actor, mid, thread)):
            raise RelayRefused("Missing immutable message owner")
        return org, actor, _fingerprint({"type": kind, "id": mid, "connection": thread,
                                          "tenant": org, "actor": actor, "scope": "reference-only"})

    if kind == "attachment.insert":
        row = _one(c, """SELECT m.sender_org,m.sender_user,m.connection_id,
            a.message_id,a.filename,a.mime,a.data,a.size_bytes,a.content_hash
            FROM messenger_attachments a JOIN messenger_messages m ON m.id=a.message_id
            WHERE a.message_id=?""", (ref,))
        org, actor, thread, mid, filename, mime, data, length, stored_hash = row
        if not all(isinstance(v, str) and v for v in (org, actor, thread, mid, filename, mime)):
            raise RelayRefused("Missing attachment provenance")
        if not isinstance(data, bytes) or not 0 < len(data) <= 5 * 1024 * 1024:
            raise RelayRefused("Invalid attachment bytes")
        if type(length) is not int or length != len(data) or not isinstance(stored_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", stored_hash) or _hash(data) != stored_hash:
            raise RelayRefused("Attachment size/hash integrity mismatch")
        return org, actor, _fingerprint({"type": kind, "message": mid, "connection": thread,
             "tenant": org, "actor": actor, "filename": filename, "mime": mime,
             "size_bytes": length, "sha256": stored_hash})

    if kind == "edit.insert":
        row = _one(c, """SELECT m.sender_org,m.sender_user,m.id,m.connection_id,
            e.id,e.message_id,e.actor_user,e.version,e.edited_at,e.previous_body,e.new_body
            FROM messenger_edits e JOIN messenger_messages m ON m.id=e.message_id
            WHERE e.id=?""", (ref,))
        org, sender, mid, thread, eid, linked, actor, version, stamp, previous, current = row
        if not (all(isinstance(x, str) and x for x in (org,sender,mid,thread,eid,linked,actor,stamp))
                and actor == sender and type(version) is int and version >= 2
                and isinstance(previous, str) and isinstance(current, str)):
            raise RelayRefused("Edited message ownership/version ambiguous")
        return org, actor, _fingerprint({"type": kind, "message": mid, "connection": thread,
            "edit_id": eid, "tenant": org, "actor": actor, "version": version,
            "edited_at": stamp, "previous_sha256": _hash(previous.encode()),
            "new_sha256": _hash(current.encode())})

    if kind == "receipt.insert":
        # No receipt UPDATE/DELETE protection in the legacy schema by default.
        # Deny instead of claiming immutable historical evidence from a mutable row.
        triggers = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
        if not {"messenger_receipt_no_update", "messenger_receipt_no_delete"}.issubset(triggers):
            raise RelayRefused("Receipt history is mutable; cannot attest event")
        row = _one(c, """SELECT m.sender_org,m.id,m.connection_id,
          c.org_a,c.org_b,r.message_id,r.receiver_org,r.receiver_user,r.received_at
          FROM messenger_receipts r JOIN messenger_messages m ON m.id=r.message_id
          JOIN messenger_connections c ON c.id=m.connection_id
          WHERE r.message_id=?""", (ref,))
        sender, mid, thread, left, right, linked, org, actor, stamp = row
        if not all(isinstance(x, str) and x for x in (sender,mid,thread,left,right,linked,org,actor,stamp)):
            raise RelayRefused("Missing receipt provenance")
        if org == sender or org not in (left,right) or sender not in (left,right):
            raise RelayRefused("Receipt signer is not receiving company")
        return org, actor, _fingerprint({"type": kind, "message": mid, "connection": thread,
                                         "receiver_org": org, "actor": actor, "received_at": stamp})
    raise RelayRefused("Unverifiable or mutable event; checkpoint held")


def _guard(source: sqlite3.Connection) -> None:
    if (os.getenv("JW_ENV", "").casefold() == "production"
            or os.getenv("JW_PG_LAB_V53") != LAB):
        raise RelayRefused("V5.3 explicit disposable lab authorization missing")
    try:
        _old_gate(source)
    except (OutboxRefused, RelayRefused) as exc:
        raise RelayRefused("V5.1/V5.2 authorization prerequisites missing") from exc
    required = {
        "messenger_messages": {"id", "sender_org", "sender_user", "connection_id"},
        "messenger_attachments": {"message_id", "filename", "mime", "data", "size_bytes", "content_hash"},
        "messenger_edits": {"id", "message_id", "actor_user", "version", "edited_at", "previous_body", "new_body"},
        "messenger_receipts": {"message_id", "receiver_org", "receiver_user", "received_at"},
        "messenger_connections": {"id", "org_a", "org_b"},
    }
    for table, cols in required.items():
        observed = {x[1] for x in source.execute(f"PRAGMA table_info({table})")}
        if not cols.issubset(observed):
            raise RelayRefused(f"Incomplete disposable schema: {table}")
    # Validate immutable evidence triggers on the real B2B schema (not mock tables).
    trigger_names = {x[0] for x in source.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    if not {"messenger_attachment_no_update", "messenger_attachment_no_delete",
            "messenger_edit_no_update", "messenger_edit_no_delete"}.issubset(trigger_names):
        raise RelayRefused("Mutable evidence table; immutable trigger protection required")


def _prepare_checkpoint(c: sqlite3.Connection) -> None:
    if c.in_transaction:
        raise RelayRefused("Preexisting transaction cannot be claimed")
    c.execute(f"""CREATE TABLE IF NOT EXISTS {STATE} (
       stream_id TEXT PRIMARY KEY CHECK(length(stream_id)=32),
       ack_seq INTEGER NOT NULL DEFAULT 0 CHECK(ack_seq>=0))""")
    cols = {x[1] for x in c.execute(f"PRAGMA table_info({STATE})")}
    if cols != {"stream_id", "ack_seq"}:
        raise RelayRefused("Checkpoint schema mismatch")
    rows = c.execute(f"SELECT stream_id,ack_seq FROM {STATE}").fetchall()
    if len(rows) == 0:
        from secrets import token_hex
        c.execute(f"INSERT INTO {STATE} VALUES (?,0)", (token_hex(16),))
    elif len(rows) != 1 or not re.fullmatch(r"[0-9a-f]{32}", str(rows[0][0])) or type(rows[0][1]) is not int or rows[0][1] < 0:
        raise RelayRefused("Invalid checkpoint row")


def relay_evidence(source: sqlite3.Connection, sink, *, limit: int = MAX_BATCH,
                   after_pg_commit=None) -> dict:
    """PG durable ledger commit then SQLite ACK. Unsupported row causes zero ACK."""
    _guard(source)
    if source.isolation_level is not None:
        raise RelayRefused("Disposable relay requires explicit SQLite autocommit connection")
    if type(limit) is not int or not 1 <= limit <= MAX_BATCH:
        raise RelayRefused("Invalid evidence batch size")
    _prepare_checkpoint(source)
    source.execute("BEGIN IMMEDIATE")
    try:
        stream, ack = source.execute(f"SELECT stream_id,ack_seq FROM {STATE}").fetchone()
        if type(ack) is not int or ack < 0:
            raise RelayRefused("Invalid source ACK")
        maxseq = source.execute(f"SELECT COALESCE(MAX(seq),0) FROM {OUTBOX}").fetchone()[0]
        if ack > maxseq or (ack and source.execute(f"SELECT 1 FROM {OUTBOX} WHERE seq=?", (ack,)).fetchone() is None):
            raise RelayRefused("ACK points to nonexistent source history")
        tenant, actor = sink.verified_identity()  # never trust caller-supplied string
        if not all(isinstance(x, str) and x for x in (tenant, actor)):
            raise RelayRefused("Invalid signed PostgreSQL identity")
        rows = source.execute(f"SELECT seq,event_type,entity_ref FROM {OUTBOX} WHERE seq>? ORDER BY seq LIMIT ?", (ack,limit)).fetchall()
        collected = []
        for seq,kind,ref in rows:
            if (type(seq) is not int or seq <= ack or (collected and seq <= collected[-1].seq)
                    or not isinstance(ref,str) or not 0 < len(ref) <= REF_LIMIT
                    or kind not in SUPPORTED):
                raise RelayRefused("Unsupported or nonmonotonic source event")
            org,user,evidence_digest = _source_integrity(source,kind,ref)
            if (org,user) != (tenant,actor):
                raise RelayRefused("Signed identity mismatch, source event ACK denied")
            fingerprint = _fingerprint({"stream": stream,"seq": seq,"kind":kind,
                                       "ref":ref,"org":org,"actor":user,
                                       "evidence_digest":evidence_digest})
            collected.append(Evidence(seq,kind,ref,org,user,fingerprint,evidence_digest))
        if not collected:
            source.execute("COMMIT")
            return {"delivered":0,"ack_seq":ack,"cutover_approved":False}
        sink.commit_events(stream, collected)
        if after_pg_commit is not None:
            if not callable(after_pg_commit):
                raise RelayRefused("Invalid fault injection")
            after_pg_commit()
        last = collected[-1].seq
        rc = source.execute(f"UPDATE {STATE} SET ack_seq=? WHERE stream_id=? AND ack_seq=?",
                            (last,stream,ack))
        if rc.rowcount != 1:
            raise RelayRefused("Lost ACK ownership")
        source.execute("COMMIT")
        return {"delivered":len(collected),"ack_seq":last,"cutover_approved":False}
    except BaseException:
        if source.in_transaction:
            source.rollback()
        raise

class Pg17EvidenceLabSink:
    """Signed RLS-only disposable ledger adapter; schema provisioned by PG gate.

    The V5.2 Pg17LabSink provides the exact trusted DSN/role/PG17 checks.
    This class does not create users, accept unsigned tenant IDs or change
    any operational table. Caller uses the signed session's verified actor.
    """

    def __init__(self, dsn: str, token: str):
        if os.getenv('JW_PG_LAB_V53') != LAB:
            raise RelayRefused('V5.3 PG sink disabled outside disposable lab')
        from app.pg_outbox_relay_v52 import Pg17LabSink
        self._prior = Pg17LabSink(dsn, token)

    def verified_identity(self):
        return self._prior.verified_identity()

    def commit_events(self, stream: str, events: list[Evidence]):
        if not re.fullmatch(r'[0-9a-f]{32}',stream) or not events:
            raise RelayRefused('Invalid V5.3 evidence batch')
        with self._prior._connect() as pg:
            with pg.cursor() as cur:
                tenant, actor = self._prior._bind(cur)
                for e in events:
                    if (tenant,actor)!=(e.org,e.actor):
                        raise RelayRefused('Signed PG identity differs from source evidence')
                    if (e.event_type not in SUPPORTED or type(e.seq) is not int or e.seq <= 0
                        or not isinstance(e.ref,str) or not 0 < len(e.ref) <= REF_LIMIT
                        or any(not re.fullmatch(r'[0-9a-f]{64}',d)
                               for d in (e.digest,e.evidence_digest))):
                        raise RelayRefused('Malformed immutable evidence envelope')
                    cur.execute('''INSERT INTO jw_relay_v53.inbox
                       (stream_id,source_seq,tenant_id,actor_id,event_type,entity_ref,
                        source_digest,evidence_digest)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                       ON CONFLICT(stream_id,source_seq) DO NOTHING''',
                       (stream,e.seq,e.org,e.actor,e.event_type,e.ref,e.digest,e.evidence_digest))
                    cur.execute('''SELECT tenant_id,actor_id,event_type,entity_ref,
                       source_digest,evidence_digest FROM jw_relay_v53.inbox
                       WHERE stream_id=%s AND source_seq=%s''',(stream,e.seq))
                    actual=cur.fetchone()
                    expected=(e.org,e.actor,e.event_type,e.ref,e.digest,e.evidence_digest)
                    if actual!=expected:
                        raise RelayRefused('PG evidence ledger tamper, conflict, or RLS denial')
            pg.commit()
