"""V5.9: actual B2B website SQLite read cursor actor journal.

A fail-closed, append-only source ledger of authenticated read advancements.
No PostgreSQL calls, no background worker, no historical actor invention.
The existing application must call record_actor_read() inside its BEGIN IMMEDIATE
transaction after checking its authenticated, entitled org/thread and cursor.
"""
from __future__ import annotations

import sqlite3

TABLE = 'messenger_read_actor_history_v59'


class ReadActorRefused(ValueError):
    """Reject unsupported/unattributable read advances before modifying state."""


def install_read_actor_schema(c: sqlite3.Connection) -> None:
    """Idempotent additive install. No rewriting of existing read positions."""
    if c.in_transaction:
        raise ReadActorRefused('schema install requires no open transaction')
    if c.execute('PRAGMA foreign_keys').fetchone()[0] != 1:
        raise ReadActorRefused('foreign keys required')
    c.executescript('''
        BEGIN IMMEDIATE;
        CREATE TABLE IF NOT EXISTS messenger_read_actor_history_v59 (
          event_id INTEGER PRIMARY KEY AUTOINCREMENT,
          connection_id TEXT NOT NULL REFERENCES messenger_connections(id),
          org_id TEXT NOT NULL REFERENCES organizations(id),
          actor_user TEXT NOT NULL REFERENCES users(id),
          previous_read_seq INTEGER NOT NULL CHECK(previous_read_seq >= 0),
          next_read_seq INTEGER NOT NULL CHECK(next_read_seq > previous_read_seq),
          recorded_at TEXT NOT NULL CHECK(length(recorded_at) >= 10),
          UNIQUE(connection_id, org_id, next_read_seq)
        );
        CREATE TRIGGER IF NOT EXISTS jw_v59_journal_no_update
          BEFORE UPDATE ON messenger_read_actor_history_v59
          BEGIN SELECT RAISE(ABORT,'read actor evidence cannot be updated'); END;
        CREATE TRIGGER IF NOT EXISTS jw_v59_journal_no_delete
          BEFORE DELETE ON messenger_read_actor_history_v59
          BEGIN SELECT RAISE(ABORT,'read actor evidence cannot be deleted'); END;
        COMMIT;
    ''')


def record_actor_read(c: sqlite3.Connection, *, connection_id: str,
                      org_id: str, actor_user: str, target_seq: int,
                      recorded_at: str) -> bool:
    """Atomically advance an org cursor and capture the precise actor.

    Caller owns a BEGIN IMMEDIATE transaction, success COMMIT, and on failure
    ROLLBACK. Returns True only for a strictly new read position. No fabricated
    journal event for a duplicate, old, or historical pre-V5.9 cursor.
    """
    if not isinstance(c, sqlite3.Connection) or not c.in_transaction:
        raise ReadActorRefused('read journal requires the web transaction')
    if c.execute('PRAGMA foreign_keys').fetchone()[0] != 1:
        raise ReadActorRefused('foreign keys required')
    if (not isinstance(target_seq, int) or isinstance(target_seq, bool)
            or target_seq <= 0 or not isinstance(recorded_at, str)
            or len(recorded_at) < 10 or not all(isinstance(x, str) and x for x in
                                                (connection_id, org_id, actor_user))):
        raise ReadActorRefused('invalid cursor or identity')
    # Query the trusted DB relationship, NOT caller-supplied actor/org claims.
    actor = c.execute('SELECT 1 FROM users WHERE id=? AND org_id=?',
                      (actor_user, org_id)).fetchone()
    member = c.execute('''SELECT 1 FROM messenger_connections WHERE id=?
                          AND status='active' AND (org_a=? OR org_b=?)''',
                       (connection_id, org_id, org_id)).fetchone()
    if not actor or not member:
        raise ReadActorRefused('employee or thread membership denied')
    cursor = c.execute('''SELECT message_seq FROM messenger_messages
                          WHERE connection_id=? AND message_seq=?''',
                       (connection_id, target_seq)).fetchone()
    if cursor is None:
        raise ReadActorRefused('cursor does not belong to this conversation')
    previous = c.execute('''SELECT COALESCE(last_read_seq,0)
                            FROM messenger_read_positions
                            WHERE connection_id=? AND org_id=?''',
                         (connection_id, org_id)).fetchone()
    old = int(previous[0]) if previous else 0
    # Preserve the existing API's monotonic cursor and timestamp semantics.
    c.execute('''INSERT INTO messenger_read_positions
        (connection_id,org_id,last_read_rowid,last_read_seq,updated_at)
        VALUES(?,?,0,?,?)
        ON CONFLICT(connection_id,org_id) DO UPDATE SET
          last_read_seq=MAX(COALESCE(messenger_read_positions.last_read_seq,0),excluded.last_read_seq),
          updated_at=excluded.updated_at''',
        (connection_id, org_id, target_seq, recorded_at))
    actual = c.execute('''SELECT last_read_seq FROM messenger_read_positions
                           WHERE connection_id=? AND org_id=?''',
                       (connection_id, org_id)).fetchone()
    expected = max(old, target_seq)
    if actual is None or actual[0] != expected:
        raise ReadActorRefused('cursor write/readback mismatch')
    if target_seq <= old:
        return False
    c.execute('''INSERT INTO messenger_read_actor_history_v59
        (connection_id,org_id,actor_user,previous_read_seq,next_read_seq,recorded_at)
        VALUES(?,?,?,?,?,?)''',
        (connection_id, org_id, actor_user, old, target_seq, recorded_at))
    return True
