"""V5.1 B2B messenger transactional outbox foundation.

Disabled by default, restricted to a verified temporary SQLite test database.
A trigger appends minimal source references in the *same* SQLite transaction as
source evidence. There is no PostgreSQL writer, publisher, migration, network
connection, production activation or retention/deletion mechanism here.
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import sqlite3

FLAG = 'JW_PG_OUTBOX_V51'
LAB = 'ONLY_DISPOSABLE_LAB'
ALLOW = 'ONLY_EPHEMERAL_LOCAL_DATABASE'
OUTBOX = 'jw_transition_outbox_v51'
REQUIRED = frozenset({
    'messenger_messages', 'messenger_edits', 'messenger_attachments',
    'messenger_receipts', 'messenger_read_positions',
})


class OutboxRefused(RuntimeError):
    """Outbox use not permitted or disposable contract incomplete."""


def _authorize(c: sqlite3.Connection) -> None:
    if (os.getenv('JW_ENV', '').casefold() == 'production'
            or os.getenv(FLAG) != LAB
            or os.getenv('JW_PG_CI_ALLOW') != ALLOW):
        raise OutboxRefused('Disposable SQLite outbox gate is not authorized')
    if not isinstance(c, sqlite3.Connection) or c.in_transaction:
        raise OutboxRefused('Disposable SQLite connection must be outside transaction')
    if c.execute('PRAGMA foreign_keys').fetchone()[0] != 1:
        raise OutboxRefused('SQLite foreign keys must be enforced')
    entries = c.execute('PRAGMA database_list').fetchall()
    main = [row[2] for row in entries if row[1] == 'main']
    if len(main) != 1 or not main[0]:
        raise OutboxRefused('Only file-backed disposable SQLite accepted')
    path = Path(main[0]); temp = Path(tempfile.gettempdir()).resolve()
    if path.is_symlink() or not path.resolve().is_relative_to(temp) or path.resolve() == temp:
        raise OutboxRefused('Refuse non-temporary or symlink SQLite database')
    present = {row[0] for row in c.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'messenger_%'")}
    if not REQUIRED.issubset(present):
        raise OutboxRefused('Legacy messenger evidence schema incomplete')
    expected = {
        'messenger_messages': {'id', 'sender_org', 'body'},
        'messenger_edits': {'id', 'message_id'},
        'messenger_attachments': {'message_id', 'data'},
        'messenger_receipts': {'message_id', 'receiver_org'},
        'messenger_read_positions': {'connection_id', 'org_id', 'last_read_seq'},
    }
    for table, fields in expected.items():
        found = {row[1] for row in c.execute('PRAGMA table_info(' + table + ')')}
        if not fields.issubset(found):
            raise OutboxRefused('Legacy messenger source columns incomplete')


def install_disposable_outbox(c: sqlite3.Connection) -> None:
    """Append reference-only events atomically; only in explicit disposable lab.

    This installs no triggers on production/regular development databases. No
    direct external writes, no plaintext message, attachment or credentials
    are duplicated into the outbox. Existing rows require a separate baseline.
    """
    _authorize(c)
    try:
        c.executescript('''
        BEGIN IMMEDIATE;
        CREATE TABLE IF NOT EXISTS jw_transition_outbox_v51 (
          seq INTEGER PRIMARY KEY AUTOINCREMENT,
          event_type TEXT NOT NULL CHECK(event_type IN
            ('message.insert','message.body_changed','edit.insert',
             'attachment.insert','receipt.insert',
             'read_position.insert','read_position.advance')),
          entity_ref TEXT NOT NULL CHECK(length(entity_ref)>0),
          recorded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE TRIGGER IF NOT EXISTS jw_v51_outbox_immutable_update
          BEFORE UPDATE ON jw_transition_outbox_v51
          BEGIN SELECT RAISE(ABORT,'outbox evidence cannot be updated'); END;
        CREATE TRIGGER IF NOT EXISTS jw_v51_outbox_immutable_delete
          BEFORE DELETE ON jw_transition_outbox_v51
          BEGIN SELECT RAISE(ABORT,'outbox evidence cannot be deleted'); END;
        CREATE TRIGGER IF NOT EXISTS jw_v51_message_new
          AFTER INSERT ON messenger_messages
          BEGIN INSERT INTO jw_transition_outbox_v51(event_type,entity_ref)
            VALUES('message.insert',NEW.id); END;
        CREATE TRIGGER IF NOT EXISTS jw_v51_message_body
          AFTER UPDATE OF body ON messenger_messages
          WHEN NEW.body IS NOT OLD.body
          BEGIN INSERT INTO jw_transition_outbox_v51(event_type,entity_ref)
            VALUES('message.body_changed',NEW.id); END;
        CREATE TRIGGER IF NOT EXISTS jw_v51_edit_new
          AFTER INSERT ON messenger_edits
          BEGIN INSERT INTO jw_transition_outbox_v51(event_type,entity_ref)
            VALUES('edit.insert',NEW.id); END;
        CREATE TRIGGER IF NOT EXISTS jw_v51_attachment_new
          AFTER INSERT ON messenger_attachments
          BEGIN INSERT INTO jw_transition_outbox_v51(event_type,entity_ref)
            VALUES('attachment.insert',NEW.message_id); END;
        CREATE TRIGGER IF NOT EXISTS jw_v51_receipt_new
          AFTER INSERT ON messenger_receipts
          BEGIN INSERT INTO jw_transition_outbox_v51(event_type,entity_ref)
            VALUES('receipt.insert',NEW.message_id); END;
        CREATE TRIGGER IF NOT EXISTS jw_v51_read_new
          AFTER INSERT ON messenger_read_positions
          BEGIN INSERT INTO jw_transition_outbox_v51(event_type,entity_ref)
            VALUES('read_position.insert',NEW.connection_id || ':' || NEW.org_id); END;
        CREATE TRIGGER IF NOT EXISTS jw_v51_read_advance
          AFTER UPDATE OF last_read_seq ON messenger_read_positions
          WHEN NEW.last_read_seq > OLD.last_read_seq
          BEGIN INSERT INTO jw_transition_outbox_v51(event_type,entity_ref)
            VALUES('read_position.advance',NEW.connection_id || ':' || NEW.org_id); END;
        COMMIT;
    ''')
    except BaseException:
        if c.in_transaction:
            c.rollback()
        raise
