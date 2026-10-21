"""V5.9 actual-web-route data contract tests against real SQLite transactions."""
import sqlite3
import tempfile
from pathlib import Path
import pytest
from app.pg_read_actor_journal_v59 import (
    ReadActorRefused, install_read_actor_schema, record_actor_read, TABLE,
)


def connection():
    c = sqlite3.connect(':memory:', isolation_level=None)
    c.execute('PRAGMA foreign_keys=ON')
    c.executescript('''
    CREATE TABLE organizations (id TEXT PRIMARY KEY);
    CREATE TABLE users (id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id));
    CREATE TABLE messenger_connections (id TEXT PRIMARY KEY, org_a TEXT, org_b TEXT, status TEXT);
    CREATE TABLE messenger_messages (id TEXT PRIMARY KEY, connection_id TEXT, message_seq INTEGER);
    CREATE TABLE messenger_read_positions (connection_id TEXT, org_id TEXT, last_read_rowid INTEGER,
      last_read_seq INTEGER, updated_at TEXT, PRIMARY KEY(connection_id,org_id));
    INSERT INTO organizations VALUES ('A'),('B'),('C');
    INSERT INTO users VALUES ('ua','A'),('ua2','A'),('ub','B'),('uc','C');
    INSERT INTO messenger_connections VALUES ('t','A','B','active'),('p','B','C','pending');
    INSERT INTO messenger_messages VALUES ('m1','t',1),('m2','t',2),('m3','t',3),('m4','t',4);
    ''')
    install_read_actor_schema(c)
    return c


def read(c, seq=2, org='A', user='ua', thread='t', timestamp='2026-10-21T10:00:00Z'):
    c.execute('BEGIN IMMEDIATE')
    try:
        result = record_actor_read(c,connection_id=thread,org_id=org,actor_user=user,
                                   target_seq=seq,recorded_at=timestamp)
        c.execute('COMMIT')
        return result
    except BaseException:
        c.execute('ROLLBACK')
        raise


def rows(c):
    return c.execute(f'SELECT org_id,actor_user,previous_read_seq,next_read_seq FROM {TABLE} ORDER BY event_id').fetchall()


def positions(c):
    return c.execute('SELECT org_id,last_read_seq FROM messenger_read_positions ORDER BY org_id').fetchall()


def test_installs_idempotently_with_no_historical_backfill():
    c=connection()
    c.execute("INSERT INTO messenger_read_positions VALUES ('t','A',0,2,'old')")
    install_read_actor_schema(c)
    assert rows(c)==[]
    assert positions(c)==[('A',2)]


def test_successive_actors_and_strict_monotonicity():
    c=connection()
    assert read(c,seq=1) is True
    assert read(c,seq=3,user='ua2') is True
    assert read(c,seq=2,user='ua') is False
    assert read(c,seq=3,user='ua') is False
    assert positions(c)==[('A',3)]
    assert rows(c)==[('A','ua',0,1),('A','ua2',1,3)]


def test_independent_org_positions_and_exact_actor():
    c=connection()
    read(c,seq=2,org='A',user='ua')
    read(c,seq=3,org='B',user='ub')
    assert positions(c)==[('A',2),('B',3)]
    assert rows(c)==[('A','ua',0,2),('B','ub',0,3)]


@pytest.mark.parametrize('org,user,thread,seq',[
    ('A','ub','t',2),('B','ua','t',2),('C','uc','t',2),
    ('B','ub','p',1),('A','ua','t',99),('A','ua','other',1),
    ('A','ua','t',0),('A','ua','t',True),
])
def test_rejection_preserves_evidence(org,user,thread,seq):
    c=connection()
    with pytest.raises(ReadActorRefused):
        read(c,org=org,user=user,thread=thread,seq=seq)
    assert rows(c)==[]
    assert positions(c)==[]


def test_history_immutable_and_repeated_installs_do_not_reset():
    c=connection();read(c)
    with pytest.raises(sqlite3.IntegrityError):
        c.execute(f"UPDATE {TABLE} SET actor_user='ub'")
    with pytest.raises(sqlite3.IntegrityError):
        c.execute(f'DELETE FROM {TABLE}')
    install_read_actor_schema(c)
    assert rows(c)==[('A','ua',0,2)]


def test_trigger_failure_rolls_back_cursor_and_journal():
    c=connection()
    c.execute(f"""CREATE TRIGGER no_actor_test BEFORE INSERT ON {TABLE}
        BEGIN SELECT RAISE(ABORT,'injected error'); END""")
    with pytest.raises(sqlite3.IntegrityError): read(c)
    assert rows(c)==[]
    assert positions(c)==[]
    c.execute('DROP TRIGGER no_actor_test')
    assert read(c) is True


def test_external_transaction_contract_and_foreign_keys():
    c=connection()
    with pytest.raises(ReadActorRefused):
        record_actor_read(c,connection_id='t',org_id='A',actor_user='ua',target_seq=1,recorded_at='2026-10-21T00:00:00Z')
    c.execute('PRAGMA foreign_keys=OFF')
    with pytest.raises(ReadActorRefused):
        install_read_actor_schema(c)


def test_duplicate_write_then_rollback_preserves_first_identity():
    c=connection();read(c,seq=1)
    c.execute('BEGIN IMMEDIATE')
    assert record_actor_read(c,connection_id='t',org_id='A',actor_user='ua2',target_seq=4,recorded_at='2026-10-21T00:00:00Z')
    c.execute('ROLLBACK')
    assert rows(c)==[('A','ua',0,1)]
    assert positions(c)==[('A',1)]


def test_external_preexisting_cursor_does_not_invent_actor():
    c=connection()
    c.execute("INSERT INTO messenger_read_positions VALUES ('t','A',0,3,'old')")
    assert read(c,seq=2) is False
    assert rows(c)==[]
    assert read(c,seq=4) is True
    assert rows(c)==[('A','ua',3,4)]


def test_production_switch_refuses_schema_and_write_before_data_change(monkeypatch):
    c=connection()
    monkeypatch.setenv('JW_ENV','PrOdUcTiOn')
    with pytest.raises(ReadActorRefused):
        install_read_actor_schema(c)
    with pytest.raises(ReadActorRefused):
        read(c)
    assert rows(c)==[]
    assert positions(c)==[]
