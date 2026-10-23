"""Deterministic concurrency model for V9.0 cursor commit inversion.

These simulate transaction lock semantics; they are NOT independent PostgreSQL
connections and do not establish SQL function E2E correctness.
"""
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from threading import Event, Lock


class CommitModel:
    def __init__(self, *, serialize):
        self.serialize = serialize
        self.seq = 0
        self.seq_lock = Lock()
        self.chat_locks = defaultdict(Lock)
        self.rows = []
        self.rows_lock = Lock()

    def write(self, chat, started: Event, release: Event):
        lock = self.chat_locks[chat] if self.serialize else Lock()
        with lock:
            with self.seq_lock:
                self.seq += 1
                cursor = self.seq
            started.set()
            if not release.wait(timeout=4):
                raise TimeoutError("Test writer was never released")
            with self.rows_lock:
                self.rows.append((chat, cursor))
        return cursor

    def seen_after(self, chat, cursor):
        with self.rows_lock:
            return sorted(seq for c, seq in self.rows if c == chat and seq > cursor)


def test_reproduces_original_commit_order_bug():
    m = CommitModel(serialize=False)
    a_started, a_finish, b_started, b_finish = Event(), Event(), Event(), Event()
    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(m.write, 'ab', a_started, a_finish)
        assert a_started.wait(timeout=2)
        b = pool.submit(m.write, 'ab', b_started, b_finish)
        assert b_started.wait(timeout=2)
        b_finish.set()
        assert b.result(timeout=2) == 2
        assert m.seen_after('ab', 0) == [2]
        a_finish.set()
        assert a.result(timeout=2) == 1
    # Receiver cursor=2 has permanently skipped the delayed commit of cursor=1.
    assert m.seen_after('ab', 2) == []
    assert sorted(m.rows) == [('ab', 1), ('ab', 2)]


def test_per_chat_transaction_lock_prevents_commit_inversion():
    m = CommitModel(serialize=True)
    a_started, a_finish, b_started, b_finish = Event(), Event(), Event(), Event()
    b_finish.set()
    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(m.write, 'ab', a_started, a_finish)
        assert a_started.wait(timeout=2)
        b = pool.submit(m.write, 'ab', b_started, b_finish)
        # While A has lock and has not committed, B must not allocate its seq.
        assert not b_started.wait(timeout=.07)
        assert m.seen_after('ab', 0) == []
        a_finish.set()
        assert a.result(timeout=2) == 1
        assert b_started.wait(timeout=2)
        assert b.result(timeout=2) == 2
    assert m.seen_after('ab', 0) == [1, 2]
    assert m.seen_after('ab', 1) == [2]


def test_other_conversations_remain_independent():
    m = CommitModel(serialize=True)
    a_started, a_finish, b_started, b_finish = Event(), Event(), Event(), Event()
    b_finish.set()
    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(m.write, 'ab', a_started, a_finish)
        assert a_started.wait(timeout=2)
        b = pool.submit(m.write, 'cd', b_started, b_finish)
        assert b_started.wait(timeout=2)
        assert b.result(timeout=2) == 2
        assert m.seen_after('cd', 0) == [2]
        a_finish.set()
        assert a.result(timeout=2) == 1
    assert m.seen_after('ab', 0) == [1]


def test_edit_timestamps_are_strict_in_same_chat_even_if_clock_stalls():
    # A formal model of greatest(now, max(previous edit time) + 1 microsecond).
    from datetime import datetime, timedelta, timezone
    frozen = datetime(2026, 10, 23, 22, 0, tzinfo=timezone.utc)
    timestamps = []
    for _ in range(40):
        event_at = max(frozen, timestamps[-1] + timedelta(microseconds=1)) if timestamps else frozen
        timestamps.append(event_at)
    assert len(timestamps) == len(set(timestamps))
    assert all(a < b for a, b in zip(timestamps, timestamps[1:]))
