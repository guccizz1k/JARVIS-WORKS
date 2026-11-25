"""Interruption negative tests for the V22.3 backup tool on DISPOSABLE, SYNTHETIC PostgreSQL 17 only (issue #140, approval 4).

What it proves (each case runs the real ``python -m scripts.pg_backup_v223 run`` as a child process against two throw-away clusters):
  C0  control        an uninterrupted run over a large synthetic table completes (so the interruptions below are not caused by size/timeouts);
  C1  dump           the pg_dump backend is terminated with pg_terminate_backend while it copies the big table;
  C2  snapshot       the snapshot-holding source session is terminated during the signature scan;
  C3  restore COPY   the pg_restore backend is terminated while it loads the big table;
  C4  restore index  the pg_restore backend is terminated while it builds an index;
  C5  SIGTERM        the backup process itself receives SIGTERM during pg_dump.
For every interruption: the kill must really have happened, the exit code is nonzero, nothing is printed on stdout (no summary, no verdict,
so no success claim), stderr carries a FAIL_V223_* code, no plaintext dump / decrypted copy / negative-test copy is left, no file carries the
plain pg_dump magic, every encrypted file is 0600 in a 0700 directory, no jw_v223_* database is left on the restore cluster, no tool session
is left, and neither the key nor a password appears in any output.

NEVER connect this to a real database: it needs JW_PG_CI_ALLOW and JW_PG_CI_SYNTHETIC and refuses a non-local source.
It never kills a Supabase connection: the clusters are the two postgres:17 service containers of the CI job.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from tempfile import TemporaryDirectory

import psycopg

from scripts import pg_backup_v223 as pb
from scripts.pg_backup_v223 import BackupError, guard_target, parse_dsn

BIG_ROWS = 1_200_000          # below pb.MAX_TABLE_ROWS (2,000,000) so the control run is allowed
PLAIN_MAGIC = b'PGDMP'
PLAIN_SUFFIXES = ('.dump', '.back', '.half', '.out', '.wrongkey', '.tamper_rejected', '.truncation_rejected')

# Each query returns the pid(s) of the backend to terminate, and is built to match only the tool's own session.
Q_DUMP = ("SELECT pid FROM pg_stat_activity WHERE application_name='pg_dump' AND state='active' "
          "AND query ILIKE 'COPY jw_dev.big%' AND pid <> pg_backend_pid()")
Q_SNAPSHOT = ("SELECT pid FROM pg_stat_activity WHERE backend_type='client backend' AND application_name='' "
              "AND state='active' AND xact_start IS NOT NULL AND query ILIKE '%md5(t::text)%' "
              "AND pid <> pg_backend_pid()")
Q_RESTORE_COPY = ("SELECT pid FROM pg_stat_activity WHERE application_name='pg_restore' AND state='active' "
                  "AND datname LIKE 'jw_v223_%' AND query ILIKE 'COPY jw_dev.big%' AND pid <> pg_backend_pid()")
Q_RESTORE_INDEX = ("SELECT pid FROM pg_stat_activity WHERE application_name='pg_restore' AND state='active' "
                   "AND datname LIKE 'jw_v223_%' AND query ILIKE 'CREATE INDEX%' AND pid <> pg_backend_pid()")
Q_TOOL_SESSIONS = ("SELECT count(*) FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND "
                   "(application_name IN ('pg_dump','pg_restore') OR datname LIKE 'jw_v223_%')")


class Killer(threading.Thread):
    """Polls pg_stat_activity until ``query`` matches, then runs ``action`` once on every matching pid."""

    def __init__(self, dsn: str, query: str, action, deadline_s: int = 300) -> None:
        super().__init__(daemon=True)
        self.dsn, self.query, self.action = dsn, query, action
        self.deadline = time.monotonic() + deadline_s
        self.hits = 0
        self.halt = threading.Event()

    def run(self) -> None:
        with psycopg.connect(self.dsn, autocommit=True) as conn:
            while not self.halt.is_set() and time.monotonic() < self.deadline:
                pids = [r[0] for r in conn.execute(self.query).fetchall()]
                if pids:
                    for pid in pids:
                        self.action(conn, pid)
                        self.hits += 1
                    return
                time.sleep(0.004)


def terminate_backend(conn, pid) -> None:
    conn.execute('SELECT pg_terminate_backend(%s)', (pid,))


def tree_problems(root: Path) -> list:
    """Plaintext or permission problems anywhere below ``root`` (labels only, never contents)."""
    bad = []
    for path in [root, *root.rglob('*')]:
        mode = path.stat().st_mode & 0o777
        if path.is_dir():
            if mode != 0o700 and path != root:
                bad.append(f'dir_mode_{oct(mode)}')
            continue
        if path.suffix in PLAIN_SUFFIXES:
            bad.append(f'plain_suffix:{path.suffix}')
        with open(path, 'rb') as fh:
            if fh.read(len(PLAIN_MAGIC)) == PLAIN_MAGIC:
                bad.append('plain_pg_dump_magic')
        if path.suffix == '.jwpgbk' and mode != 0o600:
            bad.append(f'encrypted_mode_{oct(mode)}')
    return bad


def leftover_dbs(dsn: str) -> list:
    with psycopg.connect(dsn, autocommit=True) as conn:
        return [r[0] for r in conn.execute("SELECT datname FROM pg_database WHERE datname LIKE 'jw_v223_%'")]


def tool_sessions_gone(dsns, wait_s: int = 60) -> bool:
    end = time.monotonic() + wait_s
    while time.monotonic() < end:
        counts = []
        for dsn in dsns:
            with psycopg.connect(dsn, autocommit=True) as conn:
                counts.append(conn.execute(Q_TOOL_SESSIONS).fetchone()[0])
        if not any(counts):
            return True
        time.sleep(1)
    return False


def run_tool(env: dict, killer: Killer | None, signal_proc: bool) -> tuple:
    """Run the backup CLI; optionally have the killer deliver SIGTERM to the process itself. Returns (rc, out, err)."""
    proc = subprocess.Popen([sys.executable, '-m', 'scripts.pg_backup_v223', 'run'], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if killer is not None:
        if signal_proc:
            killer.action = lambda conn, pid: proc.send_signal(signal.SIGTERM)
        killer.start()
    try:
        out, err = proc.communicate(timeout=480)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        raise AssertionError('tool did not finish within 480s (hang)')
    finally:
        if killer is not None:
            killer.halt.set()
            killer.join(timeout=10)
    return proc.returncode, out, err


def main() -> int:
    source = os.environ.get('JW_PG_SOURCE_DSN', '')
    target = os.environ.get('JW_PG_TARGET_ADMIN_DSN', '')
    if os.environ.get('JW_PG_CI_ALLOW') != 'ONLY_EPHEMERAL_LOCAL_DATABASE' or os.environ.get('JW_PG_CI_SYNTHETIC') != '1':
        raise BackupError('BLOCKED_V223_SYNTHETIC_CI_IDENTITY_REQUIRED')
    src, tgt = parse_dsn(source), parse_dsn(target)
    if src['host'] not in ('127.0.0.1', 'localhost', '::1'):
        raise BackupError('BLOCKED_V223_SYNTHETIC_SOURCE_MUST_BE_LOCAL')
    guard_target(target, source)
    if (src['host'], src['port']) == (tgt['host'], tgt['port']):
        raise BackupError('BLOCKED_V223_INDEPENDENT_CLUSTER_REQUIRED')

    key = base64.urlsafe_b64encode(os.urandom(32)).decode('ascii')
    token = secrets.token_hex(16)
    secret_values = [key, src['password'], tgt['password'], token]
    with psycopg.connect(source, autocommit=True) as conn:
        if conn.execute("SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='jw_dev')").fetchone()[0]:
            raise BackupError('BLOCKED_V223_SYNTHETIC_SCHEMA_ALREADY_PRESENT')
        conn.execute('CREATE SCHEMA jw_dev')
        conn.execute('CREATE TABLE jw_dev.invoice(id bigint PRIMARY KEY, company text NOT NULL)')
        conn.execute("INSERT INTO jw_dev.invoice VALUES (1,'synthetic-a'),(2,'synthetic-b')")
        conn.execute('CREATE TABLE jw_dev.big(id bigint PRIMARY KEY, v text NOT NULL)')
        conn.execute("INSERT INTO jw_dev.big SELECT g, md5(g::text)||md5((g*7)::text) FROM generate_series(1,%s) g", (BIG_ROWS,))
        conn.execute('CREATE INDEX big_v_idx ON jw_dev.big(v)')
    pb.provision_ephemeral_marker(target, token)
    print(f'SETUP_OK synthetic source {BIG_ROWS} rows; restore cluster marked (token not printed)')

    results: list = []

    def record(label: str, problems: list) -> None:
        ok = not problems
        results.append((label, ok))
        print(('CASE_PASS ' if ok else 'CASE_FAIL ') + label + ('' if ok else ' :: ' + '; '.join(problems)))

    def tool_env(tmp: str) -> dict:
        return {**os.environ, 'TMPDIR': tmp, 'JW_PG_BACKUP_KEY': key, 'JW_PG_TARGET_EPHEMERAL_TOKEN': token,
                'JW_PG_SOURCE_DSN': source, 'JW_PG_TARGET_ADMIN_DSN': target, 'JW_PG_SCHEMA': 'jw_dev',
                'JW_PG_REAL_SOURCE': ''}

    def common_checks(tmp: str, rc: int, out: str, err: str) -> list:
        problems = []
        if any(s and s in (out + err) for s in secret_values):
            problems.append('secret_or_key_in_output')
        problems += tree_problems(Path(tmp))
        left = leftover_dbs(target)
        if left:
            problems.append(f'leftover_databases:{len(left)}')
        if not tool_sessions_gone([source, target]):
            problems.append('tool_sessions_still_open')
        return problems

    # C0 control: nothing is interrupted.
    with TemporaryDirectory(prefix='jw_v223_intr_', dir='/tmp') as tmp:
        rc, out, err = run_tool(tool_env(tmp), None, False)
        problems = common_checks(tmp, rc, out, err)
        try:
            summary = json.loads(out)
            for field in ('snapshot_consistent', 'restore_verified', 'decrypt_sha256_matches', 'tamper_rejected',
                          'wrong_key_rejected', 'truncation_rejected', 'partial_dump_restore_rejected'):
                if summary.get(field) is not True:
                    problems.append(f'control_field_{field}')
            if summary.get('signature_mismatches') != [] or summary.get('tables') != 2:
                problems.append('control_signature_or_tables')
            if not str(summary.get('verdict', '')).startswith('NOT_P0_1_PASS'):
                problems.append('control_verdict')
            if not list(Path(tmp).rglob('*.jwpgbk')):
                problems.append('control_no_encrypted_file')
        except ValueError:
            problems.append('control_no_json_summary')
        if rc != 1:      # synthetic source -> verdict is never PASS -> exit code 1 by design
            problems.append(f'control_rc_{rc}')
        record('C0 control run (uninterrupted, large table)', problems)

    def interrupted(label: str, dsn: str, query: str, signal_proc: bool = False) -> None:
        with TemporaryDirectory(prefix='jw_v223_intr_', dir='/tmp') as tmp:
            killer = Killer(dsn, query, terminate_backend)
            try:
                rc, out, err = run_tool(tool_env(tmp), killer, signal_proc)
            except AssertionError as exc:
                record(label, [str(exc)])
                return
            problems = []
            if killer.hits < 1:
                problems.append('interruption_did_not_happen_test_invalid')
            if rc == 0:
                problems.append('exit_code_zero')
            if out.strip():
                problems.append('stdout_not_empty_possible_success_claim')
            if not err.strip().startswith('FAIL_V223_'):
                problems.append('stderr_missing_FAIL_V223_code')
            problems += common_checks(tmp, rc, out, err)
            record(label + f' (rc={rc}, code={err.strip()[:60]!r})', problems)

    try:
        interrupted('C1 pg_dump backend terminated during COPY', source, Q_DUMP)
        interrupted('C2 snapshot session terminated during signature scan', source, Q_SNAPSHOT)
        interrupted('C3 pg_restore backend terminated during COPY', target, Q_RESTORE_COPY)
        interrupted('C4 pg_restore backend terminated during CREATE INDEX', target, Q_RESTORE_INDEX)
        interrupted('C5 SIGTERM to the backup process during pg_dump', source, Q_DUMP, signal_proc=True)
    finally:
        with psycopg.connect(source, autocommit=True) as conn:
            conn.execute('DROP SCHEMA IF EXISTS jw_dev CASCADE')

    failed = [label for label, ok in results if not ok]
    print(f'SUMMARY: {len(results)} cases, {len(failed)} failed')
    if failed:
        return 1
    print('PASS_V223_SYNTHETIC_INTERRUPTION_NEGATIVE_TESTS')
    print('LIMIT_V223_SYNTHETIC_PG17_ONLY_NOT_REAL_SUPABASE_BACKUP')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except BackupError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
    except Exception as exc:
        print('FAIL_V223_INTERRUPT_GATE_' + type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
