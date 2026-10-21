import os
from pathlib import Path
from scripts import run_postgres_isolation_ci_v58 as wrapper

def test_chain_prior_failure_not_skipped(monkeypatch,capsys):
    from scripts import run_postgres_isolation_ci_v57 as parent
    from scripts import test_postgres_attachment_payload_v57 as preceding
    from scripts import test_postgres_receipt_identity_v58 as added
    for v in (54,55,56,57,58):monkeypatch.setenv(f'JW_PG_LAB_V{v}','ONLY_DISPOSABLE_LAB')
    monkeypatch.setenv('JW_PG_CI_ALLOW','ONLY_EPHEMERAL_LOCAL_DATABASE')
    monkeypatch.delenv('JW_ENV',raising=False)
    called=[]
    def synthetic_supervisor():return preceding.run()
    monkeypatch.setattr(parent,'main',synthetic_supervisor)
    monkeypatch.setattr(preceding,'run',lambda:called.append('preceding') or 1)
    monkeypatch.setattr(added,'run',lambda:called.append('added') or 0)
    assert wrapper.main()==1 and called==['preceding']
    assert preceding.run()==1

def test_chain_runs_new_only_after_pass(monkeypatch):
    from scripts import run_postgres_isolation_ci_v57 as parent
    from scripts import test_postgres_attachment_payload_v57 as preceding
    from scripts import test_postgres_receipt_identity_v58 as added
    for v in (54,55,56,57,58):monkeypatch.setenv(f'JW_PG_LAB_V{v}','ONLY_DISPOSABLE_LAB')
    monkeypatch.setenv('JW_PG_CI_ALLOW','ONLY_EPHEMERAL_LOCAL_DATABASE')
    monkeypatch.delenv('JW_ENV',raising=False)
    called=[]
    monkeypatch.setattr(parent,'main',lambda:preceding.run())
    monkeypatch.setattr(preceding,'run',lambda:called.append('preceding') or 0)
    monkeypatch.setattr(added,'run',lambda:called.append('new') or 1)
    assert wrapper.main()==1 and called==['preceding','new']

def test_environment_refused_before_prior(monkeypatch):
    from scripts import run_postgres_isolation_ci_v57 as parent
    monkeypatch.setenv('JW_ENV','PrOdUcTiOn')
    monkeypatch.setattr(parent,'main',lambda:1/0)
    assert wrapper.main()==2

def test_shell_order_preserved():
    content=Path('scripts/run_pg17_codespaces_v58.sh').read_text()
    assert 'V5_7 V5_8' in content
    assert 'JW_PG_LAB_V${v}=ONLY_DISPOSABLE_LAB' in content
    assert 'JW_PG_CI_ALLOW=ONLY_EPHEMERAL_LOCAL_DATABASE python3 -m scripts.test_mutation_snapshot_v54' in content
    assert 'JW_ENV:-' in content


def test_pg_entrypoint_without_pytest_available():
    """PG entrypoint must import without pytest or optional site packages."""
    import subprocess
    import sys
    result = subprocess.run(
        [sys.executable, '-S', '-c',
         'from scripts.test_postgres_receipt_identity_v58 import SCHEMA; '
         'import sqlite3; c=sqlite3.connect(":memory:"); '
         'c.executescript(SCHEMA); '
         'assert len(c.execute("SELECT name FROM sqlite_master WHERE type=\'table\'").fetchall()) >= 7'],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr


def test_shared_receipt_schema_same_for_local_and_pg():
    from scripts.receipt_schema_v58 import SCHEMA as shared
    from scripts.test_postgres_receipt_identity_v58 import SCHEMA as live
    from tests.test_pg_receipt_identity_v58 import SCHEMA as local
    assert shared == live == local
