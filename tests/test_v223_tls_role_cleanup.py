"""Disposable TLS runner must revoke only the role it created, even on failure."""
import pytest
from scripts import ci_cinema_pg_validated_tls_e2e_v223 as runner

@pytest.mark.parametrize('failure', [False, True])
def test_owned_role_is_removed_after_e2e(monkeypatch, failure):
    monkeypatch.setenv('JW_CINEMA_PG_DISPOSABLE', '1')
    monkeypatch.setenv('PGHOST', '127.0.0.1')
    monkeypatch.setenv('JW_PG_CI_TLS_CA', '/synthetic/ca.pem')
    monkeypatch.delenv('JW_CINEMA_KEEP_DB', raising=False)
    statements = []
    class Connection:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def execute(self, statement): statements.append(statement.as_string())
    monkeypatch.setattr(runner.psycopg, 'connect', lambda **kw: Connection())
    def execute():
        runner._role_created = True
        if failure: raise RuntimeError('synthetic TLS failure')
        return 0
    monkeypatch.setattr(runner.e2e, 'main', execute)
    monkeypatch.setattr(runner, '_role_created', False, raising=False)
    if failure:
        with pytest.raises(RuntimeError, match='synthetic TLS failure'): runner.main()
    else:
        assert runner.main() == 0
    assert statements == ['DROP ROLE "jw_ci_v223_tls_business"']
    assert runner._role_created is False


def test_preexisting_role_is_never_removed(monkeypatch):
    monkeypatch.setenv('JW_CINEMA_PG_DISPOSABLE', '1')
    monkeypatch.setenv('PGHOST', '127.0.0.1')
    monkeypatch.setenv('JW_PG_CI_TLS_CA', '/synthetic/ca.pem')
    monkeypatch.delenv('JW_CINEMA_KEEP_DB', raising=False)
    monkeypatch.setattr(runner, '_role_created', False, raising=False)
    def collision(): raise RuntimeError('preexisting role collision')
    monkeypatch.setattr(runner.e2e, 'main', collision)
    def forbidden(**kw): raise AssertionError('preexisting role must be preserved')
    monkeypatch.setattr(runner.psycopg, 'connect', forbidden)
    with pytest.raises(RuntimeError, match='preexisting role collision'): runner.main()
