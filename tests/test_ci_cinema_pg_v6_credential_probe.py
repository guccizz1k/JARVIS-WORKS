import pytest
from scripts import ci_cinema_pg_v6_credential_probe as p

class FakeConn:
    def __init__(self,verifier):
        self.verifier=verifier
    def execute(self,sql):
        assert 'pg_authid' in sql
        return self
    def fetchone(self):
        return (self.verifier,) if self.verifier is not None else None

VERIFIER='SCRAM-SHA-256$4096:mockSalt$mockKey:mockServer'

def test_matching_server_verifier():
    assert p.verifier_matches(FakeConn(VERIFIER),VERIFIER)

def test_different_server_verifier_fails_closed():
    with pytest.raises(p.CredentialBlocked,match='server_scram_mismatch'):
        p.verifier_matches(FakeConn(VERIFIER+'changed'),VERIFIER)

def test_missing_or_non_scram_verifier_fails_closed():
    for value in (None,'md5hash',''):
        with pytest.raises(p.CredentialBlocked,match='server_scram_unavailable'):
            p.verifier_matches(FakeConn(value),VERIFIER)

def test_diagnostics_do_not_emit_credentials(capsys,monkeypatch):
    def fail():
        raise p.CredentialBlocked('server_scram_mismatch')
    monkeypatch.setattr(p,'check',fail)
    assert p.main()==2
    out=capsys.readouterr().out
    assert 'server_scram_mismatch' in out
    assert VERIFIER not in out
    assert 'NO_ROLE_CHANGE_NO_BACKUP' in out
