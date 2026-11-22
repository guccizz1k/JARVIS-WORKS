import pytest
from scripts import ci_cinema_pg_v6_credential_probe as p
from scripts.ci_cinema_pg_q import make_verifier

class FakeConn:
    def __init__(self, verifier):
        self.verifier=verifier
    def execute(self, sql):
        assert 'pg_authid' in sql
        return self
    def fetchone(self):
        return (self.verifier,) if self.verifier is not None else None

PASSWORD='a'*64
SALT_A=b'a'*16
SALT_B=b'b'*16

def test_same_password_different_scram_salt_passes():
    server=make_verifier(PASSWORD,SALT_A)
    locally_generated=make_verifier(PASSWORD,SALT_B)
    assert server != locally_generated
    assert p.verifier_matches(FakeConn(server),PASSWORD)

def test_same_password_different_iteration_passes():
    server=make_verifier(PASSWORD,SALT_A,8192)
    assert p.verifier_matches(FakeConn(server),PASSWORD)

def test_different_password_fails_closed():
    server=make_verifier(PASSWORD,SALT_A)
    with pytest.raises(p.CredentialBlocked,match='server_scram_password_mismatch'):
        p.verifier_matches(FakeConn(server),'b'*64)

def test_missing_or_non_scram_verifier_fails_closed():
    for value in (None,'md5hash','', 'SCRAM-SHA-256$bad'):
        with pytest.raises(p.CredentialBlocked,match='server_scram_unavailable'):
            p.verifier_matches(FakeConn(value),PASSWORD)

@pytest.mark.parametrize('n',[4095,1000001])
def test_out_of_policy_iterations_fail_closed(n):
    server=make_verifier(PASSWORD,SALT_A)
    modified=server.replace('4096:',str(n)+':',1)
    with pytest.raises(p.CredentialBlocked,match='server_scram_iterations_out_of_policy'):
        p.verifier_matches(FakeConn(modified),PASSWORD)

def test_password_and_verifier_never_printed(capsys,monkeypatch):
    def fail():
        raise p.CredentialBlocked('server_scram_password_mismatch')
    monkeypatch.setattr(p,'check',fail)
    assert p.main()==2
    out=capsys.readouterr().out
    assert 'server_scram_password_mismatch' in out
    assert PASSWORD not in out
    assert make_verifier(PASSWORD,SALT_A) not in out
    assert 'NO_ROLE_CHANGE_NO_BACKUP' in out
