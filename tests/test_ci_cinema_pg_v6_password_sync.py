"""Negative, approval and least-privilege tests for development SCRAM sync."""
from datetime import datetime
from io import StringIO
from unittest.mock import patch
from zoneinfo import ZoneInfo
import pytest
from scripts import ci_cinema_pg_v6_password_sync as sync

KST=ZoneInfo('Asia/Seoul')

class FakeInput(StringIO):
    def __init__(self, text, tty=True):
        super().__init__(text)
        self.tty=tty
    def isatty(self):
        return self.tty

class FakeSQL:
    class SQL:
        def __init__(self,template):
            self.template=template
        def format(self,*args):
            return self.template,args
    class Identifier:
        def __init__(self,value):
            self.value=value
    class Literal:
        def __init__(self,value):
            self.value=value

class FakeConn:
    def __init__(self):
        self.executed=[]
    def execute(self,query):
        self.executed.append(query)

@pytest.mark.parametrize('at,valid',[
    (datetime(2026,11,22,20,25,tzinfo=KST),True),
    (datetime(2026,11,22,23,59,tzinfo=KST),True),
    (datetime(2026,11,23,0,59,59,tzinfo=KST),True),
    (datetime(2026,11,23,1,0,tzinfo=KST),False),
    (datetime(2026,11,22,20,24,tzinfo=KST),False),
])
def test_window(at,valid):
    if valid:
        assert sync.check_window(at) is None
    else:
        with pytest.raises(sync.SyncBlocked,match='approval_window_closed'):
            sync.check_window(at)

def test_requires_real_tty():
    with pytest.raises(sync.SyncBlocked,match='owner_tty_required'):
        sync.confirm_owner(FakeInput(sync.CONFIRM,False),StringIO())

def test_exact_owner_confirmation_only():
    with pytest.raises(sync.SyncBlocked,match='owner_confirmation_required'):
        sync.confirm_owner(FakeInput('YES\n'),StringIO())
    assert sync.confirm_owner(FakeInput('RESET jw_backup_ro\n'),StringIO()) is None

def test_blocked_role_never_changes_verifier():
    db=FakeConn()
    with patch.object(sync,'verify_baseline',side_effect=sync.SyncBlocked('unsafe')):
        with pytest.raises(sync.SyncBlocked):
            sync.apply_password(db,'pw','SCRAM...',FakeSQL)
    assert db.executed==[]

def test_same_password_never_changes_verifier():
    db=FakeConn()
    with patch.object(sync,'verify_baseline'), \
         patch.object(sync,'verifier_matches',return_value=True):
        assert sync.apply_password(db,'pw','SCRAM...',FakeSQL)=='ALREADY_MATCH'
    assert db.executed==[]

def test_mismatch_changes_only_password_with_postwrite_proof():
    db=FakeConn()
    mismatch=sync.CredentialBlocked('server_scram_password_mismatch')
    with patch.object(sync,'verify_baseline') as guard, \
         patch.object(sync,'verifier_matches',side_effect=[mismatch,True]) as proof:
        assert sync.apply_password(db,'pw','SCRAM...',FakeSQL)=='PASSWORD_SYNCHRONIZED'
    assert len(db.executed)==1
    template,args=db.executed[0]
    assert template=='ALTER ROLE {} PASSWORD {}'
    assert args[0].value=='jw_backup_ro'
    assert args[1].value=='SCRAM...'
    assert guard.call_count==3
    assert proof.call_count==2

def test_unusable_server_verifier_cannot_be_overwritten():
    db=FakeConn()
    with patch.object(sync,'verify_baseline'), \
         patch.object(sync,'verifier_matches',side_effect=sync.CredentialBlocked('server_scram_unavailable')):
        with pytest.raises(sync.SyncBlocked,match='server_scram_unusable'):
            sync.apply_password(db,'pw','SCRAM...',FakeSQL)
    assert db.executed==[]

def test_postwrite_proof_failure_aborts_transaction():
    db=FakeConn()
    failure=sync.CredentialBlocked('server_scram_password_mismatch')
    with patch.object(sync,'verify_baseline'), \
         patch.object(sync,'verifier_matches',side_effect=[failure,failure]):
        with pytest.raises(sync.CredentialBlocked):
            sync.apply_password(db,'pw','SCRAM...',FakeSQL)
    assert len(db.executed)==1

def test_no_sensitive_data_echoed(capsys):
    with patch.object(sync,'execute_sync',side_effect=sync.SyncBlocked('local_verifier_invalid')):
        assert sync.main()==2
    assert capsys.readouterr().out==(
        'V6_PASSWORD_SYNC_BLOCKED local_verifier_invalid\n'
        'NO_BACKUP_NO_ROLE_ACTIVATION\n')

def test_expired_window_blocks_before_sources_and_secrets():
    with patch.dict('os.environ',{'CODESPACES':'true'}), \
         patch.object(sync,'check_window',side_effect=sync.SyncBlocked('approval_window_closed')), \
         patch.object(sync,'verify_sources') as verify:
        with pytest.raises(sync.SyncBlocked,match='approval_window_closed'):
            sync.execute_sync()
        verify.assert_not_called()
