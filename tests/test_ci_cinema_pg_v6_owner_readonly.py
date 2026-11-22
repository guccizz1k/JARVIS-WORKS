from unittest.mock import patch
import pytest
from scripts import ci_cinema_pg_v6_owner_readonly as v

def test_manifest_exact():
    assert len(v.ALLOWED)==13
    assert 'scripts/pg_backup_v223.py' not in v.ALLOWED
    assert 'scripts/ci_cinema_pg_v223_codespace_run.py' not in v.ALLOWED

def test_reject_non_codespace():
    with patch.dict('os.environ',{'CODESPACES':'false'}):
        with pytest.raises(v.Blocked,match='codespace_required'):
            v.verify_sources()

def test_reject_wrong_branch():
    with patch.dict('os.environ',{'CODESPACES':'true'}),patch.object(v,'git',return_value='wrong'):
        with pytest.raises(v.Blocked,match='branch_mismatch'):
            v.verify_sources()

def test_reject_remote_mismatch():
    def fake(*args):
        if args[:2]==('branch','--show-current'):return ''
        if args[:2]==('rev-parse','HEAD'):return 'head'
        return 'remote'
    with patch.dict('os.environ',{'CODESPACES':'true'}),patch.object(v,'git',side_effect=fake):
        with pytest.raises(v.Blocked,match='remote_sha_mismatch'):
            v.verify_sources()

def test_main_blocks_without_running_backup():
    with patch.object(v,'check',side_effect=v.Blocked('blocked')):
        assert v.main()==2
