from datetime import datetime
from zoneinfo import ZoneInfo
from unittest.mock import patch
import pytest
from scripts import ci_cinema_pg_v6_owner_live as live
from scripts import ci_cinema_pg_v6_owner_readonly as readonly

KST=ZoneInfo('Asia/Seoul')

def test_approval_bounds():
    assert live.expiry_value(datetime(2026,11,22,20,25,tzinfo=KST))=='2026-11-23 01:00:00+09'
    with pytest.raises(readonly.Blocked):live.expiry_value(datetime(2026,11,23,1,0,tzinfo=KST))
    with pytest.raises(readonly.Blocked):live.expiry_value(datetime(2026,11,22,20,24,tzinfo=KST))

def test_preflight_calls_exact_v6_checks():
    with patch.object(live.checks,'check') as check:
        with patch.object(live,'expiry_value',return_value='bounded'):
            live.preflight()
    check.assert_called_once_with()

def test_original_functions_restored_on_failure():
    original_preflight=live.owner.preflight
    original_expiry=live.owner.expiry_value
    original_sql=live.owner.ROLE_SQL
    original_revoke=live.runner.stage_revoke
    with patch.object(live.integration,'install'),patch.object(live.owner,'run_live',side_effect=RuntimeError('abort')):
        with pytest.raises(RuntimeError):
            live.main()
    assert live.owner.preflight is original_preflight
    assert live.owner.expiry_value is original_expiry
    assert live.owner.ROLE_SQL==original_sql
    assert live.runner.stage_revoke is original_revoke

def test_live_launcher_never_executes_without_owner_confirmation():
    with patch.object(live.integration,'install'),patch.object(live.owner,'run_live',return_value=2) as run:
        assert live.main()==2
        run.assert_called_once_with()

def test_revocation_restores_expired_baseline():
    with patch.object(live.integration,'install'), \
         patch.object(live.runner,'stage_revoke',return_value={'revoke':'applied'}) as original, \
         patch.object(live.role_expiry,'restore_expired',return_value='EXPIRY_RESTORED') as expire, \
         patch.object(live.owner,'run_live',side_effect=lambda: live.runner.stage_revoke()):
        assert live.main()=={'revoke':'applied'}
        original.assert_called_once()
        expire.assert_called_once()
