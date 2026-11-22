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
    with patch.object(live.integration,'install'),patch.object(live.owner,'run_live',side_effect=RuntimeError('abort')):
        with pytest.raises(RuntimeError):
            live.main()
    assert live.owner.preflight is original_preflight
    assert live.owner.expiry_value is original_expiry

def test_live_launcher_never_executes_without_owner_confirmation():
    with patch.object(live.integration,'install'),patch.object(live.owner,'run_live',return_value=2) as run:
        assert live.main()==2
        run.assert_called_once_with()
