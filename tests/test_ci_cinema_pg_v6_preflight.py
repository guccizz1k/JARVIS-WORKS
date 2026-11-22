from unittest.mock import patch
import pytest
from scripts import ci_cinema_pg_v6_preflight as p
from scripts import ci_cinema_pg_v6_owner_readonly as v

def test_checks_all_readonly_gates():
    calls=[]
    def fake(label):
        return lambda: calls.append(label)
    with patch.object(p.v6,'check',fake('source_target')), \
         patch.object(p.runner,'check_tools',fake('tools')), \
         patch.object(p.runner,'check_private_inputs',fake('private')), \
         patch.object(p,'load_key',fake('key')), \
         patch.object(p,'load_dashboard_ca',fake('ca')), \
         patch.object(p,'read_password_file',fake('auth')), \
         patch.object(p.owner,'check_live_admin_state',fake('admin')):
        assert p.check() is True
    assert calls==['source_target','tools','private','key','ca','auth','admin']

def test_admin_failure_is_blocked_without_leaking():
    with patch.object(p.v6,'check'), \
         patch.object(p.runner,'check_tools'), \
         patch.object(p.runner,'check_private_inputs'), \
         patch.object(p,'load_key'), \
         patch.object(p,'load_dashboard_ca'), \
         patch.object(p,'read_password_file'), \
         patch.object(p.owner,'check_live_admin_state',side_effect=RuntimeError('private secret')):
        with pytest.raises(v.Blocked,match='PREFLIGHT_ADMIN_READONLY') as exc:
            p.check()
    assert 'private secret' not in str(exc.value)

def test_main_fails_closed():
    with patch.object(p,'check',side_effect=v.Blocked('failed')):
        assert p.main()==2
