from unittest.mock import patch
from urllib.parse import urlsplit, unquote
import pytest
from scripts import ci_cinema_pg_v6_target_binding as b

LEGACY = {'JW_PG_TARGET_ADMIN_DSN':'private',
          'JW_PG_TARGET_EPHEMERAL_TOKEN':'t'*48,
          'JW_PG_CI_ALLOW':'ONLY_EPHEMERAL_LOCAL_DATABASE'}
PARSED = {'host':'127.0.0.1','port':'55432','dbname':'postgres',
          'user':'postgres','password':'p@ss:/word'}

def bind(cfg=None, parsed=None):
    with patch.object(b,'read_private_target',return_value=LEGACY if cfg is None else cfg), \
         patch.object(b,'parse_dsn',return_value=PARSED if parsed is None else parsed), \
         patch.object(b.gate,'prove_target',return_value=True) as proof:
        result=b.checked_target_config(None,None)
        proof.assert_called_once()
        return result

def test_binds_exact_port_and_password():
    target=bind()
    u=urlsplit(target['JW_PG_TARGET_ADMIN_DSN'])
    assert u.hostname=='127.0.0.1' and u.port==55433
    assert unquote(u.password)=='p@ss:/word'
    assert target['JW_PG_TARGET_EPHEMERAL_TOKEN']=='t'*48

def test_keeps_original_env_unchanged():
    env={'SAFE':'yes','JW_PG_TARGET_ADMIN_DSN':'old'}
    with patch.object(b,'checked_target_config',return_value={'JW_PG_TARGET_ADMIN_DSN':'new'}):
        child=b.bind_backup_environment(env,None,None)
    assert env['JW_PG_TARGET_ADMIN_DSN']=='old'
    assert child['JW_PG_TARGET_ADMIN_DSN']=='new'

@pytest.mark.parametrize('key,value',[
    ('host','remote'),('port','55433'),('dbname','other'),('user','other')
])
def test_reject_legacy_contract_change(key,value):
    p=dict(PARSED);p[key]=value
    with patch.object(b,'read_private_target',return_value=LEGACY), \
         patch.object(b,'parse_dsn',return_value=p), \
         patch.object(b.gate,'prove_target') as proof:
        with pytest.raises(b.BindingBlocked): b.checked_target_config(None,None)
        proof.assert_not_called()

def test_reject_disabled_guard():
    c=dict(LEGACY);c['JW_PG_CI_ALLOW']='disabled'
    with patch.object(b,'read_private_target',return_value=c), \
         patch.object(b,'parse_dsn',return_value=PARSED), \
         patch.object(b.gate,'prove_target') as proof:
        with pytest.raises(b.BindingBlocked): b.checked_target_config(None,None)
        proof.assert_not_called()

def test_reject_invalid_environment():
    with pytest.raises(b.BindingBlocked): b.bind_backup_environment(None,None,None)

def test_gate_failure_propagates():
    with patch.object(b,'read_private_target',return_value=LEGACY), \
         patch.object(b,'parse_dsn',return_value=PARSED), \
         patch.object(b.gate,'prove_target',side_effect=b.gate.TargetBlocked('mismatch')):
        with pytest.raises(b.gate.TargetBlocked): b.checked_target_config(None,None)
