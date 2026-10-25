"""No real PG operations or external connections in this test suite."""
import pytest
from scripts import jw_v113_ephemeral_pg_integration as gate

class NoConnect:
    def connect(self,*args,**kwargs):
        raise AssertionError('preflight unexpectedly connected')

def test_requires_explicit_isolated_ack(monkeypatch):
    monkeypatch.delenv('JW_PG_CI_ALLOW',raising=False)
    with pytest.raises(RuntimeError,match='CI_DISPOSABLE_ACK_REQUIRED'):
        gate._preflight(NoConnect(),lambda d:{},'postgresql://user:fake@localhost/anything')

@pytest.mark.parametrize("change",[
 {'host':'external.example'},
 {'dbname':'business'},
 {'user':'business_admin'},
 {'port':'5433'},
 {'sslmode':'disable'},
 {'connect_timeout':'60'},
 {'host':'localhost'},
])
def test_preflight_rejects_shared_network_and_unsafe_settings(monkeypatch,change):
    monkeypatch.setenv('JW_PG_CI_ALLOW','ONLY_EPHEMERAL_LOCAL_DATABASE')
    info={'host':'127.0.0.1','port':'5432','dbname':'postgres','user':'postgres',
          'connect_timeout':'5'}
    info.update(change)
    with pytest.raises(RuntimeError,match='REFUSE_ANY_NONLOCAL_OR_NONROOT_DATABASE'):
        gate._preflight(NoConnect(),lambda _:info,'fixture')

def test_manual_pg_contract_marks_unrun_live_work():
    import inspect
    source=inspect.getsource(gate._prove)
    assert "2_render_instances':'NOT_RUN'" in source
    assert 'concurrent_skip_locked' in source
    assert 'rollback_no_notify' in source
    assert 'actor_org_check' in source
