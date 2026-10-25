"""V8.7 standalone non-secret connection test. No real DB required."""
import json
import pytest

from app.pg_connection_gate_v87 import check_two_connections, LOGIN_PROBE, ROLE_PROBE


class Cursor:
    def __init__(self, kind, behavior=None):
        self.kind, self.behavior = kind, behavior or {}
        self.role = False
        self.queries = []
        self.which = None
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def execute(self, q):
        self.queries.append(q)
        if 'SET LOCAL ROLE' in q: self.role = True
        if q == LOGIN_PROBE: self.which = 'login'
        if q == ROLE_PROBE: self.which = 'role'
    def fetchone(self):
        if self.which == 'login':
            s = ('jw_auth_login_v86' if self.kind == 'auth' else 'jw_trade_login_v86')
            return (s,s,self.behavior.get('admin',False),
                self.behavior.get('can_auth',self.kind=='auth'),
                self.behavior.get('can_trade',self.kind=='trade'),
                self.behavior.get('direct',False),
                self.behavior.get('ssl',True),self.behavior.get('major',17),
                self.behavior.get('canlogin',True))
        if self.which == 'role':
            return ('jw_auth_stage_v85' if self.kind == 'auth' else 'jw_app_dev',
                self.behavior.get('read_users',False),False,
                self.behavior.get('read_customers',self.kind=='trade'),False,
                self.kind=='auth',self.kind=='trade')
        return None


class Connection:
    def __init__(self, kind, behavior=None):
        self.cur = Cursor(kind,behavior)
        self.closed = False
        self.rolled_back = False
    def cursor(self):return self.cur
    def rollback(self):self.rolled_back=True
    def close(self):self.closed=True


def env(**kwargs):
    return {'JW_PG_V87_CONNECT_GATE':'ISOLATED_DEV_ONLY','JW_ENV':'development',
            'JW_PG_AUTH_STAGE_DSN':'auth_secret','JW_PG_STAGE_DSN':'trade_secret',**kwargs}


def test_missing_opt_in_fails_closed():
    assert check_two_connections(env={})['result']=='BLOCKED'
    assert check_two_connections(env=env(JW_ENV='production'))['result']=='BLOCKED'
    assert check_two_connections(env=env(JW_INSECURE_LOCAL_DEV='1'))['result']=='BLOCKED'


def test_missing_or_reused_dsn_fails_closed():
    assert check_two_connections(env=env(JW_PG_STAGE_DSN=''))['result']=='BLOCKED'
    assert check_two_connections(env=env(JW_PG_STAGE_DSN='auth_secret'))['result']=='BLOCKED'


def test_read_only_role_switch_both_connections():
    dbs=[]; opts=[]
    def connector(dsn,**kw):
        opts.append(kw)
        c=Connection('auth' if dsn=='auth_secret' else 'trade');dbs.append(c);return c
    result=check_two_connections(connector=connector,env=env())
    assert result['result']=='PASS' and result['production_cutover'] is False
    assert len(dbs)==2 and all(d.closed and d.rolled_back for d in dbs)
    assert all('SET TRANSACTION READ ONLY' in d.cur.queries for d in dbs)
    assert all('SET LOCAL ROLE' in ' '.join(d.cur.queries) for d in dbs)
    assert all(k=={'sslmode':'verify-full','connect_timeout':5} for k in opts)
    assert 'secret' not in json.dumps(result)


@pytest.mark.parametrize('behavior',[{'admin':True},{'direct':True},{'ssl':False},
                                     {'can_trade':True},{'can_auth':False},
                                     {'read_users':True},{'major':16},
                                     {'canlogin':False}])
def test_privilege_or_tls_violation_fails_closed(behavior):
    def connector(dsn,**kw):return Connection('auth' if dsn=='auth_secret' else 'trade',
                                              behavior if dsn=='auth_secret' else None)
    assert check_two_connections(connector=connector,env=env())['result']=='BLOCKED'


def test_network_error_does_not_leak_dsn():
    def connector(*args,**kwargs):raise RuntimeError('postgresql://auth:secret-password@db')
    res=check_two_connections(connector=connector,env=env())
    assert res['result']=='BLOCKED'
    assert 'secret-password' not in json.dumps(res)


def test_db_rejection_does_not_leak_dsn():
    def connector(*args,**kwargs):
        c=Connection('auth' if args[0]=='auth_secret' else 'trade')
        def explode(q):raise RuntimeError('token=security-secret')
        c.cur.execute=explode
        return c
    res=check_two_connections(connector=connector,env=env())
    assert res['result']=='BLOCKED' and 'security-secret' not in str(res)


def test_gate_is_query_only():
    q=LOGIN_PROBE+' '+ROLE_PROBE
    assert 'FROM jw_dev.users u' not in q
    assert 'COPY ' not in q and 'DELETE ' not in q and 'UPDATE ' not in q

def test_supavisor_backend_ssl_exception_does_not_change_default_v87_gate():
    from app.pg_connection_gate_v87 import _check_one
    class C:
        def __init__(self):self.mode=None
        def __enter__(self):return self
        def __exit__(self,*a):return False
        def execute(self,q):
            if q==LOGIN_PROBE:self.mode="login"
            elif q==ROLE_PROBE:self.mode="role"
        def fetchone(self):
            if self.mode=="login":
                return ("jw_auth_gateway_v90","jw_auth_gateway_v90",False,True,
                        False,False,False,17,True)
            return ("jw_auth_stage_v85",False,False,False,False,True,False)
    class Conn:
        def cursor(self):return C()
    assert "tls_or_postgres_mismatch" in _check_one(Conn(),kind="auth")[1]
    assert _check_one(Conn(),kind="auth",trusted_pooler_tls=True)[1]==[]
