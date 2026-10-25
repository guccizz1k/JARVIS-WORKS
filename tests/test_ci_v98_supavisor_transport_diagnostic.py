"""V9.8 no-password redacted preflight guards."""
from scripts import ci_v98_supavisor_transport_diagnostic as x
from scripts import ci_v97_supavisor_restricted_auth as gate

def test_missing_secret_fails_closed():
    out=x.diagnose({"JW_ENV":"review","JW_V97_LIVE_ACK":gate.ACK})
    assert out["status"]=="BLOCKED"

def test_production_fails_closed():
    assert x.diagnose({"JW_ENV":"production"})["status"]=="BLOCKED"

def test_separate_tls_hops_with_mock_readonly():
    class Conn:
        def __init__(self,u):self.user=u;self.info=self
        def get_parameters(self):return {"sslmode":"verify-full",
            "sslrootcert":str(gate.CA),"host":gate.POOLER_HOST,"port":"5432"}
        def cursor(self):return self
        def __enter__(self):return self
        def __exit__(self,*a):return False
        def execute(self,q):assert q.startswith(("SET TRANSACTION","SELECT session_user"))
        def fetchone(self):return (self.user,self.user,17,False)
        def rollback(self):pass
        def close(self):pass
    def conn(dsn):
        return Conn("jw_auth_gateway_v90" if "jw_auth" in dsn else "jw_trade_gateway_v90")
    def dsn(kind):
        return "postgresql://"+gate.USERS[kind]+":fake-only@"+gate.POOLER_HOST+":5432/postgres?sslmode=verify-full"
    e={"JW_ENV":"review","JW_V97_LIVE_ACK":gate.ACK,
       "JW_V97_AUTH_DSN":dsn("auth"),"JW_V97_TRADE_DSN":dsn("trade")}
    out=x.diagnose(e,conn)
    assert out["status"]=="DIAGNOSED"
    assert out["roles"]["auth"]["postgres_17"] is True
    assert out["roles"]["trade"]["upstream_ssl"]=="FALSE"
    assert "fake-only" not in str(out)
