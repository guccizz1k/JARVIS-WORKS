"""No secrets, direct customer reads, role writes or insecure TLS allowed."""
from contextlib import contextmanager
import json
from scripts import ci_v98_supavisor_tls_legs as r
from scripts import ci_v97_supavisor_restricted_auth as v97

def env():
    return {"JW_ENV":"review","JW_V97_LIVE_ACK":v97.ACK,
            "JW_V97_TRADE_DSN":"fictional-trade",
            "JW_V97_AUTH_DSN":"fictional-auth"}

class FakeCursor:
    def __init__(self,backend_ssl=False):self.backend_ssl=backend_ssl
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def execute(self,q,params=None):
        assert q=="SET TRANSACTION READ ONLY" or (
            "pg_stat_ssl" in q and params in
            (("jw_trade_gateway_v90",),("jw_auth_gateway_v90",)))
    def fetchone(self):return (17,self.backend_ssl,True,True)
class FakeDB:
    def __init__(self,backend_ssl=False):self.c=FakeCursor(backend_ssl);self.rollbacks=0
    def cursor(self):return self.c
    def close(self):pass
    def rollback(self):self.rollbacks+=1

def test_backend_ssl_false_is_reported_without_success_verdict(monkeypatch):
    monkeypatch.setattr(v97,"valid_dsn",lambda d,k:True)
    monkeypatch.setattr(v97,"trusted_ca",lambda:True)
    dbs=[FakeDB(),FakeDB()]
    out=r.diagnose(env=env(),connector=lambda *_:dbs.pop(0))
    assert out["result"]=="DIAGNOSED"
    assert all(not x["backend_pg_stat_ssl"] for x in out["components"].values())
    assert out["authenticated"] is False and out["production_cutover"] is False
    assert "fictional-" not in json.dumps(out)

def test_missing_secret_fails_before_connector():
    e=env();e["JW_V97_AUTH_DSN"]=""
    assert r.diagnose(env=e,connector=lambda *_:1)["reason"]=="TWO_SECRETS_MISSING"

def test_production_fails_closed():
    e=env();e["JW_ENV"]="production"
    assert r.diagnose(env=e,connector=lambda *_:1)["result"]=="BLOCKED"

def test_no_decrypted_credentials_or_customer_tables_in_diagnostic():
    import inspect
    code=inspect.getsource(r)
    assert "SELECT * FROM" not in code
    assert 'sslmode="verify-full"' in code
    assert "sslrootcert=str(v97.CA)" in code
    assert "db.rollback()" in code
    assert "production_cutover" in code
