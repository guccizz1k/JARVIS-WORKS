"""V9.7: only project-qualified restricted roles over verified-full TLS."""
import json
import pytest
from scripts import ci_v97_supavisor_restricted_auth as r

PW="CI-SYNTHETIC-NOT-SECRET"
H=r.POOLER_HOST
P=r.PROJECT_REF

def uri(kind,host=H,port=5432,user=None,extra=""):
    role=("jw_auth_gateway_v90" if kind=="auth" else "jw_trade_gateway_v90")+"."+P
    return "postgresql://"+(user or role)+":"+PW+"@"+host+":"+str(port)+"/postgres?sslmode=verify-full"+extra

def env(**kwargs):
    return {"JW_ENV":"review","JW_V97_LIVE_ACK":r.ACK,
        "JW_V97_TRADE_DSN":uri("trade"),"JW_V97_AUTH_DSN":uri("auth"),**kwargs}

def test_exact_ca_trusted():
    assert r.trusted_ca()

def test_good_restricted_pooler_names_and_tls():
    assert r.valid_dsn(uri("trade"),"trade")
    assert r.valid_dsn(uri("auth"),"auth")

@pytest.mark.parametrize("dsn",[
    uri("trade",user="postgres."+P),
    uri("trade",user="postgres"),
    uri("trade",user="jw_trade_gateway_v90"),
    uri("trade",user="jw_auth_gateway_v90."+P),
    uri("trade",user="jw_trade_gateway_v90.other-project"),
    uri("trade",host="example.com"),
    uri("trade",port=6543),
    uri("trade",extra="&sslmode=disable"),
    uri("trade",extra="&sslrootcert=/tmp/wrong-ca.crt"),
    uri("trade",extra="&hostaddr=127.0.0.1"),
    uri("trade",extra="&options=-c%20search_path%3Dpublic"),
])
def test_wrong_or_privileged_dsn_denied(dsn):
    assert not r.valid_dsn(dsn,"trade")

@pytest.mark.parametrize("missing",["JW_V97_TRADE_DSN","JW_V97_AUTH_DSN"])
def test_missing_secret_does_not_attempt_connection(missing,monkeypatch):
    def forbidden(**kwargs):raise AssertionError("Network unexpectedly used")
    monkeypatch.setattr(r,"check_two_connections",forbidden)
    e=env()
    e[missing]=""
    v=r.check(env=e)
    assert v["decision"]=="BLOCKED" and v["authenticated"] is False
    assert PW not in json.dumps(v)

def test_production_or_no_approval_denied():
    for d in ({"JW_ENV":"production","JW_V97_LIVE_ACK":r.ACK},
              {"JW_ENV":"review"},{}):
        assert r.check(env=d)["decision"]=="BLOCKED"

def test_read_only_role_gate_wiring_and_redacted_failure(monkeypatch):
    seen=[]
    def fake(*,connector,env,client_tls_guard=None):
        assert callable(client_tls_guard)
        seen.append(env["JW_ENV"])
        assert env["JW_PG_V87_CONNECT_GATE"]=="ISOLATED_DEV_ONLY"
        return {"result":"BLOCKED","failed_checks":["connection_or_tenant_role_failed"]}
    monkeypatch.setattr(r,"check_two_connections",fake)
    v=r.check(env=env(),connector=lambda *a,**kw:None)
    assert v["decision"]=="BLOCKED" and seen==["dev"]
    assert PW not in json.dumps(v)

def test_mock_good_gate_is_not_production_authorization(monkeypatch):
    monkeypatch.setattr(r,"check_two_connections",lambda **_:{"result":"PASS"})
    monkeypatch.setattr(r,"check_independent_boundaries",lambda **_:{
        "decision":"PASS","catalog_only":True,"tenant_row_isolation":"NOT RUN"},raising=False)
    v=r.check(env=env(),connector=lambda *_a,**_k:None)
    assert v["authenticated"] is True and v["production_cutover"] is False
    assert v["production_deployed"] is False

def test_legacy_pass_cannot_override_independent_boundary_failure(monkeypatch):
    monkeypatch.setattr(r,"check_two_connections",lambda **_:{"result":"PASS"})
    monkeypatch.setattr(r,"check_independent_boundaries",lambda **_:{
        "decision":"BLOCKED","failed_checks":["login_inherits"]},raising=False)
    v=r.check(env=env(),connector=lambda *_a,**_k:None)
    assert v["decision"]=="BLOCKED" and v["authenticated"] is False
    assert v["reason"]=="INDEPENDENT_BOUNDARY_REJECTED"

def test_inherited_libpq_configuration_blocks_before_network(monkeypatch):
    def forbidden(**_):raise AssertionError("connection attempted")
    monkeypatch.setattr(r,"check_two_connections",forbidden)
    v=r.check(env=env(PGOPTIONS="-c default_transaction_read_only=off"))
    assert v["reason"]=="AMBIENT_LIBPQ_SETTINGS"

def test_real_connector_forces_read_only_and_bounded_statements(monkeypatch):
    import psycopg
    seen=[]
    monkeypatch.setattr(psycopg,"connect",lambda dsn,**kw:seen.append(kw))
    def legacy(*,connector,env,client_tls_guard=None):
        assert callable(client_tls_guard)
        connector(env["JW_PG_STAGE_DSN"],sslmode="verify-full")
        return {"result":"PASS"}
    monkeypatch.setattr(r,"check_two_connections",legacy)
    monkeypatch.setattr(r,"check_independent_boundaries",lambda **_:{"decision":"PASS"},raising=False)
    r.check(env=env())
    assert seen[0]["sslmode"]=="verify-full"
    assert seen[0]["sslrootcert"]==str(r.CA)
    assert "default_transaction_read_only=on" in seen[0]["options"]
    assert "statement_timeout=5000" in seen[0]["options"]

def test_pooler_tls_attestation_requires_exact_libpq_config():
    from types import SimpleNamespace
    good={"host":r.POOLER_HOST,"port":"5432","sslmode":"verify-full",
          "sslrootcert":str(r.CA),"gssencmode":"disable"}
    conn=lambda fields:SimpleNamespace(info=SimpleNamespace(get_parameters=lambda:fields))
    assert r.verified_pooler_client_tls(conn(good))
    for key,bad in [("sslmode","require"),("sslmode","disable"),
                    ("sslrootcert","/tmp/unapproved.crt"),
                    ("host","evil.invalid"),("port","6543"),
                    ("gssencmode","prefer")]:
        fields=dict(good)
        fields[key]=bad
        assert not r.verified_pooler_client_tls(conn(fields)),key
    assert not r.verified_pooler_client_tls(object())
