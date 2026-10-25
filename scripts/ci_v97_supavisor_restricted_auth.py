"""Read-only J1–J6 V9.7 real Supavisor login gate. No secrets in logs/source."""
from __future__ import annotations
import hashlib, json, os, ssl, sys
from pathlib import Path
from app.pg_connection_gate_v87 import check_two_connections
from scripts.ci_v95_supavisor_session_tls import POOLER_HOST, POOLER_PORT, PROJECT_REF
from scripts.ci_v97_independent_boundary import check_independent_boundaries

CA = Path(__file__).resolve().parents[1]/"tests"/"certs"/"prod-ca-2021.crt"
CA_DER_SHA256 = "807025ad50d4ed219d2c9c7d299c004f824eb00cf7f65afef607d07b72e6cafa"
ACK = "READ_ONLY_SUPAVISOR_ACCEPTANCE_V97"
USERS = {"trade":"jw_trade_gateway_v90."+PROJECT_REF,
         "auth":"jw_auth_gateway_v90."+PROJECT_REF}
FIELDS = frozenset({"host","port","dbname","user","password",
                    "sslmode","sslrootcert","connect_timeout","application_name"})

def trusted_ca()->bool:
    try:
        pem=CA.read_text("ascii")
        if pem.count("-----BEGIN CERTIFICATE-----")!=1 or "PRIVATE KEY" in pem:
            return False
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()==CA_DER_SHA256
    except (OSError,ValueError,UnicodeError):
        return False

def valid_dsn(value:str,kind:str)->bool:
    if kind not in USERS or not isinstance(value,str) or not value:
        return False
    try:
        from psycopg.conninfo import conninfo_to_dict
        d=conninfo_to_dict(value)
        if not set(d).issubset(FIELDS):
            return False
        if (d.get("host")!=POOLER_HOST or str(d.get("port"))!=str(POOLER_PORT)
                or d.get("dbname")!="postgres" or d.get("user")!=USERS[kind]
                or not d.get("password") or d.get("sslmode","verify-full")!="verify-full"):
            return False
        if d.get("sslrootcert") and Path(d["sslrootcert"]).resolve()!=CA.resolve():
            return False
        if "connect_timeout" in d and not 1<=int(d["connect_timeout"])<=5:
            return False
        if d.get("application_name","jw_v97_readonly")!="jw_v97_readonly":
            return False
        return True
    except Exception:
        return False

def check(*,env=None,connector=None)->dict:
    e=os.environ if env is None else env
    base={"decision":"BLOCKED","authenticated":False,"read_only":True,
          "production_cutover":False,"production_deployed":False}
    if e.get("JW_ENV")!="review" or e.get("JW_V97_LIVE_ACK")!=ACK:
        return {**base,"reason":"REVIEW_OPT_IN_MISSING"}
    if not trusted_ca():
        return {**base,"reason":"ROOT_CA_INVALID"}
    trade=e.get("JW_V97_TRADE_DSN","")
    auth=e.get("JW_V97_AUTH_DSN","")
    if not trade or not auth:
        return {**base,"reason":"TWO_INDEPENDENT_SECRETS_MISSING"}
    # Reject ambient libpq service/password/options overrides; never inspect values.
    if any(key.startswith("PG") for key in e):
        return {**base,"reason":"AMBIENT_LIBPQ_SETTINGS"}
    if not valid_dsn(trade,"trade") or not valid_dsn(auth,"auth") or trade==auth:
        return {**base,"reason":"PRIVILEGED_OR_WRONG_POOLER_DSN"}
    if connector is None:
        if any(key.startswith("PG") for key in os.environ):
            return {**base,"reason":"AMBIENT_LIBPQ_SETTINGS"}
        try:
            import psycopg
        except ImportError:
            return {**base,"reason":"DRIVER_UNAVAILABLE"}
        def connector(dsn,**kwargs):
            return psycopg.connect(dsn,sslmode="verify-full",
                sslrootcert=str(CA),connect_timeout=5,
                application_name="jw_v97_readonly",gssencmode="disable",
                options="-c default_transaction_read_only=on -c statement_timeout=5000 "
                        "-c lock_timeout=1000 -c idle_in_transaction_session_timeout=10000")
    try:
        verdict=check_two_connections(connector=connector,env={
            "JW_ENV":"dev","JW_PG_V87_CONNECT_GATE":"ISOLATED_DEV_ONLY",
            "JW_PG_STAGE_DSN":trade,"JW_PG_AUTH_STAGE_DSN":auth})
    except Exception:
        return {**base,"reason":"ROLE_GATE_ERROR"}
    if verdict.get("result")!="PASS":
        return {**base,"reason":"ROLE_GATE_REJECTED",
                "failed_checks":verdict.get("failed_checks",[])}
    try:
        independent=check_independent_boundaries(connector=connector,
            trade_dsn=trade,auth_dsn=auth,env=e)
    except Exception:
        return {**base,"reason":"INDEPENDENT_BOUNDARY_ERROR"}
    if independent.get("decision")!="PASS":
        return {**base,"reason":"INDEPENDENT_BOUNDARY_REJECTED",
                "failed_checks":independent.get("failed_checks",[])}
    return {**base,"decision":"PASS","authenticated":True,
            "role_boundaries":"PASS","independent_boundary":independent,
            "tenant_row_isolation":"NOT RUN",
            "reason":"RESTRICTED_READ_ONLY_GATE_VERIFIED"}

def main()->int:
    result=check()
    print(json.dumps(result,sort_keys=True))
    return 3 if "--require-authenticated" in sys.argv and result["decision"]!="PASS" else 0

if __name__=="__main__":
    raise SystemExit(main())
