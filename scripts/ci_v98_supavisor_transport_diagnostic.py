"""Read-only, redacted Supavisor hop diagnostic, exact restricted roles only."""
import json, os
from contextlib import closing
from scripts import ci_v97_supavisor_restricted_auth as gate

def diagnose(env=None,connector=None):
    e=os.environ if env is None else env
    base={"status":"BLOCKED","reason":"UNVERIFIED","production_cutover":False}
    if e.get("JW_ENV")!="review" or e.get("JW_V97_LIVE_ACK")!=gate.ACK:
        return {**base,"reason":"REVIEW_NOT_ENABLED"}
    if not gate.trusted_ca():
        return {**base,"reason":"ROOT_CA_INVALID"}
    auth=e.get("JW_V97_AUTH_DSN","")
    trade=e.get("JW_V97_TRADE_DSN","")
    if not gate.valid_dsn(auth,"auth") or not gate.valid_dsn(trade,"trade"):
        return {**base,"reason":"MISSING_OR_INVALID_SECRET"}
    if connector is None:
        import psycopg
        def connector(dsn):
            return psycopg.connect(
                dsn,sslmode="verify-full",sslrootcert=str(gate.CA),
                connect_timeout=5,gssencmode="disable",
                application_name="jw_v98_readonly",
                options="-c default_transaction_read_only=on -c statement_timeout=5000")
    by_role={}
    for kind,dsn in (("auth",auth),("trade",trade)):
        try:
            with closing(connector(dsn)) as conn:
                params=conn.info.get_parameters()
                if params.get("sslmode") != "verify-full":
                    return {**base,"reason":"LIBPQ_SSLMODE_UNTRUSTED"}
                if params.get("sslrootcert") != str(gate.CA):
                    return {**base,"reason":"LIBPQ_ROOT_CA_UNTRUSTED"}
                # libpq get_parameters() omits parameters equal to defaults;
                # ConnectionInfo.host/port report the actual connected target.
                if conn.info.host != gate.POOLER_HOST or str(conn.info.port) != "5432":
                    return {**base,"reason":"LIBPQ_PEER_ENDPOINT_MISMATCH"}
                with conn.cursor() as cur:
                    cur.execute("SET TRANSACTION READ ONLY")
                    cur.execute("""SELECT session_user,current_user,
                        current_setting('server_version_num')::integer / 10000,
                        (SELECT ssl FROM pg_catalog.pg_stat_ssl WHERE pid=pg_backend_pid())""")
                    row=cur.fetchone()
                conn.rollback()
            if not row or row[0]!=gate.USERS[kind].split(".")[0] or row[1]!=row[0]:
                return {**base,"reason":"ROLE_IDENTITY_MISMATCH"}
            by_role[kind]={"postgres_17":row[2]==17,
                            "upstream_ssl":"TRUE" if row[3] is True else "FALSE" if row[3] is False else "UNKNOWN",
                            "client_verify_full_connection":True}
        except Exception:
            return {**base,"reason":"CONNECTION_OR_QUERY_FAILED"}
    return {"status":"DIAGNOSED","reason":"CLIENT_AND_UPSTREAM_HOPS_MEASURED",
            "roles":by_role,"production_cutover":False}

if __name__=="__main__":
    print(json.dumps(diagnose(),sort_keys=True))
