"""Synthetic two-cluster PostgreSQL 17 integration; no live source connections."""
import os
import sys
import time
from pathlib import Path
import psycopg
from scripts import jw_role_proof_v223 as m

def require(ok, code):
    if not ok:
        raise RuntimeError(code)

def connect(side, port):
    require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("JW_SYNTHETIC_ROLE_CI") == "1", "CI_ONLY")
    require((side, port) in (("source", 55432), ("target", 55433)), "ENDPOINT_DENIED")
    for _ in range(45):
        try:
            c = psycopg.connect(host="127.0.0.1", hostaddr="127.0.0.1", port=port,
                dbname="jw_role_"+side, user="postgres", password="synthetic_role_ci_only",
                sslmode="disable", connect_timeout=2, autocommit=True,
                options="-c statement_timeout=15000")
            break
        except psycopg.OperationalError:
            time.sleep(1)
    else:
        raise RuntimeError("PG17_NOT_READY")
    try:
        require(c.execute("SELECT current_database(), current_user, current_setting('server_version_num')::int").fetchone()[0:2] == ("jw_role_"+side, "postgres"), "TARGET_IDENTITY")
        require(170000 <= c.info.server_version < 180000, "PG17_REQUIRED")
        require(c.execute("SELECT count(*) FROM pg_roles WHERE rolname LIKE 'jw_role_ci_%'").fetchone()[0] == 0, "FIXTURE_ALREADY_PRESENT")
        return c
    except BaseException:
        c.close()
        raise

SCOPE = ["jw_role_ci_app"]
GRANT = "GRANT jw_role_ci_reader TO jw_role_ci_app WITH ADMIN FALSE, INHERIT TRUE, SET TRUE"

def setup(c):
    c.execute("CREATE ROLE jw_role_ci_app NOLOGIN NOSUPERUSER NOBYPASSRLS")
    c.execute("CREATE ROLE jw_role_ci_reader NOLOGIN NOSUPERUSER NOBYPASSRLS")
    c.execute("CREATE ROLE jw_role_ci_login NOLOGIN NOSUPERUSER NOBYPASSRLS")
    c.execute(GRANT)
    c.execute("GRANT jw_role_ci_app TO jw_role_ci_login WITH ADMIN FALSE, INHERIT TRUE, SET TRUE")

def main():
    checks=0
    with connect("source",55432) as source, connect("target",55433) as target:
        require(source.execute("SELECT current_database()").fetchone()!=target.execute("SELECT current_database()").fetchone(),"SAME_DATABASE")
        setup(source); setup(target)
        a=m.capture(source,SCOPE)
        pin=m.digest(a)
        require(m.compare(a,m.capture(target,SCOPE),pin)["scoped_role_graph"]=="PASS","BASELINE_MISMATCH");checks+=1
        for option, value in (("ADMIN","TRUE"),("INHERIT","FALSE"),("SET","FALSE")):
            target.execute("GRANT jw_role_ci_reader TO jw_role_ci_app WITH "+option+" "+value)
            result=m.compare(a,m.capture(target,SCOPE),pin)
            require(result["membership_edges_equal"] is False and result["scoped_role_graph"]=="FAIL","MEMBERSHIP_MUTATION_MISSED")
            target.execute(GRANT)
            require(m.compare(a,m.capture(target,SCOPE),pin)["scoped_role_graph"]=="PASS","MEMBERSHIP_RESET_MISMATCH")
            checks+=1
        target.execute("ALTER ROLE jw_role_ci_app BYPASSRLS")
        require(m.compare(a,m.capture(target,SCOPE),pin)["role_attributes_equal"] is False,"ROLE_MUTATION_MISSED");checks+=1
        target.execute("ALTER ROLE jw_role_ci_app NOBYPASSRLS")
        target.execute("REVOKE jw_role_ci_reader FROM jw_role_ci_app")
        require(m.compare(a,m.capture(target,SCOPE),pin)["scoped_role_graph"]=="FAIL","REMOVED_EDGE_MISSED");checks+=1
        target.execute(GRANT)
        target.execute("CREATE ROLE jw_role_ci_extra NOLOGIN")
        target.execute("GRANT jw_role_ci_app TO jw_role_ci_extra")
        require(m.compare(a,m.capture(target,SCOPE),pin)["scoped_role_graph"]=="FAIL","EXTRA_EDGE_MISSED");checks+=1
        target.execute("DROP ROLE jw_role_ci_extra")
        require(m.compare(a,m.capture(target,SCOPE),pin)["scoped_role_graph"]=="PASS","FINAL_BASELINE_MISMATCH");checks+=1
        try:
            m.capture(target,["jw_role_ci_missing"])
        except m.Blocked as exc:
            require(str(exc)=="REQUIRED_ROLE_MISSING","WRONG_BLOCKER")
        else:
            raise RuntimeError("MISSING_ROLE_NOT_BLOCKED")
        require(target.info.transaction_status==0,"ERROR_ROLLBACK_FAILED");checks+=1
        target.execute("BEGIN")
        try:
            try:
                m.capture(target,SCOPE)
            except m.Blocked as exc:
                require(str(exc)=="IDLE_CONNECTION_REQUIRED","WRONG_BUSY_BLOCKER")
            else:
                raise RuntimeError("BUSY_CONNECTION_NOT_BLOCKED")
            require(target.info.transaction_status!=0,"CALLER_TRANSACTION_TOUCHED");checks+=1
        finally:
            target.execute("ROLLBACK")
        require(target.info.transaction_status==0,"FINAL_ROLLBACK_FAILED")
        require(m.digest(m.capture(source,SCOPE))==pin,"SOURCE_CHANGED");checks+=1
    require(checks==11,"CHECK_COUNT_INVALID")
    print("PG17_SYNTHETIC_ROLE_GRAPH_PASS checks=11 overall=BLOCKED")
    return 0

if __name__=="__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        code=str(exc) if isinstance(exc,(RuntimeError,m.Blocked)) and str(exc).isupper() and str(exc).replace("_","").isalnum() else type(exc).__name__
        print("PG17_ROLE_PROOF_FAIL:"+code,file=sys.stderr)
        sys.exit(1)
