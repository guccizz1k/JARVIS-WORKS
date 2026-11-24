"""Synthetic real PG17 current metadata comparison, never live source."""
from live_checks.pg17_role_proof_smoke import connect,require
from scripts import jw_current_authz_proof_v223 as m
from scripts import jw_role_proof_v223 as role

def setup(c):
    for n in ("jw_app_dev","jw_auth_stage_v85","jw_role_ci_owner"):
        c.execute("CREATE ROLE "+n+" NOLOGIN")
    c.execute("CREATE SCHEMA jw_dev AUTHORIZATION jw_role_ci_owner")
    c.execute("CREATE TABLE jw_dev.sample (id int, note text)")
    c.execute("ALTER TABLE jw_dev.sample OWNER TO jw_role_ci_owner")
    c.execute("GRANT USAGE ON SCHEMA jw_dev TO jw_app_dev")
    c.execute("GRANT SELECT ON jw_dev.sample TO jw_app_dev")
    c.execute("CREATE FUNCTION jw_dev.sample_fn() RETURNS int LANGUAGE sql AS 'SELECT 1'")
    c.execute("CREATE TYPE jw_dev.sample_type AS ENUM ('synthetic')")
    c.execute("CREATE SEQUENCE jw_dev.sample_seq")

def capture(c):
    return m.collect(c,identity_check=lambda conn: require(conn.info.server_version//10000==17,"PG17_REQUIRED"))

def main():
    with connect("source",55432) as a,connect("target",55433) as b:
        # Earlier CI role fixtures may exist; setup uses fresh independent names
        # except the helper checks jw_role_ci_* absent. Run on separate clusters.
        setup(a);setup(b)
        # Same SQL digest profile used by the actual source metadata readback.
        from pathlib import Path
        from scripts import jw_current_authz_archive_v223 as archive
        q=(Path(__file__).resolve().parents[1]/"db/review/jw_current_authz_sql_v1.sql").read_text()
        def sql_profile(c):
            import csv,io
            output=io.StringIO()
            csv.writer(output).writerows([["t" if x is True else "f" if x is False else x for x in row] for row in c.execute(q).fetchall()])
            return archive.parse(output.getvalue())
        sa,sb=sql_profile(a),sql_profile(b)
        require(all(x["match"] for x in archive.compare(sb,{k:[v[0],v[1]] for k,v in sa.items()}).values()),"SQL_PROFILE_BASELINE")
        print("PG17_SQL_PROFILE_BASELINE_PASS")
        src=capture(a);pin=role.digest(src)
        require(m.compare(src,capture(b),pin)["current_scoped_metadata"]=="PASS","BASELINE")
        count=1
        for sql,field in (
            ("GRANT SELECT ON jw_dev.sample TO jw_app_dev WITH GRANT OPTION","object_acl_sha256"),
            ("GRANT UPDATE(note) ON jw_dev.sample TO jw_app_dev","object_acl_sha256"),
            ("ALTER TABLE jw_dev.sample OWNER TO jw_auth_stage_v85","owner_sha256"),
            ("ALTER DEFAULT PRIVILEGES FOR ROLE jw_role_ci_owner IN SCHEMA jw_dev GRANT SELECT ON TABLES TO jw_app_dev","default_acl_sha256"),
            ("ALTER DEFAULT PRIVILEGES FOR ROLE jw_role_ci_owner GRANT EXECUTE ON FUNCTIONS TO jw_app_dev","default_acl_sha256"),
            ("GRANT jw_auth_stage_v85 TO jw_app_dev WITH SET FALSE","role_graph_sha256"),
        ):
            before=capture(b);b.execute(sql);after=capture(b)
            require(m.compare(before,after,role.digest(before))["equal"][field] is False,"MUTATION_MISSED")
            count+=1
        try:
            m.collect(b,identity_check=lambda _: (_ for _ in ()).throw(role.Blocked("IDENTITY_DENIED")))
        except role.Blocked:
            require(b.info.transaction_status==0,"ROLLBACK_FAILED");count+=1
        else: raise RuntimeError("IDENTITY_GUARD_FAILED")
        require(role.digest(capture(a))==pin,"SOURCE_CHANGED");count+=1
        require(count==9,"COUNT_INVALID")
        print("PG17_CURRENT_AUTHZ_SYNTHETIC_PASS checks=9 overall=BLOCKED")
if __name__=="__main__": main()
