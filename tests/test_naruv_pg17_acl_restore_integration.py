"""Two fresh networkless PG17 clusters: synthetic authorization restore only.
No real backup, credentials, role names, external DB or production changes.
"""
import os,re,secrets,subprocess,time
from scripts import jw_independent_security_v223 as auth
from scripts import jw_pg17_role_graph_v223 as graph

def denied_42501(p):
    return p.returncode!=0 and re.search(rb"(?m)^ERROR:\s+42501:",p.stderr) is not None

def test_sqlstate_classifier_regression():
    # Exact redacted stderr shape from failed CI 45839966885.
    for status,stderr,expected in (
        (1,b'ERROR:  42501: new row violates row-level security policy',True),
        (1,b'ERROR:  42P01: relation missing',False),
        (0,b'ERROR:  42501: synthetic',False),
        (1,b'NOTICE:  42501: synthetic',False),
        (1,b'ERROR:  425010: synthetic',False),
        (1,b'ERROR:  42501x: synthetic',False)):
        assert denied_42501(subprocess.CompletedProcess([],status,b"",stderr)) is expected

def test_full_authorization_restore_and_runtime_rls():
    assert os.environ.get("GITHUB_ACTIONS")=="true"
    assert os.environ.get("GITHUB_REPOSITORY")=="guccizz1k/JARVIS-WORKS"
    assert os.environ.get("JW_SYNTHETIC_ACL_RESTORE_CI")=="1"
    env={k:os.environ[k] for k in ("PATH","HOME","DOCKER_CONFIG","DOCKER_HOST","DOCKER_CONTEXT","XDG_RUNTIME_DIR") if k in os.environ}
    assert not os.environ.get("DOCKER_TLS_VERIFY")
    assert not env.get("DOCKER_HOST") or env["DOCKER_HOST"].startswith("unix://")
    def cmd(*args,data=None,check=True,timeout=60):
        p=subprocess.run(["docker",*args],env=env,input=data,capture_output=True,timeout=timeout)
        if check:assert p.returncode==0,"SYNTHETIC_DOCKER_COMMAND_FAILED"
        return p
    assert cmd("context","inspect","--format","{{.Endpoints.docker.Host}}").stdout.strip().startswith(b"unix://")
    image=cmd("image","inspect","postgres:17","--format","{{.Id}}").stdout.decode().strip()
    assert re.fullmatch(r"sha256:[a-f0-9]{64}",image)
    owned=[]
    def launch():
        name="naruv-acl-ci-"+secrets.token_hex(10)
        cid=cmd("run","--rm","--pull","never","-d","--name",name,"--network","none","--log-driver","none","--tmpfs","/var/lib/postgresql/data:rw,size=1073741824","--tmpfs","/var/run/postgresql:rw,size=16777216","-e","POSTGRES_HOST_AUTH_METHOD=trust",image).stdout.decode().strip()
        owned.append(name)
        assert re.fullmatch("[a-f0-9]{64}",cid)
        for _ in range(60):
            if cmd("exec",cid,"sh","-c",'test "$(cat /proc/1/comm)" = postgres && pg_isready -q -U postgres',check=False).returncode==0:break
            time.sleep(.5)
        else:raise AssertionError("PG17_NOT_READY")
        assert b"PostgreSQL) 17." in cmd("exec",cid,"postgres","--version").stdout
        return cid
    roles="""CREATE ROLE naruv_ci_owner NOLOGIN;
    CREATE ROLE naruv_ci_a NOLOGIN;
    CREATE ROLE naruv_ci_b NOLOGIN;
    CREATE ROLE naruv_ci_read NOLOGIN;
    GRANT naruv_ci_read TO naruv_ci_a WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;
    GRANT naruv_ci_read TO naruv_ci_b WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;"""
    db="jw_p1_offline_0"
    def sql(c,q,db=db,check=True):
        return cmd("exec",c,"psql","-X","-qAt","-U","postgres","-d",db,"-v","ON_ERROR_STOP=1","-v","VERBOSITY=verbose","-c",q,check=check)
    def security(c,d=db):
        return auth.probe(lambda cid,args,timeout:cmd("exec",cid,*args,timeout=timeout),c,d)
    def global_pin(c):
        return graph.canonical(graph.parse(sql(c,graph.SQL,"postgres").stdout.strip()))
    def role_sql(c,role,q,d=db,check=True):
        assert role in ("naruv_ci_a","naruv_ci_b","naruv_ci_owner")
        return sql(c,"BEGIN; SET SESSION AUTHORIZATION "+role+"; "+q+"; ROLLBACK;",d,check)
    def assert_runtime(c):
        for role,expected in (("naruv_ci_a",b"1"),("naruv_ci_b",b"2"),("naruv_ci_owner",b"1")):
            assert role_sql(c,role,"SELECT string_agg(id::text,',' ORDER BY id) FROM jw_dev.t00").stdout.strip()==expected
        for role,q in (("naruv_ci_a","INSERT INTO jw_dev.t00 VALUES(3,2)"),("naruv_ci_b","UPDATE jw_dev.t00 SET tenant=1 WHERE id=2"),("naruv_ci_a","SET LOCAL ROLE naruv_ci_b"),("naruv_ci_a","SELECT * FROM jw_dev.t01")):
            p=role_sql(c,role,q,check=False)
            assert denied_42501(p)
        assert role_sql(c,"naruv_ci_a","WITH x AS (UPDATE jw_dev.t00 SET tenant=1 WHERE id=2 RETURNING 1) SELECT count(*) FROM x").stdout.strip()==b"0"
    try:
        source,target=launch(),launch()
        for c in (source,target):
            sql(c,roles,"postgres")
            cmd("exec",c,"createdb","-U","postgres",db)
        sql(source,"CREATE SCHEMA jw_dev; "+ "".join("CREATE TABLE jw_dev.t%02d(id integer PRIMARY KEY, tenant integer NOT NULL);"%i for i in range(65))+"""
        INSERT INTO jw_dev.t00 VALUES(1,1),(2,2);
        ALTER TABLE jw_dev.t00 OWNER TO naruv_ci_owner;
        GRANT USAGE ON SCHEMA jw_dev TO naruv_ci_read,naruv_ci_owner;
        GRANT SELECT ON jw_dev.t00 TO naruv_ci_read;
        GRANT INSERT,UPDATE ON jw_dev.t00 TO naruv_ci_a,naruv_ci_b;
        ALTER TABLE jw_dev.t00 ENABLE ROW LEVEL SECURITY;
        ALTER TABLE jw_dev.t00 FORCE ROW LEVEL SECURITY;
        CREATE POLICY pa ON jw_dev.t00 TO naruv_ci_a USING(tenant=1) WITH CHECK(tenant=1);
        CREATE POLICY pb ON jw_dev.t00 TO naruv_ci_b USING(tenant=2) WITH CHECK(tenant=2);
        CREATE POLICY po ON jw_dev.t00 TO naruv_ci_owner USING(tenant=1) WITH CHECK(tenant=1);
        ALTER DEFAULT PRIVILEGES IN SCHEMA jw_dev GRANT SELECT ON TABLES TO naruv_ci_read;
        """)
        baseline=security(source)
        source_graph=global_pin(source)
        assert_runtime(source)
        dump=cmd("exec",source,"pg_dump","-U","postgres","-Fc","--schema=jw_dev","--no-owner",db).stdout
        assert dump.startswith(b"PGDMP")
        cmd("exec","-i",target,"pg_restore","-U","postgres","--exit-on-error","-d",db,data=dump)
        assert security(target)==baseline,"FULL_AUTHZ_CHECKPOINT_MISMATCH"
        assert graph.compare(source_graph,global_pin(target),expected_reference_pin=graph.pin(source_graph))["role_graph_checkpoint"].startswith("PASS_")
        assert_runtime(target)
        stripped="jw_p1_offline_1"
        cmd("exec",target,"createdb","-U","postgres",stripped)
        cmd("exec","-i",target,"pg_restore","-U","postgres","--exit-on-error","--no-owner","--no-acl","-d",stripped,data=dump)
        observed=security(target,stripped)
        assert observed["owners"]!=baseline["owners"]
        assert observed["object_acl"]!=baseline["object_acl"]
        p=role_sql(target,"naruv_ci_a","SELECT * FROM jw_dev.t00",stripped,False)
        assert denied_42501(p)
        sql(target,"ALTER ROLE naruv_ci_a BYPASSRLS")
        assert security(target)["role_attributes"]!=baseline["role_attributes"]
        assert role_sql(target,"naruv_ci_a","SELECT count(*) FROM jw_dev.t00").stdout.strip()==b"2"
        sql(target,"ALTER ROLE naruv_ci_a NOBYPASSRLS")
        assert security(target)==baseline
        assert_runtime(target)
        print("SYNTHETIC_FULL_ACL_RESTORE_AND_EFFECTIVE_RLS=PASS")
    finally:
        for name in reversed(owned):cmd("rm","-f",name)
