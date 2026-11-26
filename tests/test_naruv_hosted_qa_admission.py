import unittest
from app.naruv_hosted_qa_admission import ACK,PURPOSES,AdmissionBlocked,parse_config,run,verify_catalog,PROTECTED

class HostedQAAdmission(unittest.TestCase):
    def env(self):
        host="dpg-abcdefgh1234-a.singapore-postgres.render.com"
        db="naruv_qa_abcdefgh"
        e={"NARUV_HOSTED_QA_ADMISSION":ACK,"JW_ENV":"review",
           "NARUV_HOSTED_QA_DB_HOST":host,"NARUV_HOSTED_QA_DB_NAME":db,
           "NARUV_HOSTED_QA_SOURCE_SHA":"a"*40,"RENDER_GIT_COMMIT":"a"*40,
           "NARUV_HOSTED_QA_DB_MARKER":"b"*64}
        for i,(variable,user,_) in enumerate(PURPOSES.values()):
            e[variable]=f"host={host} port=5432 dbname={db} user={user} password={'x'*24}{i} sslmode=verify-full sslrootcert=system"
        return e
    def test_valid_and_no_secret_repr(self):
        c=parse_config(self.env())
        self.assertEqual(set(c.dsns),set(PURPOSES))
        self.assertNotIn("x"*24,repr(c));self.assertNotIn("b"*64,repr(c))
    def test_fail_closed_environment_and_sha(self):
        for changes in ({"JW_ENV":"prod"},{"NARUV_HOSTED_QA_ADMISSION":""},
          {"GITHUB_ACTIONS":"true"},{"JW_PG_STAGE_DSN":"hidden"},{"DATABASE_URL":"hidden"},
          {"PGSERVICE":"hidden"},{"PGOPTIONS":"hidden"},{"RENDER_GIT_COMMIT":"c"*40},
          {"NARUV_HOSTED_QA_DB_NAME":"postgres"},{"NARUV_HOSTED_QA_DB_HOST":"localhost"}):
            with self.subTest(changes=changes),self.assertRaises(AdmissionBlocked):
                parse_config(dict(self.env(),**changes))
    def test_invalid_dsn_and_no_sensitive_exception(self):
        key=PURPOSES["business"][0]
        for suffix in (" sslmode=require"," hostaddr=127.0.0.1"," options='-c role=postgres'",
                       " service=wrong"," user=postgres"," dbname=postgres"," port=6543",
                       " sslrootcert=/tmp/attacker.pem"," password=short"," host=wrong.example"):
            e=self.env();e[key]+=suffix
            with self.subTest(suffix=suffix),self.assertRaises(AdmissionBlocked) as ex:
                parse_config(e)
            self.assertNotIn("x"*24,str(ex.exception))
        e=self.env();e[key]="malformed secret text"
        with self.assertRaisesRegex(AdmissionBlocked,"HOSTED_QA_DSN"):parse_config(e)
    def test_distinct_credentials_and_no_injected_environment(self):
        e=self.env();e[PURPOSES["auth"][0]]=e[PURPOSES["auth"][0]].replace("x"*24+"1","x"*24+"0")
        with self.assertRaisesRegex(AdmissionBlocked,"HOSTED_QA_DSN_SCOPE"):parse_config(e)
        with self.assertRaisesRegex(AdmissionBlocked,"HOSTED_QA_ENV_OVERRIDE"):run(self.env())

    def test_catalog_fail_closed_logic(self):
        # Scripted cursor tests only: actual remote DB and TLS remain unverified.
        c=parse_config(self.env())
        def rows():
            return [(c.database,"naruv_qa_business","naruv_qa_business",17,"on",True),
              (True,False,False,False,False,False,False),
              (False,False,False,False,False,False),[("jw_app_dev",)],(True,False),
              *[(True,True),(False,False),(False,False)]*len(PROTECTED),
              ("naruv_qa_boundary_owner",False),(False,False,False,False),
              (False,False,False,False),[(c.marker,c.source_sha)]]
        class Cursor:
            def __init__(self,responses):self.pending=iter(responses);self.current=None
            def execute(self,sql,args=()):self.current=next(self.pending)
            def fetchone(self):return self.current
            def fetchall(self):return self.current
        verify_catalog(Cursor(rows()),purpose="business",config=c)
        for index,bad,reason in (
          (0,(c.database,"naruv_qa_business","naruv_qa_business",17,"on",False),"HOSTED_QA_DB_TLS"),
          (1,(True,True,False,False,False,False,False),"HOSTED_QA_LOGIN_ROLE"),
          (2,(True,False,False,False,False,False),"HOSTED_QA_DELEGATED_ROLE"),
          (3,[("jw_app_dev",),("naruv_native_owner",)],"HOSTED_QA_ROLE_MEMBERSHIP"),
          (4,(True,True),"HOSTED_QA_ROLE_DELEGATION"),
          (5,(True,False),"HOSTED_QA_RLS"),
          (6,(False,True),"HOSTED_QA_DIRECT_GRANT"),
          (-4,("wrong_owner",False),"HOSTED_QA_BOUNDARY_OWNER"),
          (-3,(False,False,True,False),"HOSTED_QA_BOUNDARY_WRITABLE"),
          (-1,[("wrong",c.source_sha)],"HOSTED_QA_BOUNDARY_MISMATCH")):
            values=rows();values[index]=bad
            with self.subTest(reason=reason),self.assertRaisesRegex(AdmissionBlocked,reason):
                verify_catalog(Cursor(values),purpose="business",config=c)


    def test_dedicated_deployment_metadata(self):
        from app.naruv_hosted_qa_admission import verify_deployment_metadata
        service={"id":"srv-abcdefgh1234567890","name":"naruv-one-qa-20261126","branch":"review/naruv-hosted-qa-20261126","autoDeploy":"no","type":"web_service","autoDeployTrigger":"off",
                 "ownerId":"tea-abcdefgh1234567890","repo":"https://github.com/example/project",
                 "suspended":"not_suspended","serviceDetails":{"plan":"free"}}
        deploy={"status":"live","commit":{"id":"a"*40}}
        args=dict(service=service,deploy=deploy,queried_service_id=service["id"],expected_sha="a"*40,expected_branch=service["branch"],expected_name=service["name"],expected_workspace_id=service["ownerId"],expected_repo=service["repo"])
        self.assertEqual(verify_deployment_metadata(**args)["status"],"METADATA_MATCH_ONLY")
        for changes in ({"service":dict(service,autoDeploy="yes")},{"service":dict(service,name="jw-existing")},
                        {"service":dict(service,branch="main")},{"deploy":dict(deploy,status="build_in_progress")},
                        {"deploy":dict(deploy,commit={"id":"b"*40})},{"deploy":dict(deploy,serviceId="srv-other")},
                        {"queried_service_id":"srv-other"},{"expected_branch":"main"}, {"service":dict(service,ownerId="tea-other")},
                        {"service":dict(service,repo="https://github.com/example/fork")},
                        {"service":dict(service,autoDeployTrigger="commit")},
                        {"service":dict(service,suspended="suspended")},
                        {"service":dict(service,serviceDetails={"plan":"starter"})},
                        {"service":dict(service,serviceDetails=None)},
                        {"expected_repo":"https://other.example/project"}, {"expected_workspace_id":"tea-other"}):
            with self.assertRaises(AdmissionBlocked):verify_deployment_metadata(**dict(args,**changes))


class SupabaseManagedAdmission(unittest.TestCase):
    def test_exact_new_project_and_catalog_no_authority(self):
        from app.naruv_supabase_qa_admission import verify_provider_project,QA_REF,QA_ORG,QA_NAME,PROBE_VERSION,PROBE_NAME
        p=dict(id=QA_REF,ref=QA_REF,organization_id=QA_ORG,name=QA_NAME,region="ap-northeast-2",
            status="ACTIVE_HEALTHY",database=dict(host="db."+QA_REF+".supabase.co",postgres_engine="17"))
        migrations=[dict(version=PROBE_VERSION,name=PROBE_NAME)]
        catalog=dict(current_user="postgres",session_user="postgres",current_database="postgres",version_num=170012,
            superuser=False,createrole=True,bypassrls=True,existing_erp_schemas=0,conflicting_roles=0)
        rollback=dict(schema_rolled_back=True,roles_rolled_back=True,original_fixture_intact=True)
        args=dict(project=p,expected_sha="a"*40,migrations=migrations,catalog=catalog,rollback=rollback)
        result=verify_provider_project(**args)
        self.assertEqual(result["status"],"DEDICATED_MANAGED_DB_PREFLIGHT_ONLY")
        for k in ("migration_authorized","deployment_authorized","production_authorized","runtime_credentials_verified"):
            self.assertIs(result[k],False)
        for change in (dict(project=dict(p,id="other")),dict(project=dict(p,ref="other")),dict(project=dict(p,status="INACTIVE")),
            dict(project=dict(p,database=dict(p["database"],postgres_engine="18"))),dict(migrations=[]),
            dict(migrations=migrations+[dict(version="new",name="unexpected")]),
            dict(catalog=dict(catalog,superuser=True)),dict(catalog=dict(catalog,existing_erp_schemas=1)),
            dict(catalog=dict(catalog,conflicting_roles=False)),dict(rollback=dict(rollback,roles_rolled_back=False)),
            dict(expected_sha="main")):
            with self.subTest(change=list(change)),self.assertRaises(AdmissionBlocked):
                verify_provider_project(**dict(args,**change))

    def test_raw_ci_sources_cannot_be_promoted_by_renaming(self):
        from app.naruv_supabase_qa_admission import require_hosted_sql_source
        for path,sql in (("db/review/ci_v92_quote_ephemeral.sql","SELECT 1"),
            ("db/review/naruv_supabase_hosted_test.sql","-- NEVER migrate onto Supabase"),
            ("db/review/naruv_supabase_hosted_test.sql","SELECT set_config('naruv.foo','DISPOSABLE_ONLY',true)"),
            ("db/review/naruv_supabase_hosted_test.sql","ALTER SYSTEM SET ssl='off'"),
            ("db/review/naruv_supabase_hosted_../test.sql","SELECT 1")):
            with self.assertRaises(AdmissionBlocked):require_hosted_sql_source(path,sql)
        self.assertFalse(require_hosted_sql_source("db/review/naruv_supabase_hosted_test.sql","SELECT 1")["migration_authorized"])
