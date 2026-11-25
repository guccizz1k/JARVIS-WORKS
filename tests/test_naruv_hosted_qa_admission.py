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
        service={"id":"srv-abcdefgh1234567890","name":"naruv-one-qa-20261126","branch":"review/naruv-hosted-qa-20261126","autoDeploy":"no","type":"web_service"}
        deploy={"serviceId":service["id"],"status":"live","commit":{"id":"a"*40}}
        args=dict(service=service,deploy=deploy,expected_sha="a"*40,expected_branch=service["branch"],expected_name=service["name"])
        self.assertEqual(verify_deployment_metadata(**args)["status"],"METADATA_MATCH_ONLY")
        for changes in ({"service":dict(service,autoDeploy="yes")},{"service":dict(service,name="jw-existing")},
                        {"service":dict(service,branch="main")},{"deploy":dict(deploy,status="build_in_progress")},
                        {"deploy":dict(deploy,commit={"id":"b"*40})},{"deploy":dict(deploy,serviceId="srv-other")},
                        {"expected_branch":"main"}):
            with self.assertRaises(AdmissionBlocked):verify_deployment_metadata(**dict(args,**changes))
