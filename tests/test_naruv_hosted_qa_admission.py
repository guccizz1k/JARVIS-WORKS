import unittest
from app.naruv_hosted_qa_admission import ACK,PURPOSES,AdmissionBlocked,parse_config,run

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
