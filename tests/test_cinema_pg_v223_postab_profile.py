"""Strict post-A/B source-only audit, no credentials and no DB access."""
from __future__ import annotations
import os
import unittest
from unittest.mock import patch
from scripts import ci_cinema_pg_v223_postab_profile as p

ID=(65,64,72,74,"x","y",p.FINGERPRINT)
EXTRA=(1,3,3,65,0,22)
ROLE=(True,True,False,False,False,False,2,True,"2026-11-09T00:00+09")

class PostABProfileTests(unittest.TestCase):
    def test_exact_pinned_source_schema(self):
        self.assertEqual(p.FINGERPRINT,"d3e6284dfbd277b43041052ea8f927ca")
        self.assertEqual((p.EXPECTED["tables"],p.EXPECTED["force_rls"],
                          p.EXPECTED["functions"],p.EXPECTED["triggers"]),
                         (65,64,72,74))

    def test_valid_readonly_65_state(self):
        self.assertEqual(p.classify(ID,EXTRA,ROLE),[])

    def test_every_identity_change_fails_closed(self):
        for i in (0,1,2,3,6):
            with self.subTest(index=i):
                arr=list(ID)
                arr[i]= "000bad" if i==6 else int(arr[i])-1
                self.assertNotEqual(p.classify(tuple(arr),EXTRA,ROLE),[])

    def test_all_six_ab_acl_and_row_invariants_enforced(self):
        for i in range(len(EXTRA)):
            with self.subTest(index=i):
                arr=list(EXTRA)
                arr[i]= int(arr[i])+1
                self.assertNotEqual(p.classify(ID,tuple(arr),ROLE),[])

    def test_role_state_all_fields_and_expiration(self):
        for i in range(8):
            with self.subTest(index=i):
                arr=list(ROLE)
                arr[i] = (not arr[i]) if isinstance(arr[i],bool) else 3
                self.assertIn("backup_role_privilege_or_expiration",
                              p.classify(ID,EXTRA,tuple(arr)))
        self.assertIn("backup_role_privilege_or_expiration",
                      p.classify(ID,EXTRA,(*ROLE[:8],None)))

    def test_no_short_or_string_replacement_for_counts(self):
        self.assertIn("source_identity_row_shape",p.classify(ID[:6],EXTRA,ROLE))
        self.assertIn("ab_security_row_shape",p.classify(ID,EXTRA[:5],ROLE))
        self.assertIn("tables",p.classify(("65",*ID[1:]),EXTRA,ROLE))

    def test_sql_only_selects_and_no_ddl_dml(self):
        self.assertTrue(p.EXTRA_SQL.strip().startswith("WITH objects AS"))
        self.assertTrue(p.ROLE_SQL.strip().startswith("SELECT"))
        for query in (p.EXTRA_SQL,p.ROLE_SQL):
            for unsafe in ("DROP TABLE","ALTER TABLE","CREATE TABLE",
                           "INSERT INTO","DELETE FROM","UPDATE jw_dev",
                           "GRANT ", "REVOKE "):
                self.assertNotIn(unsafe,query.upper())
        self.assertIn("acl.grantee=0",p.EXTRA_SQL)
        self.assertIn("relforcerowsecurity",p.EXTRA_SQL)
        self.assertIn("convalidated",p.EXTRA_SQL)

    def test_missing_secrets_fail_closed_without_network(self):
        with patch.dict(os.environ,{"JW_ENV":"review"},clear=True):
            self.assertEqual(p.main(),2)

    def test_nonreview_mode_fail_closed_without_network(self):
        with patch.dict(os.environ,{"JW_ENV":"production","JW_PG_SOURCE_DSN":"BAD"},clear=True):
            self.assertEqual(p.main(),2)

    def test_guard_source_called_before_psycopg_connection(self):
        with patch.dict(os.environ,{"JW_ENV":"review","JW_PG_SOURCE_DSN":"invalid"},clear=True),\
             patch.object(p,"guard_source",side_effect=RuntimeError("no credential leak")):
            self.assertEqual(p.main(),2)

if __name__=="__main__":
    unittest.main()
