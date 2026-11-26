import unittest
from app.erp_migration_recovery import result

class RecoveryDecisionTests(unittest.TestCase):
    def test_exact_evidence(self):
        for approval,receipt,rid,want in (
            (None,None,"r","UNKNOWN"),
            (("APPROVED",None,False),None,"r","NOT_COMMITTED_AT_CHECK"),
            (("REVOKED",None,False),None,"r","BLOCKED_REVOKED"),
            (("RESERVED","r",False),None,"r","BLOCKED_INCONSISTENT"),
            (("RESERVED","r",False),("FIXTURE_COMMITTED",2,False),"r","COMMITTED_RECEIPT_PRESENT"),
            (("RESERVED","other",False),("FIXTURE_COMMITTED",2,False),"r","BLOCKED_INCONSISTENT"),
            (("APPROVED",None,False),("FIXTURE_COMMITTED",2,False),"r","BLOCKED_INCONSISTENT"),
            (None,("FIXTURE_COMMITTED",2,False),"r","BLOCKED_INCONSISTENT"),
        ):
            with self.subTest(want=want):
                self.assertEqual(result(approval,receipt,rid),{"outcome":want,"automatic_retry":False,"production_import_authorized":False})
    def test_malformed_inputs_fail_closed(self):
        for approval,receipt,rid in (
            (("RESERVED","r",True),("FIXTURE_COMMITTED",2,False),"r"),
            (("RESERVED","r",0),("FIXTURE_COMMITTED",2,False),"r"),
            (("RESERVED","r",False),("FIXTURE_COMMITTED",True,False),"r"),
            (("RESERVED","r",False),("FIXTURE_COMMITTED",0,False),"r"),
            (("RESERVED","r",False),("FIXTURE_COMMITTED",1001,False),"r"),
            (("RESERVED","r",False),("FIXTURE_COMMITTED",2,True),"r"),
            (["RESERVED","r",False],("FIXTURE_COMMITTED",2,False),"r"),
            (("RESERVED","r",False),("FIXTURE_COMMITTED",2,False),None),
        ):
            with self.subTest(approval=approval,receipt=receipt,rid=rid):
                self.assertEqual(result(approval,receipt,rid)["outcome"],"BLOCKED_INVALID_EVIDENCE")
