"""Run against candidate installed only in a disposable exact-source checkout."""
import os,tempfile
from pathlib import Path
from tests.test_naruv_operational_readiness import OperationalReadinessTests
from app.naruv_operational_readiness import review_and_consume_local_challenge

class CustodyJournalPathTests(OperationalReadinessTests):
    def test_ancestor_path_rejection_and_no_consumption(self):
        a=self.custody()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            parent=root/"parent";parent.mkdir(mode=0o700)
            leaf=parent/"journal";leaf.mkdir(mode=0o700)
            alias=root/"alias";alias.symlink_to(parent,target_is_directory=True)
            bad=[str(alias/"journal"),str(parent)+"/../parent/journal",str(parent)+"//journal"]
            for path in bad:
                with self.subTest(path=path),self.assertRaisesRegex(ValueError,"CUSTODY_LOCAL_DIRECTORY"):
                    review_and_consume_local_challenge(journal_dir=path,**a)
                self.assertEqual(list(leaf.iterdir()),[])
            parent.chmod(0o777)
            with self.assertRaisesRegex(ValueError,"CUSTODY_LOCAL_DIRECTORY"):
                review_and_consume_local_challenge(journal_dir=str(leaf),**a)
            self.assertEqual(list(leaf.iterdir()),[])
            parent.chmod(0o700)
            result=review_and_consume_local_challenge(journal_dir=str(leaf),**a)
            self.assertTrue(result["local_challenge_consumed"])
            self.assertFalse(result["production_authorized"])
            with self.assertRaisesRegex(ValueError,"CUSTODY_LOCAL_REPLAY"):
                review_and_consume_local_challenge(journal_dir=str(leaf),**a)
