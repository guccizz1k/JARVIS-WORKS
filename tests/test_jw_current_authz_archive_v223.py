import unittest
from scripts import jw_current_authz_archive_v223 as m

def rows():
    return "\n".join(f"JW-PG17-AUTHZ-SQL-V1,{k},{n},{'a'*64},2,10,0,t" for k,n in
        (("acl",10),("owners",10),("defaults",0),("roles",3),("members",1)))

class TestArchiveProfile(unittest.TestCase):
    def test_parse_compare(self):
        actual=m.parse(rows())
        ref={k:[v[0],v[1]] for k,v in actual.items()}
        self.assertTrue(all(x["match"] for x in m.compare(actual,ref).values()))
        ref["roles"][1]="b"*64
        self.assertFalse(m.compare(actual,ref)["roles"]["match"])
    def test_missing_or_duplicate(self):
        for text in (rows().split("\n",1)[1],rows()+"\n"+rows().splitlines()[0]):
            with self.assertRaises(RuntimeError):m.parse(text)
    def test_unknown_owners(self):
        with self.assertRaises(RuntimeError):m.parse(rows().replace(",2,10,0,t",",2,10,1,t"))
    def test_missing_role(self):
        with self.assertRaises(RuntimeError):m.parse(rows().replace(",2,10,0,t",",1,10,0,t"))
    def test_wrong_profile(self):
        with self.assertRaises(RuntimeError):m.parse(rows().replace("SQL-V1","SQL-V2"))
    def test_bad_count(self):
        with self.assertRaises(RuntimeError):m.parse(rows().replace(",owners,10,",",owners,9,"))
