import os
import random
import unittest
from dataclasses import replace
from app.erp_migration_mapping import MappingBlocked
from app.erp_migration_review import prepare_header_review
from app.erp_migration_preflight import (
    MAX_ROWS, MAX_EXISTING_IDS, make_target_snapshot, prepare_row_preflight, check_row_preflight,
)

ORG, SOURCE, ENTITY, REV = "org-a", "erp-source-1", "item", "revision-1"
HEADERS = ("sku", "item_name", "unit")
ROWS = (("00017", "부품 A", "EA"), ("00018", "부품 B", None))

class RowPreflightTests(unittest.TestCase):
    def setUp(self):
        self.review = prepare_header_review(ORG,SOURCE,ENTITY,HEADERS)
        self.target = make_target_snapshot(ORG,SOURCE,ENTITY,REV,("00001",))
        self.args = dict(organization_id=ORG,source_id=SOURCE,entity=ENTITY,
                         headers=HEADERS,rows=ROWS,target=self.target)

    def prep(self, **changes):
        return prepare_row_preflight(self.review, **dict(self.args, **changes))

    def reject(self, code, **changes):
        with self.assertRaisesRegex(MappingBlocked,"^"+code+"$"):
            self.prep(**changes)

    def test_deterministic_no_import_or_raw_values(self):
        p=self.prep()
        self.assertEqual(p,self.prep(rows=[list(r) for r in ROWS]))
        self.assertFalse(p.row_import_authorized)
        self.assertEqual(p.row_count,2)
        self.assertNotIn("부품 A",repr(p))
        self.assertNotIn("00017",repr(p))
        self.assertEqual(p,check_row_preflight(p,self.review,**self.args))

    def test_customer_and_optional_business_number(self):
        h=("customer_id","customer_name","business_number")
        r=prepare_header_review(ORG,SOURCE,"customer",h)
        target=make_target_snapshot(ORG,SOURCE,"customer",REV,())
        args=dict(organization_id=ORG,source_id=SOURCE,entity="customer",headers=h,target=target)
        p=prepare_row_preflight(r,**args,rows=(("001","고객사","123-45-67890"),("002","고객사2",None)))
        self.assertEqual(p.row_count,2)
        for bad in (1234567890,"1.23E+09","123-4-67890"," 1234567890","１２３４５６７８９０"):
            with self.assertRaisesRegex(MappingBlocked,"^ROW_BUSINESS_NUMBER_FORMAT$"):
                prepare_row_preflight(r,**args,rows=(("001","고객사",bad),))

    def test_optional_column_absence(self):
        h=("sku","item_name")
        r=prepare_header_review(ORG,SOURCE,ENTITY,h)
        p=prepare_row_preflight(r,**dict(self.args,headers=h,rows=(("001","품목"),)))
        self.assertEqual(p.row_count,1)

    def test_header_or_scope_mismatch(self):
        self.reject("REVIEW_SCOPE_MISMATCH",organization_id="org-b")
        self.reject("REVIEW_SCOPE_MISMATCH",source_id="different")
        self.reject("REVIEW_HEADER_MISMATCH",headers=("item_name","sku","unit"))
        self.reject("REVIEW_HEADER_MISMATCH",headers=("item_id","item_name","unit"))

    def test_target_scope_and_forgery(self):
        for org,source,entity in (("org-b",SOURCE,ENTITY),(ORG,"other",ENTITY),(ORG,SOURCE,"customer")):
            self.reject("TARGET_SCOPE_MISMATCH",target=make_target_snapshot(org,source,entity,REV,()))
        self.reject("TARGET_TYPE",target={})
        self.reject("TARGET_SNAPSHOT_MISMATCH",target=replace(self.target,snapshot_sha256="0"*64))
        self.reject("TARGET_SNAPSHOT_MISMATCH",target=replace(self.target,existing_source_ids=()))
        self.reject("TARGET_SNAPSHOT_MISMATCH",target=replace(self.target,revision="revision-2"))

    def test_target_invalid_inputs(self):
        for args, code in (
            ((ORG,SOURCE,ENTITY,REV,("x","X")),"TARGET_AMBIGUOUS_ID"),
            ((ORG,SOURCE,ENTITY,REV,(True,)),"TARGET_SOURCE_ID_INVALID"),
            ((ORG,SOURCE,ENTITY,REV,["x"]*(MAX_EXISTING_IDS+1)),"TARGET_COUNT"),
            ((ORG,SOURCE,ENTITY,REV,"x"),"TARGET_COUNT"),
            ((ORG,SOURCE,ENTITY,None,()),"TARGET_REVISION_INVALID"),
            ((ORG,SOURCE,"other",REV,()),"TARGET_ENTITY_INVALID"),
            ((True,SOURCE,ENTITY,REV,()),"TARGET_IDENTITY_INVALID")):
            with self.assertRaisesRegex(MappingBlocked,"^"+code+"$"):
                make_target_snapshot(*args)

    def test_row_count_and_width(self):
        for rows in (None, [], {}, "text", [ROWS[0]]*(MAX_ROWS+1)):
            self.reject("ROW_COUNT",rows=rows)
        for row in (None,{}, "abc", ("a","name"), ("a","name","EA","extra")):
            self.reject("ROW_WIDTH",rows=(row,))

    def test_ids_exact_strings_no_coercion(self):
        for val in (17,17.0,True,None,"", " 17","17 ","=17","1e+3","１２","a/b","a\n","x"*129):
            self.reject("ROW_SOURCE_ID_INVALID",rows=((val,"name","EA"),))
        a=self.prep(rows=(("001","name","EA"),))
        b=self.prep(rows=(("1","name","EA"),))
        self.assertNotEqual(a.rows_sha256,b.rows_sha256)

    def test_duplicate_and_existing_conflicts(self):
        self.reject("ROW_DUPLICATE_SOURCE_ID",rows=(("A","a",None),("a","b",None)))
        self.reject("ROW_TARGET_CONFLICT",rows=(("00001","a",None),))
        target=make_target_snapshot(ORG,SOURCE,ENTITY,REV,("ABC",))
        self.reject("ROW_TARGET_CONFLICT",target=target,rows=(("abc","a",None),))

    def test_text_and_formula_like_data(self):
        for val in (None,True,1,"","x"*121):
            self.reject("ROW_TEXT_TYPE_OR_LENGTH",rows=(("id",val,None),))
        for val in (" name","name ","x\n","x\u200b","x\u202e","x\u2028","x\ud800","e\u0301"):
            self.reject("ROW_TEXT_UNSAFE",rows=(("id",val,None),))
        for val in ("=SUM(A1)","+1","-1","@cmd"):
            self.reject("ROW_FORMULA_LIKE",rows=(("id",val,None),))
        self.reject("ROW_TEXT_TYPE_OR_LENGTH",rows=(("id","name","x"*33),))

    def test_changed_rows_and_target_version_rejected(self):
        p=self.prep()
        for changes in (dict(rows=tuple(reversed(ROWS))),
                        dict(rows=(("00017","changed","EA"),ROWS[1])),
                        dict(rows=(ROWS[0],("00018","부품 B",""))),
                        dict(target=make_target_snapshot(ORG,SOURCE,ENTITY,"revision-2",("00001",))),
                        dict(target=make_target_snapshot(ORG,SOURCE,ENTITY,REV,("00002",)))):
            with self.assertRaisesRegex(MappingBlocked,"^PREFLIGHT_STALE_OR_CHANGED$"):
                check_row_preflight(p,self.review,**dict(self.args,**changes))

    def test_forged_preflight_cannot_authorize(self):
        p=self.prep()
        for value in (True,0,None):
            with self.assertRaisesRegex(MappingBlocked,"^PREFLIGHT_IMPORT_FORBIDDEN$"):
                check_row_preflight(replace(p,row_import_authorized=value),self.review,**self.args)
        for change in (dict(row_count=True),dict(binding_sha256="0"*64),dict(organization_id="org-b")):
            with self.assertRaisesRegex(MappingBlocked,"^PREFLIGHT_STALE_OR_CHANGED$"):
                check_row_preflight(replace(p,**change),self.review,**self.args)
        with self.assertRaisesRegex(MappingBlocked,"^PREFLIGHT_TYPE$"):
            check_row_preflight({},self.review,**self.args)

    def test_maximum_batch_and_snapshot(self):
        target=make_target_snapshot(ORG,SOURCE,ENTITY,REV,tuple(f"old-{i}" for i in range(MAX_EXISTING_IDS)))
        rows=tuple((f"new-{i}","품목","EA") for i in range(MAX_ROWS))
        self.assertEqual(self.prep(rows=rows,target=target).row_count,MAX_ROWS)
        # Snapshot order is irrelevant; row order is not.
        other=make_target_snapshot(ORG,SOURCE,ENTITY,REV,tuple(reversed(target.existing_source_ids)))
        self.assertEqual(other,target)

    def test_varied_rows_scope_and_stale_negative_controls(self):
        rng=random.Random(int(os.environ.get("NARUV_TEST_SEED","1")))
        for i in range(100):
            org=f"org-{rng.randrange(100000)}"
            source=f"erp-{i}"
            header=list(HEADERS)
            rng.shuffle(header)
            data={"sku":f"{i:06d}","item_name":f"품목 {i}","unit":"EA"}
            row=tuple(data[h] for h in header)
            review=prepare_header_review(org,source,ENTITY,header)
            target=make_target_snapshot(org,source,ENTITY,REV,())
            args=dict(organization_id=org,source_id=source,entity=ENTITY,headers=header,rows=(row,),target=target)
            p=prepare_row_preflight(review,**args)
            self.assertFalse(p.row_import_authorized)
            self.assertEqual(p,check_row_preflight(p,review,**args))
            with self.assertRaisesRegex(MappingBlocked,"^ROW_DUPLICATE_SOURCE_ID$"):
                prepare_row_preflight(review,**dict(args,rows=(row,row)))
            with self.assertRaisesRegex(MappingBlocked,"^TARGET_SCOPE_MISMATCH$"):
                prepare_row_preflight(review,**dict(args,target=make_target_snapshot(org+"-other",source,ENTITY,REV,())))
            with self.assertRaisesRegex(MappingBlocked,"^PREFLIGHT_STALE_OR_CHANGED$"):
                check_row_preflight(p,review,**dict(args,target=make_target_snapshot(org,source,ENTITY,"rev-2",())))
