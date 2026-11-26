import os
import random
import unittest
from dataclasses import replace
from app.erp_migration_mapping import MappingBlocked
from app.erp_migration_review import prepare_header_review, check_header_review

ORG = "org-a"
SOURCE = "export-001"
HEADERS = ("sku", "item_name", "unit")

class MigrationReviewTests(unittest.TestCase):
    def setUp(self):
        self.review = prepare_header_review(ORG, SOURCE, "item", HEADERS)

    def check(self, review=None, **changes):
        args = dict(organization_id=ORG, source_id=SOURCE, entity="item", headers=HEADERS)
        args.update(changes)
        return check_header_review(self.review if review is None else review, **args)

    def test_deterministic_binding_never_authorizes_import(self):
        self.assertEqual(self.review, self.check())
        self.assertFalse(self.check().row_import_authorized)
        self.assertEqual(len(self.review.binding_sha256), 64)

    def test_same_headers_distinct_enterprise_or_source(self):
        for org, source in (("org-b", SOURCE), (ORG, "export-002")):
            other = prepare_header_review(org, source, "item", HEADERS)
            self.assertEqual(other.source_headers_sha256, self.review.source_headers_sha256)
            self.assertNotEqual(other.binding_sha256, self.review.binding_sha256)
            with self.assertRaisesRegex(MappingBlocked, "^REVIEW_SCOPE_MISMATCH$"):
                self.check(organization_id=org, source_id=source)

    def test_stale_order_and_alias(self):
        for headers in (("item_name", "sku", "unit"), ("item_id", "item_name", "unit"),
                        ("SKU", "item_name", "unit"), ("sku", "item_name")):
            with self.subTest(headers=headers), self.assertRaisesRegex(MappingBlocked, "^REVIEW_HEADER_MISMATCH$"):
                self.check(headers=headers)

    def test_invalid_identity(self):
        for v in (None, True, 1, "", " ", "a/b", "a\n", "x"*129, "기업"):
            for org, source in ((v, SOURCE), (ORG, v)):
                with self.subTest(v=v), self.assertRaisesRegex(MappingBlocked, "^REVIEW_IDENTITY_INVALID$"):
                    prepare_header_review(org, source, "item", HEADERS)

    def test_mutation_rejection(self):
        for values, code in (
            ({"organization_id":"org-b"}, "REVIEW_SCOPE_MISMATCH"),
            ({"source_id":"export-002"}, "REVIEW_SCOPE_MISMATCH"),
            ({"entity":"customer"}, "REVIEW_HEADER_MISMATCH"),
            ({"source_headers_sha256":"0"*64}, "REVIEW_HEADER_MISMATCH"),
            ({"fields":((False,"source_item_id"),(1,"name"),(2,"unit"))}, "REVIEW_MAPPING_MISMATCH"),
            ({"fields":((0,"name"),(1,"source_item_id"),(2,"unit"))}, "REVIEW_MAPPING_MISMATCH"),
            ({"row_import_authorized":True}, "REVIEW_IMPORT_FORBIDDEN"),
            ({"row_import_authorized":0}, "REVIEW_IMPORT_FORBIDDEN"),
            ({"binding_sha256":"0"*64}, "REVIEW_BINDING_MISMATCH"),
        ):
            with self.subTest(code=code), self.assertRaisesRegex(MappingBlocked,"^"+code+"$"):
                self.check(replace(self.review, **values))

    def test_recomputed_binding_is_not_authentication(self):
        # Anyone with the public metadata can compute a hash; no authority claim.
        other=prepare_header_review("org-b",SOURCE,"item",HEADERS)
        self.assertFalse(self.check(other,organization_id="org-b").row_import_authorized)
        with self.assertRaisesRegex(MappingBlocked, "^REVIEW_SCOPE_MISMATCH$"):
            self.check(other)

    def test_mapping_validation_preserved(self):
        for headers, code in ((("sku","SKU","item_name"),"DUPLICATE_HEADER"),
                              (("sku","item_name","unknown"),"UNMAPPED_HEADER"),
                              (("sku",),"REQUIRED_FIELD_MISSING")):
            with self.assertRaisesRegex(MappingBlocked,"^"+code+"$"):
                self.check(headers=headers)

    def test_varied_scope_and_header_mutations(self):
        rng=random.Random(int(os.environ.get("NARUV_TEST_SEED","1")))
        for index in range(100):
            org=f"org-{rng.randrange(1000000)}"
            source=f"source-{index}"
            headers=[rng.choice(("sku","item_id","품목코드")),
                     rng.choice(("item_name","품목명")),rng.choice(("unit","단위"))]
            rng.shuffle(headers)
            review=prepare_header_review(org,source,"item",headers)
            args=dict(organization_id=org,source_id=source,entity="item",headers=headers)
            self.assertEqual(review,check_header_review(review,**args))
            self.assertFalse(review.row_import_authorized)
            with self.assertRaisesRegex(MappingBlocked,"^REVIEW_SCOPE_MISMATCH$"):
                check_header_review(review,**dict(args,organization_id=org+"-other"))
            with self.assertRaisesRegex(MappingBlocked,"^REVIEW_HEADER_MISMATCH$"):
                check_header_review(review,**dict(args,headers=list(reversed(headers))))
