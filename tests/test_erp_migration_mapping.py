import hashlib
import json
import os
import random
import unittest
from dataclasses import FrozenInstanceError
from app.erp_migration_mapping import MappingBlocked, plan_headers

class MigrationHeaderTests(unittest.TestCase):
    def reject(self, entity, headers, code):
        with self.assertRaisesRegex(MappingBlocked, "^"+code+"$"):
            plan_headers(entity, headers)
    def test_customer_mapping(self):
        p=plan_headers("customer", ["거래처코드","거래처명","사업자등록번호"])
        self.assertEqual(p.fields, ((0,"source_customer_id"),(1,"name"),(2,"business_number")))
        self.assertFalse(p.row_import_authorized)
    def test_item_mapping(self):
        p=plan_headers("item", ["SKU","Item Name","Unit"])
        self.assertEqual(p.fields, ((0,"source_item_id"),(1,"name"),(2,"unit")))
    def test_exact_digest(self):
        h=["거래처코드","거래처명"]
        p=plan_headers("customer",h)
        want=hashlib.sha256(json.dumps({"version":1,"entity":"customer","headers":h},ensure_ascii=False,separators=(",",":"),sort_keys=True).encode()).hexdigest()
        self.assertEqual(p.source_headers_sha256,want)
        h.reverse()
        self.assertNotEqual(p.source_headers_sha256,plan_headers("customer",h).source_headers_sha256)
    def test_frozen_plan(self):
        p=plan_headers("item",["sku","품목명"])
        with self.assertRaises(FrozenInstanceError):
            p.row_import_authorized=True
    def test_duplicate_header(self):
        self.reject("item",["SKU","sku","품목명"],"DUPLICATE_HEADER")
    def test_duplicate_target(self):
        self.reject("customer",["customer_id","거래처코드","거래처명"],"DUPLICATE_TARGET")
    def test_missing_required(self):
        self.reject("customer",["거래처명"],"REQUIRED_FIELD_MISSING")
    def test_unknown_header_no_silent_drop(self):
        self.reject("customer",["거래처코드","거래처명","급여"],"UNMAPPED_HEADER")
    def test_unsupported_entity(self):
        self.reject("payroll",["name"],"ENTITY_UNSUPPORTED")
    def test_bad_header_character(self):
        for bad in ["=SUM(A1)","거래처명\u200b","ＳＫＵ","sku\n","sku\t","sku\u202e","sku\x00"]:
            with self.subTest(bad=repr(bad)):
                self.reject("item",["품목코드",bad],"HEADER_UNSUPPORTED_CHARACTER")
    def test_invalid_shape(self):
        for bad in [None,"sku",[],["sku"]*65]:
            self.reject("item",bad,"HEADER_COUNT")
        for bad in [True,1,None,"x"*101]:
            self.reject("item",["sku",bad],"HEADER_TYPE_OR_LENGTH")
        self.reject("item",["sku","  "],"HEADER_EMPTY")
    def test_varied_order_and_aliases(self):
        rng=random.Random(int(os.environ.get("NARUV_TEST_SEED","1")))
        choices=[("source_item_id",["sku","item_id","품목 코드"]),("name",["item_name","품목명","item name"]),("unit",["unit","단위"])]
        for _ in range(100):
            pairs=[(field,rng.choice(variants)) for field,variants in choices]
            rng.shuffle(pairs)
            headers=[s for _,s in pairs]
            p=plan_headers("item",headers)
            self.assertEqual(p.fields,tuple((i,f) for i,(f,_) in enumerate(pairs)))
            self.assertFalse(p.row_import_authorized)
            self.assertEqual(p,plan_headers("item",tuple(headers)))
            mutated=list(headers)
            mutated[rng.randrange(len(mutated))]="unknown_"+str(rng.randrange(100000))
            self.reject("item",mutated,"UNMAPPED_HEADER")
