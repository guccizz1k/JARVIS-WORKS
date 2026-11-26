import csv
from dataclasses import replace
import hashlib
import io
import os
import random
import unittest

from app.erp_migration_mapping import MappingBlocked
from app.erp_migration_preflight import make_target_snapshot
from app.erp_migration_csv import (
    MAX_CSV_BYTES, MAX_CELL_CHARS, _parse, prepare_csv_preview, check_csv_preview,
)

ORG,SOURCE,ENTITY="org-a","erp-1","item"
RAW="sku,item_name,unit\n0001,품목 A,EA\n0002,품목 B,\n".encode()

def encode(rows,ending="\n"):
    f=io.StringIO(newline="")
    csv.writer(f,lineterminator=ending).writerows(rows)
    return f.getvalue().encode("utf-8")

class CsvPreviewTests(unittest.TestCase):
    def setUp(self):
        self.target=make_target_snapshot(ORG,SOURCE,ENTITY,"rev-1",())
        self.args=dict(organization_id=ORG,source_id=SOURCE,entity=ENTITY,target=self.target)

    def prepare(self,raw=RAW,**change):
        return prepare_csv_preview(raw,**dict(self.args,**change))

    def reject(self,reason,raw=RAW,**change):
        with self.assertRaisesRegex(MappingBlocked,"^"+reason+"$"):
            self.prepare(raw,**change)

    def test_exact_bytes_no_raw_values_in_preview(self):
        p=self.prepare()
        self.assertEqual(p.preflight.row_count,2)
        self.assertEqual(p.raw_sha256,hashlib.sha256(RAW).hexdigest())
        self.assertFalse(p.row_import_authorized)
        self.assertNotIn("품목 A",repr(p))
        self.assertNotIn("0001",repr(p))
        self.assertEqual(p,check_csv_preview(p,RAW,**self.args))

    def test_korean_customer_and_business_number(self):
        rows=(("거래처코드","거래처명","사업자등록번호"),
              ("00001","기업 A","012-34-56789"),("00002","기업 B",""))
        raw=encode(rows)
        target=make_target_snapshot(ORG,SOURCE,"customer","rev-1",())
        p=self.prepare(raw,entity="customer",target=target)
        self.assertEqual(p.preflight.row_count,2)
        self.assertEqual(_parse(raw),(rows[0],rows[1:]))

    def test_quoted_comma_double_quote_and_leading_zero(self):
        rows=(("sku","item_name","unit"),("00001",'부품 "A", 특수',"EA"))
        raw=encode(rows)
        self.assertEqual(_parse(raw),(rows[0],rows[1:]))
        self.assertEqual(self.prepare(raw).preflight.row_count,1)

    def test_bom_and_crlf_bound_exactly(self):
        rows=(("sku","item_name"),("001","품목"))
        a=encode(rows)
        b=b"\xef\xbb\xbf"+encode(rows,"\r\n")
        pa,pb=self.prepare(a),self.prepare(b)
        self.assertEqual(pa.preflight,pb.preflight)
        self.assertNotEqual(pa.raw_sha256,pb.raw_sha256)
        with self.assertRaisesRegex(MappingBlocked,"^CSV_SOURCE_CHANGED$"):
            check_csv_preview(pa,b,**self.args)

    def test_encoding_and_control_errors(self):
        self.reject("CSV_ENCODING",b"sku,item_name\n001,\xff")
        self.reject("CSV_NUL",b"sku,item_name\n001,a\x00")
        self.reject("CSV_LINE_ENDING",b"sku,item_name\r\n001,a\n")
        self.reject("CSV_LINE_ENDING",b"sku,item_name\r001,a")
        self.reject("ROW_TEXT_UNSAFE","sku,item_name\n001,a\u200b".encode())

    def test_malformed_quotes(self):
        for raw in (b'sku,item_name\n001,"open',b'sku,item_name\n001,a"b',
                    b'sku,item_name\n001,"a"tail',b'sku,item_name\n001,"a\nb"'):
            self.reject("CSV_QUOTE_SYNTAX",raw)

    def test_blank_missing_and_excess_records(self):
        self.reject("CSV_RECORD_COUNT",b"sku,item_name\n")
        self.reject("CSV_BLANK_RECORD",b"sku,item_name\n\n001,a")
        self.reject("CSV_BLANK_RECORD",b"sku,item_name\n001,a\n\n")
        self.reject("CSV_RECORD_COUNT",b"sku,item_name\n"+b"001,a\n"*1001)

    def test_byte_column_cell_limits(self):
        for raw in (None,True,"text",b"",bytearray(RAW),b"x"*(MAX_CSV_BYTES+1)):
            self.reject("CSV_BYTE_LIMIT",raw)
        self.reject("CSV_COLUMN_COUNT",b",".join([b"x"]*65)+b"\n001,a")
        self.reject("CSV_CELL_LENGTH",b"sku,item_name\n001,"+b"x"*(MAX_CELL_CHARS+1))

    def test_existing_planner_and_preflight_fail_closed(self):
        for raw,reason in (
            (b"sku,unknown\n001,a","UNMAPPED_HEADER"),
            (b"sku,SKU,item_name\n001,001,a","DUPLICATE_HEADER"),
            (b"sku,item_name\n001","ROW_WIDTH"),
            (b"sku,item_name\n001,a,EA","ROW_WIDTH"),
            (b"sku,item_name\n001,","ROW_TEXT_TYPE_OR_LENGTH"),
            (b"sku,item_name\n001,=SUM(A1)","ROW_FORMULA_LIKE"),
            (b"sku,item_name\n001,a\n001,b","ROW_DUPLICATE_SOURCE_ID"),
            (b"sku,item_name\nABC,a\nabc,b","ROW_DUPLICATE_SOURCE_ID"),
            (b"sku,item_name\n1e+3,a","ROW_SOURCE_ID_INVALID"),
        ):
            with self.subTest(reason=reason):
                self.reject(reason,raw)

    def test_target_collision_and_scope(self):
        target=make_target_snapshot(ORG,SOURCE,ENTITY,"rev-1",("0001",))
        self.reject("ROW_TARGET_CONFLICT",target=target)
        self.reject("TARGET_SCOPE_MISMATCH",organization_id="org-b")
        p=self.prepare()
        with self.assertRaisesRegex(MappingBlocked,"^REVIEW_SCOPE_MISMATCH$"):
            check_csv_preview(p,RAW,**dict(self.args,source_id="erp-2"))

    def test_stale_target_and_raw_changes(self):
        p=self.prepare()
        for raw in (RAW.replace(b"0001",b"0003"),RAW+b"\n"):
            with self.assertRaisesRegex(MappingBlocked,"^CSV_SOURCE_CHANGED$"):
                check_csv_preview(p,raw,**self.args)
        target=make_target_snapshot(ORG,SOURCE,ENTITY,"rev-2",())
        with self.assertRaisesRegex(MappingBlocked,"^PREFLIGHT_STALE_OR_CHANGED$"):
            check_csv_preview(p,RAW,**dict(self.args,target=target))

    def test_forged_preview_metadata(self):
        p=self.prepare()
        for mutated,reason in (
            (replace(p,row_import_authorized=0),"CSV_IMPORT_FORBIDDEN"),
            (replace(p,byte_count=True),"CSV_SOURCE_CHANGED"),
            (replace(p,raw_sha256="가"*64),"CSV_SOURCE_CHANGED"),
            (replace(p,review=replace(p.review,row_import_authorized=True)),"REVIEW_IMPORT_FORBIDDEN"),
            (replace(p,preflight=replace(p.preflight,row_import_authorized=True)),"PREFLIGHT_IMPORT_FORBIDDEN"),
            (replace(p,preflight=replace(p.preflight,row_count=True)),"PREFLIGHT_STALE_OR_CHANGED"),
        ):
            with self.assertRaisesRegex(MappingBlocked,"^"+reason+"$"):
                check_csv_preview(mutated,RAW,**self.args)

    def test_maximum_row_count(self):
        rows=[("sku","item_name")]+[(f"{i:06d}","품목") for i in range(1000)]
        self.assertEqual(self.prepare(encode(rows)).preflight.row_count,1000)

    def test_varied_csv_writer_oracle_and_negative_controls(self):
        rng=random.Random(int(os.environ.get("NARUV_TEST_SEED","1")))
        for i in range(100):
            h=["sku","item_name","unit"]
            rng.shuffle(h)
            data={"sku":f"{i:06d}","item_name":f'품목 "{i}", A',"unit":"EA"}
            row=tuple(data[k] for k in h)
            raw=encode((tuple(h),row),rng.choice(("\n","\r\n")))
            if rng.randrange(2):raw=b"\xef\xbb\xbf"+raw
            self.assertEqual(_parse(raw),(tuple(h),(row,)))
            p=self.prepare(raw)
            self.assertEqual(p,check_csv_preview(p,raw,**self.args))
            with self.assertRaisesRegex(MappingBlocked,"^CSV_SOURCE_CHANGED$"):
                check_csv_preview(p,raw+b"x",**self.args)
            self.reject("ROW_DUPLICATE_SOURCE_ID",encode((h,row,row)))
            self.reject("ROW_WIDTH",encode((h,row[:-1])))
