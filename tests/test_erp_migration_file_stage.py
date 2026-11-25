import io
import zipfile
import unittest
from dataclasses import replace
import os
import random
import warnings

from openpyxl import Workbook
from app.erp_migration_mapping import MappingBlocked
from app.erp_migration_preflight import make_target_snapshot
from app.erp_migration_xlsx import parse_xlsx
from app.erp_migration_file_stage import prepare_file_stage, check_file_stage

H=("sku","item_name")
ROWS=(("0001","품목 A"),("0002","품목 B"))
ORG,SOURCE,ENTITY="org-a","erp-1","item"

def workbook(rows=(H,*ROWS), edit=None):
    w=Workbook()
    for row in rows:w.active.append(row)
    if edit:edit(w)
    out=io.BytesIO()
    w.save(out)
    w.close()
    return out.getvalue()

def mutate(raw,path,fn=None,extra=None):
    out=io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw)) as src, zipfile.ZipFile(out,"w",compression=zipfile.ZIP_DEFLATED) as dst:
        for info in src.infolist():
            content=src.read(info)
            if info.filename==path and fn:content=fn(content)
            dst.writestr(info,content)
        if extra:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore",UserWarning)
                dst.writestr(*extra)
    return out.getvalue()

class FileStageTests(unittest.TestCase):
    def setUp(self):
        self.target=make_target_snapshot(ORG,SOURCE,ENTITY,"rev-1",())
        self.args=dict(organization_id=ORG,source_id=SOURCE,entity=ENTITY,target=self.target)
        self.raw=workbook()

    def stage(self,raw=None,format="xlsx",**changes):
        return prepare_file_stage(self.raw if raw is None else raw,format=format,**dict(self.args,**changes))

    def reject(self,reason,raw):
        with self.assertRaisesRegex(MappingBlocked,"^"+reason+"$"):self.stage(raw)

    def test_real_xlsx_exact_data_and_stage(self):
        self.assertEqual(parse_xlsx(self.raw),(H,ROWS))
        p=self.stage()
        self.assertEqual(p.canonical_rows[0],(("name","품목 A"),("source_item_id","0001")))
        self.assertNotIn("품목 A",repr(p))
        self.assertFalse(p.row_import_authorized)
        self.assertEqual(p,check_file_stage(p,self.raw,format="xlsx",**self.args))

    def test_csv_xlsx_same_semantics_distinct_file_binding(self):
        csv="sku,item_name\n0001,품목 A\n0002,품목 B\n".encode()
        a,b=self.stage(),self.stage(csv,format="csv")
        self.assertEqual(a.preflight,b.preflight)
        self.assertEqual(a.canonical_rows,b.canonical_rows)
        self.assertNotEqual(a.stage_sha256,b.stage_sha256)
        with self.assertRaisesRegex(MappingBlocked,"^FILE_SOURCE_CHANGED$"):
            check_file_stage(a,csv,format="csv",**self.args)

    def test_customer_text_ids(self):
        raw=workbook((("거래처코드","거래처명","사업자번호"),("0001","기업","012-34-56789")))
        p=self.stage(raw,entity="customer",target=make_target_snapshot(ORG,SOURCE,"customer","rev-1",()))
        self.assertEqual(dict(p.canonical_rows[0])["business_number"],"012-34-56789")

    def test_shared_strings_fixture(self):
        # Convert one ordinary inline cell to a shared string and add exact
        # manifest/relationship entries, preserving the other workbook parts.
        raw=mutate(self.raw,"xl/worksheets/sheet1.xml",lambda b:b.replace(
            b'<c r="A2" t="inlineStr"><is><t>0001</t></is></c>',b'<c r="A2" t="s"><v>0</v></c>'))
        raw=mutate(raw,"xl/_rels/workbook.xml.rels",lambda b:b.replace(b"</Relationships>",
            b'<Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml" Id="rId99"/></Relationships>'))
        raw=mutate(raw,"[Content_Types].xml",lambda b:b.replace(b"</Types>",
            b'<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/></Types>'),
            extra=("xl/sharedStrings.xml",b'<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" uniqueCount="1"><si><t>0001</t></si></sst>'))
        self.assertEqual(parse_xlsx(raw),(H,ROWS))
        self.assertEqual(self.stage(raw).preflight,self.stage().preflight)
        bad=mutate(raw,"xl/worksheets/sheet1.xml",lambda b:b.replace(b'<v>0</v>',b'<v>9</v>'))
        self.reject("XLSX_SHARED_INDEX",bad)

    def test_numbers_formulas_and_bool_rejected(self):
        for val in (1,1.5,True,"=1+1"):
            self.reject("XLSX_TEXT_CELLS_ONLY",workbook((H,(val,"품목"))))

    def test_hidden_and_multiple_sheet_rejected(self):
        self.reject("XLSX_UNSUPPORTED_PART",workbook(edit=lambda w:w.create_sheet("Hidden")))
        self.reject("XLSX_ROW_STRUCTURE",workbook(edit=lambda w:setattr(w.active.row_dimensions[2],"hidden",True)))
        self.reject("XLSX_SHEET_FEATURE",workbook(edit=lambda w:setattr(w.active.column_dimensions["A"],"hidden",True)))
        self.reject("XLSX_SHEET_SCOPE",mutate(self.raw,"xl/workbook.xml",lambda b:b.replace(b'state="visible"',b'state="hidden"')))

    def test_merged_and_sparse_cells_rejected(self):
        self.reject("XLSX_SHEET_FEATURE",workbook(edit=lambda w:w.active.merge_cells("A2:B2")))
        self.reject("XLSX_CELL_STRUCTURE",mutate(self.raw,"xl/worksheets/sheet1.xml",lambda b:b.replace(b'r="B2"',b'r="C2"')))
        self.reject("XLSX_DIMENSION",mutate(self.raw,"xl/worksheets/sheet1.xml",lambda b:b.replace(b'A1:B3',b'A1:XFD1048576')))

    def test_duplicate_and_disallowed_package(self):
        for path in ("XL/WORKBOOK.XML","xl/workbook.xml"):
            self.reject("XLSX_DUPLICATE_PART",mutate(self.raw,None,extra=(path,b"<x/>")))
        for path in ("xl/../hidden.xml","xl/vbaProject.bin","xl/externalLinks/externalLink1.xml","xl/embeddings/x.bin"):
            self.reject("XLSX_UNSUPPORTED_PART",mutate(self.raw,None,extra=(path,b"<x/>")))

    def test_external_and_wrong_relationships(self):
        self.reject("XLSX_RELATIONSHIP",mutate(self.raw,"xl/_rels/workbook.xml.rels",lambda b:b.replace(b'Target="/xl/worksheets/sheet1.xml"',b'Target="https://invalid.example/a" TargetMode="External"')))
        self.reject("XLSX_RELATIONSHIP",mutate(self.raw,"xl/_rels/workbook.xml.rels",lambda b:b.replace(b'Target="/xl/worksheets/sheet1.xml"',b'Target="/xl/worksheets/wrong.xml"')))

    def test_xml_dtd_and_limits(self):
        self.reject("XLSX_XML_UNSAFE",mutate(self.raw,"xl/workbook.xml",lambda b:b'<!DOCTYPE workbook [<!ENTITY x "a">]>'+b))
        self.reject("XLSX_BYTE_LIMIT",b"x"*(1024*1024+1))
        self.reject("XLSX_PACKAGE_INVALID",b"not a zip")
        self.reject("XLSX_CELL_LENGTH",workbook((H,("001","x"*257))))

    def test_existing_preflight_checks(self):
        self.reject("ROW_DUPLICATE_SOURCE_ID",workbook((H,("ABC","a"),("abc","b"))))
        self.reject("ROW_FORMULA_LIKE",workbook((H,("001","@cmd"))))
        self.reject("UNMAPPED_HEADER",workbook((("sku","unknown"),("001","a"))))

    def test_exact_source_and_scope_recheck(self):
        p=self.stage()
        with self.assertRaisesRegex(MappingBlocked,"^FILE_SOURCE_CHANGED$"):
            check_file_stage(p,workbook((H,("0001","changed"))),format="xlsx",**self.args)
        with self.assertRaisesRegex(MappingBlocked,"^REVIEW_SCOPE_MISMATCH$"):
            check_file_stage(p,self.raw,format="xlsx",**dict(self.args,source_id="other"))
        with self.assertRaisesRegex(MappingBlocked,"^PREFLIGHT_STALE_OR_CHANGED$"):
            check_file_stage(p,self.raw,format="xlsx",**dict(self.args,target=make_target_snapshot(ORG,SOURCE,ENTITY,"rev-2",())))

    def test_forged_stage(self):
        p=self.stage()
        for q,reason in ((replace(p,row_import_authorized=0),"FILE_STAGE_TYPE_OR_AUTHORITY"),
                         (replace(p,stage_sha256="0"*64),"FILE_STAGE_CHANGED"),
                         (replace(p,canonical_rows=()),"FILE_STAGE_CHANGED"),
                         (replace(p,preflight=replace(p.preflight,row_import_authorized=True)),"PREFLIGHT_IMPORT_FORBIDDEN")):
            with self.assertRaisesRegex(MappingBlocked,"^"+reason+"$"):
                check_file_stage(q,self.raw,format="xlsx",**self.args)

    def test_varied_actual_workbooks(self):
        rng=random.Random(int(os.environ.get("NARUV_TEST_SEED","17")))
        for i in range(20):
            h=list(H);rng.shuffle(h)
            data={"sku":f"{i:06d}","item_name":f'품목 "{i}", A'}
            row=tuple(data[k] for k in h)
            raw=workbook((tuple(h),row))
            self.assertEqual(parse_xlsx(raw),(tuple(h),(row,)))
            p=self.stage(raw)
            self.assertEqual(dict(p.canonical_rows[0])["source_item_id"],data["sku"])
            self.assertEqual(p,check_file_stage(p,raw,format="xlsx",**self.args))
            self.reject("ROW_DUPLICATE_SOURCE_ID",workbook((tuple(h),row,row)))
