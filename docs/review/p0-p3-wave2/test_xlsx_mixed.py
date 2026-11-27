import io,zipfile,unittest
from openpyxl import Workbook
from app.erp_migration_xlsx import parse_xlsx,MappingBlocked
class Mixed(unittest.TestCase):
    def original(self):
        w=Workbook();w.active.append(["sku","item_name"]);w.active.append(["001","Widget"])
        f=io.BytesIO();w.save(f);w.close();return f.getvalue()
    def mutate(self,old,new):
        a=io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(self.original())) as z,zipfile.ZipFile(a,"w",zipfile.ZIP_DEFLATED) as out:
            for n in z.namelist():
                b=z.read(n)
                if n=="xl/worksheets/sheet1.xml":
                    self.assertEqual(b.count(old),1);b=b.replace(old,new)
                out.writestr(n,b)
        return a.getvalue()
    def test_original(self):
        self.assertEqual(parse_xlsx(self.original()),(("sku","item_name"),(("001","Widget"),)))
    def test_nonempty_mixed(self):
        for a,b in ((b"<is><t>Widget</t></is>",b"<is>BAD<t>Widget</t></is>"),(b"<is><t>Widget</t></is>",b"<is><t>Widget</t>BAD</is>"),(b"<is><t>Widget</t></is>",b"BAD<is><t>Widget</t></is>")):
            with self.subTest(b=b),self.assertRaisesRegex(MappingBlocked,"XLSX_MIXED_CONTENT"):parse_xlsx(self.mutate(a,b))
    def test_formatting_space(self):
        self.assertEqual(parse_xlsx(self.mutate(b"<is><t>Widget</t></is>",b"<is> \n<t>Widget</t>\n </is>")),parse_xlsx(self.original()))
if __name__=="__main__":unittest.main()
