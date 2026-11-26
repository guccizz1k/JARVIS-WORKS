"""Strict bounded OOXML master-data reader; only the documented subset.

Reuses the ZIP safety principles from reviewed PR151 (518c6c2), with a
narrower exact part/relationship allowlist. No change to import_engine.
No openpyxl interpretation of untrusted cells, no formula evaluation,
filesystem extraction, external network, or implicit numeric conversion.
"""
import io
import re
import stat
import zipfile
from xml.etree import ElementTree as ET

from app.erp_migration_mapping import MappingBlocked
from app.erp_migration_preflight import MAX_ROWS

MAX_BYTES=1024*1024
MAX_EXPANDED=8*1024*1024
MAX_PART=4*1024*1024
S="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
R="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
P="http://schemas.openxmlformats.org/package/2006/relationships"
C="http://schemas.openxmlformats.org/package/2006/content-types"
REQUIRED={"[Content_Types].xml","_rels/.rels","xl/workbook.xml",
          "xl/_rels/workbook.xml.rels","xl/worksheets/sheet1.xml"}
OPTIONAL={"docProps/app.xml","docProps/core.xml","xl/theme/theme1.xml",
          "xl/styles.xml","xl/sharedStrings.xml"}
TYPES={
    "xl/workbook.xml":"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
    "xl/worksheets/sheet1.xml":"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml",
    "xl/styles.xml":"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml",
    "xl/theme/theme1.xml":"application/vnd.openxmlformats-officedocument.theme+xml",
    "xl/sharedStrings.xml":"application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml",
    "docProps/core.xml":"application/vnd.openxmlformats-package.core-properties+xml",
    "docProps/app.xml":"application/vnd.openxmlformats-officedocument.extended-properties+xml",
}

def need(ok,reason):
    if not ok:
        raise MappingBlocked(reason)

def q(name,ns=S):
    return "{"+ns+"}"+name

def only(parent,allowed,reason):
    need(all(child.tag in {q(x) for x in allowed} for child in parent),reason)

def one(parent,name):
    nodes=parent.findall(q(name))
    need(len(nodes)==1,"XLSX_STRUCTURE")
    return nodes[0]

def xml(raw):
    try:
        text=raw.decode("utf-8-sig")
        need("<!DOCTYPE" not in text.upper() and "<!ENTITY" not in text.upper()
             and "\x00" not in text,"XLSX_XML_UNSAFE")
        return ET.fromstring(text)
    except (UnicodeError,ET.ParseError):
        raise MappingBlocked("XLSX_XML_INVALID") from None

def package(raw):
    need(type(raw) is bytes and 0<len(raw)<=MAX_BYTES,"XLSX_BYTE_LIMIT")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            parts=z.infolist()
            need(len(parts)<=len(REQUIRED|OPTIONAL)
                 and sum(p.file_size for p in parts)<=MAX_EXPANDED
                 and all(0<p.file_size<=MAX_PART for p in parts),"XLSX_PACKAGE_LIMIT")
            names=[p.filename for p in parts]
            need(len(set(n.casefold() for n in names))==len(names),"XLSX_DUPLICATE_PART")
            need(REQUIRED<=set(names)<=REQUIRED|OPTIONAL,"XLSX_UNSUPPORTED_PART")
            for p in parts:
                need(not p.flag_bits&1 and p.compress_type in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED)
                    and not (p.create_system==3 and stat.S_IFMT(p.external_attr>>16)==stat.S_IFLNK),
                    "XLSX_PACKAGE_MEMBER")
            return {p.filename:xml(z.read(p)) for p in parts}
    except MappingBlocked:
        raise
    except (zipfile.BadZipFile,RuntimeError,ValueError,OSError,NotImplementedError):
        raise MappingBlocked("XLSX_PACKAGE_INVALID") from None

def relationships(root,expected):
    need(root.tag==q("Relationships",P),"XLSX_RELATIONSHIP")
    result={}
    seen=set()
    for link in root:
        need(link.tag==q("Relationship",P) and set(link.attrib)=={"Id","Type","Target"},
             "XLSX_RELATIONSHIP")
        ident,kind,target=(link.get(k) for k in ("Id","Type","Target"))
        need(bool(ident) and ident not in result and kind in expected
             and kind not in seen and target in expected[kind],"XLSX_RELATIONSHIP")
        result[ident]=kind
        seen.add(kind)
    need(seen==set(expected),"XLSX_RELATIONSHIP")
    return result

def check_manifest(parts):
    root=parts["[Content_Types].xml"]
    need(root.tag==q("Types",C),"XLSX_CONTENT_TYPE")
    overrides={}
    defaults={}
    for node in root:
        if node.tag==q("Override",C):
            key=node.get("PartName")
            need(key not in overrides and set(node.attrib)=={"PartName","ContentType"},
                 "XLSX_CONTENT_TYPE")
            overrides[key]=node.get("ContentType")
        elif node.tag==q("Default",C):
            key=node.get("Extension")
            need(key not in defaults and set(node.attrib)=={"Extension","ContentType"},
                 "XLSX_CONTENT_TYPE")
            defaults[key]=node.get("ContentType")
        else:
            raise MappingBlocked("XLSX_CONTENT_TYPE")
    need(defaults=={"rels":"application/vnd.openxmlformats-package.relationships+xml",
                    "xml":"application/xml"},"XLSX_CONTENT_TYPE")
    need(overrides=={"/"+p:TYPES[p] for p in parts if p in TYPES},"XLSX_CONTENT_TYPE")
    root_links={R+"/officeDocument":{"xl/workbook.xml","/xl/workbook.xml"}}
    if "docProps/core.xml" in parts:
        root_links[P+"/metadata/core-properties"]={"docProps/core.xml","/docProps/core.xml"}
    if "docProps/app.xml" in parts:
        root_links[R+"/extended-properties"]={"docProps/app.xml","/docProps/app.xml"}
    relationships(parts["_rels/.rels"],root_links)
    book_links={R+"/worksheet":{"worksheets/sheet1.xml","/xl/worksheets/sheet1.xml"}}
    for path,kind in (("xl/styles.xml","styles"),("xl/theme/theme1.xml","theme"),
                      ("xl/sharedStrings.xml","sharedStrings")):
        if path in parts:
            book_links[R+"/"+kind]={path[3:],"/"+path}
    links=relationships(parts["xl/_rels/workbook.xml.rels"],book_links)
    book=parts["xl/workbook.xml"]
    need(book.tag==q("workbook"),"XLSX_WORKBOOK")
    only(book,{"workbookPr","workbookProtection","bookViews","sheets","definedNames",
               "calcPr","fileVersion"},"XLSX_WORKBOOK_FEATURE")
    sheets=one(book,"sheets")
    need(len(sheets)==1 and sheets[0].tag==q("sheet"),"XLSX_SINGLE_SHEET")
    sheet=sheets[0]
    need(sheet.get("state","visible")=="visible" and links.get(sheet.get(q("id",R)))==R+"/worksheet",
         "XLSX_SHEET_SCOPE")
    for names in book.findall(q("definedNames")):
        need(len(names)==0,"XLSX_DEFINED_NAMES")
    for view in book.iter(q("workbookView")):
        need(view.get("visibility","visible")=="visible","XLSX_SHEET_SCOPE")

def text_node(parent):
    need(len(parent)==1 and parent[0].tag==q("t") and len(parent[0])==0,
         "XLSX_STRING_TYPE")
    value=parent[0].text or ""
    need(len(value)<=256,"XLSX_CELL_LENGTH")
    return value

def shared_strings(parts):
    if "xl/sharedStrings.xml" not in parts:
        return ()
    root=parts["xl/sharedStrings.xml"]
    need(root.tag==q("sst") and len(root)<=((MAX_ROWS+1)*64),"XLSX_SHARED_STRINGS")
    values=[]
    for node in root:
        need(node.tag==q("si"),"XLSX_SHARED_STRINGS")
        values.append(text_node(node))
    if "uniqueCount" in root.attrib:
        need(root.get("uniqueCount")==str(len(values)),"XLSX_SHARED_STRINGS")
    return tuple(values)

def cell_name(index,row):
    name=""
    while index:
        index,d=divmod(index-1,26)
        name=chr(65+d)+name
    return name+str(row)

def parse_xlsx(raw):
    parts=package(raw)
    check_manifest(parts)
    shared=shared_strings(parts)
    sheet=parts["xl/worksheets/sheet1.xml"]
    need(sheet.tag==q("worksheet"),"XLSX_STRUCTURE")
    only(sheet,{"sheetPr","dimension","sheetViews","sheetFormatPr","sheetData","pageMargins"},
         "XLSX_SHEET_FEATURE")
    for view in sheet.iter(q("sheetView")):
        need(view.get("showZeros","1")!="0","XLSX_SHEET_FEATURE")
    data=one(sheet,"sheetData")
    need(2<=len(data)<=MAX_ROWS+1,"XLSX_ROW_COUNT")
    matrix=[]
    width=None
    for i,row in enumerate(data,1):
        need(row.tag==q("row") and row.get("r")==str(i)
             and set(row.attrib)<={"r","spans"},"XLSX_ROW_STRUCTURE")
        need(1<=len(row)<=64,"XLSX_COLUMN_COUNT")
        values=[]
        for j,cell in enumerate(row,1):
            need(cell.tag==q("c") and cell.get("r")==cell_name(j,i)
                 and set(cell.attrib)<={"r","t","s"} and cell.get("s","0")=="0",
                 "XLSX_CELL_STRUCTURE")
            kind=cell.get("t")
            if kind=="inlineStr":
                if len(cell)==0:
                    value=""
                else:
                    value=text_node(one(cell,"is"))
                    need(len(cell)==1,"XLSX_CELL_STRUCTURE")
            elif kind=="s":
                node=one(cell,"v")
                raw_index=node.text or ""
                need(len(cell)==1 and len(node)==0 and re.fullmatch(r"0|[1-9][0-9]{0,5}",raw_index)
                     is not None and int(raw_index)<len(shared),"XLSX_SHARED_INDEX")
                value=shared[int(raw_index)]
            else:
                raise MappingBlocked("XLSX_TEXT_CELLS_ONLY")
            values.append(value)
        if width is None:
            width=len(values)
        need(len(values)==width,"XLSX_ROW_WIDTH")
        matrix.append(tuple(values))
    dims=sheet.findall(q("dimension"))
    if dims:
        need(len(dims)==1 and dims[0].get("ref")=="A1:"+cell_name(width,len(matrix)),
             "XLSX_DIMENSION")
    return matrix[0],tuple(matrix[1:])
