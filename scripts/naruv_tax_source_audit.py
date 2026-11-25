"""Independent official Appendix 2 extraction audit; no network or payroll action.
Input must be a trusted independently obtained official PDF. Never derive
expected values from the candidate table. SHA256 records the exact input.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROW = re.compile(r"^\s*([0-9][0-9,]*)\s+([0-9][0-9,]*)\s+(.+?)\s*$")
TEN = re.compile(r"^\s*10,?000\s*천원\s+(.+?)\s*$")
CELL = re.compile(r"(?:[0-9]+|[0-9]{1,3}(?:,[0-9]{3})+|[-–—−])\Z")
OFFICIAL_PDF_SHA256 = "5307b1d45c8f946ca2d54f10b1731b2ec8cfd1a26efb653673c13d660ae3b698"
def verify_source_digest(raw):
    need(type(raw) is bytes and hashlib.sha256(raw).hexdigest()==OFFICIAL_PDF_SHA256,"SOURCE_EDITION_DIGEST_CHANGED")

NAMES = ("KR_TABLE_LOWEST","KR_TABLE_LOWER","KR_TABLE_BEFORE","KR_TABLE_ROWS","KR_TABLE_AFTER")

def need(ok, code):
    if not ok: raise ValueError(code)

def cells(value):
    parts=value.split()
    need(len(parts)==11 and all(CELL.fullmatch(x) for x in parts),"SOURCE_CELL_SHAPE")
    return tuple(0 if x in "-–—−" else int(x.replace(",","")) for x in parts)

def extract(text):
    need(type(text) is str and len(text)<=2_000_000,"SOURCE_TEXT_SIZE")
    pages=text.split("\f")
    if pages[-1].strip()=="":pages.pop()
    need(len(pages)==27 and re.search(r"2026\.\s*2\.\s*27\.",pages[0]),"SOURCE_EDITION_OR_PAGES")
    rows={};ten=None;page_counts=[]
    for page in pages[1:]:
        count=0
        for line in page.splitlines():
            m=TEN.fullmatch(line)
            if m:
                # The final page repeats the 10m label in the formula's
                # threshold description. Only a complete numeric row is data.
                if re.match(r"^(초과|이하)(?:\s|$)",m[1]):
                    continue
                need(ten is None,"SOURCE_DUPLICATE_10M")
                ten=cells(m[1]);continue
            m=ROW.fullmatch(line)
            if not m:continue
            low,high=(int(m[i].replace(",",""))*1000 for i in (1,2))
            # Column-header numbers aren't wage intervals.
            if not 770000<=low<10000000:continue
            need(low not in rows,"SOURCE_DUPLICATE_BAND")
            rows[low]=(high,cells(m[3]));count+=1
        page_counts.append(count)
    need(page_counts==[17]+[26]*24+[5],"SOURCE_PAGE_ROW_COUNTS")
    need(ten is not None and len(rows)==646,"SOURCE_COVERAGE")
    return rows,ten

def expected_rows(candidate):
    tree=ast.parse(candidate)
    vals={}
    for node in tree.body:
        if isinstance(node,ast.Assign):
            for target in node.targets:
                if isinstance(target,ast.Name) and target.id in (*NAMES,"KR_TABLE_TEN_MILLION"):
                    need(target.id not in vals,"CANDIDATE_DUPLICATE_CONSTANT")
                    vals[target.id]=ast.literal_eval(node.value)
    need(set(vals)==set((*NAMES,"KR_TABLE_TEN_MILLION")),"CANDIDATE_CONSTANTS")
    bands=((770000,[5000]*146+[10000]*79),(2290000,[10000]*52),
           (2810000,[10000]*19+[20000]*7),(3140000,[20000]*26),
           (3660000,[20000]*317))
    out={}
    for name,(low,steps) in zip(NAMES,bands,strict=True):
        need(len(vals[name])==len(steps),"CANDIDATE_COVERAGE")
        for step,row in zip(steps,vals[name],strict=True):
            need(type(row) is tuple and len(row)==11 and all(type(x) is int and x>=0 for x in row),"CANDIDATE_CELL_SHAPE")
            out[low]=(low+step,row);low+=step
    return out,vals["KR_TABLE_TEN_MILLION"]

def compare(source,candidate):
    actual,ten=source;expected,base=candidate
    need(set(actual)==set(expected),"SOURCE_BAND_MISMATCH")
    mismatches=[]
    for low,(high,row) in sorted(actual.items()):
        want_high,want_row=expected[low]
        need(high==want_high,"SOURCE_INTERVAL_MISMATCH")
        for i,(official,code) in enumerate(zip(row,want_row,strict=True),1):
            if official!=code:mismatches.append((low,i,official,code))
    for i,(official,code) in enumerate(zip(ten,base,strict=True),1):
        if official!=code:mismatches.append((10000000,i,official,code))
    return mismatches

def main():
    p=argparse.ArgumentParser();p.add_argument("pdf",type=Path);p.add_argument("candidate",type=Path)
    a=p.parse_args()
    need(a.pdf.is_file() and 1<=a.pdf.stat().st_size<=10_000_000,"SOURCE_PDF_SIZE")
    raw=a.pdf.read_bytes();need(raw.startswith(b"%PDF-"),"SOURCE_NOT_PDF")
    verify_source_digest(raw)
    proc=subprocess.run(["pdftotext","-layout",str(a.pdf),"-"],capture_output=True,timeout=30,check=True)
    extracted=extract(proc.stdout.decode("utf-8"))
    mismatch=compare(extracted,expected_rows(a.candidate.read_text("utf-8")))
    # Emit complete affected rows, not only the first 100 cells; the review
    # candidate is never auto-mutated by network input.
    affected=sorted({low for low,_,_,_ in mismatch})
    for low in affected:
        high,row=extracted[0][low] if low!=10000000 else (None,extracted[1])
        print("NARUV_OFFICIAL_MISMATCH_ROW "+json.dumps([low,high,*row],separators=(",",":")),flush=True)
    print(json.dumps({"source_sha256":hashlib.sha256(raw).hexdigest(),"bands":646,"cells":7117,
        "mismatch_count":len(mismatch),"first_mismatches":mismatch[:100]},ensure_ascii=True),flush=True)
    need(not mismatch,"SOURCE_TABLE_MISMATCH")
    print("NARUV_OFFICIAL_TABLE_SOURCE_COMPARE_PASS; not statutory or production acceptance",flush=True)

if __name__=="__main__":main()
