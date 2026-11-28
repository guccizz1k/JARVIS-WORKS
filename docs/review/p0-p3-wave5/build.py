"""Build exact review overlays; no live systems or credentials."""
import hashlib, json, sys
from pathlib import Path

source,out=map(Path,sys.argv[1:])
out.mkdir(parents=True,exist_ok=False)
def gitblob(b):
    return hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
def change(name,expected,pairs=(),append=""):
    raw=(source/name).read_bytes()
    assert gitblob(raw)==expected, "SOURCE_BLOB_MISMATCH: "+name
    s=raw.decode("utf-8")
    for old,new in pairs:
        assert s.count(old)==1, "SOURCE_ANCHOR_NOT_UNIQUE: "+name
        s=s.replace(old,new,1)
    if append:
        s=s.rstrip("\n")+"\n"+append
    compile(s,name,"exec")
    (out/name).write_bytes(s.encode("utf-8"))
    print(name,hashlib.sha256(s.encode("utf-8")).hexdigest())
change("cleanroom-pipe-candidate.py","a2162cec7e00bffe85cf341e73639423b91a74c4",[
('key=base64.urlsafe_b64decode(bytes(key_raw).strip())','encoded=bytes(key_raw).strip()\n            key=base64.b64decode(encoded,altchars=b"-_",validate=True)\n            if base64.urlsafe_b64encode(key)!=encoded:\n                raise Blocked("EXTERNAL_KEY_ENCODING_INVALID")'),
('not SHA1.fullmatch(obj.get("blob_sha1","")) or\n                not SHA256.fullmatch(obj.get("cipher_sha256",""))','type(obj.get("blob_sha1")) is not str or\n                type(obj.get("cipher_sha256")) is not str or\n                not SHA1.fullmatch(obj["blob_sha1"]) or\n                not SHA256.fullmatch(obj["cipher_sha256"])'),
('or not SHA1.fullmatch(tree.get("sha","")))','or type(tree.get("sha")) is not str or not SHA1.fullmatch(tree["sha"]))'),
('not SHA1.fullmatch(o.get("sha","")))','type(o.get("sha")) is not str or not SHA1.fullmatch(o["sha"]))')])
change("xlsx-candidate.py","cbf4b43ba75f9d5d52ef1442e68199741728a895",[
('    data=one(sheet,"sheetData")\n','    data=one(sheet,"sheetData")\n    no_mixed_content(data)\n'),
('        need(1<=len(row)<=64,"XLSX_COLUMN_COUNT")','        no_mixed_content(row)\n        need(1<=len(row)<=64,"XLSX_COLUMN_COUNT")'),
('    values=[]\n    for node in root:','    no_mixed_content(root)\n    values=[]\n    for node in root:'),
('    need(sheet.tag==q("worksheet"),"XLSX_STRUCTURE")','    need(sheet.tag==q("worksheet"),"XLSX_STRUCTURE")\n    no_mixed_content(sheet)')])
change("payroll-statement-candidate.py","ea4199c46f1e4704d19765f9c32124a407dd3ae4",append='''

def verify_fixed_week_statement_source_2026(*,draft,tenant,assessment_sha256,expected_review_sha256):
    """Rebind internal draft to independently trusted server evidence; never authorize issuance."""
    code="KR_PAID_STATEMENT_SOURCE"
    require(type(tenant) is str and ID.fullmatch(tenant),code)
    require(all(type(x) is str and HEX.fullmatch(x) for x in (assessment_sha256,expected_review_sha256)),code)
    require(type(draft) is dict,code)
    fields=("worker","period","proposed_payment_date","components","deductions","gross_krw","deductions_krw","net_krw","source_review_sha256","rounding")
    flags=("completeness_verified","payment_date_verified","statutory_validated","payment_authorized","delivery_authorized","production_authorized")
    require(set(draft)==set(fields)|set(flags)|{"status","review_sha256"},code)
    require(draft["status"]=="FIXED_WEEK_PAID_REST_LEAVE_STATEMENT_DRAFT_ONLY" and all(draft[x] is False for x in flags),code)
    require(type(draft["review_sha256"]) is str and draft["review_sha256"]==expected_review_sha256,code)
    core={k:draft[k] for k in fields}
    try:
        calculated=hash_input({"v":"KR_FIXED_WEEK_STATEMENT_DRAFT_2026_V1","tenant":tenant,"core":core,"assessment":assessment_sha256})
    except (TypeError,ValueError,OverflowError,RecursionError):
        raise PayrollBlocked(code) from None
    require(calculated==expected_review_sha256,code)
    return {"status":"DRAFT_SOURCE_INTEGRITY_ONLY","statutory_validated":False,"payment_authorized":False,"delivery_authorized":False,"production_authorized":False}
''')
change("incident-evidence.py","cf9d0a0d3fadff0850d4c98e2bc3e59ed5d59ed7",[
('    return dict(status=status,reasons=reasons,provider_verified=False,','    observed_signals=[]\n    if not health_ok:observed_signals.append("HEALTH_FAILURE")\n    if request_count and error_count*10000>request_count*policy["max_error_bps"]:observed_signals.append("ERROR_RATE_EXCEEDED")\n    if p95_ms is not None and p95_ms>policy["max_p95_ms"]:observed_signals.append("LATENCY_EXCEEDED")\n    return dict(status=status,reasons=reasons,observed_signals_unverified=observed_signals,provider_verified=False,')])
