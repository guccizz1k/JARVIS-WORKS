"""Common CSV/XLSX source-bound staging proposal, never authorization."""
from dataclasses import dataclass, field
import hashlib
import json
import hmac

from app.erp_migration_mapping import MappingBlocked
from app.erp_migration_csv import _parse as parse_csv
from app.erp_migration_xlsx import parse_xlsx
from app.erp_migration_review import HeaderReview, prepare_header_review, check_header_review
from app.erp_migration_preflight import RowPreflight, prepare_row_preflight, check_row_preflight

@dataclass(frozen=True)
class FileStage:
    format: str
    raw_sha256: str
    byte_count: int
    review: HeaderReview
    preflight: RowPreflight
    stage_sha256: str
    # Values are not included in repr/logs. Caller must protect them as data.
    canonical_rows: tuple = field(repr=False)
    row_import_authorized: bool = False

def _require(ok,reason):
    if not ok:
        raise MappingBlocked(reason)

def prepare_file_stage(raw, *, format, organization_id, source_id, entity, target):
    _require(type(format) is str and format in ("csv","xlsx"),"FILE_FORMAT")
    headers,rows=(parse_csv if format=="csv" else parse_xlsx)(raw)
    review=prepare_header_review(organization_id,source_id,entity,headers)
    p=prepare_row_preflight(review,organization_id=organization_id,
        source_id=source_id,entity=entity,headers=headers,rows=rows,target=target)
    canonical=tuple(tuple(sorted((field,row[i]) for i,field in review.fields)) for row in rows)
    raw_hash=hashlib.sha256(raw).hexdigest()
    payload={"version":1,"purpose":"file-stage-only","format":format,
             "raw_sha256":raw_hash,"byte_count":len(raw),"preflight":p.binding_sha256,
             "canonical_rows":canonical,"row_import_authorized":False}
    binding=hashlib.sha256(json.dumps(payload,ensure_ascii=False,sort_keys=True,
                       separators=(",",":")).encode("utf-8")).hexdigest()
    return FileStage(format,raw_hash,len(raw),review,p,binding,canonical)

def check_file_stage(previous,raw,*,format,organization_id,source_id,entity,target):
    _require(type(previous) is FileStage and previous.row_import_authorized is False,
             "FILE_STAGE_TYPE_OR_AUTHORITY")
    _require(type(raw) is bytes and 0<len(raw)<=1024*1024,"FILE_BYTE_LIMIT")
    _require(type(previous.format) is str and previous.format==format
             and type(previous.byte_count) is int and previous.byte_count==len(raw)
             and type(previous.raw_sha256) is str and previous.raw_sha256.isascii()
             and hmac.compare_digest(previous.raw_sha256,hashlib.sha256(raw).hexdigest()),
             "FILE_SOURCE_CHANGED")
    current=prepare_file_stage(raw,format=format,organization_id=organization_id,
                      source_id=source_id,entity=entity,target=target)
    # Reuse exact nested validators, not dataclass equality alone (bool == int).
    headers,rows=(parse_csv if format=="csv" else parse_xlsx)(raw)
    review=check_header_review(previous.review,organization_id=organization_id,
                         source_id=source_id,entity=entity,headers=headers)
    check_row_preflight(previous.preflight,review,organization_id=organization_id,
                      source_id=source_id,entity=entity,headers=headers,rows=rows,target=target)
    _require(type(previous.stage_sha256) is str and previous.stage_sha256.isascii()
             and hmac.compare_digest(previous.stage_sha256,current.stage_sha256)
             and type(previous.canonical_rows) is tuple
             and all(type(row) is tuple and all(type(p) is tuple and len(p)==2
                      and type(p[0]) is str and type(p[1]) is str for p in row)
                      for row in previous.canonical_rows)
             and previous.canonical_rows==current.canonical_rows,"FILE_STAGE_CHANGED")
    return current
