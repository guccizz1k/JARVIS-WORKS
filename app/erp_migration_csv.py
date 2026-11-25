"""Bounded CSV bytes -> existing ERP metadata review and row preflight.

Read-only, no upload route, filesystem, database, or import authorization.
Accept an explicit UTF-8 comma-separated master-data format, never guess a
vendor schema or infer a type. Trusted caller provides tenant/source/target.
"""
from dataclasses import dataclass
import hashlib
import hmac

from app.erp_migration_mapping import MappingBlocked
from app.erp_migration_review import HeaderReview, prepare_header_review, check_header_review
from app.erp_migration_preflight import (
    MAX_ROWS, RowPreflight, prepare_row_preflight, check_row_preflight,
)

MAX_CSV_BYTES = 1024 * 1024
MAX_COLUMNS = 64
MAX_CELL_CHARS = 256
MAX_LINE_CHARS = MAX_COLUMNS * (2 * MAX_CELL_CHARS + 3)

def _need(ok, reason):
    if not ok:
        raise MappingBlocked(reason)

def _line(line):
    """Strict single-record CSV grammar, including doubled quote escapes."""
    _need(0 < len(line) <= MAX_LINE_CHARS, "CSV_LINE_LENGTH")
    values, cell = [], []
    state = "START"
    def append(ch):
        _need(len(cell) < MAX_CELL_CHARS, "CSV_CELL_LENGTH")
        cell.append(ch)
    def finish():
        _need(len(values) < MAX_COLUMNS, "CSV_COLUMN_COUNT")
        values.append("".join(cell))
        cell.clear()
    for ch in line:
        if state == "QUOTED":
            if ch == '"':
                state = "AFTER_QUOTE"
            else:
                append(ch)
        elif state == "AFTER_QUOTE":
            if ch == '"':
                append(ch)
                state = "QUOTED"
            elif ch == ",":
                finish()
                state = "START"
            else:
                raise MappingBlocked("CSV_QUOTE_SYNTAX")
        elif ch == ",":
            finish()
            state = "START"
        elif ch == '"':
            _need(state == "START", "CSV_QUOTE_SYNTAX")
            state = "QUOTED"
        else:
            append(ch)
            state = "UNQUOTED"
    _need(state != "QUOTED", "CSV_QUOTE_SYNTAX")
    finish()
    return tuple(values)

def _parse(raw):
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_CSV_BYTES, "CSV_BYTE_LIMIT")
    try:
        text = raw.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError:
        raise MappingBlocked("CSV_ENCODING") from None
    _need("\x00" not in text, "CSV_NUL")
    # Single optional terminal newline; LF or CRLF, never mixed or lone CR.
    if "\r" in text:
        _need(text.count("\r")==text.count("\r\n")==text.count("\n"), "CSV_LINE_ENDING")
        text=text.replace("\r\n","\n")
    _need(text.count("\n") <= MAX_ROWS+1, "CSV_RECORD_COUNT")
    if text.endswith("\n"):
        text=text[:-1]
    lines=text.split("\n")
    _need(2 <= len(lines) <= MAX_ROWS+1, "CSV_RECORD_COUNT")
    _need(all(lines), "CSV_BLANK_RECORD")
    headers=_line(lines[0])
    rows=tuple(_line(line) for line in lines[1:])
    return headers,rows

@dataclass(frozen=True)
class CsvPreview:
    raw_sha256: str
    byte_count: int
    review: HeaderReview
    preflight: RowPreflight
    row_import_authorized: bool = False

def prepare_csv_preview(raw, *, organization_id, source_id, entity, target):
    headers,rows=_parse(raw)
    review=prepare_header_review(organization_id,source_id,entity,headers)
    preflight=prepare_row_preflight(review,organization_id=organization_id,
        source_id=source_id,entity=entity,headers=headers,rows=rows,target=target)
    return CsvPreview(hashlib.sha256(raw).hexdigest(),len(raw),review,preflight)

def check_csv_preview(previous, raw, *, organization_id, source_id, entity, target):
    _need(type(previous) is CsvPreview, "CSV_PREVIEW_TYPE")
    _need(previous.row_import_authorized is False, "CSV_IMPORT_FORBIDDEN")
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_CSV_BYTES, "CSV_BYTE_LIMIT")
    _need(type(previous.byte_count) is int and previous.byte_count==len(raw)
          and type(previous.raw_sha256) is str and previous.raw_sha256.isascii()
          and hmac.compare_digest(previous.raw_sha256,hashlib.sha256(raw).hexdigest()),
          "CSV_SOURCE_CHANGED")
    headers,rows=_parse(raw)
    verified=check_header_review(previous.review,organization_id=organization_id,
        source_id=source_id,entity=entity,headers=headers)
    preflight=check_row_preflight(previous.preflight,verified,
        organization_id=organization_id,source_id=source_id,entity=entity,
        headers=headers,rows=rows,target=target)
    return CsvPreview(previous.raw_sha256,len(raw),verified,preflight)
