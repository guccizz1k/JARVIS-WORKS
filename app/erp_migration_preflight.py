"""Bounded, read-only ERP row preflight lab for customer/item metadata.

No I/O, DB, cache, external model, approval, or import. Scope and target snapshot
must eventually come from authenticated server-side state. A digest is not a
signature or authorization. Future writer must atomically revalidate current
state and enforce tenant uniqueness/idempotency in a transaction.
"""
from dataclasses import dataclass, fields
import hashlib
import json
import re
import unicodedata

from app.erp_migration_mapping import MappingBlocked
from app.erp_migration_review import check_header_review, prepare_header_review

MAX_ROWS = 1000
MAX_EXISTING_IDS = 10000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_BUSINESS = re.compile(r"(?:[0-9]{10}|[0-9]{3}-[0-9]{2}-[0-9]{5})")
_ID_FIELD = {"customer": "source_customer_id", "item": "source_item_id"}

def _require(ok, reason):
    if not ok:
        raise MappingBlocked(reason)

def _id(value, reason):
    _require(type(value) is str and _ID.fullmatch(value) is not None, reason)
    return value

def _sequence(value, maximum, reason, *, minimum=0):
    _require(type(value) in (list, tuple) and minimum <= len(value) <= maximum, reason)
    result = tuple(value)
    _require(minimum <= len(result) <= maximum, reason)
    return result

def _digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()

def _text(value, limit, *, optional=False):
    if optional and (value is None or (type(value) is str and value == "")):
        return value
    _require(type(value) is str and 1 <= len(value) <= limit, "ROW_TEXT_TYPE_OR_LENGTH")
    # Do not silently trim, normalize, coerce, or repair source data.
    _require(value == value.strip() and value == unicodedata.normalize("NFC", value)
             and not any(unicodedata.category(c).startswith("C") or c in "\u2028\u2029"
                         for c in value), "ROW_TEXT_UNSAFE")
    _require(value[0] not in "=+-@", "ROW_FORMULA_LIKE")
    return value

def _cell(field, value):
    if field in ("source_customer_id", "source_item_id"):
        return _id(value, "ROW_SOURCE_ID_INVALID")
    if field == "name":
        return _text(value, 120)
    if field == "unit":
        return _text(value, 32, optional=True)
    if field == "business_number":
        if value is None or (type(value) is str and value == ""):
            return value
        # Shape only; never claims registry/checksum verification.
        _require(type(value) is str and _BUSINESS.fullmatch(value) is not None,
                 "ROW_BUSINESS_NUMBER_FORMAT")
        return value
    raise MappingBlocked("ROW_UNKNOWN_FIELD")

@dataclass(frozen=True)
class TargetSnapshot:
    organization_id: str
    source_id: str
    entity: str
    revision: str
    existing_source_ids: tuple[str, ...]
    snapshot_sha256: str

def make_target_snapshot(organization_id, source_id, entity, revision, existing_source_ids):
    org = _id(organization_id, "TARGET_IDENTITY_INVALID")
    source = _id(source_id, "TARGET_IDENTITY_INVALID")
    _require(type(entity) is str and entity in _ID_FIELD, "TARGET_ENTITY_INVALID")
    rev = _id(revision, "TARGET_REVISION_INVALID")
    ids = _sequence(existing_source_ids, MAX_EXISTING_IDS, "TARGET_COUNT")
    ids = tuple(_id(v, "TARGET_SOURCE_ID_INVALID") for v in ids)
    _require(len({v.casefold() for v in ids}) == len(ids), "TARGET_AMBIGUOUS_ID")
    ids = tuple(sorted(ids))
    digest = _digest({"version":1,"organization_id":org,"source_id":source,
                      "entity":entity,"revision":rev,"existing_source_ids":ids})
    return TargetSnapshot(org, source, entity, rev, ids, digest)

def _same_exact(actual, expected):
    return type(actual) is type(expected) and all(
        type(getattr(actual, f.name)) is type(getattr(expected, f.name))
        and getattr(actual, f.name) == getattr(expected, f.name)
        for f in fields(expected))

@dataclass(frozen=True)
class RowPreflight:
    organization_id: str
    source_id: str
    entity: str
    header_binding_sha256: str
    rows_sha256: str
    target_snapshot_sha256: str
    row_count: int
    binding_sha256: str
    row_import_authorized: bool = False

def prepare_row_preflight(review, *, organization_id, source_id, entity, headers,
                          rows, target):
    # Capture only bounded in-memory sequences. Caller must provide an immutable
    # or transaction-consistent snapshot, not live concurrently mutated inputs.
    header_snapshot = _sequence(headers, 64, "HEADER_COUNT", minimum=1)
    verified = check_header_review(review, organization_id=organization_id,
        source_id=source_id, entity=entity, headers=header_snapshot)
    _require(type(target) is TargetSnapshot, "TARGET_TYPE")
    _require(type(target.organization_id) is str and type(target.source_id) is str
             and type(target.entity) is str and
             (target.organization_id,target.source_id,target.entity) ==
             (organization_id,source_id,entity), "TARGET_SCOPE_MISMATCH")
    expected_target = make_target_snapshot(organization_id,source_id,entity,
        target.revision,target.existing_source_ids)
    _require(_same_exact(target,expected_target), "TARGET_SNAPSHOT_MISMATCH")
    batch = _sequence(rows, MAX_ROWS, "ROW_COUNT", minimum=1)
    seen = set()
    existing = {v.casefold() for v in expected_target.existing_source_ids}
    checked = []
    for raw in batch:
        row = _sequence(raw, len(header_snapshot), "ROW_WIDTH", minimum=len(header_snapshot))
        # header mapping came from trusted deterministic planner, not external AI.
        values = {field:_cell(field,row[index]) for index,field in verified.fields}
        source_key = values[_ID_FIELD[entity]].casefold()
        _require(source_key not in seen, "ROW_DUPLICATE_SOURCE_ID")
        _require(source_key not in existing, "ROW_TARGET_CONFLICT")
        seen.add(source_key)
        checked.append(row)
    row_hash = _digest({"version":1,"header_binding_sha256":verified.binding_sha256,
                        "rows":checked})
    payload = {"version":1,"purpose":"row-preflight-only",
               "organization_id":organization_id,"source_id":source_id,"entity":entity,
               "header_binding_sha256":verified.binding_sha256,"rows_sha256":row_hash,
               "target_snapshot_sha256":expected_target.snapshot_sha256,
               "row_count":len(checked),"row_import_authorized":False}
    return RowPreflight(organization_id,source_id,entity,verified.binding_sha256,
                        row_hash,expected_target.snapshot_sha256,len(checked),_digest(payload))

def check_row_preflight(previous, review, *, organization_id, source_id, entity,
                        headers, rows, target):
    _require(type(previous) is RowPreflight, "PREFLIGHT_TYPE")
    _require(previous.row_import_authorized is False, "PREFLIGHT_IMPORT_FORBIDDEN")
    current = prepare_row_preflight(review,organization_id=organization_id,source_id=source_id,
        entity=entity,headers=headers,rows=rows,target=target)
    _require(_same_exact(previous,current), "PREFLIGHT_STALE_OR_CHANGED")
    return current
