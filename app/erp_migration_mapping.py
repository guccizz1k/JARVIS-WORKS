"""NARUV ONE metadata-only ERP mapping lab. No I/O, row import, or AI guesses."""
from dataclasses import dataclass
import hashlib
import json
import re
import unicodedata

class MappingBlocked(ValueError):
    """Safe reason code, never source contents."""

_SCHEMAS = {
    "customer": (
        ("source_customer_id", True, ("거래처코드", "거래처 코드", "customer_id", "customer code")),
        ("name", True, ("거래처명", "거래처 명", "customer_name", "customer name")),
        ("business_number", False, ("사업자등록번호", "사업자번호", "business_number")),
    ),
    "item": (
        ("source_item_id", True, ("품목코드", "품목 코드", "item_id", "item code", "sku")),
        ("name", True, ("품목명", "품목 명", "item_name", "item name")),
        ("unit", False, ("단위", "unit")),
    ),
}

def _header(value):
    if type(value) is not str or not 1 <= len(value) <= 100:
        raise MappingBlocked("HEADER_TYPE_OR_LENGTH")
    text = unicodedata.normalize("NFC", value)
    if not re.fullmatch(r"[A-Za-z0-9_ \uAC00-\uD7A3]+", text):
        raise MappingBlocked("HEADER_UNSUPPORTED_CHARACTER")
    text = " ".join(text.split()).lower()
    if not text:
        raise MappingBlocked("HEADER_EMPTY")
    return text

@dataclass(frozen=True)
class HeaderPlan:
    entity: str
    source_headers_sha256: str
    fields: tuple[tuple[int, str], ...]
    row_import_authorized: bool = False

def plan_headers(entity, headers):
    if type(entity) is not str or entity not in _SCHEMAS:
        raise MappingBlocked("ENTITY_UNSUPPORTED")
    if type(headers) not in (list, tuple) or not 1 <= len(headers) <= 64:
        raise MappingBlocked("HEADER_COUNT")
    raw = tuple(headers)
    normalized = tuple(_header(h) for h in raw)
    if len(set(normalized)) != len(normalized):
        raise MappingBlocked("DUPLICATE_HEADER")
    aliases = {}
    required = set()
    for field, mandatory, options in _SCHEMAS[entity]:
        if mandatory:
            required.add(field)
        for option in options:
            alias = _header(option)
            if alias in aliases:
                raise MappingBlocked("SCHEMA_ALIAS_CONFLICT")
            aliases[alias] = field
    fields = []
    used = set()
    for index, name in enumerate(normalized):
        field = aliases.get(name)
        if field is None:
            raise MappingBlocked("UNMAPPED_HEADER")
        if field in used:
            raise MappingBlocked("DUPLICATE_TARGET")
        used.add(field)
        fields.append((index, field))
    if not required.issubset(used):
        raise MappingBlocked("REQUIRED_FIELD_MISSING")
    encoded = json.dumps({"version": 1, "entity": entity, "headers": raw},
                         ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return HeaderPlan(entity, hashlib.sha256(encoded).hexdigest(), tuple(fields))
