"""Trusted disposable-lab staging adapter; never expose as a public API.

Requires the existing validated FileStage and a transaction-consistent target.
The custodian must lock the tenant/target and use a separate privileged lab
connection. The application login can only approve and commit stored stages.
"""
from dataclasses import dataclass, field
import hashlib
import json
import re

_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}')
_SHA = re.compile(r'[0-9a-f]{64}')
_FIELDS = {'item': ('source_item_id', 'unit'), 'customer': ('source_customer_id', 'business_number')}
BASE_SHA = '620c2c5dc6d582ed5456d12095d8844d7278f2a5'


def require(ok, code):
    if not ok:
        raise ValueError(code)


def _identifier(v):
    require(type(v) is str and _ID.fullmatch(v) is not None, 'TX_ID')
    return v


def _hash(v):
    require(type(v) is str and _SHA.fullmatch(v) is not None, 'TX_HASH')
    return v


@dataclass(frozen=True)
class StagedPayload:
    organization_id: str
    source_id: str
    entity: str
    stage_id: str
    file_format: str
    raw_sha256: str
    byte_count: int
    stage_sha256: str
    preflight_sha256: str
    rows_sha256: str
    snapshot_sha256: str
    next_snapshot_sha256: str
    expected_ids: tuple = field(repr=False)
    next_revision: int
    rows_json: str = field(repr=False)
    raw: bytes = field(repr=False)

    def params(self):
        return (self.organization_id, self.stage_id, self.source_id, self.entity,
                self.file_format, self.raw, self.raw_sha256, self.byte_count,
                self.stage_sha256, self.preflight_sha256, self.rows_sha256,
                self.snapshot_sha256, self.next_snapshot_sha256,
                list(self.expected_ids), self.next_revision, self.rows_json)


def _encode_rows(entity, rows, expected_ids):
    """Lossless validated-row serialization; never drops optional fields."""
    require(type(entity) is str and entity in _FIELDS, 'TX_ENTITY')
    id_field, optional = _FIELDS[entity]
    require(type(rows) is tuple and 1 <= len(rows) <= 1000, 'TX_ROWS')
    require(type(expected_ids) is tuple and len(expected_ids) <= 10000, 'TX_TARGET_IDS')
    seen = {_identifier(v).lower() for v in expected_ids}
    require(len(seen) == len(expected_ids), 'TX_TARGET_DUPLICATE')
    output, ids = [], []
    for row in rows:
        require(type(row) is tuple and all(type(p) is tuple and len(p) == 2 and
            type(p[0]) is str and type(p[1]) is str for p in row), 'TX_ROW_SHAPE')
        data = dict(row)
        require(len(data) == len(row) and set(data) in ({id_field, 'name'},
            {id_field, 'name', optional}), 'TX_FIELDS')
        code = _identifier(data[id_field])
        require(1 <= len(data['name']) <= 120, 'TX_NAME')
        if optional in data:
            value = data[optional]
            if entity == 'item':
                require(len(value) <= 32, 'TX_UNIT')
            else:
                require(value == '' or re.fullmatch(r'(?:[0-9]{10}|[0-9]{3}-[0-9]{2}-[0-9]{5})',value), 'TX_BUSINESS_NUMBER')
        require(code.lower() not in seen, 'TX_DUPLICATE')
        seen.add(code.lower())
        ids.append(code)
        output.append(data)
    require(len(seen) <= 10000, 'TX_TARGET_CAPACITY')
    return json.dumps(output,ensure_ascii=False,sort_keys=True,separators=(',',':')), tuple(sorted((*expected_ids,*ids)))


def build_payload(raw, *, file_format, organization_id, source_id, entity,
                  stage_id, revision, expected_ids, stored_snapshot_sha256,
                  previously_reviewed):
    """Revalidate the exact reviewed file against the locked current target."""
    from app.erp_migration_file_stage import check_file_stage
    from app.erp_migration_preflight import make_target_snapshot
    for v in (organization_id, source_id, stage_id):
        _identifier(v)
    require(type(revision) is int and 0 <= revision < 2**63-1, 'TX_REVISION')
    require(type(raw) is bytes and 0 < len(raw) <= 1024*1024, 'TX_BYTES')
    require(type(expected_ids) is tuple and expected_ids == tuple(sorted(expected_ids)), 'TX_TARGET_ORDER')
    target = make_target_snapshot(organization_id,source_id,entity,f'rev-{revision}',expected_ids)
    require(target.snapshot_sha256 == _hash(stored_snapshot_sha256),'TX_TARGET_CHANGED')
    stage = check_file_stage(previously_reviewed,raw,format=file_format,
              organization_id=organization_id,source_id=source_id,entity=entity,target=target)
    require(stage.row_import_authorized is False,'TX_STAGE_AUTHORITY')
    require(stage.raw_sha256 == hashlib.sha256(raw).hexdigest() and stage.byte_count == len(raw),'TX_RAW_CHANGED')
    encoded, next_ids = _encode_rows(entity,stage.canonical_rows,expected_ids)
    p = stage.preflight
    require(p.row_count == len(stage.canonical_rows),'TX_COUNT')
    next_target = make_target_snapshot(organization_id,source_id,entity,f'rev-{revision+1}',next_ids)
    return StagedPayload(organization_id,source_id,entity,stage_id,file_format,
        stage.raw_sha256,len(raw),_hash(stage.stage_sha256),_hash(p.binding_sha256),
        _hash(p.rows_sha256),target.snapshot_sha256,next_target.snapshot_sha256,
        expected_ids,revision+1,encoded,raw)


def stage_reviewed_file(conn, raw, *, file_format, organization_id, source_id,
                        entity, stage_id, previously_reviewed):
    """Privileged *lab* custodian only. Caller owns commit/rollback, no auto-commit."""
    require(getattr(conn,'autocommit',None) is False,'TX_TRANSACTION_REQUIRED')
    import os
    require(os.environ.get('NARUV_APPROVAL_PG_ALLOW')=='ONLY_DISPOSABLE_CI' and os.environ.get('GITHUB_ACTIONS')=='true','TX_DISPOSABLE_CI_REQUIRED')
    expected_addr = os.environ.get('NARUV_FILE_TX_SERVER_ADDR')
    import ipaddress
    try:
        require(ipaddress.ip_address(expected_addr).version == 4, 'TX_SERVICE_ADDR')
    except (ValueError, TypeError):
        raise ValueError('TX_SERVICE_ADDR') from None
    identity = conn.execute("SELECT current_database(),current_setting('server_version_num')::int,session_user,host(inet_server_addr())").fetchone()
    require(identity is not None and identity[0]=='naruv_approval_ci' and 170000<=identity[1]<180000 and identity[2:] == ('postgres',expected_addr),'TX_DISPOSABLE_PG17_REQUIRED')
    a=conn.execute('SELECT organization_id FROM naruv_approval_lab.actors WHERE organization_id=%s FOR UPDATE',(organization_id,)).fetchone()
    require(a is not None,'TX_ORG_MISSING')
    scope=(organization_id,source_id,entity)
    t=conn.execute('SELECT snapshot_sha256 FROM naruv_approval_lab.targets WHERE organization_id=%s AND source_id=%s AND entity=%s FOR UPDATE',scope).fetchone()
    r=conn.execute('SELECT revision FROM naruv_approval_lab.file_revisions WHERE organization_id=%s AND source_id=%s AND entity=%s FOR UPDATE',scope).fetchone()
    require(t is not None and r is not None,'TX_TARGET_MISSING')
    ids=tuple(x[0] for x in conn.execute('SELECT source_record_id FROM naruv_approval_lab.file_records WHERE organization_id=%s AND source_id=%s AND entity=%s ORDER BY source_record_id COLLATE "C"',scope).fetchall())
    payload=build_payload(raw,file_format=file_format,organization_id=organization_id,source_id=source_id,entity=entity,stage_id=stage_id,revision=r[0],expected_ids=ids,stored_snapshot_sha256=t[0],previously_reviewed=previously_reviewed)
    conn.execute('''INSERT INTO naruv_approval_lab.file_stages(organization_id,stage_id,source_id,entity,file_format,raw,raw_sha256,byte_count,stage_sha256,preflight_sha256,rows_sha256,snapshot_sha256,next_snapshot_sha256,expected_ids,next_revision,rows_json) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)''',payload.params())
    return payload
