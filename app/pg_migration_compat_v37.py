"""V3.7 lossless *operational-shape* PostgreSQL rehearsal, synthetic records only.

Never connected to FastAPI or customer data. Creates a fresh, RLS-protected
compatibility schema solely inside the disposable jw_v20_test_* PG17 database.
No existing public.messenger_* tables, tenant identities or data are mutated.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re

from app.pg_migration_shadow_v36 import (
    MigrationBlocked, Record, TABLES, canonical_bytes, row_key,
)

SCHEMA = 'jw_migration_v37'
DATABASE = re.compile(r'^jw_v20_test_[a-f0-9]{12}$')

# Exact SQLite V2.6 column contracts; do not drop unknown/new columns silently.
COLUMNS = {
    'messenger_companies': ('org_id','business_number','verified_at','verification_kind'),
    'messenger_connections': ('id','org_a','org_b','requester_org','status','created_at','accepted_at','connection_seq'),
    'messenger_messages': ('id','connection_id','sender_org','sender_user','kind','body','order_id',
                           'immutable_order_snapshot','actor_name','request_id','version','created_at','edited_at','message_seq'),
    'messenger_edits': ('id','message_id','previous_body','new_body','actor_user','edited_at','version'),
    'messenger_attachments': ('message_id','filename','mime','data','size_bytes','content_hash'),
    'messenger_read_positions': ('connection_id','org_id','last_read_rowid','updated_at','last_read_seq'),
    'messenger_receipts': ('message_id','receiver_org','actor_name','receiver_user','received_at'),
}
PK = {table: ('connection_id','org_id') if table=='messenger_read_positions'
      else ('org_id',) if table=='messenger_companies'
      else ('message_id',) if table in ('messenger_attachments','messenger_receipts')
      else ('id',) for table in TABLES}
# SQL types intentionally preserve timestamp strings and JSON snapshots byte-for-byte.
DDL = r'''
CREATE SCHEMA jw_migration_v37 AUTHORIZATION postgres;
REVOKE ALL ON SCHEMA jw_migration_v37 FROM PUBLIC;
CREATE TABLE jw_migration_v37.messenger_companies (
 org_id text PRIMARY KEY, business_number text NOT NULL UNIQUE,
 verified_at text NOT NULL, verification_kind text NOT NULL);
CREATE TABLE jw_migration_v37.messenger_connections (
 id text PRIMARY KEY, org_a text NOT NULL REFERENCES jw_migration_v37.messenger_companies(org_id),
 org_b text NOT NULL REFERENCES jw_migration_v37.messenger_companies(org_id),
 requester_org text NOT NULL, status text NOT NULL, created_at text NOT NULL,
 accepted_at text, connection_seq bigint NOT NULL UNIQUE,
 CHECK(org_a < org_b), CHECK(requester_org IN (org_a,org_b)),
 CHECK(status IN ('pending','active')));
CREATE TABLE jw_migration_v37.messenger_messages (
 id text PRIMARY KEY, connection_id text NOT NULL REFERENCES jw_migration_v37.messenger_connections(id),
 sender_org text NOT NULL REFERENCES jw_migration_v37.messenger_companies(org_id),
 sender_user text NOT NULL, kind text NOT NULL CHECK(kind IN ('text','order')),
 body text NOT NULL, order_id text, immutable_order_snapshot text,
 actor_name text NOT NULL, request_id text NOT NULL, version integer NOT NULL CHECK(version>=1),
 created_at text NOT NULL, edited_at text, message_seq bigint NOT NULL UNIQUE CHECK(message_seq>0),
 UNIQUE(sender_org,request_id),
 CHECK ((kind='text' AND order_id IS NULL AND immutable_order_snapshot IS NULL AND actor_name='') OR
 (kind='order' AND order_id IS NOT NULL AND immutable_order_snapshot IS NOT NULL AND length(actor_name)>=2)));
CREATE INDEX jw_v37_thread_seq ON jw_migration_v37.messenger_messages(connection_id,message_seq);
CREATE TABLE jw_migration_v37.messenger_edits (
 id text PRIMARY KEY, message_id text NOT NULL REFERENCES jw_migration_v37.messenger_messages(id),
 previous_body text NOT NULL, new_body text NOT NULL, actor_user text NOT NULL,
 edited_at text NOT NULL, version integer NOT NULL CHECK(version>=2), UNIQUE(message_id,version));
CREATE TABLE jw_migration_v37.messenger_attachments (
 message_id text PRIMARY KEY REFERENCES jw_migration_v37.messenger_messages(id),
 filename text NOT NULL, mime text NOT NULL, data bytea NOT NULL,
 size_bytes integer NOT NULL CHECK(size_bytes>0 AND size_bytes<=5242880),
 content_hash text NOT NULL,
 CONSTRAINT jw_v37_file_sha256 CHECK (
   octet_length(data)=size_bytes AND content_hash ~ '^[a-f0-9]{64}$'
   AND content_hash=encode(public.digest(data,'sha256'),'hex')));
CREATE TABLE jw_migration_v37.messenger_read_positions (
 connection_id text NOT NULL REFERENCES jw_migration_v37.messenger_connections(id),
 org_id text NOT NULL REFERENCES jw_migration_v37.messenger_companies(org_id),
 last_read_rowid bigint NOT NULL CHECK(last_read_rowid>=0), updated_at text NOT NULL,
 last_read_seq bigint NOT NULL CHECK(last_read_seq>=0), PRIMARY KEY(connection_id,org_id));
CREATE TABLE jw_migration_v37.messenger_receipts (
 message_id text PRIMARY KEY REFERENCES jw_migration_v37.messenger_messages(id),
 receiver_org text NOT NULL REFERENCES jw_migration_v37.messenger_companies(org_id),
 actor_name text NOT NULL, receiver_user text NOT NULL, received_at text NOT NULL);
-- Tenant-checked, READ-ONLY compatibility view. Never grant DML to jw_app.
ALTER TABLE jw_migration_v37.messenger_companies ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_migration_v37.messenger_companies FORCE ROW LEVEL SECURITY;
CREATE POLICY jw_v37_company ON jw_migration_v37.messenger_companies FOR SELECT TO jw_app USING
 (org_id=jw_guard.current_tenant());
ALTER TABLE jw_migration_v37.messenger_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_migration_v37.messenger_connections FORCE ROW LEVEL SECURITY;
CREATE POLICY jw_v37_thread ON jw_migration_v37.messenger_connections FOR SELECT TO jw_app USING
 (status='active' AND jw_guard.current_tenant() IN (org_a,org_b));
ALTER TABLE jw_migration_v37.messenger_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_migration_v37.messenger_messages FORCE ROW LEVEL SECURITY;
CREATE POLICY jw_v37_message ON jw_migration_v37.messenger_messages FOR SELECT TO jw_app USING
 (jw_guard.current_tenant() IS NOT NULL AND EXISTS
 (SELECT 1 FROM jw_migration_v37.messenger_connections c WHERE c.id=connection_id));
ALTER TABLE jw_migration_v37.messenger_edits ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_migration_v37.messenger_edits FORCE ROW LEVEL SECURITY;
CREATE POLICY jw_v37_edit ON jw_migration_v37.messenger_edits FOR SELECT TO jw_app USING
 (jw_guard.current_tenant() IS NOT NULL AND EXISTS
 (SELECT 1 FROM jw_migration_v37.messenger_messages m WHERE m.id=message_id));
ALTER TABLE jw_migration_v37.messenger_attachments ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_migration_v37.messenger_attachments FORCE ROW LEVEL SECURITY;
CREATE POLICY jw_v37_attachment ON jw_migration_v37.messenger_attachments FOR SELECT TO jw_app USING
 (jw_guard.current_tenant() IS NOT NULL AND EXISTS
 (SELECT 1 FROM jw_migration_v37.messenger_messages m WHERE m.id=message_id));
ALTER TABLE jw_migration_v37.messenger_read_positions ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_migration_v37.messenger_read_positions FORCE ROW LEVEL SECURITY;
CREATE POLICY jw_v37_read_pos ON jw_migration_v37.messenger_read_positions FOR SELECT TO jw_app USING
 (org_id=jw_guard.current_tenant() AND EXISTS
 (SELECT 1 FROM jw_migration_v37.messenger_connections c WHERE c.id=connection_id));
ALTER TABLE jw_migration_v37.messenger_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_migration_v37.messenger_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY jw_v37_receipt ON jw_migration_v37.messenger_receipts FOR SELECT TO jw_app USING
 (jw_guard.current_tenant() IS NOT NULL AND EXISTS
 (SELECT 1 FROM jw_migration_v37.messenger_messages m WHERE m.id=message_id));
REVOKE ALL ON ALL TABLES IN SCHEMA jw_migration_v37 FROM PUBLIC,jw_app;
GRANT USAGE ON SCHEMA jw_migration_v37 TO jw_app;
GRANT SELECT(org_id) ON jw_migration_v37.messenger_companies TO jw_app;
GRANT SELECT ON jw_migration_v37.messenger_connections, jw_migration_v37.messenger_messages,
 jw_migration_v37.messenger_edits, jw_migration_v37.messenger_attachments,
 jw_migration_v37.messenger_read_positions, jw_migration_v37.messenger_receipts TO jw_app;
'''


def _decode(token):
    if not isinstance(token, list) or len(token)!=2:
        raise MigrationBlocked('Malformed canonical SQLite token')
    kind,value=token
    if kind=='null' and value is None:
        return None
    if kind=='text' and isinstance(value,str):
        return value
    if kind=='integer' and isinstance(value,str) and re.fullmatch(r'-?(0|[1-9][0-9]*)',value):
        return int(value)
    if kind=='bytes' and isinstance(value,str):
        import base64
        try: return base64.b64decode(value,validate=True)
        except ValueError as exc: raise MigrationBlocked('Invalid attachment encoding') from exc
    # No lossy coercions, e.g. an unexpected float or boolean.
    raise MigrationBlocked('Unsupported canonical SQLite column type')


def build_contract(records: list[Record]) -> dict:
    """Validate complete legacy behavior before any SQL is executed."""
    by_table={table:[] for table in TABLES}
    if not records or len(records)>5000:
        raise MigrationBlocked('Missing or oversized source')
    for r in records:
        if r.entity not in COLUMNS or sha256(r.payload).hexdigest()!=r.digest:
            raise MigrationBlocked('Source record hash/type mismatch')
        try: obj=json.loads(r.payload)
        except (ValueError,UnicodeError) as exc: raise MigrationBlocked('Invalid source encoding') from exc
        cols=COLUMNS[r.entity]
        if obj.get('entity')!=r.entity or tuple(obj.get('columns',()))!=cols or not isinstance(obj.get('values'),list) or len(obj['values'])!=len(cols):
            raise MigrationBlocked('Schema mismatch: unrepresentable legacy field')
        data={key:_decode(val) for key,val in zip(cols,obj['values'])}
        if r.payload!=canonical_bytes(r.entity,cols,[data[x] for x in cols]):
            raise MigrationBlocked('Noncanonical row cannot be preserved exactly')
        if r.row_key!=row_key([data[k] for k in PK[r.entity]]):
            raise MigrationBlocked('Primary key mismatch')
        by_table[r.entity].append(data)
    if any(not by_table[t] for t in ('messenger_companies','messenger_connections','messenger_messages')):
        raise MigrationBlocked('Insufficient synthetic data to prove isolation')
    for table,rows in by_table.items():
        keys=[tuple(r[c] for c in PK[table]) for r in rows]
        if len(set(keys))!=len(keys): raise MigrationBlocked('Duplicate synthetic primary key')
    companies={r['org_id'] for r in by_table['messenger_companies']}
    threads={r['id']:r for r in by_table['messenger_connections']}
    messages={r['id']:r for r in by_table['messenger_messages']}
    message_seqs=set()
    for t in threads.values():
        if t['org_a'] not in companies or t['org_b'] not in companies or t['org_a']>=t['org_b'] or t['requester_org'] not in (t['org_a'],t['org_b']) or not isinstance(t['connection_seq'],int) or t['connection_seq']<1:
            raise MigrationBlocked('Thread membership/sequence mismatch')
    for msg in messages.values():
        thread=threads.get(msg['connection_id'])
        if (thread is None or thread['status']!='active' or
                msg['sender_org'] not in (thread['org_a'],thread['org_b']) or
                msg['kind'] not in ('text','order')):
            raise MigrationBlocked('Message sender/connection/kind mismatch')
        if not isinstance(msg['message_seq'],int) or msg['message_seq']<1 or msg['message_seq'] in message_seqs or not isinstance(msg['version'],int) or msg['version']<1:
            raise MigrationBlocked('Invalid message sequence/version')
        message_seqs.add(msg['message_seq'])
        if msg['kind']=='order':
            if not msg['order_id'] or not msg['immutable_order_snapshot'] or not msg['actor_name'] or len(msg['actor_name'])<2:
                raise MigrationBlocked('Order message missing required immutable snapshot')
            try: snapshot=json.loads(msg['immutable_order_snapshot'])
            except (TypeError,ValueError) as exc: raise MigrationBlocked('Invalid immutable order JSON') from exc
            if not isinstance(snapshot,dict): raise MigrationBlocked('Order snapshot is not an object')
            # The historical demonstration fixture uses orderId while the
            # running SQLite app uses source_order_id. Accept both forms but
            # never silently map a snapshot referring to a different order.
            for original_id_field in ('source_order_id','orderId'):
                if original_id_field in snapshot and snapshot[original_id_field]!=msg['order_id']:
                    raise MigrationBlocked('Order snapshot source ID mismatch')
        elif msg['order_id'] is not None or msg['immutable_order_snapshot'] is not None or msg['actor_name']!='':
            raise MigrationBlocked('Text message contains order evidence')
    by_message={}
    for edit in by_table['messenger_edits']:
        msg=messages.get(edit['message_id'])
        if (not msg or msg['kind']!='text' or edit['actor_user']!=msg['sender_user']
                or not isinstance(edit['version'],int) or edit['version']<2):
            raise MigrationBlocked('Invalid edited evidence')
        by_message.setdefault(edit['message_id'],[]).append(edit)
    for msg in messages.values():
        revisions=sorted(by_message.get(msg['id'],()),key=lambda e:e['version'])
        if msg['version']!=1+len(revisions) or [e['version'] for e in revisions]!=list(range(2,msg['version']+1)):
            raise MigrationBlocked('Message edit history is missing or noncontiguous')
        for first,second in zip(revisions,revisions[1:]):
            if first['new_body']!=second['previous_body']:
                raise MigrationBlocked('Message edit chain does not match')
        if revisions and revisions[-1]['new_body']!=msg['body']:
            raise MigrationBlocked('Message current body does not match edit history')
    for att in by_table['messenger_attachments']:
        msg=messages.get(att['message_id'])
        if not msg or msg['kind']!='text' or att['message_id'] in by_message or not isinstance(att['data'],bytes) or not att['data']:
            raise MigrationBlocked('Attachment cannot be mapped to its text-bearing message')
        if att['size_bytes']!=len(att['data']) or len(att['data'])>5242880 or att['content_hash']!=sha256(att['data']).hexdigest():
            raise MigrationBlocked('Legacy attachment length/hash conflict')
        if not att['filename'] or not att['mime']:
            raise MigrationBlocked('Missing attachment provenance')
    for r in by_table['messenger_read_positions']:
        t=threads.get(r['connection_id'])
        if not t or r['org_id'] not in (t['org_a'],t['org_b']) or not isinstance(r['last_read_seq'],int):
            raise MigrationBlocked('Read position membership mismatch')
        max_seq=max((m['message_seq'] for m in messages.values() if m['connection_id']==t['id']),default=0)
        if (r['last_read_seq']<0 or r['last_read_seq']>max_seq or
                (r['last_read_seq'] and not any(m['connection_id']==t['id'] and m['message_seq']==r['last_read_seq'] for m in messages.values())) or
                not isinstance(r['last_read_rowid'],int) or r['last_read_rowid']<0):
            raise MigrationBlocked('Read cursor exceeds actual thread history')
    for receipt in by_table['messenger_receipts']:
        m=messages.get(receipt['message_id'])
        if not m or m['kind']!='order': raise MigrationBlocked('Receipt must reference an order message')
        t=threads[m['connection_id']]
        other=t['org_b'] if m['sender_org']==t['org_a'] else t['org_a']
        if receipt['receiver_org']!=other or not receipt['receiver_user'] or not receipt['actor_name']:
            raise MigrationBlocked('Receipt sender/receiver evidence mismatch')
    return by_table


def _guard(cur, *, pristine):
    cur.execute('SELECT current_database(),current_user,current_setting(%s)',('server_version_num',))
    database,user,version=cur.fetchone()
    if not DATABASE.fullmatch(database) or user!='postgres' or int(version)//10000!=17:
        raise MigrationBlocked('Refuse non-disposable PostgreSQL 17 administrator')
    if pristine:
        cur.execute('SELECT to_regnamespace(%s)',(SCHEMA,))
        if cur.fetchone()[0] is not None:
            raise MigrationBlocked('Compatibility schema exists; refuse replacement')


def stage_compat(pg, records, *, inject_failure_after=None):
    """Create/read-only RLS schema and insert typed values, atomically."""
    if inject_failure_after is not None and (not isinstance(inject_failure_after,int) or isinstance(inject_failure_after,bool) or inject_failure_after<1):
        raise MigrationBlocked('Invalid fault injection')
    contract=build_contract(records)
    from psycopg import sql
    with pg.transaction():
        with pg.cursor() as cur:
            _guard(cur,pristine=True)
            cur.execute(DDL)
            i=0
            for entity in TABLES:
                cols=COLUMNS[entity]
                statement=sql.SQL('INSERT INTO {}.{} ({}) VALUES ({})').format(
                    sql.Identifier(SCHEMA),sql.Identifier(entity),
                    sql.SQL(',').join(map(sql.Identifier,cols)),
                    sql.SQL(',').join(sql.Placeholder() for _ in cols))
                for row in contract[entity]:
                    cur.execute(statement,tuple(row[c] for c in cols))
                    i+=1
                    if i==inject_failure_after: raise MigrationBlocked('Injected V3.7 rollback')
    return i


def verify_compat(pg, source):
    """Independent typed read-back; compare SHA-256 and raw canonical bytes."""
    contract=build_contract(source)
    actual=[]
    from psycopg import sql
    with pg.cursor() as cur:
        _guard(cur,pristine=False)
        for table in TABLES:
            cols=COLUMNS[table]
            statement=sql.SQL('SELECT {} FROM {}.{}').format(sql.SQL(',').join(map(sql.Identifier,cols)),
                sql.Identifier(SCHEMA),sql.Identifier(table))
            cur.execute(statement)
            for row in cur.fetchall():
                row=[bytes(x) if isinstance(x,memoryview) else x for x in row]
                payload=canonical_bytes(table,cols,row)
                keys=[row[cols.index(name)] for name in PK[table]]
                actual.append(Record(table,row_key(keys),payload,sha256(payload).hexdigest()))
    from app.pg_migration_shadow_v36 import compare_records
    return compare_records(source,actual)


def drop_compat(pg):
    with pg.transaction():
        with pg.cursor() as cur:
            _guard(cur,pristine=False)
            cur.execute('DROP SCHEMA IF EXISTS jw_migration_v37 CASCADE')
