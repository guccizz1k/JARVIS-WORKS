"""Defense-in-depth helpers. Not a substitute for PostgreSQL RLS or container sandboxing."""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


def data_cipher():
    key = os.getenv('JW_DATA_KEY', '')
    if not key:
        raise RuntimeError('JW_DATA_KEY is required for MFA enrollment (generate with Fernet.generate_key())')
    try:
        return Fernet(key.encode('ascii'))
    except (ValueError, TypeError) as exc:
        raise RuntimeError('JW_DATA_KEY is not a valid Fernet key') from exc


def totp_code(secret: str, counter: int) -> str:
    key=base64.b32decode(secret.upper() + '=' * (-len(secret) % 8),casefold=True)
    digest=hmac.new(key,counter.to_bytes(8,'big'),hashlib.sha1).digest()
    off=digest[-1] & 0x0f
    number=int.from_bytes(digest[off:off+4],'big') & 0x7fffffff
    return f'{number % 1_000_000:06d}'


def match_totp(secret: str, code: str, last_step: int=-1, when: float|None=None) -> int|None:
    if not isinstance(code,str) or len(code)!=6 or not code.isascii() or not code.isdigit():return None
    step=int((time.time() if when is None else when)//30)
    for current in (step-1,step,step+1):
        if current>last_step and current>=0 and hmac.compare_digest(totp_code(secret,current),code):
            return current
    return None


def secret_for_user(ciphertext: str) -> str:
    try:
        return data_cipher().decrypt(ciphertext.encode('ascii')).decode('ascii')
    except (InvalidToken, UnicodeError) as exc:
        raise RuntimeError('Unable to decrypt MFA secret: check JW_DATA_KEY') from exc


def lock_file_scan(raw:bytes)->str:
    """Scan using a locally installed ClamAV binary; production fails closed.

    Executable names are fixed, not supplied by untrusted user input.
    """
    mode=os.getenv('JW_UPLOAD_SCAN','off' if os.getenv('JW_ENV','').lower()!='production' else 'clamav')
    if mode=='off':
        if os.getenv('JW_ENV','').lower()=='production':
            raise RuntimeError('Production cannot disable upload antivirus scanning')
        return 'not_scanned_dev'
    if mode!='clamav':raise RuntimeError('JW_UPLOAD_SCAN must be clamav or dev-only off')
    import shutil
    scanner=shutil.which('clamscan')
    if scanner is None:raise RuntimeError('ClamAV is not installed; uploads fail closed')
    with tempfile.TemporaryDirectory(prefix='jwscan-') as d:
        p=Path(d)/'incoming'
        p.write_bytes(raw)
        p.chmod(0o600)
        try:
            done=subprocess.run([scanner,'--no-summary',str(p)],capture_output=True,timeout=15,check=False)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError('Antivirus scan timed out') from exc
        if done.returncode != 0:
            # Do not copy scanner paths or content to the user response.
            raise RuntimeError('Upload blocked: antivirus scan failed or reported a threat')
    return 'clean_clamav'


def limited_extract(filename:str, raw:bytes):
    """Run untrusted PDF/XLSX parsers out of the app process with resource ceilings.

    The worker still has host/network access. Deployment must use a network-disabled
    restricted container/worker for complete isolation.
    """
    limit=5*1024*1024
    if not raw or len(raw)>limit:raise ValueError('Uploaded file is empty or exceeds 5MB')
    lock_file_scan(raw)
    src=base64.b64encode(raw)
    data=json.dumps({'filename':filename,'base64':src.decode('ascii')},ensure_ascii=False).encode('utf-8')
    def restrict():
        if os.name!='posix':return
        import resource
        resource.setrlimit(resource.RLIMIT_CPU,(12,13))
        resource.setrlimit(resource.RLIMIT_AS,(768*1024*1024,768*1024*1024))
        resource.setrlimit(resource.RLIMIT_FSIZE,(4*1024*1024,4*1024*1024))
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    timeout=int(os.getenv('JW_IMPORT_TIMEOUT','18'))
    if not 5<=timeout<=60:raise RuntimeError('JW_IMPORT_TIMEOUT must be 5-60 seconds')
    try:
        done=subprocess.run([sys.executable,'-m','app.import_worker'],input=data,
            capture_output=True,timeout=timeout,cwd=str(Path(__file__).resolve().parent.parent),
            preexec_fn=restrict if os.name=='posix' else None,check=False,
            env={k:v for k,v in os.environ.items() if k in ('PATH','PYTHONPATH','LANG','LC_ALL','HOME','VIRTUAL_ENV')})
    except subprocess.TimeoutExpired as exc:
        raise ValueError('Document analysis timed out; upload not saved') from exc
    if done.returncode!=0 or len(done.stdout)>2_000_000:
        raise ValueError('Document analysis failed safely; upload not saved')
    try:
        payload=json.loads(done.stdout)
    except ValueError as exc:
        raise ValueError('Document analysis returned invalid data') from exc
    if payload.get('error'):raise ValueError(payload['error'])
    if not isinstance(payload.get('result'),dict):raise ValueError('Invalid document analysis result')
    return payload['result']


def install_tenant_relationship_guards(connection):
    """DB-enforced **write relation consistency**, NOT DB row-level read isolation."""
    relations={
        'quotes': [('customer_id','customers','id')],
        'quote_items':[('quote_id','quotes','id')],
        'orders':[('customer_id','customers','id'),('quote_id','quotes','id')],
        'order_items':[('order_id','orders','id')],
        'invoices':[('customer_id','customers','id'),('order_id','orders','id')],
        'invoice_items':[('invoice_id','invoices','id')],
        'payments':[('invoice_id','invoices','id')],
        'import_previews':[('uploaded_by','users','id'),('order_id','orders','id'),('quote_id','quotes','id')],
        'audit_logs':[('actor_id','users','id')],
        'security_events':[('actor_id','users','id')],
    }
    # No user-controlled SQL identifiers; these constants are internal audited schema names.
    for child, parents in relations.items():
        for col, parent, parentkey in parents:
            if child in ('quote_items','order_items','invoice_items'):
                # Item tables have no org_id: parent FK guarantees existing parent linkage.
                continue
            guard=f'''NEW.{col} IS NOT NULL AND NOT EXISTS (
                   SELECT 1 FROM {parent} parent WHERE parent.{parentkey}=NEW.{col}
                   AND parent.org_id=NEW.org_id)'''
            for op in ('INSERT','UPDATE'):
                name=f'jw_guard_{child}_{col}_{op.lower()}'
                connection.execute(f'''CREATE TRIGGER IF NOT EXISTS {name}
                  BEFORE {op} ON {child} FOR EACH ROW WHEN {guard}
                  BEGIN SELECT RAISE(ABORT,'cross-tenant relational reference'); END''')
    # No claim of full RLS: these triggers only reject inconsistent writes.


def install_item_link_guards(connection):
    """Protect original item lineage from accidental references to another order/quote."""
    guards={
      'order_items':("NEW.source_quote_item_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM quote_items qi JOIN orders o ON o.quote_id=qi.quote_id WHERE qi.id=NEW.source_quote_item_id AND o.id=NEW.order_id)"),
      'invoice_items':("NEW.source_order_item_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM order_items oi JOIN invoices inv ON inv.order_id=oi.order_id WHERE oi.id=NEW.source_order_item_id AND inv.id=NEW.invoice_id)"),
    }
    for table, guard in guards.items():
        for op in ('INSERT','UPDATE'):
            connection.execute(f'''CREATE TRIGGER IF NOT EXISTS jw_lineage_{table}_{op.lower()}
                  BEFORE {op} ON {table} FOR EACH ROW WHEN {guard}
                  BEGIN SELECT RAISE(ABORT,'invalid cross-document item lineage'); END''')


def sealed_json(value) -> str:
    """Encrypt sensitive *import evidence* JSON when JW_DATA_KEY is configured.

    This does not encrypt SQLite index fields, customers, quotes or payments;
    full-database encryption and key rotation remain outstanding.
    """
    src=value if isinstance(value,str) else json.dumps(value,ensure_ascii=False,sort_keys=True)
    if src.startswith('ENC1:'):return src
    if not os.getenv('JW_DATA_KEY'):return src
    return 'ENC1:'+data_cipher().encrypt(src.encode('utf-8')).decode('ascii')


def unseal_json(value:str):
    if value.startswith('ENC1:'):
        try: return json.loads(data_cipher().decrypt(value[5:].encode('ascii')).decode('utf-8'))
        except (InvalidToken, UnicodeError, ValueError) as exc:
            raise RuntimeError('Cannot decrypt stored document evidence (wrong data key or damaged record)') from exc
    return json.loads(value)


def migrate_evidence_encryption(connection):
    """Idempotent migration; caller must have made a verified backup."""
    if not os.getenv('JW_DATA_KEY'):return 0
    count=0
    for table,column in (('import_previews','normalized_json'),('quotes','source_document_meta'),('orders','source_document_meta')):
        # Only rows containing actual source evidence, not default '{}'.
        rows=connection.execute(f'''SELECT id,{column} as raw FROM {table}
               WHERE {column} IS NOT NULL AND {column} NOT IN ('','{{}}')
               AND {column} NOT LIKE 'ENC1:%' ''').fetchall()
        for r in rows:
            # Fail closed on malformed old data before attempting to rewrite.
            json.loads(r['raw'])
            connection.execute(f'UPDATE {table} SET {column}=? WHERE id=?',(sealed_json(r['raw']),r['id']))
            count+=1
    return count


def issue_recovery_codes(count: int=8) -> list[str]:
    """Return unpredictable 128-bit one-time codes; never persist plaintext."""
    if count!=8:raise ValueError('Recovery code count is fixed')
    return [secrets.token_hex(16) for _ in range(count)]


def recovery_hash(user_id: str, code: str) -> str:
    if not isinstance(code,str) or len(code)!=32 or not all(ch in '0123456789abcdefABCDEF' for ch in code):
        raise ValueError('Invalid recovery code')
    return hashlib.sha256(('jw-recovery-v1:' + user_id + ':' + code.lower()).encode('ascii')).hexdigest()
