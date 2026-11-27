"""Versioned, signed future recovery evidence. No live restore or key handling.
An authenticated claim is not evidence that its asserted operation really ran.
Expected bindings and verifier public key must come from independent approval.
"""
import hashlib
import json
import re
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

DOMAIN = b'NARUV_RECOVERY_RECEIPT_V4\x00'
SCOPES = ('legacy', 'staged')
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
SHA1 = re.compile(r'[0-9a-f]{40}\Z', re.ASCII)
RUN = re.compile(r'[0-9a-f]{32}\Z', re.ASCII)
TIME = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\Z', re.ASCII)
BIND = {'scope','run_id','challenge','manifest_sha256','reference_sha256','runner_commit','archives'}
FIELDS = BIND | {'version','started_at','ended_at','results','environment','cleanup'}
ENV = {'networkless_restore','swap_disabled','provider_credentials_absent'}
CLEANUP = {'disposable_pg_removed','plaintext_workspace_removed'}


def need(ok, code):
    if not ok:
        raise ValueError(code)


def unique(pairs):
    d = {}
    for k,v in pairs:
        need(k not in d,'DUPLICATE_FIELD')
        d[k]=v
    return d


def decode(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 65536,'RECEIPT_SIZE')
    try:
        return json.loads(raw.decode('ascii'),object_pairs_hook=unique,parse_constant=lambda _:need(False,'JSON_CONSTANT'))
    except (UnicodeError,RecursionError):
        raise ValueError('RECEIPT_JSON') from None


def canonical(x):
    return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def hexval(x, pattern=HEX):
    return type(x) is str and pattern.fullmatch(x) is not None


def stamp(x):
    need(type(x) is str and TIME.fullmatch(x),'TIMESTAMP_FORMAT')
    return datetime.strptime(x,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def exact(x, fields, code):
    need(type(x) is dict and set(x)==fields,code)


def binding(p):
    exact(p,BIND,'BINDING_FIELDS')
    need(p['scope'] in SCOPES and hexval(p['run_id'],RUN),'RUN_BINDING')
    for k in ('challenge','manifest_sha256','reference_sha256'):
        need(hexval(p[k]),'BINDING_HASH')
    need(hexval(p['runner_commit'],SHA1),'RUNNER_COMMIT')
    a=p['archives']
    need(type(a) is list and len(a)==11 and all(hexval(x) for x in a),'ARCHIVE_SET')
    need(a==sorted(set(a)),'ARCHIVE_ORDER_OR_DUPLICATE')
    return p


def verify_pair(reports, expected, public_key, *, window_start, window_end):
    """Check two separately preauthorized runs, without asserting historical facts."""
    exact(reports,set(SCOPES),'REPORT_SCOPES');exact(expected,set(SCOPES),'EXPECTED_SCOPES')
    need(type(public_key) is bytes and len(public_key)==32,'PUBLIC_KEY')
    a,b=(binding(expected[s]) for s in SCOPES)
    need(a['scope']=='legacy' and b['scope']=='staged','EXPECTED_SCOPE')
    for field in ('run_id','challenge','reference_sha256'):
        need(a[field]!=b[field],'EXPECTED_NOT_INDEPENDENT')
    need(a['manifest_sha256']==b['manifest_sha256'],'EXPECTED_MANIFEST_MISMATCH')
    need(not (set(a['archives']) & set(b['archives'])),'EXPECTED_ARCHIVE_OVERLAP')
    start,end=stamp(window_start),stamp(window_end)
    need(start<end,'APPROVED_WINDOW')
    hashes={}
    for scope in SCOPES:
        env=decode(reports[scope]);exact(env,{'payload','signature_hex'},'ENVELOPE_FIELDS')
        p=env['payload'];exact(p,FIELDS,'RECEIPT_FIELDS')
        need(type(p['version']) is int and p['version']==4,'RECEIPT_VERSION')
        sig=env['signature_hex'];need(type(sig) is str and re.fullmatch(r'[0-9a-f]{128}',sig,re.ASCII),'SIGNATURE_FORMAT')
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(bytes.fromhex(sig),DOMAIN+canonical(p))
        except (InvalidSignature,ValueError):
            raise ValueError('SIGNATURE_INVALID') from None
        observed=binding({k:p[k] for k in BIND})
        need(observed==expected[scope],'BINDING_MISMATCH')
        need(start<=stamp(p['started_at'])<stamp(p['ended_at'])<=end,'RUN_WINDOW')
        for k,fields in [('environment',ENV),('cleanup',CLEANUP)]:
            exact(p[k],fields,'STATUS_FIELDS')
            need(all(v is True for v in p[k].values()),'STATUS_NOT_PASS')
        rows=p['results'];need(type(rows) is list and len(rows)==11,'RESULT_COUNT')
        for row,archive in zip(rows,p['archives']):
            exact(row,{'archive_sha256','authenticated','restored','rows_match','catalog_match'},'RESULT_FIELDS')
            need(row['archive_sha256']==archive,'RESULT_ARCHIVE_MISMATCH')
            need(all(row[k] is True for k in ('authenticated','restored','rows_match','catalog_match')),'ARCHIVE_NOT_PASS')
        hashes[scope]=hashlib.sha256(reports[scope]).hexdigest()
    return {'signed_future_receipt_pair':'PASS_STRUCTURAL_AND_SIGNATURE_CHECKS','receipt_sha256':hashes,
            'independent_signer_control':'NOT_ATTESTED','actual_execution':'NOT_ATTESTED',
            'historical_provenance':'NOT_ATTESTED','production_authorized':False,'gate5':'BLOCKED'}
