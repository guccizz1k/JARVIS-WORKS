"""Synthetic legal review intake. Signature verification is not legal acceptance."""
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

ROLES = ('labor', 'tax')


def need(ok):
    if not ok:
        raise ValueError('STATUTORY_REVIEW_INTAKE_DENIED')


def unique(pairs):
    result = {}
    for k, v in pairs:
        need(k not in result)
        result[k] = v
    return result


def decode(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 131072)
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                          parse_constant=lambda _: need(False))
    except (UnicodeError, ValueError, RecursionError):
        raise ValueError('STATUTORY_REVIEW_INTAKE_DENIED') from None


def canonical(doc):
    return json.dumps(doc, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def verify(inventory_raw, expected_sha256, reports, public_keys):
    """Trust pins supplied by authorized operator, never by report sender."""
    need(type(inventory_raw) is bytes and hashlib.sha256(inventory_raw).hexdigest() == expected_sha256)
    inv = decode(inventory_raw)
    need(type(inv) is dict and inv.get('classification') == 'SYNTHETIC_ONLY_NOT_LEGAL_ACCEPTANCE'
         and inv.get('submission_authorized') is False and inv.get('reviewer_expected_values') is None)
    need(type(inv.get('cases')) is list and len(inv['cases']) == 9)
    cases = {}
    for case in inv['cases']:
        need(type(case) is dict and type(case.get('id')) is str and case['id'] not in cases)
        q = case.get('questions')
        need(type(q) is list and q and all(type(x) is str and x for x in q) and len(set(q)) == len(q))
        cases[case['id']] = set(q)
    need(set(cases) == {f'KR{i:02}' for i in range(1, 10)})
    need(type(reports) is dict and set(reports) == set(ROLES) and type(public_keys) is dict and set(public_keys) == set(ROLES))
    need(all(type(k) is bytes and len(k) == 32 for k in public_keys.values()) and public_keys['labor'] != public_keys['tax'])
    findings = {}
    for role in ROLES:
        envelope = decode(reports[role])
        need(type(envelope) is dict and set(envelope) == {'payload', 'signature_hex'})
        payload = envelope['payload']
        need(type(payload) is dict and set(payload) == {'role', 'inventory_sha256', 'cases'})
        need(payload['role'] == role and payload['inventory_sha256'] == expected_sha256)
        sig = envelope['signature_hex']
        need(type(sig) is str and len(sig) == 128 and all(c in '0123456789abcdef' for c in sig))
        try:
            Ed25519PublicKey.from_public_bytes(public_keys[role]).verify(bytes.fromhex(sig), b'NARUV_STATUTORY_REVIEW_V1\0' + canonical(payload))
        except (InvalidSignature, ValueError):
            raise ValueError('STATUTORY_REVIEW_INTAKE_DENIED') from None
        rows = payload['cases']
        need(type(rows) is dict and set(rows) == set(cases))
        for cid, questions in cases.items():
            row = rows[cid]
            need(type(row) is dict and set(row) == {'answers', 'official_sources', 'disposition'})
            need(row['disposition'] in ('ASSESSED', 'MISSING_FACTS', 'OUTSIDE_SCOPE'))
            answers = row['answers']
            need(type(answers) is dict and set(answers) == questions and all(type(v) is str and 0 < len(v.strip()) <= 4000 for v in answers.values()))
            urls = row['official_sources']
            need(type(urls) is list and 0 < len(urls) <= 20 and all(type(x) is str and x.startswith('https://') and len(x) <= 2048 for x in urls))
        findings[role] = sum(row['disposition'] == 'ASSESSED' for row in rows.values())
    return {'signed_response_structure_verified': True, 'assessed_case_counts': findings,
            'professional_credentials_verified': False, 'legal_correctness_verified': False,
            'production_authorized': False, 'p1_acceptance': 'BLOCKED'}
