"""PortOne V2 TEST-channel review only. No production route or session issuance."""
import datetime as dt
import hashlib
import hmac
import http.client
import json
import re
import ssl
from urllib.parse import urlencode

MAX_BODY = 65536


def need(ok):
    if not ok:
        raise ValueError('PORTONE_TEST_REVIEW_DENIED')


def token(value):
    return type(value) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value) is not None


def unique(pairs):
    result = {}
    for k, v in pairs:
        need(k not in result)
        result[k] = v
    return result


def timestamp(value):
    need(type(value) is str and len(value) <= 40 and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})', value))
    return dt.datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()


def inspect(raw, *, expected_id, channel_key, pg_provider, tenant, store_id,
            identifier_kind, expected_tag, pepper, issued_at, expires_at, now):
    """Inspect only trusted server-retrieved response; never trust a browser result.
    Tag must be separately enrolled. No identity proof or session authorization.
    """
    try:
        need(all(token(x) for x in (expected_id, channel_key, pg_provider, tenant, store_id)))
        need(identifier_kind in ('ci', 'di') and type(pepper) is bytes and len(pepper) == 32)
        need(type(expected_tag) is str and re.fullmatch('[0-9a-f]{64}', expected_tag))
        need(all(type(v) is int for v in (issued_at, expires_at, now)) and 0 <= issued_at <= now < expires_at and expires_at-issued_at <= 300)
        need(type(raw) is bytes and 0 < len(raw) <= MAX_BODY)
        doc = json.loads(raw.decode('utf-8'), object_pairs_hook=unique, parse_constant=lambda _: need(False))
        need(type(doc) is dict and doc.get('status') == 'VERIFIED' and doc.get('version') == 'V2' and doc.get('id') == expected_id)
        ch = doc.get('channel')
        need(type(ch) is dict and ch.get('type') == 'TEST' and ch.get('key') == channel_key and ch.get('pgProvider') == pg_provider)
        requested, verified = timestamp(doc.get('requestedAt')), timestamp(doc.get('verifiedAt'))
        need(issued_at <= requested <= verified <= now < expires_at)
        customer = doc.get('verifiedCustomer')
        need(type(customer) is dict)
        subject = customer.get(identifier_kind)
        need(type(subject) is str and 1 <= len(subject) <= 256 and re.fullmatch(r'[A-Za-z0-9+/=_-]+', subject))
        msg = '\0'.join(('NARUV_PORTONE_TEST_V1', tenant, store_id, channel_key, identifier_kind, subject)).encode('ascii')
        need(hmac.compare_digest(hmac.new(pepper, msg, hashlib.sha256).hexdigest(), expected_tag))
        return {'test_response_binding_match': True, 'identity_proofing_verified': False,
                'session_authorized': False, 'delivery_authorized': False, 'production_authorized': False}
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError, OSError):
        raise ValueError('PORTONE_TEST_REVIEW_DENIED') from None


def retrieve_test(*, approved, api_secret, store_id, expected_id):
    """Fixed HTTPS GET, no proxy or redirect; actual invocation requires separate approval.
    Returns private bytes for immediate inspection, never logging them.
    """
    need(approved is True and token(store_id) and token(expected_id))
    need(type(api_secret) is str and re.fullmatch(r'[!-~]{1,512}', api_secret))
    conn = http.client.HTTPSConnection('api.portone.io', timeout=5, context=ssl.create_default_context())
    try:
        conn.request('GET', '/identity-verifications/'+expected_id+'?'+urlencode({'storeId':store_id}),
                     headers={'Authorization':'PortOne '+api_secret,'Accept':'application/json','Accept-Encoding':'identity'})
        response = conn.getresponse()
        need(response.status == 200 and response.getheader('Content-Type','').split(';')[0].strip().lower() == 'application/json')
        need(response.getheader('Content-Encoding','identity').lower() == 'identity')
        raw = response.read(MAX_BODY+1)
        need(0 < len(raw) <= MAX_BODY)
        return raw
    except (OSError, http.client.HTTPException, ValueError):
        raise ValueError('PORTONE_TEST_REVIEW_DENIED') from None
    finally:
        conn.close()
