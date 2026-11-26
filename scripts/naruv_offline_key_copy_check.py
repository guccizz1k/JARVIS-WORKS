#!/usr/bin/env python3
"""Owner-operated offline comparison; never sends or prints recovery key material."""
import base64
import getpass
import hmac
import json
import sys
import warnings


def parse(raw):
    if type(raw) is not str or len(raw) > 128:
        raise ValueError('KEY_COPY_INVALID')
    try:
        encoded = raw.strip().encode('ascii')
        key = base64.b64decode(encoded, altchars=b'-_', validate=True)
        if len(key) != 32 or not hmac.compare_digest(base64.urlsafe_b64encode(key), encoded):
            raise ValueError()
        return key
    except (ValueError, UnicodeError):
        raise ValueError('KEY_COPY_INVALID') from None


def compare(legacy, staged):
    if any(type(x) is not tuple or len(x) != 3 for x in (legacy, staged)):
        raise ValueError('KEY_COPY_INVALID')
    a, b = tuple(parse(v) for v in legacy), tuple(parse(v) for v in staged)
    if hmac.compare_digest(a[0], b[0]) or not all(hmac.compare_digest(s[0], v) for s in (a, b) for v in s[1:]):
        raise ValueError('KEY_COPY_MISMATCH')
    return {'copy_values_match': True, 'scopes_distinct': True, 'copies_compared': 4,
            'storage_independence_verified': False, 'archive_authentication_verified': False,
            'p2_acceptance': 'BLOCKED'}


def main():
    if len(sys.argv) != 1 or not sys.stdin.isatty() or not sys.stderr.isatty():
        print('BLOCKED=LOCAL_INTERACTIVE_TERMINAL_REQUIRED')
        return 1
    try:
        warnings.simplefilter('error', getpass.GetPassWarning)
        def read(scope):
            return tuple(getpass.getpass(f'{scope} {label} (hidden): ') for label in ('original', 'iCloud copy', 'offline copy'))
        print(json.dumps(compare(read('LEGACY'), read('STAGED')), sort_keys=True))
        return 0
    except (Exception, KeyboardInterrupt):
        print('BLOCKED=KEY_COPY_CHECK_FAILED')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
