"""Replay a PostgreSQL deparser boundary; no private schema/row fixture.

Real PG17.11 catalog -> PG17.12 reparse/dump evidence is kept separately.
These unit cases pin the captured default/pretty response distinction and
retain strict missing/changed constraint detection through fetch_signature.
"""
import hashlib
import re
import pytest
from scripts import pg_backup_v223 as backup

RAW_NESTED = 'CHECK ((((length(display_name) >= 2) AND (length(display_name) <= 120)) AND (display_name = btrim(display_name))))'
RAW_FLAT = 'CHECK (((length(display_name) >= 2) AND (length(display_name) <= 120) AND (display_name = btrim(display_name))))'
CANONICAL = 'CHECK (length(display_name) >= 2 AND length(display_name) <= 120 AND display_name = btrim(display_name))'


class CatalogReplay:
    def __init__(self, raw, canonical):
        self.raw, self.canonical, self.rows = raw, canonical, []
    def cursor(self): return self
    def __enter__(self): return self
    def __exit__(self, *_): pass
    def execute(self, query, params=None):
        self.rows = []
        if 'pg_get_constraintdef' in query and self.raw is not None:
            pretty = re.search(r'pg_get_constraintdef\(k\.oid,\s*true\)', query, re.I)
            definition = self.canonical if pretty else self.raw
            self.rows = [('sample.name_check', hashlib.md5(definition.encode()).hexdigest())]
    def fetchall(self): return self.rows


def test_associative_and_display_difference_is_not_restore_corruption():
    source = backup.fetch_signature(CatalogReplay(RAW_NESTED, CANONICAL), 'jw_dev')
    restored = backup.fetch_signature(CatalogReplay(RAW_FLAT, CANONICAL), 'jw_dev')
    assert backup.diff_signatures(source, restored) == []


@pytest.mark.parametrize('changed', [
    CANONICAL.replace('>= 2', '>= 3'),
    CANONICAL.replace('<= 120', '<= 121'),
    'CHECK ((length(display_name) >= 2 OR length(display_name) <= 120) AND display_name = btrim(display_name))',
    CANONICAL + ' NOT VALID',
    "CHECK (display_name = 'A AND B')",
    None,
])
def test_real_constraint_changes_and_removal_still_fail(changed):
    source = backup.fetch_signature(CatalogReplay(RAW_NESTED, CANONICAL), 'jw_dev')
    restored = backup.fetch_signature(CatalogReplay(changed, changed), 'jw_dev')
    assert backup.diff_signatures(source, restored) == ['constraints:sample.name_check']
