"""Independent review findings: no unsafe DB diagnostic echo or synthetic zero."""
import json
import subprocess
from pathlib import Path

import pytest
from fastapi import HTTPException
from app.pg_cinema_trade_v1 import _map_error

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('sqlstate,expected', [
    ('23514', 422), ('42501', 403), ('23505', 409),
    ('P0002', 404), ('40P01', 409), ('XX000', 503),
])
def test_database_diagnostics_are_not_echoed(sqlstate, expected):
    class Diagnostic:
        message_primary = 'password=SECRET_VALUE, customer=EXAMPLE_PRIVATE'
        constraint_name = None

    class DbError(Exception):
        diag = Diagnostic()

    error = DbError()
    error.sqlstate = sqlstate
    result = _map_error(error)
    assert isinstance(result, HTTPException)
    assert result.status_code == expected
    assert 'SECRET_VALUE' not in result.detail
    assert 'PRIVATE' not in result.detail
    assert len(result.detail) <= 100


def test_js_server_ledger_numbers_fail_closed_without_changing_visual_layer():
    js = (ROOT / 'app/cinema_bridge_v3.js').read_text(encoding='utf-8')
    start = js.index('const _jwV3Int=n=>{')
    end = js.index('\n};', start) + 3
    implementation = js[start:end]
    program = implementation + '''
const good=[0,1,-1,1000000,"0","100000000"];
const bad=[null,undefined,"",true,false,"abc","4.5","1e9",9007199254740992];
for(const x of good){if(!Number.isSafeInteger(_jwV3Int(x)))process.exit(12)}
for(const x of bad){let failed=false;try{_jwV3Int(x)}catch(e){failed=true};if(!failed)process.exit(13)}
'''
    result = subprocess.run(['node', '-e', program], capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr


def test_js_invalid_source_timestamps_are_not_replaced_with_now():
    js = (ROOT / 'app/cinema_bridge_v3.js').read_text(encoding='utf-8')
    start = js.index('const _jwV3Time=v=>{')
    end = js.index('\n};', start) + 3
    implementation = js[start:end]
    program = implementation + '''
for(const x of [null,undefined,"","not-a-date"]){let failed=false;try{_jwV3Time(x)}catch(e){failed=true}if(!failed)process.exit(14)}
if(_jwV3Time('2026-11-04T06:30:00Z')!==Date.parse('2026-11-04T06:30:00Z'))process.exit(15);
'''
    result = subprocess.run(['node','-e',program],capture_output=True,text=True,timeout=5)
    assert result.returncode == 0, result.stderr
