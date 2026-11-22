from pathlib import Path
from unittest.mock import patch
import pytest

from scripts import ci_cinema_pg_v6_forward_recover as r

def test_known_local_socat_listener():
    output=b'LISTEN 0 5 127.0.0.1:55433 0.0.0.0:* users:(("socat",pid=456,fd=5))'
    args=(b'/usr/bin/socat\x00'+r.LISTEN_ARG.encode()+b'\x00'+r.EXEC_ARG.encode()+b'\x00')
    with patch.object(r,'command',side_effect=[output,args]):
        assert r.find_listener()==456

def test_unknown_listener_never_killed():
    output=b'LISTEN 0 5 127.0.0.1:55433 0.0.0.0:* users:(("other",pid=456,fd=5))'
    args=b'/usr/bin/other\x00unrelated\x00'
    with patch.object(r,'command',side_effect=[output,args]):
        with pytest.raises(r.RecoveryBlocked,match='foreign_listener'):
            r.find_listener()

def test_public_socket_rejected():
    output=b'LISTEN 0 5 0.0.0.0:55433 0.0.0.0:* users:(("socat",pid=456,fd=5))'
    with patch.object(r,'command',return_value=output):
        with pytest.raises(r.RecoveryBlocked,match='unexpected_listener_address'):
            r.find_listener()

def test_listener_owner_missing_rejected():
    output=b'LISTEN 0 5 127.0.0.1:55433 0.0.0.0:*'
    with patch.object(r,'command',return_value=output):
        with pytest.raises(r.RecoveryBlocked,match='listener_owner_unknown'):
            r.find_listener()

def test_write_relay_has_real_newlines(tmp_path):
    path=tmp_path/'relay.sh'
    with patch.object(r,'RELAY',path),patch.object(r.shutil,'which',return_value='/usr/bin/tool'):
        r.write_relay(456)
    assert path.read_text()=='#!/bin/sh\nexec /usr/bin/nsenter -t 456 -n /usr/bin/socat STDIO TCP:127.0.0.1:5432\n'
    assert path.stat().st_mode & 0o777==0o700

def test_no_restart_if_healthy():
    with patch.object(r,'check_container',return_value=('id',123)), \
         patch.object(r,'ready'), \
         patch.object(r,'live_target_ok',return_value=True), \
         patch.object(r,'checked_target_config',return_value={'safe':True}) as check, \
         patch.object(r,'find_listener') as find:
        assert r.repair(None,None)=='ALREADY_HEALTHY'
        check.assert_called_once()
        find.assert_not_called()

def test_local_command_failure_fails_closed():
    p=type('Process',(),{'returncode':1,'stdout':b''})()
    with patch.object(r.subprocess,'run',return_value=p):
        with pytest.raises(r.RecoveryBlocked,match='local_command_failed'):
            r.command('docker','inspect','x')
