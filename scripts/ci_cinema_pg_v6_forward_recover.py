#!/usr/bin/env python3
"""Fail-closed local 55433 relay recovery after a Codespaces/Docker restart.

Only touches the localhost forwarding process for the protected isolated
jw-b2b3-clean-1122 container. Does not change PG roles or run backups.
Never kills a listener unless its complete argv matches the previously reviewed
socat relay. No Docker port publishing, network changes or container recreation.
"""
from __future__ import annotations
import os
import re
import shutil
import socket
import stat
import subprocess
import time
from pathlib import Path

from scripts import ci_cinema_pg_v6_target_adapter as gate
from scripts.ci_cinema_pg_v6_target_binding import checked_target_config

RELAY = Path('/tmp/jw-b2b3-connect.sh')
LISTEN_ARG = 'TCP-LISTEN:55433,bind=127.0.0.1,reuseaddr,fork'
EXEC_ARG = 'EXEC:' + str(RELAY)

class RecoveryBlocked(Exception): pass

def command(*args, timeout=15):
    result = subprocess.run(args, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RecoveryBlocked('local_command_failed')
    return result.stdout

def find_listener():
    data = command('sudo','-n','ss','-H','-ltnp','sport = :55433').decode('utf-8', 'replace')
    rows = [line for line in data.splitlines() if line.strip()]
    if not rows:
        return None
    if len(rows) != 1 or '127.0.0.1:55433' not in rows[0]:
        raise RecoveryBlocked('unexpected_listener_address_or_count')
    matches = re.findall(r'pid=(\\d+)', rows[0])
    if len(matches) != 1:
        raise RecoveryBlocked('listener_owner_unknown')
    pid = int(matches[0])
    argv = command('sudo','-n','cat',f'/proc/{pid}/cmdline').split(b'\\x00')
    argv = [arg.decode('utf-8', 'replace') for arg in argv if arg]
    if not argv or Path(argv[0]).name != 'socat' or argv[1:] != [LISTEN_ARG, EXEC_ARG]:
        raise RecoveryBlocked('foreign_listener_do_not_kill')
    return pid

def check_container():
    import json
    gate.check_docker_identity()
    info = json.loads(command('docker','inspect',gate.NAME))
    if len(info) != 1 or not info[0].get('State',{}).get('Running'):
        raise RecoveryBlocked('container_not_running')
    pid = info[0]['State'].get('Pid')
    if type(pid) is not int or pid <= 1:
        raise RecoveryBlocked('container_pid_invalid')
    return info[0]['Id'], pid

def ready():
    for _ in range(30):
        result=subprocess.run(['docker','exec','-u','postgres',gate.NAME,
                               'pg_isready','-q','-h','/var/run/postgresql','-p','5432'],
                              capture_output=True, timeout=10)
        if result.returncode==0:
            return
        time.sleep(1)
    raise RecoveryBlocked('postgres_not_ready')

def live_target_ok(psycopg, engine):
    # An existing listener might connect to another PG cluster: such a
    # server MUST block recovery rather than being killed and replaced.
    from scripts.ci_cinema_pg_m import read_private_target
    from scripts.pg_backup_v223 import parse_dsn
    cfg=read_private_target()
    options=parse_dsn(cfg['JW_PG_TARGET_ADMIN_DSN'])
    try:
        with psycopg.connect(host='127.0.0.1',port=gate.PORT,
                  dbname='postgres',user='postgres',
                  password=options['password'],sslmode='disable',
                  connect_timeout=3) as conn:
            inside=gate._cmd('docker','exec','-u','postgres',gate.NAME,
                       'psql','-X','-At','-d','postgres','-c',
                       'SELECT system_identifier FROM pg_control_system()')
            outside=str(conn.execute('SELECT system_identifier FROM pg_control_system()').fetchone()[0])
            if inside != outside:
                raise RecoveryBlocked('foreign_pg_cluster_do_not_replace')
            engine.verify_ephemeral_target(conn,cfg['JW_PG_TARGET_EPHEMERAL_TOKEN'])
            return True
    except psycopg.OperationalError:
        return False

def write_relay(pid):
    for executable in ('socat','nsenter'):
        if not shutil.which(executable):
            raise RecoveryBlocked('relay_dependency_missing')
    if RELAY.is_symlink():
        raise RecoveryBlocked('relay_symlink')
    if RELAY.exists():
        st=RELAY.stat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid():
            raise RecoveryBlocked('relay_ownership_invalid')
    flags=os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os,'O_NOFOLLOW',0)
    fd=os.open(RELAY,flags,0o700)
    with os.fdopen(fd,'w') as f:
        f.write('#!/bin/sh\\nexec /usr/bin/nsenter -t '+str(pid)+
                ' -n /usr/bin/socat STDIO TCP:127.0.0.1:5432\\n')
    os.chmod(RELAY,0o700)

def repair(psycopg,engine):
    identity,pid=check_container()
    ready()
    try:
        if live_target_ok(psycopg,engine):
            checked_target_config(psycopg,engine)
            return 'ALREADY_HEALTHY'
    except Exception:
        # If SQL connects but fails any proof, do NOT attempt repair.
        raise
    listener=find_listener()
    if listener is not None:
        command('sudo','-n','kill','-TERM',str(listener))
        for _ in range(20):
            time.sleep(.1)
            if find_listener() is None:
                break
        if find_listener() is not None:
            raise RecoveryBlocked('verified_old_listener_not_stopped')
    if check_container() != (identity,pid):
        raise RecoveryBlocked('container_changed_before_rebind')
    write_relay(pid)
    log=Path('/tmp/jw-b2b3-v6-forward.log')
    with log.open('ab') as stream:
        subprocess.Popen(['sudo','-n','socat',LISTEN_ARG,EXEC_ARG],
                          stdin=subprocess.DEVNULL,stdout=stream,
                          stderr=stream,start_new_session=True)
    for _ in range(20):
        try:
            checked_target_config(psycopg,engine)
            if check_container() != (identity,pid):
                raise RecoveryBlocked('container_changed_after_rebind')
            return 'RELAY_RECOVERED'
        except (psycopg.OperationalError,gate.TargetBlocked):
            time.sleep(.25)
    raise RecoveryBlocked('relay_rebind_not_proven')

def main():
    try:
        import psycopg
        from scripts import pg_backup_v223 as engine
        state=repair(psycopg,engine)
        print('V6_TARGET_55433_'+state+'_PASS')
        return 0
    except BaseException as exc:
        known=(RecoveryBlocked,gate.TargetBlocked)
        reason=str(exc) if isinstance(exc,known) else type(exc).__name__
        safe={'local_command_failed','unexpected_listener_address_or_count',
              'listener_owner_unknown','foreign_listener_do_not_kill',
              'container_not_running','container_pid_invalid','postgres_not_ready',
              'foreign_pg_cluster_do_not_replace','relay_dependency_missing',
              'relay_symlink','relay_ownership_invalid',
              'verified_old_listener_not_stopped','container_changed_before_rebind',
              'container_changed_after_rebind','relay_rebind_not_proven',
              'command_failed','container_identity_or_isolation','system_id_mismatch'}
        print('V6_TARGET_RECOVERY_BLOCKED',reason if reason in safe else type(exc).__name__)
        return 2
    finally:
        print('NO_ROLE_CHANGE_NO_BACKUP')

if __name__=='__main__':
    raise SystemExit(main())
