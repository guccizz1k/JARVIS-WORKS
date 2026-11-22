"""Read-only, fail-closed identity gate for a dedicated PG17 restore target.

Not a replacement for the pinned backup/restore engine or source approval checks.
"""
from __future__ import annotations
import json
import subprocess

NAME = 'jw-b2b3-clean-1122'
PORT = 55433

class TargetBlocked(Exception):
    pass

def _cmd(*args):
    r = subprocess.run(args, capture_output=True, text=True, timeout=15, check=False)
    if r.returncode:
        raise TargetBlocked('command_failed')
    return r.stdout.strip()

def check_docker_identity():
    """Verify exact container name, image, isolation, and no Docker port mappings."""
    try:
        obj = json.loads(_cmd('docker', 'inspect', NAME))
        if len(obj) != 1:
            raise TargetBlocked('container_count')
        d = obj[0]
        networks = d['NetworkSettings']['Networks']
        if (d['Name'] != '/' + NAME or
            d['Config']['Image'] != 'postgres:17' or
            d['State']['Running'] is not True or
            d['HostConfig']['NetworkMode'] != 'none' or
            set(networks) not in (set(), {'none'}) or
            d['HostConfig']['PortBindings'] not in (None, {}) or
            d['NetworkSettings'].get('Ports') not in (None, {}, {'5432/tcp': None})):
            raise TargetBlocked('container_identity_or_isolation')
        return d['Id']
    except (KeyError, TypeError, ValueError, IndexError) as e:
        raise TargetBlocked('invalid_docker_metadata') from e

def prove_target(psycopg, password: str, token: str, backup_module):
    """Require Docker identity stable before/after SQL and marker proof.

    The target is read-only. The caller must separately verify approved SHA,
    time window, live source and role state. No credentials are printed.
    """
    before = check_docker_identity()
    sql = 'SELECT system_identifier FROM pg_control_system()'
    inside = _cmd('docker', 'exec', '-u', 'postgres', NAME,
                  'psql', '-X', '-At', '-d', 'postgres', '-c', sql)
    if not inside.isdigit():
        raise TargetBlocked('invalid_inside_system_id')
    with psycopg.connect(host='127.0.0.1', port=PORT, dbname='postgres',
                         user='postgres', password=password, connect_timeout=5,
                         sslmode='disable') as conn:
        outside = conn.execute(sql).fetchone()[0]
        if str(outside) != inside:
            raise TargetBlocked('system_id_mismatch')
        backup_module.verify_ephemeral_target(conn, token)
    if check_docker_identity() != before:
        raise TargetBlocked('container_replaced_during_check')
    return True
