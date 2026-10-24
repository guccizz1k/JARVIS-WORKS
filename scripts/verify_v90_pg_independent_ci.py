"""Independent live PG17 transaction-lock proof on a throwaway CI service only.

This probes the exact V9 chat advisory-lock key using two *real* nonprivileged
backend connections. It is not a production messenger RPC/RLS acceptance test.
It must refuse shared/external PostgreSQL and clean up minted login roles.
"""
from __future__ import annotations
import os
import secrets
import sys
import time
from concurrent.futures import ThreadPoolExecutor


def run():
    if os.getenv('JW_PG_CI_ALLOW') != 'ONLY_EPHEMERAL_LOCAL_DATABASE':
        print('BLOCKED: isolated CI explicit opt-in absent')
        return 2
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    dsn = os.getenv('JW_PG_CI_ROOT_DSN', '')
    try:
        opts = conninfo_to_dict(dsn)
    except Exception:
        print('BLOCKED: invalid DSN')
        return 2
    if (opts.get('host') not in {'localhost','127.0.0.1','::1'}
            or opts.get('user') != 'postgres' or opts.get('dbname') != 'postgres'
            or not opts.get('password')):
        print('BLOCKED: only ephemeral local postgres CI allowed')
        return 2
    prefix = 'jw_ci_' + secrets.token_hex(4)
    data_role, auth_role = prefix+'_data', prefix+'_auth'
    app_login, auth_login = prefix+'_api', prefix+'_login'
    app_pass, auth_pass = secrets.token_urlsafe(30), secrets.token_urlsafe(30)
    created = []
    connections = []
    root = None
    result = 1
    try:
        root = psycopg.connect(dsn,autocommit=True,connect_timeout=5)
        with root.cursor() as cur:
            cur.execute('SELECT current_user, current_database(), current_setting(%s)',('server_version_num',))
            usr,db,ver=cur.fetchone()
            cur.execute("SELECT count(*) FROM pg_database WHERE NOT datistemplate AND datname <> 'postgres'")
            dbcount=cur.fetchone()[0]
            cur.execute("SELECT count(*) FROM pg_roles WHERE rolname <> 'postgres' AND rolname !~ '^pg_'")
            rolecount=cur.fetchone()[0]
            if (usr,db)!=(opts['user'],opts['dbname']) or int(ver)//10000!=17 or dbcount or rolecount:
                print('BLOCKED: refusing shared/non-PG17 server')
                return 2
            for role in (data_role,auth_role):
                cur.execute(sql.SQL('CREATE ROLE {} NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE').format(sql.Identifier(role)))
                created.append(role)
            for user,password in ((app_login,app_pass),(auth_login,auth_pass)):
                cur.execute(sql.SQL('CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE PASSWORD {}').format(sql.Identifier(user),sql.Literal(password)))
                created.append(user)
            cur.execute(sql.SQL('GRANT {} TO {} WITH INHERIT FALSE, SET TRUE').format(sql.Identifier(data_role),sql.Identifier(app_login)))
            cur.execute(sql.SQL('GRANT {} TO {} WITH INHERIT FALSE, SET TRUE').format(sql.Identifier(auth_role),sql.Identifier(auth_login)))
            cur.execute("SELECT pg_has_role(%s,%s,'MEMBER'), pg_has_role(%s,%s,'MEMBER')",
                        (app_login,auth_role,auth_login,data_role))
            assert cur.fetchone()==(False,False),'role boundary violated'
        make=lambda user,pwd:psycopg.connect(make_conninfo(dsn,user=user,password=pwd),autocommit=True,connect_timeout=5)
        a,b=make(app_login,app_pass),make(app_login,app_pass)
        auth=make(auth_login,auth_pass)
        connections.extend((a,b,auth))
        with a.cursor() as ca,b.cursor() as cb,auth.cursor() as cc:
            ca.execute('SELECT pg_backend_pid(),session_user,rolsuper,rolbypassrls FROM pg_roles WHERE rolname=session_user')
            pa=ca.fetchone()
            cb.execute('SELECT pg_backend_pid(),session_user,rolsuper,rolbypassrls FROM pg_roles WHERE rolname=session_user')
            pb=cb.fetchone()
            cc.execute('SELECT pg_backend_pid(),session_user,rolsuper,rolbypassrls FROM pg_roles WHERE rolname=session_user')
            pc=cc.fetchone()
        assert len({pa[0],pb[0],pc[0]})==3
        assert all(x[2:]==(False,False) for x in (pa,pb,pc)),'privileged connection'
        assert pa[1]==pb[1]==app_login and pc[1]==auth_login
        with auth.cursor() as cur:
            cur.execute("SELECT pg_has_role(session_user,%s,'MEMBER')",(data_role,))
            assert cur.fetchone()==(False,), 'auth login can adopt data role'
        def lock(conn,chat,blocking=False):
            stmt=('SELECT pg_advisory_xact_lock(hashtextextended(\'jw_dev.v90.messenger/\'||%s,0))' if blocking
                  else 'SELECT pg_try_advisory_xact_lock(hashtextextended(\'jw_dev.v90.messenger/\'||%s,0))')
            with conn.cursor() as cur:
                cur.execute(stmt,(chat,))
                return cur.fetchone()[0]
        with a.transaction():
            assert lock(a,'chat-A') is True
            with b.transaction():
                assert lock(b,'chat-A') is False,'second transaction took same lock'
                assert lock(b,'chat-B') is True,'unrelated chat unexpectedly blocked'
        with b.transaction():
            assert lock(b,'chat-A') is True,'COMMIT did not release lock'
        def contender():
            with b.transaction():
                start=time.monotonic()
                lock(b,'chat-A',True)
                return time.monotonic()-start
        with ThreadPoolExecutor(max_workers=1) as pool:
            with a.transaction():
                lock(a,'chat-A',True)
                future=pool.submit(contender)
                time.sleep(0.35)
                assert not future.done(),'two independent transactions did not overlap/block'
            delay=future.result(timeout=8)
        assert delay>=0.2,'lock wait was not actually observed'
        print('PASS: 3 real backends; two separate nonprivileged logins; no cross-role membership')
        print('PASS: same-chat contention, unrelated-chat availability, COMMIT release, blocking waiter')
        result=0
    except Exception as exc:
        print('FAIL: '+type(exc).__name__+'; SQL details and passwords withheld',file=sys.stderr)
        result=1
    finally:
        for conn in connections:
            try:conn.close()
            except Exception:pass
        if root is not None:
            try:
                with root.cursor() as cur:
                    for name in reversed(created):
                        cur.execute(sql.SQL('DROP ROLE IF EXISTS {}').format(sql.Identifier(name)))
                print('PASS: ephemeral roles cleaned up')
            except Exception as exc:
                print('FAIL: ephemeral role cleanup '+type(exc).__name__,file=sys.stderr)
                result=1
            finally:
                root.close()
    return result


if __name__=='__main__':
    raise SystemExit(run())
