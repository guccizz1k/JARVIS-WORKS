"""Read-only route discrimination, then previously pinned paired review.
No transaction-pooler writes, no security-policy change, no credential logging."""
import getpass
import hashlib
import importlib.util
import ipaddress
import os
from pathlib import Path
import re
import socket
import sys
import warnings
from contextlib import closing
import psycopg

ROOT=Path.home()/'.naruv-qa-review'
PIN='70bd3cfd4e76c3f8debe5a2d39c7897890100f38'
def need(ok,code):
    if not ok:raise RuntimeError(code)
def load():
    p=ROOT/'route-review.py'
    raw=p.read_bytes()
    need(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==PIN,'RUNNER_PIN')
    spec=importlib.util.spec_from_file_location('pinned_route_review',p)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m
def addresses(host,port,family):
    try:
        return list(dict.fromkeys(str(ipaddress.ip_address(x[4][0])) for x in socket.getaddrinfo(host,port,family,socket.SOCK_STREAM)))[:2]
    except OSError:
        return []
def kwargs(m,route,addr,database,user,pw):
    need(route in ('direct','session','transaction'),'ROUTE')
    need(database=='postgres' or re.fullmatch(r'naruv_qa_workload_[a-f0-9]{12}',database) is not None,'DB_SCOPE')
    if route=='transaction':need(database=='postgres' and user=='postgres','DIAGNOSTIC_ONLY')
    return dict(host=m.DIRECT if route=='direct' else m.HOST,hostaddr=addr,
        port=6543 if route=='transaction' else 5432,dbname=database,
        user=user if route=='direct' else user+'.'+m.REF,password=pw,
        sslmode='verify-full',sslrootcert=str(ROOT/'ca.crt'),gssencmode='disable',
        connect_timeout=6,autocommit=True,prepare_threshold=None,
        application_name='naruv_qa_route_diagnostic')
def classify(m,e):
    code=m.safe_reason(e)
    if code!='UNCLASSIFIED':return code
    msg=str(e).lower()
    if 'network is unreachable' in msg or 'no route to host' in msg:return 'NO_NETWORK_ROUTE'
    if 'connection refused' in msg:return 'TCP_REFUSED'
    return 'UNCLASSIFIED'
def probe(m,route,addr,pw):
    with closing(psycopg.connect(**kwargs(m,route,addr,'postgres','postgres',pw))) as a:
        # No session settings, advisory locks or writes in diagnostic mode.
        with a.transaction():
            a.execute('SET TRANSACTION READ ONLY')
            m.baseline(a)
            need(m.one(a,"SELECT count(*) FROM pg_database WHERE left(datname,18)='naruv_qa_workload_'")==(0,),'OLD_WORKLOAD_DB')
            need(m.one(a,"SELECT count(*) FROM pg_roles WHERE left(rolname,3)='nq_'")==(0,),'OLD_WORKLOAD_ROLES')
            pid=m.one(a,'SELECT pg_backend_pid()')[0]
            if route!='transaction':
                with closing(psycopg.connect(**kwargs(m,route,addr,'postgres','postgres',pw))) as b:
                    with b.transaction():
                        b.execute('SET TRANSACTION READ ONLY')
                        m.baseline(b)
                        need(pid!=m.one(b,'SELECT pg_backend_pid()')[0],'INDEPENDENT_SESSION_REQUIRED')
    return True
def run(m,pw,src):
    # Only current DNS results of the official hostnames; never guess hosts.
    v6=addresses(m.DIRECT,5432,socket.AF_INET6)
    v4=addresses(m.HOST,5432,socket.AF_INET)
    print('ROUTE_DNS_COUNTS',len(v6),len(v4),flush=True)
    for route,items in (('direct',v6[:1]),('session',v4),('transaction',v4[:1])):
        for index,addr in enumerate(items,1):
            try:
                probe(m,route,addr,pw)
            except psycopg.OperationalError as e:
                reason=classify(m,e)
                print('ROUTE_DIAG_BLOCKED',route,index,reason,flush=True)
                # No further login attempt on auth/TLS/security or unknown failure.
                if reason not in ('BACKEND_REFUSED','TCP_REFUSED','NO_NETWORK_ROUTE','TIMEOUT'):
                    raise RuntimeError('ROUTE_SECURITY_STOP') from None
                continue
            print('ROUTE_DIAG_PASS',route,index,flush=True)
            if route=='transaction':
                print('TRANSACTION_READ_ONLY_PASS_SESSION_REQUIRED',flush=True)
                return 2
            def fixed(selected,database,user,password,ca):
                need(selected==route,'ROUTE_CHANGED')
                return psycopg.connect(**kwargs(m,route,addr,database,user,password))
            m.route_connect=fixed
            print('PAIRED_REVIEW_START',route,index,flush=True)
            return m.run(pw,src,route)
    print('NO_VERIFIED_ROUTE_PROVIDER_ESCALATION',flush=True)
    return 2
def main():
    m=load()
    m.selftest()
    for k in list(os.environ):
        if k.startswith('PG'):os.environ.pop(k,None)
    warnings.simplefilter('error',getpass.GetPassWarning)
    need(sys.stdin.isatty(),'TTY_REQUIRED')
    src=m.pinned(ROOT/'hosted-schema.sql',m.SCHEMA_PIN).decode()
    return run(m,getpass.getpass('QA DB Password: '),src)
if __name__=='__main__':
    try:sys.exit(main())
    except Exception as e:
        print('ROUTE_REVIEW_BLOCKED',type(e).__name__,str(e) if type(e) is RuntimeError else 'SANITIZED_ERROR',flush=True)
        sys.exit(1)
