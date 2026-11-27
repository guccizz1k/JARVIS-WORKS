"""Actual overlapping PG17 transactions, disposable CI only.
Do not connect to managed QA or production. Uses the exact managed rehearsal setup.
"""
import os
from pathlib import Path
import subprocess
import secrets
from contextlib import contextmanager
import psycopg
from psycopg import sql

DSN=dict(host='127.0.0.1',port=55439,dbname='postgres',connect_timeout=4)
ADMIN=dict(DSN,user='postgres',password='synthetic_review_only')
AUTH='naruv_hid_auth'
BUSINESS='naruv_hid_business'
H='naruv_hosted_identity_review.'
T='naruv_hosted_tx_review.'
CSRF='c'*32
PIN='9c449c805d272c73962ebb7deb549192faea6815'
def need(ok,code):
    if not ok:raise RuntimeError(code)
def boot():
    need(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='guccizz1k/JARVIS-WORKS' and os.environ.get('NARUV_AUTH_TX_CI')=='DISPOSABLE_ONLY','CI_SCOPE')
    path=Path(__file__).resolve().parents[1]/'db/review/naruv_supabase_hosted_auth_tx_rehearsal.sql'
    need(subprocess.check_output(['git','hash-object',str(path)],text=True).strip()==PIN,'SOURCE_PIN')
    raw=path.read_text()
    marker='-- END_SETUP_BEGIN_SYNTHETIC_TESTS'
    need(raw.count(marker)==1 and raw.rstrip().endswith('ROLLBACK;'),'SOURCE_BOUNDARY')
    setup=raw.split(marker)[0]
    passwords={r:secrets.token_urlsafe(32) for r in (AUTH,BUSINESS)}
    with psycopg.connect(**ADMIN,autocommit=True) as c:
        need(c.info.server_version//10000==17,'PG17')
        need(c.execute("SELECT to_regnamespace('naruv_qa_probe')").fetchone()==(None,),'NOT_FRESH')
        c.execute("CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN; CREATE ROLE service_role NOLOGIN; CREATE SCHEMA naruv_qa_probe; CREATE TABLE naruv_qa_probe.fixture(n int); INSERT INTO naruv_qa_probe.fixture VALUES(1),(2)")
        c.execute(setup)
        c.execute('COMMIT')
        for role,pw in passwords.items():
            c.execute(sql.SQL('ALTER ROLE {} LOGIN PASSWORD {}').format(sql.Identifier(role),sql.Literal(pw)))
    return passwords
@contextmanager
def connection(role,passwords):
    need(role in (AUTH,BUSINESS),'ROLE')
    with psycopg.connect(**DSN,user=role,password=passwords[role],autocommit=True) as c:
        need(c.execute('SELECT session_user,current_user').fetchone()==(role,role),'DIRECT_LOGIN')
        c.execute("SET statement_timeout='5s'")
        c.execute("SET lock_timeout='250ms'")
        yield c
def expect(c,code,query,args=()):
    try:c.execute(query,args)
    except psycopg.Error as e:need(e.sqlstate==code,'SQLSTATE_'+str(e.sqlstate)+'_EXPECTED_'+code)
    else:raise RuntimeError('EXPECTED_DENIAL_'+code)
def issue(a,token):
    need(a.execute('SELECT '+H+'issue(%s,%s,%s,3600)',('actor-a',token,CSRF)).fetchone()==(True,),'ISSUE')
def revoke(a,token):
    need(a.execute('SELECT '+H+'revoke(%s)',(token,)).fetchone()==(True,),'REVOKE')
def change(a,active,role):
    need(a.execute('SELECT '+H+'change_actor(%s,%s,%s)',('actor-a',active,role)).fetchone()==(True,),'CHANGE')
def bind(b,token):
    b.execute("SELECT set_config('jw.session_hash',%s,false)",(token,))
def post(b,rid):
    return b.execute('SELECT '+T+'post_authenticated(%s,%s,%s,%s)',('ci-a',rid,100,CSRF)).fetchone()[0]
def deny_post(b,rid,code='42501'):
    expect(b,code,'SELECT '+T+'post_authenticated(%s,%s,%s,%s)',('ci-a',rid,100,CSRF))
def read(b):
    return dict(b.execute('SELECT * FROM '+T+'read_authenticated(%s,%s)',('ci-a',CSRF)).fetchall())
def main():
    pw=boot()
    with connection(AUTH,pw) as a,connection(BUSINESS,pw) as b:
        token='a'*64;issue(a,token);bind(b,token)
        # Business wins: revocation waits until the transaction commits.
        b.execute('BEGIN')
        need(post(b,'business-first')=='POSTED','BUSINESS_FIRST')
        expect(a,'55P03','SELECT '+H+'revoke(%s)',(token,))
        b.execute('COMMIT')
        revoke(a,token);deny_post(b,'business-first')
        print('AUTH_TX_BUSINESS_FIRST_PASS',flush=True)
        # Revocation wins: business cannot acquire the session lock, then denies.
        token='b'*64;issue(a,token);bind(b,token)
        a.execute('BEGIN');revoke(a,token)
        deny_post(b,'revoke-first','55P03')
        a.execute('COMMIT');deny_post(b,'revoke-first')
        print('AUTH_TX_REVOKE_FIRST_PASS',flush=True)
        # Business rollback: held locks release and no partial pair survives.
        token='d'*64;issue(a,token);bind(b,token)
        b.execute('BEGIN');need(post(b,'rolled-back')=='POSTED','ROLLBACK_POST')
        expect(a,'55P03','SELECT '+H+'change_actor(%s,false,%s)',('actor-a','admin'))
        b.execute('ROLLBACK')
        change(a,False,'admin');change(a,True,'admin');deny_post(b,'rolled-back')
        token='e'*64;issue(a,token);bind(b,token)
        need(read(b)=={'business-first':100},'ROLLBACK_READBACK')
        need(post(b,'rolled-back')=='POSTED','ROLLBACK_CORRECTED')
        print('AUTH_TX_ROLLBACK_PASS',flush=True)
        # Role downgrade wins, with user-row lock held by auth transaction.
        a.execute('BEGIN');change(a,True,'member')
        deny_post(b,'downgrade-first','55P03')
        a.execute('COMMIT');deny_post(b,'downgrade-first')
        token='f'*64;issue(a,token);bind(b,token);deny_post(b,'member-token')
        change(a,True,'admin')
        token='1'*64;issue(a,token);bind(b,token)
        need(read(b)=={'business-first':100,'rolled-back':100},'FINAL_EXACT_ROWS')
        print('AUTH_TX_DOWNGRADE_FIRST_PASS',flush=True)
        b.execute('BEGIN ISOLATION LEVEL REPEATABLE READ')
        deny_post(b,'snapshot','25000')
        b.execute('ROLLBACK')
        need(read(b)=={'business-first':100,'rolled-back':100},'ISOLATION_READBACK')
        print('AUTH_TX_ISOLATION_BOUNDARY_PASS',flush=True)
    print('AUTH_TX_CONCURRENCY_REVIEW_PASS cases=5 production_authorized=false gate5=BLOCKED',flush=True)
if __name__=='__main__':main()
