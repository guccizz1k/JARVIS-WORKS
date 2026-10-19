"""Destructive-in-TEST-DB-only PostgreSQL RLS adversarial integration test.

PRECONDITIONS: an isolated throwaway database named jw_v19_test_*, dedicated
jw_app unprivileged connection, public schema fixture applied, hardened policy
applied by trusted migration role. See docs/V1_9_RLS_HARDENING.md.

This is NOT executed by default pytest and does not contact any remote server
without two explicit DSNs. Exit 2 = NOT RUN, 1 = FAIL, 0 = PASS.
"""
import hashlib
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone


def _fail(message):
    raise AssertionError(message)


def _is_expected_error(fn, psycopg, expected_sqlstates):
    """A negative attack passes only for the specific denial being tested.

    Network errors, syntax errors, missing objects, and unrelated SQL failures
    must never be misreported as successful enforcement.
    """
    if not expected_sqlstates:
        raise ValueError('expected_sqlstates must be explicit')
    try:
        fn()
    except psycopg.Error as exc:
        actual = getattr(exc, 'sqlstate', None)
        if actual not in expected_sqlstates:
            _fail('Unexpected SQLSTATE in negative attack: '
                  + str(actual) + '; expected ' + ','.join(sorted(expected_sqlstates)))
        return
    _fail('Expected security denial did not occur')


PRIVILEGE_DENIED = frozenset({'42501'})
AUTH_DENIED = frozenset({'P0001'})
TENANT_FK_DENIED = frozenset({'42501', '23503'})


def _check_db(conn, require_user=None):
    with conn.cursor() as cur:
        cur.execute('SELECT current_database(),session_user')
        db, role=cur.fetchone()
    if not db.startswith(('jw_v19_test_', 'jw_v20_test_')):
        raise RuntimeError('REFUSED: non-ephemeral database: ' + db)
    if require_user and role != require_user:
        raise RuntimeError('REFUSED: expected separate jw_app login, found '+role)


def run():
    admin_dsn=os.environ.get('JW_PG_TEST_ADMIN_DSN')
    app_dsn=os.environ.get('JW_PG_TEST_APP_DSN')
    if not admin_dsn or not app_dsn:
        print('NOT RUN: both PostgreSQL test DSNs are required',file=sys.stderr)
        return 2
    if os.environ.get('JW_PG_ALLOW_TEST_WRITES') != 'ONLY_EPHEMERAL_DATABASE':
        print('NOT RUN: explicit ephemeral test permission missing',file=sys.stderr)
        return 2
    try:
        import psycopg
    except ImportError:
        print('NOT RUN: psycopg missing', file=sys.stderr)
        return 2
    from scripts.check_postgres_rls import audit
    try:
        with psycopg.connect(admin_dsn) as admin, psycopg.connect(app_dsn) as app:
            _check_db(admin)
            _check_db(app,'jw_app')
            issues=audit(admin)
            if issues: _fail('catalog audit FAIL: '+ '; '.join(issues))
            # All records are fictional. No customer or real session data is used.
            tok_a=secrets.token_urlsafe(40)
            tok_b=secrets.token_urlsafe(40)
            tok_not_mfa=secrets.token_urlsafe(40)
            tok_expired=secrets.token_urlsafe(40)
            expiry=datetime.now(timezone.utc)+timedelta(minutes=30)
            old_expiry=datetime.now(timezone.utc)-timedelta(minutes=1)
            with admin.cursor() as cur:
                cur.execute('TRUNCATE jw_guard.authenticated_sessions')
                cur.executemany('''INSERT INTO jw_guard.authenticated_sessions
                   (token_digest,org_id,user_id,mfa_verified,expires_at)
                   VALUES (%s,%s,%s,%s,%s)''',[
                   (hashlib.sha256(tok_a.encode()).digest(),'tenant_a','ua',True,expiry),
                   (hashlib.sha256(tok_b.encode()).digest(),'tenant_b','ub',True,expiry),
                   (hashlib.sha256(tok_not_mfa.encode()).digest(),'tenant_a','ua',False,expiry),
                   (hashlib.sha256(tok_expired.encode()).digest(),'tenant_a','ua',True,old_expiry)
                ])
            admin.commit()
            app.rollback()
            with app.cursor() as cur:
                cur.execute('SELECT count(*) FROM public.customers')
                assert cur.fetchone()[0] == 0, 'Unbound session leaked rows'
                # Bare SET jw.ctx_org must NOT confer privileges.
                cur.execute("SELECT set_config('jw.ctx_org','tenant_b',true)")
                cur.execute('SELECT count(*) FROM public.customers')
                assert cur.fetchone()[0] == 0, 'Plain org GUC spoof leaked rows'
            app.rollback()
            with app.cursor() as cur:
                _is_expected_error(lambda: cur.execute('SELECT jw_guard.bind_session(%s)',(tok_not_mfa,)),psycopg,AUTH_DENIED)
            app.rollback()
            with app.cursor() as cur:
                _is_expected_error(lambda: cur.execute('SELECT jw_guard.bind_session(%s)',(tok_expired,)),psycopg,AUTH_DENIED)
            app.rollback()
            with app.cursor() as cur:
                cur.execute('SELECT jw_guard.bind_session(%s)',(tok_a,))
                for table in ('customers','quotes','quote_items','orders','order_items','invoices','invoice_items','payments','audit_logs','import_previews'):
                    cur.execute('SELECT count(*) FROM public.'+table)
                    assert cur.fetchone()[0] == 1, 'Tenant A wrong visibility on '+table
                cur.execute("SELECT * FROM public.customers WHERE id='cb'")
                assert cur.fetchone() is None
                cur.execute("UPDATE public.customers SET name='attack' WHERE id='cb'")
                assert cur.rowcount == 0, 'Cross-tenant UPDATE succeeded'
                cur.execute("DELETE FROM public.customers WHERE id='cb'")
                assert cur.rowcount == 0, 'Cross-tenant DELETE succeeded'
                # An existing A row must not be re-keyed into company B.
                # A dedicated row without child FKs isolates RLS WITH CHECK from
                # FK failure (a false-positive security denial).
                cur.execute("INSERT INTO public.customers VALUES ('tenant_rekey_canary','tenant_a','Canary')")
                cur.execute('SAVEPOINT retenant_own_row')
                _is_expected_error(lambda:cur.execute(
                    "UPDATE public.customers SET org_id='tenant_b' WHERE id='tenant_rekey_canary'"),
                    psycopg,PRIVILEGE_DENIED)
                cur.execute('ROLLBACK TO SAVEPOINT retenant_own_row')
                cur.execute("DELETE FROM public.customers WHERE id='tenant_rekey_canary'")
                cur.execute('SAVEPOINT cross_tenant_insert')
                _is_expected_error(lambda:cur.execute("INSERT INTO public.customers VALUES ('evil','tenant_b','attack')"),psycopg,PRIVILEGE_DENIED)
                cur.execute('ROLLBACK TO SAVEPOINT cross_tenant_insert')
                cur.execute('SAVEPOINT foreign_child')
                _is_expected_error(lambda:cur.execute("INSERT INTO public.quote_items VALUES('evil','tenant_a','qb','attack')"),psycopg,TENANT_FK_DENIED)
                cur.execute('ROLLBACK TO SAVEPOINT foreign_child')
                # A forged *same tenant* row linking to an invisible other-tenant
                # customer/order must fail by composite FK, even though its org_id
                # passes the RLS WITH CHECK predicate.
                for label,sql in (
                    ('quote->foreign customer',
                     "INSERT INTO public.quotes VALUES('evilquote','tenant_a','cb')"),
                    ('order->foreign quote',
                     "INSERT INTO public.orders VALUES('evilorder','tenant_a','qb')"),
                    ('invoice->foreign order',
                     "INSERT INTO public.invoices VALUES('evilinvoice','tenant_a','ob')"),
                    ('payment->foreign invoice',
                     "INSERT INTO public.payments VALUES('evilpayment','tenant_a','ib')"),
                    ('child->foreign quote',
                     "INSERT INTO public.quote_items VALUES('evilqi','tenant_a','qb','attack')"),
                    ('child->foreign order',
                     "INSERT INTO public.order_items VALUES('eviloi','tenant_a','ob','qia')"),
                    ('child->foreign invoice',
                     "INSERT INTO public.invoice_items VALUES('evilii','tenant_a','ib','attack')"),
                ):
                    cur.execute('SAVEPOINT fk_guard')
                    _is_expected_error(lambda sql=sql:cur.execute(sql),psycopg,TENANT_FK_DENIED)
                    cur.execute('ROLLBACK TO SAVEPOINT fk_guard')
                cur.execute('SAVEPOINT fk_update')
                _is_expected_error(lambda:cur.execute(
                   "UPDATE public.quotes SET customer_id='cb' WHERE id='qa'"),psycopg,TENANT_FK_DENIED)
                cur.execute('ROLLBACK TO SAVEPOINT fk_update')
                # TRUNCATE is outside PostgreSQL RLS; GRANT must deny it.
                cur.execute('SAVEPOINT refuse_truncate')
                _is_expected_error(lambda:cur.execute('TRUNCATE public.customers'),psycopg,PRIVILEGE_DENIED)
                cur.execute('ROLLBACK TO SAVEPOINT refuse_truncate')
                # Tenant role must not inherit a more privileged SQL role.
                cur.execute('SAVEPOINT refuse_set_role')
                _is_expected_error(lambda:cur.execute('SET ROLE postgres'),psycopg,PRIVILEGE_DENIED)
                cur.execute('ROLLBACK TO SAVEPOINT refuse_set_role')
                for table in ('audit_logs','security_events'):
                    for operation in ('UPDATE','DELETE'):
                        cur.execute('SAVEPOINT protected_log')
                        attack=("UPDATE public.%s SET org_id='tenant_a' WHERE id='aa'" % table)
                        if operation=='DELETE':
                            attack='DELETE FROM public.'+table
                        _is_expected_error(lambda attack=attack:cur.execute(attack),psycopg,PRIVILEGE_DENIED)
                        cur.execute('ROLLBACK TO SAVEPOINT protected_log')
                # Tenant binding cannot be changed mid-transaction, even with a
                # legitimate B token. Rollback the failed statement only.
                cur.execute('SAVEPOINT rebind')
                _is_expected_error(lambda:cur.execute('SELECT jw_guard.bind_session(%s)',(tok_b,)),psycopg,AUTH_DENIED)
                cur.execute('ROLLBACK TO SAVEPOINT rebind')
                for table in ('users','sessions','mfa_credentials'):
                    cur.execute('SAVEPOINT no_identity')
                    _is_expected_error(lambda:cur.execute('SELECT * FROM public.'+table),psycopg,PRIVILEGE_DENIED)
                    cur.execute('ROLLBACK TO SAVEPOINT no_identity')
                cur.execute('SAVEPOINT no_signing_key')
                _is_expected_error(lambda:cur.execute('SELECT * FROM jw_guard.signing_key'),psycopg,PRIVILEGE_DENIED)
                cur.execute('ROLLBACK TO SAVEPOINT no_signing_key')
                cur.execute('SELECT current_setting(\'jw.ctx_org\'), current_setting(\'jw.ctx_xid\'), current_setting(\'jw.ctx_session_digest\'), current_setting(\'jw.ctx_proof\')')
                saved=cur.fetchone()
                cur.execute("SELECT set_config('jw.ctx_org','tenant_b',true)")
                cur.execute('SELECT count(*) FROM public.customers')
                assert cur.fetchone()[0] == 0, 'Signed tenant ID was spoofed'
            app.commit()
            # A previous transaction's valid proof MUST NOT survive COMMIT or pool reuse.
            with app.cursor() as cur:
                cur.execute('SELECT txid_current()')
                for k,v in zip(('jw.ctx_org','jw.ctx_xid','jw.ctx_session_digest','jw.ctx_proof'),saved):
                    cur.execute('SELECT set_config(%s,%s,true)',(k,v))
                cur.execute('SELECT count(*) FROM public.customers')
                assert cur.fetchone()[0] == 0, 'Old transaction claim replayed'
            app.rollback()
            with app.cursor() as cur:
                cur.execute('SELECT jw_guard.bind_session(%s)',(tok_b,))
                cur.execute('SELECT id FROM public.customers')
                assert cur.fetchall() == [('cb',)], 'Tenant B visibility incorrect'
            # Revoke B in another committed transaction while app's READ COMMITTED
            # transaction remains open: next statement must lose access.
            with admin.cursor() as admin_cur:
                admin_cur.execute('UPDATE jw_guard.authenticated_sessions SET revoked_at=now() WHERE token_digest=%s',
                                  (hashlib.sha256(tok_b.encode()).digest(),))
            admin.commit()
            with app.cursor() as cur:
                cur.execute('SELECT count(*) FROM public.customers')
                assert cur.fetchone()[0] == 0, 'Revoked bound session retained row access'
            app.rollback()
            with admin.cursor() as cur:
                cur.execute('UPDATE jw_guard.authenticated_sessions SET revoked_at=now() WHERE token_digest=%s', (hashlib.sha256(tok_a.encode()).digest(),))
            admin.commit()
            with app.cursor() as cur:
                _is_expected_error(lambda:cur.execute('SELECT jw_guard.bind_session(%s)',(tok_a,)),psycopg,AUTH_DENIED)
            app.rollback()
            print('PASS: isolated PG RLS authorization, spoof, replay, CRUD, child, auth and revocation tests')
            return 0
    except Exception as exc:
        print('FAIL: '+type(exc).__name__+': '+str(exc)[:300],file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(run())
