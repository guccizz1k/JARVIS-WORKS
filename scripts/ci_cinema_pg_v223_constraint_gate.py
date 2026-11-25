"""Five varied PG17 constraint/dump/encryption rounds on an EMPTY local CI cluster.

Never connects to source Supabase. PostgreSQL executes the counterexamples;
no client-side removal of parentheses, literals or constraints is permitted.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile

import psycopg
from psycopg import sql
from scripts import pg_backup_v223 as backup

CANONICAL = 'CHECK (length(display_name) >= 2 AND length(display_name) <= 120 AND display_name = btrim(display_name))'
EXPRESSION = '(length(display_name)>=2 AND length(display_name)<=120) AND display_name=btrim(display_name)'


def require(condition, label):
    if not condition:
        raise RuntimeError(label)


def accepts(connection, value):
    try:
        with connection.transaction(force_rollback=True):
            connection.execute('INSERT INTO trial.child(id,parent_id,display_name) VALUES(999,NULL,%s)', (value,))
        return True
    except psycopg.errors.CheckViolation:
        return False


def deferred_insert(connection):
    try:
        with connection.transaction(force_rollback=True):
            connection.execute('INSERT INTO trial.child VALUES(998,998,NULL)')
            connection.execute('INSERT INTO trial.parent VALUES(998)')
        return True
    except psycopg.errors.ForeignKeyViolation:
        return False


def main():
    require(os.getenv('JW_CINEMA_PG_DISPOSABLE') == '1' and
            os.getenv('PGHOST') in ('127.0.0.1','localhost'), 'DISPOSABLE_LOOPBACK_REQUIRED')
    source='jw_constraint_src_'+secrets.token_hex(6)
    target='jw_constraint_dst_'+secrets.token_hex(6)
    created=[];rounds=[]
    opts={k:os.environ[v] for k,v in (('host','PGHOST'),('port','PGPORT'),('user','PGUSER'),('password','PGPASSWORD'))}
    opts.update(dbname=source,sslmode='',sslrootcert='')
    with psycopg.connect(dbname='postgres',autocommit=True) as admin:
        version=int(admin.execute('SHOW server_version_num').fetchone()[0])
        require(170000<=version<180000,'PG17_REQUIRED')
        # Reject an existing application/source cluster before CREATE/DROP.
        require(admin.execute("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND c.relkind IN ('r','p')").fetchone()[0]==0,'NONEMPTY_ADMIN_DATABASE')
        require(admin.execute("SELECT count(*) FROM pg_database WHERE NOT datistemplate AND datname<>'postgres'").fetchone()[0]==0,'EXISTING_USER_DATABASE')
        try:
            for db in (source,target):
                admin.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(db)));created.append(db)
            with tempfile.TemporaryDirectory(prefix='jw-constraint-rounds-') as tmp:
                tmp=Path(tmp)
                for index,size in enumerate((0,1,7,13,31)):
                    with psycopg.connect(dbname=source,autocommit=True) as src:
                        src.execute('DROP SCHEMA IF EXISTS trial CASCADE')
                        src.execute('CREATE SCHEMA trial')
                        src.execute('CREATE TABLE trial.parent(id integer PRIMARY KEY)')
                        src.execute('CREATE TABLE trial.child(id integer PRIMARY KEY,parent_id integer,display_name text,CONSTRAINT parent_fk FOREIGN KEY(parent_id) REFERENCES trial.parent(id) DEFERRABLE INITIALLY DEFERRED,CONSTRAINT name_check CHECK('+EXPRESSION+'))')
                        for row in range(size):
                            src.execute('INSERT INTO trial.child VALUES(%s,NULL,%s)',(row,None if row%3==0 else 'valid_'+str(row)))
                        with src.transaction(): before=backup.fetch_signature(src,'trial')
                    dump=tmp/'fixture.dump';cipher=tmp/'fixture.encrypted';back=tmp/'restore.dump'
                    for f in (dump,cipher,back):f.unlink(missing_ok=True)
                    backup.run_tool(['pg_dump','--format=custom','--schema=trial','--no-owner','--file',str(dump)],opts,60)
                    key=secrets.token_bytes(32)
                    encrypted=backup.encrypt_file(dump,cipher,key)
                    require(backup.decrypt_file(cipher,back,key)==encrypted['plain_sha256'],'DECRYPT_HASH_MISMATCH')
                    try:backup.decrypt_file(cipher,tmp/'wrong-key',bytes(x^1 for x in key))
                    except backup.BackupError as error:require(str(error)=='BLOCKED_V223_BACKUP_AUTH_FAILED','WRONG_KEY_ERROR_CLASS')
                    else:raise RuntimeError('WRONG_KEY_ACCEPTED')
                    for kind in ('tamper','truncation'):
                        bad=tmp/('bad-'+kind);plain=tmp/('plain-'+kind);bad.unlink(missing_ok=True)
                        backup.write_negative_cipher_copy(cipher,bad,kind)
                        try:backup.decrypt_file(bad,plain,key)
                        except backup.BackupError:require(not plain.exists(),'PARTIAL_PLAINTEXT_REMAINS')
                        else:raise RuntimeError('DAMAGED_CIPHERTEXT_ACCEPTED')
                    with psycopg.connect(dbname=target,autocommit=True) as dst:dst.execute('DROP SCHEMA IF EXISTS trial CASCADE')
                    backup.run_tool(['pg_restore','--no-owner','--exit-on-error','--dbname',target,str(back)],{**opts,'dbname':target},60)
                    with psycopg.connect(dbname=source,autocommit=True) as src, psycopg.connect(dbname=target,autocommit=True) as dst:
                        with dst.transaction():after=backup.fetch_signature(dst,'trial')
                        require(backup.diff_signatures(before,after)==[],'UNCHANGED_RESTORE_DIFFERS')
                        canonical=dict(after['constraints'])['child.name_check']
                        require(canonical==hashlib.md5(CANONICAL.encode()).hexdigest(),'NONCANONICAL_CONSTRAINT_SIGNATURE')
                        # Direct PG truth table covers NULL, endpoints, whitespace,
                        # non-ASCII and strings containing SQL operator words.
                        for value in (None,'ab','x','a'*120,'a'*121,' padded ','한글','A AND B'):
                            require(accepts(src,value)==accepts(dst,value),'RESTORED_CHECK_BEHAVIOR_DIFFERS')
                        if index==4:
                            dst.execute('ALTER TABLE trial.child DROP CONSTRAINT parent_fk')
                            dst.execute('ALTER TABLE trial.child ADD CONSTRAINT parent_fk FOREIGN KEY(parent_id) REFERENCES trial.parent(id) NOT DEFERRABLE')
                            require(deferred_insert(src) and not deferred_insert(dst),'DEFERRABILITY_COUNTEREXAMPLE_FAILED')
                        else:
                            dst.execute('ALTER TABLE trial.child DROP CONSTRAINT name_check')
                            changed=(EXPRESSION.replace('>=2','>=3') if index==0 else
                                     EXPRESSION.replace('<=120','<=119') if index==1 else
                                     EXPRESSION.replace(' AND length(display_name)<=120',' OR length(display_name)<=120') if index==2 else EXPRESSION)
                            dst.execute('ALTER TABLE trial.child ADD CONSTRAINT name_check CHECK('+changed+')'+(' NOT VALID' if index==3 else ''))
                            if index<3:
                                probe=('ab','a'*120,'x')[index]
                                require(accepts(src,probe)!=accepts(dst,probe),'MUTATION_COUNTEREXAMPLE_FAILED')
                        with dst.transaction():mutated=backup.fetch_signature(dst,'trial')
                        require(any(x.startswith('constraints:') for x in backup.diff_signatures(before,mutated)),'REAL_CONSTRAINT_CHANGE_IGNORED')
                        dst.execute('ALTER TABLE trial.child DROP CONSTRAINT name_check')
                        with dst.transaction():missing=backup.fetch_signature(dst,'trial')
                        require(backup.diagnose_signature_mismatches(before,missing)['constraints']['missing_in_restore']==1,'MISSING_CONSTRAINT_NOT_CLASSIFIED')
                    rounds.append({'round':index+1,'fixture_rows':size,'restore':'PASS','canonical_signature':'PASS','actual_sql_counterexamples':'PASS','mutation_and_missing_detection':'PASS','encryption_and_negative_cases':'PASS'})
                    print('PASS_CONSTRAINT_ROUND_'+str(index+1),flush=True)
        finally:
            for db in reversed(created):admin.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(db)))
    print(json.dumps({'scope':'DISPOSABLE_PG17_SYNTHETIC_ONLY','rounds':rounds,'failed':0,'skipped':0,'cleanup':'PASS'},sort_keys=True))


if __name__=='__main__':main()
