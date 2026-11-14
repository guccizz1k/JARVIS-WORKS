import os, re, json, base64, hashlib, tempfile, subprocess, secrets, time, stat, sys
from pathlib import Path
from urllib.request import Request, urlopen
from scripts.pg_backup_v223 import decrypt_file

from scripts.pg_backup_v223 import fetch_signature, signature_digest, MAX_TABLE_ROWS

# Prior independently recorded PG17 restored-catalog signature (2026-11-11).
# This is not the source signature; one approved V151 semantic difference
# existed in the historic raw source-vs-restored comparison.
HISTORICAL_RESTORED_RAW_SHA='dc048c8e7e1dd1525cd637aa5e167a9c6a92db699491a178be3392fccf184dc0'

REPO='guccizz1k/jw-backup-vault-261111'
MODE = 'legacy' if sys.argv[1:] == ['--legacy'] else 'rotated'
assert sys.argv[1:] in ([], ['--legacy']), 'EXPECTED_ONLY_OPTION_--legacy'
if MODE == 'legacy':
    REL='archives/2026-11-11/8af9b9cf32.jwpgbk'
    SHA='dfe012b2521b7331564467c371356db27357275aff37a8d7d016e70193652d10'
else:
    REL='archives/2026-11-13/jw-v223-rotated-757ea54caec464bf.jwpgbk'
    SHA='84304f6d785b2f49f16c826118fac8580b8bcfe5ec30290f625b9a3e70661d7e'
PLAIN='c9566b8bd2202e822ad520c706b4dd7023eaa95610ec81eb7e01c30efef39da3'
IMAGE='sha256:ff87138949ad9a46f32ff23bd6852b52ce024a13dffe9b4087be98292cdd3b4f'
KEY=Path('/dev/shm/jw-new-key-tb_yiu9h')
NAME='jw-remote-verify-'+secrets.token_hex(5)


def run(cmd, *, data=None, timeout=90):
    r=subprocess.run(cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if r.returncode:
        # Classify failure without printing SQL, credentials, or private stderr.
        err=r.stderr.decode('utf-8','replace').lower()
        if 'does not exist' in err and 'database ' in err:
            reason='DATABASE_NOT_CREATED'
        elif 'does not exist' in err and 'role ' in err:
            reason='ROLE_MISSING'
        elif 'already exists' in err:
            reason='OBJECT_ALREADY_EXISTS'
        elif 'permission denied' in err or 'must be owner' in err:
            reason='PERMISSION_OR_OWNER'
        elif 'extension ' in err:
            reason='EXTENSION_DEPENDENCY'
        elif 'no space left on device' in err:
            reason='OUT_OF_SPACE'
        elif 'could not connect' in err or 'connection refused' in err:
            reason='CONNECTIVITY'
        else:
            reason='UNCLASSIFIED'
        raise RuntimeError('COMMAND_FAILED: '+cmd[0]+' '+cmd[1]+' EXIT='+str(r.returncode)+' CLASS='+reason)
    return r.stdout.decode().strip()


def sql(statement, db='restore'):
    return run(['docker','exec',NAME,'psql','-X','-A','-t','-v','ON_ERROR_STOP=1','-U','postgres','-d',db,'-c',statement],timeout=60)


# The previous dict-based adapter dropped a duplicate 'coalesce' column.
# Regression: order and all three values must survive a duplicate JSON key.
assert json.loads('{"count":22,"coalesce":"11","coalesce":"22"}',
                  object_pairs_hook=lambda pairs:[v for _,v in pairs]) == [22,"11","22"]

class PsqlCursorAdapter:
    """Read-only DB-API subset for the existing signature implementation.

    Executes the original deterministic SELECT queries inside the ephemeral
    network-isolated container. Returns typed JSON row values matching psycopg's
    simple scalar mappings (text, bool, int). Never prints private row content.
    """
    def __enter__(self): return self
    def __exit__(self, exc_type, exc_value, traceback): return False
    def execute(self, query, params=None):
        q=query.strip().rstrip(';')
        if q.startswith("SELECT set_config('statement_timeout'"):
            assert params==('300s',)
            self.rows=[]
            return
        if isinstance(params,dict):
            assert params=={'s':'jw_dev'}
            q=q.replace('%(s)s', "'jw_dev'")
        elif isinstance(params,tuple):
            assert params==(MAX_TABLE_ROWS+1,)
            q=q.replace('%s',str(MAX_TABLE_ROWS+1))
        else:
            assert params is None
        assert q.lstrip().startswith('SELECT '), 'BLOCKED_NON_SELECT_SIGNATURE_QUERY'
        assert '%(s)s' not in q and '%s' not in q
        wrapped='SELECT row_to_json(q) FROM ('+q+') AS q'
        output=sql(wrapped)
        # row_to_json emits duplicate labels for the two coalesce columns in
        # the streamed row digest query. A normal dict silently drops one.
        # Preserve values by position, including repeated JSON object keys.
        self.rows=[json.loads(line, object_pairs_hook=lambda pairs:
                              [value for _, value in pairs])
                   for line in output.splitlines()]
    def fetchall(self): return self.rows
    def fetchone(self): return self.rows[0]

class PsqlConnectionAdapter:
    def cursor(self): return PsqlCursorAdapter()

if MODE == 'legacy':
    # The original archive must remain recoverable after temporary re-key file loss.
    # Do not print the key; never rewrite original or rotated archives.
    key=base64.urlsafe_b64decode(os.environ['JW_PG_BACKUP_KEY'])
else:
    assert KEY.is_file() and not KEY.is_symlink()
    assert stat.S_IMODE(KEY.stat().st_mode)==0o600
    key=base64.urlsafe_b64decode(KEY.read_bytes())
assert len(key)==32
assert run(['docker','image','inspect','postgres:17','--format','{{.Id}}'])==IMAGE, 'BLOCKED_IMAGE_ID_CHANGED'
assert '17.' in run(['pg_restore','--version']), 'BLOCKED_PG_RESTORE_VERSION'

url=f'https://api.github.com/repos/{REPO}/contents/{REL}'
req=Request(url, headers={'Authorization':'Bearer '+os.environ['JW_VAULT_UPLOAD_PAT'],'Accept':'application/vnd.github+json'})
with urlopen(req,timeout=45) as response:
    data=base64.b64decode(''.join(json.load(response)['content'].split()))
assert len(data)==484971
assert hashlib.sha256(data).hexdigest()==SHA, 'REMOTE_HASH_MISMATCH'

created=False
try:
    with tempfile.TemporaryDirectory(prefix='jw-remote-pg17-', dir='/dev/shm') as d:
        archive=Path(d)/'archive.jwpgbk'
        dump=Path(d)/'restore.dump'
        archive.write_bytes(data)
        assert decrypt_file(archive,dump,key)==PLAIN, 'DECRYPT_HASH_MISMATCH'
        assert dump.stat().st_size==484939, 'DUMP_SIZE_MISMATCH'
        run(['pg_restore','--list',str(dump)],timeout=30)
        schema=run(['pg_restore','--schema-only','--file','-',str(dump)],timeout=50)
        roles=set()
        for line in schema.splitlines():
            if line.startswith(('GRANT ','REVOKE ','ALTER DEFAULT PRIVILEGES ','CREATE POLICY ')):
                for match in re.finditer(r'\b(?:TO|FROM|FOR ROLE)\s+([^;]+)',line):
                    for part in match.group(1).split(','):
                        token=part.strip().split()[0].strip('"') if part.strip() else ''
                        if re.fullmatch(r'[a-z][a-z0-9_]{0,62}',token) and token not in ('postgres','public') and not token.startswith('pg_'):
                            roles.add(token)
        # A new, disposable, network-isolated cluster. All storage is tmpfs.
        run(['docker','run','-d','--rm','--pull','never','--name',NAME,
             '--network','none','--read-only','--memory','768m','--cpus','1','--pids-limit','128',
             '--tmpfs','/var/lib/postgresql/data:rw,nosuid,size=384m',
             '--tmpfs','/var/run/postgresql:rw,nosuid,size=16m',
             '--tmpfs','/tmp:rw,nosuid,size=32m',
             '-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:17'],timeout=40)
        created=True
        inspection=json.loads(run(['docker','inspect',NAME,'--format','{{json .Mounts}}']))
        assert not any(m.get('Type') in ('bind','volume') for m in inspection), 'BLOCKED_NON_TMPFS_MOUNT'
        assert run(['docker','inspect',NAME,'--format','{{.HostConfig.NetworkMode}}'])=='none', 'BLOCKED_NETWORK'
        # On first initialization, the official postgres image starts a
        # temporary server which may answer pg_isready, then shuts it down
        # before exec'ing the permanent server. Do not race that transition.
        # /proc/1/comm becomes "postgres" only after final entrypoint exec.
        ready=False
        phase='ENTRYPOINT_INITIALIZING'
        for i in range(120):
            p=subprocess.run(['docker','exec',NAME,'cat','/proc/1/comm'],
                             stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                             timeout=8)
            if p.returncode==0 and p.stdout.strip()==b'postgres':
                phase='FINAL_SERVER_CONNECTING'
                try:
                    version=sql('SHOW server_version', db='postgres')
                    if version.startswith('17.'):
                        ready=True
                        break
                    raise RuntimeError('PG_VERSION_MISMATCH')
                except RuntimeError as e:
                    if str(e)=='PG_VERSION_MISMATCH':
                        raise
            time.sleep(.5)
        if not ready:
            # Only lifecycle metadata; no SQL output, credentials, or logs.
            state=subprocess.run(
                ['docker','inspect',NAME,'--format',
                 '{{.State.Status}}|{{.State.ExitCode}}|{{.State.OOMKilled}}'],
                stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10)
            status=state.stdout.decode().strip() if state.returncode==0 else 'INSPECT_UNAVAILABLE'
            raise RuntimeError('ISOLATED_PG17_FINAL_SERVER_NOT_READY: '+phase+' STATUS='+status)
        for role in sorted(roles | {'jw_auth_stage_v85','jw_dev_import_review_executor_v201'}):
            sql('CREATE ROLE "'+role+'" NOLOGIN',db='postgres')
        run(['docker','exec',NAME,'createdb','-U','postgres','restore'],timeout=30)
        sql('CREATE SCHEMA IF NOT EXISTS extensions')
        sql('CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions')
        run(['docker','exec','-i',NAME,'pg_restore','--no-owner','--exit-on-error','-U','postgres','-d','restore'],data=dump.read_bytes(),timeout=180)
        ns="n.nspname='jw_dev'"
        tables=int(sql("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON c.relnamespace=n.oid WHERE "+ns+" AND c.relkind='r'"))
        force_rls=int(sql("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON c.relnamespace=n.oid WHERE "+ns+" AND c.relkind='r' AND c.relforcerowsecurity"))
        funcs=int(sql("SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON p.pronamespace=n.oid WHERE "+ns))
        triggers=int(sql("SELECT count(*) FROM pg_trigger t JOIN pg_class c ON t.tgrelid=c.oid JOIN pg_namespace n ON c.relnamespace=n.oid WHERE "+ns+" AND NOT t.tgisinternal"))
        names=sql("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON c.relnamespace=n.oid WHERE "+ns+" AND c.relkind='r' ORDER BY c.relname").splitlines()
        assert len(names)==tables
        union=' UNION ALL '.join('SELECT count(*) AS n FROM "jw_dev"."'+t.replace('"','""')+'"' for t in names)
        rows=int(sql('SELECT sum(n) FROM ('+union+') q'))
        counts={'tables':tables,'force_rls':force_rls,'rows':rows,'functions':funcs,'triggers':triggers}
        assert counts=={'tables':65,'force_rls':64,'rows':22,'functions':72,'triggers':74}, 'RESTORE_COUNT_MISMATCH'
        restored=fetch_signature(PsqlConnectionAdapter(),'jw_dev')
        assert len(restored['tables'])==65
        assert sum(record[0] for record in restored['rows'].values())==22
        restored_digest=signature_digest(restored)
        assert restored_digest==HISTORICAL_RESTORED_RAW_SHA, 'HISTORICAL_FULL_RESTORED_SIGNATURE_MISMATCH'

finally:
    if created:
        subprocess.run(['docker','rm','-f',NAME],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=40)
        inspect=subprocess.run(['docker','inspect',NAME],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
        assert inspect.returncode!=0, 'BLOCKED_CONTAINER_CLEANUP_FAILED'

print(MODE.upper()+'_REMOTE_PG17_REAL_RESTORE_PASS')
print('RESTORE_COUNTS_PASS: tables=65 force_rls=64 rows=22 functions=72 triggers=74')
print('EXISTING_DB_AND_VOLUMES_UNTOUCHED')
print('TEMP_AND_CONTAINER_CLEANED')
print('HISTORICAL_RESTORED_FULL_SCHEMA_ROW_DIGEST_PASS')
print('SOURCE_RAW_SIGNATURE_EQUIVALENCE_NOT_REASSERTED')
