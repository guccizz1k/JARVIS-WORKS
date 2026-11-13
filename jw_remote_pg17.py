import os, re, json, base64, hashlib, tempfile, subprocess, secrets, time, stat
from pathlib import Path
from urllib.request import Request, urlopen
from scripts.pg_backup_v223 import decrypt_file

REPO='guccizz1k/jw-backup-vault-261111'
REL='archives/2026-11-13/jw-v223-rotated-757ea54caec464bf.jwpgbk'
SHA='84304f6d785b2f49f16c826118fac8580b8bcfe5ec30290f625b9a3e70661d7e'
PLAIN='c9566b8bd2202e822ad520c706b4dd7023eaa95610ec81eb7e01c30efef39da3'
IMAGE='sha256:ff87138949ad9a46f32ff23bd6852b52ce024a13dffe9b4087be98292cdd3b4f'
KEY=Path('/dev/shm/jw-new-key-tb_yiu9h')
NAME='jw-remote-verify-'+secrets.token_hex(5)


def run(cmd, *, data=None, timeout=90):
    r=subprocess.run(cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if r.returncode:
        raise RuntimeError('COMMAND_FAILED: '+cmd[0]+' '+cmd[1] if len(cmd)>1 else 'COMMAND_FAILED: '+cmd[0])
    return r.stdout.decode().strip()


def sql(statement, db='restore'):
    return run(['docker','exec',NAME,'psql','-X','-A','-t','-v','ON_ERROR_STOP=1','-U','postgres','-d',db,'-c',statement],timeout=60)


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
        for i in range(50):
            if subprocess.run(['docker','exec',NAME,'pg_isready','-U','postgres'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:
                break
            time.sleep(.4)
        else:
            raise RuntimeError('ISOLATED_PG17_NOT_READY')
        assert sql('SHOW server_version').startswith('17.'), 'PG_VERSION_MISMATCH'
        for role in sorted(roles):
            sql('CREATE ROLE "'+role+'" NOLOGIN',db='postgres')
        run(['docker','exec',NAME,'createdb','-U','postgres','restore'],timeout=30)
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
finally:
    if created:
        subprocess.run(['docker','rm','-f',NAME],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=40)
        inspect=subprocess.run(['docker','inspect',NAME],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
        assert inspect.returncode!=0, 'BLOCKED_CONTAINER_CLEANUP_FAILED'

print('NEW_REMOTE_PG17_REAL_RESTORE_PASS')
print('RESTORE_COUNTS_PASS: tables=65 force_rls=64 rows=22 functions=72 triggers=74')
print('EXISTING_DB_AND_VOLUMES_UNTOUCHED')
print('TEMP_AND_CONTAINER_CLEANED')
print('FULL_INDEPENDENT_SCHEMA_DIGEST_NOT_RUN')
