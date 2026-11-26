"""Actual synthetic 65-table x 11 provider-cipher -> networkless PG17 restore.

Runs ONLY in GitHub's already-disposable PG17 Docker job. No real vault,
real custodian key, production credentials, or external access.
"""
from __future__ import annotations

import subprocess
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scripts import p1_external_custodian_pg17_v223 as ext
from scripts import p1_cleanroom_key_recovery_v223 as clean
from scripts import pg_backup_v223 as backup

SOURCE_CONTAINER="jw-p1-source"
SOURCE_DB="jw_second_site_source"


def docker(*args, data=None):
    return subprocess.run(["docker",*args],input=data,
        capture_output=True,timeout=150,check=True)


def test_eleven_synthetic_external_ciphers_really_restore_pg17(monkeypatch):
    # Existing GitHub job created jw-p1-source with disposable PG17; this
    # test uses a separate synthetic database, never another task's source.
    docker("exec",SOURCE_CONTAINER,"createdb","-U","postgres",SOURCE_DB)
    try:
        sql="CREATE SCHEMA jw_dev;"+"""
        DO $$ DECLARE i int; BEGIN
          FOR i IN 0..64 LOOP
            EXECUTE format('CREATE TABLE jw_dev.test_%s (id int PRIMARY KEY, value text NOT NULL)',i);
            EXECUTE format('INSERT INTO jw_dev.test_%s VALUES (1, %L)',i, 'synthetic-only');
          END LOOP;
        END $$;
        """
        docker("exec","-i",SOURCE_CONTAINER,"psql","-X","-q","-v",
               "ON_ERROR_STOP=1","-U","postgres","-d",SOURCE_DB,data=sql.encode())
        dump=docker("exec",SOURCE_CONTAINER,"pg_dump","-Fc","-U","postgres",
                    "--dbname",SOURCE_DB,"--schema=jw_dev").stdout
        assert dump.startswith(b"PGDMP")
        from tests.test_p1_external_custodian_pg17_v223 import cipher
        key=b"S"*32
        candidates=[cipher(key,dump,legacy=(i%2==1),nonce_seed=i+1) for i in range(11)]
        # The backup and vault are fakes; real Docker and actual pg_restore are NOT.
        import hashlib
        ids=[hashlib.sha1(b"blob "+str(len(x)).encode()+b"\0"+x).hexdigest() for x in candidates]
        assert len(set(ids))==11
        scope=hashlib.sha256(("JW-WORM-OWNER-SCOPE-V1\n"+"\n".join(sorted(ids))+"\n").encode()).hexdigest()
        monkeypatch.setenv("JW_WORM_OWNER_SCOPE_SHA256", scope)
        pairs=list(zip(ids,[hashlib.sha256(x).hexdigest() for x in candidates]))
        known=dict(zip(ids,candidates))
        monkeypatch.setattr(ext,"preflight",lambda:"PASS")
        monkeypatch.setattr(clean,"_inputs",lambda:("c"*40,key if selected_scope=="legacy" else b"T"*32,pairs))
        monkeypatch.setattr(clean,"_head_tree",lambda _:set(known))
        monkeypatch.setattr(clean,"_download",lambda blob,expected:known[blob])
        report=ext.run()
        assert report["external_pg17_restore"]=="PASS_ELEVEN_PROVIDER_CIPHERS_NETWORKLESS_PG17",report
        assert report["restored_pg17_archive_count"]==11
        assert report["restored_65_table_archive_count"]==11
        assert report["verified_provider_cipher_count"]==11
        assert report["owner_scope_pin_checked"] is True
        assert report["disposable_pg17_removed"]=="PASS"
        assert report["decrypted_dump_written_to_host"] is False
        assert report["independent_key_custody"]=="NOT_ATTESTED"
        assert report["overall"]=="BLOCKED"
    finally:
        docker("exec",SOURCE_CONTAINER,"dropdb","-U","postgres","--force",SOURCE_DB)


import pytest

@pytest.mark.parametrize("selected_scope",["legacy","staged"])
def test_b2_staged_scope_actual_pg17_catalog_without_github(monkeypatch,tmp_path,selected_scope):
    import hashlib,json
    from scripts import naruv_b2_offline_stage as stage
    from tests.test_p1_external_custodian_pg17_v223 import cipher
    db="jw_b2_stage_source"
    docker("exec",SOURCE_CONTAINER,"createdb","-U","postgres",db)
    try:
        sql="CREATE SCHEMA jw_dev;"+"""
        DO $$ DECLARE i int; BEGIN
          FOR i IN 0..64 LOOP
            EXECUTE format('CREATE TABLE jw_dev.test_%s (id int PRIMARY KEY, value text NOT NULL)',i);
            EXECUTE format('INSERT INTO jw_dev.test_%s VALUES (1, %L)',i,'b2-synthetic-only');
          END LOOP;
        END $$;
        """
        docker("exec","-i",SOURCE_CONTAINER,"psql","-X","-q","-v","ON_ERROR_STOP=1","-U","postgres","-d",db,data=sql.encode())
        dump=docker("exec",SOURCE_CONTAINER,"pg_dump","-Fc","-U","postgres","--dbname",db,"--schema=jw_dev").stdout
        key=b"S"*32
        data=[cipher(key if i<11 else b"T"*32,dump,legacy=(i<11),nonce_seed=i+1) for i in range(22)]
        rows=[dict(scope="legacy" if i<11 else "staged",file_id=str(i),size=len(x),
                   sha256=stage.hash256(x),git_blob_sha1=stage.git_blob(x)) for i,x in enumerate(data)]
        raw=json.dumps(dict(version=1,archives=rows)).encode()
        pin=stage.hash256(raw)
        directory=stage.stage(raw,pin,tmp_path,lambda r:data[int(r["file_id"])])
        pairs=[(r["git_blob_sha1"],r["sha256"]) for r in rows if r["scope"]==selected_scope]
        scope=ext.equivalence.owner_scope([b for b,_ in pairs])
        # Independently query the synthetic source, not the restored target.
        manifest=ext.offline._audit_restored_row_manifest(SOURCE_CONTAINER,db)
        assert manifest is not None and manifest[:2]==(65,65)
        q="""SELECT encode(sha256(convert_to(coalesce(string_agg(c.relname||'.'||k.conname||'='||pg_get_constraintdef(k.oid,true),E'\\n' ORDER BY c.relname,k.conname),''),'UTF8')),'hex') FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='jw_dev';"""
        constraint=docker("exec",SOURCE_CONTAINER,"psql","-X","-qAt","-U","postgres","-d",db,"-c",q).stdout.decode().strip()
        catalog=json.loads(docker("exec",SOURCE_CONTAINER,"psql","-X","-qAt","-U","postgres","-d",db,"-v","ON_ERROR_STOP=1","-c",ext.catalog.SQL).stdout)
        refs=[dict(git_blob_sha1=b,cipher_sha256=h,table_count=65,row_count=65,
                   constraint_sha256=constraint,row_manifest_c_sha256=manifest[10],
                   table_names_c_sha256=manifest[8],empty_table_names_c_sha256=manifest[9],
                   populated_tables=65) for b,h in pairs]
        reference=ext.equivalence.canonical(dict(format=ext.catalog.FORMAT,algorithm=ext.catalog.ALGORITHM,
            data_reference=dict(format=ext.equivalence.FORMAT,algorithm=ext.equivalence.ALGORITHM,
                                vault_commit_sha1="c"*40,archives=refs),
            catalog_archives=[dict(git_blob_sha1=b,cipher_sha256=h,sections=catalog) for b,h in pairs]))
        monkeypatch.setattr(ext,"preflight",lambda:"PASS")
        monkeypatch.setenv("JW_PG_B2_OFFLINE_ACK",ext.B2_ACK)
        monkeypatch.setenv("JW_WORM_OWNER_SCOPE_SHA256",scope)
        for k in ("GH_TOKEN","GITHUB_TOKEN","B2_APPLICATION_KEY","B2_APPLICATION_KEY_ID","AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY"):
            monkeypatch.delenv(k,raising=False)
        monkeypatch.setattr(clean,"_inputs",lambda:("c"*40,key,pairs))
        def forbid(*args):raise AssertionError("GitHub access forbidden")
        monkeypatch.setattr(clean,"_head_tree",forbid)
        monkeypatch.setattr(clean,"_download",forbid)
        report=ext.run(reference,hashlib.sha256(reference).hexdigest(),catalog_required=True,
                       staged=(raw,pin,directory,selected_scope))
        assert report["b2_staged_scope_bound"] is True,report
        assert report["restored_pg17_archive_count"]==11,report
        assert report["normalized_catalog_comparison"]=="PASS_11_SCOPED_CATALOG_CHECKPOINTS",report
        assert report["disposable_pg17_removed"]=="PASS"
        assert report["overall"]=="BLOCKED"
    finally:
        docker("exec",SOURCE_CONTAINER,"dropdb","-U","postgres","--force",db)
