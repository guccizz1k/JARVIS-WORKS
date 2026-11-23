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
        monkeypatch.setattr(clean,"_inputs",lambda:("c"*40,key,pairs))
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
