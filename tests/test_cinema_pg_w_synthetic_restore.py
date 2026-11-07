#!/usr/bin/env python3
"""Full restore-only algorithm acceptance on synthetic PG17 data, never Supabase.

Creates then deletes a throwaway 62-table source locally, encrypts its pg_dump
in the same format as Windows, then invokes the real isolated restore script.
Does NOT represent real development database P0/DR proof.
"""
from __future__ import annotations
import base64
import io
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts import ci_cinema_pg_w as w
from scripts.ci_cinema_pg_m import read_private_target
from scripts.pg_backup_v223 import (
    decrypt_file, encrypt_file, fetch_signature, roles_in_acl,
    verify_ephemeral_target,
)
import psycopg
from psycopg import sql


def main():
    if os.environ.get("CODESPACES") != "true":
        raise RuntimeError("synthetic job must be isolated runner")
    cfg=read_private_target()
    dsn=cfg["JW_PG_TARGET_ADMIN_DSN"]
    token=cfg["JW_PG_TARGET_EPHEMERAL_TOKEN"]
    with psycopg.connect(dsn,autocommit=True) as c:
        verify_ephemeral_target(c,token)
    name="jw_ci_src_"+secrets.token_hex(4)
    owner="jw_ci_owner_"+secrets.token_hex(4)
    # Reproduce verified source ACL-only grantees omitted by the old
    # Windows manifest inventory: no table ACL or policy mentions them.
    acl_only=w.SOURCE_VERIFIED_SCHEMA_FUNCTION_ONLY_GRANTEES
    label="20261107-114900Z-"+secrets.token_hex(3)
    os.umask(0o077)
    w.STAGING.mkdir(exist_ok=True)
    created=False
    try:
        with psycopg.connect(dsn,autocommit=True) as c:
            c.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(owner)))
            for role in acl_only:
                c.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
            c.execute(sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(sql.Identifier(name)))
            created=True
        with psycopg.connect(dsn,dbname=name,autocommit=True) as c:
            c.execute("CREATE SCHEMA jw_dev")
            c.execute(sql.SQL("GRANT USAGE ON SCHEMA jw_dev TO {}").format(sql.Identifier(owner)))
            for role in acl_only:
                c.execute(sql.SQL("GRANT USAGE ON SCHEMA jw_dev TO {}").format(sql.Identifier(role)))
            c.execute("CREATE FUNCTION jw_dev.synthetic_ping() RETURNS integer "
                      "LANGUAGE SQL AS $ SELECT 1 $")
            for role in acl_only:
                c.execute(sql.SQL("GRANT EXECUTE ON FUNCTION jw_dev.synthetic_ping() TO {}")
                          .format(sql.Identifier(role)))
            for i in range(62):
                t=f"t{i:02d}"
                c.execute(sql.SQL("CREATE TABLE jw_dev.{} (id integer PRIMARY KEY, note text)")
                          .format(sql.Identifier(t)))
                if i<61:
                    c.execute(sql.SQL("ALTER TABLE jw_dev.{} ENABLE ROW LEVEL SECURITY")
                              .format(sql.Identifier(t)))
                    c.execute(sql.SQL("ALTER TABLE jw_dev.{} FORCE ROW LEVEL SECURITY")
                              .format(sql.Identifier(t)))
            for i in range(22):
                c.execute("INSERT INTO jw_dev.t00 VALUES (%s,%s)",(i,"synthetic"+str(i)))
            c.execute(sql.SQL("ALTER TABLE jw_dev.t00 OWNER TO {}").format(sql.Identifier(owner)))
            c.execute(sql.SQL("GRANT SELECT ON jw_dev.t01 TO {}").format(sql.Identifier(owner)))
        with psycopg.connect(dsn,dbname=name) as c:
            sig=fetch_signature(c,"jw_dev")
            roles=roles_in_acl(c,"jw_dev")
        if any(role in roles for role in acl_only):
            raise RuntimeError("test fixture must expose missing schema/function-only roles")
        if len(sig["tables"])!=62 or sum(v[0] for v in sig["rows"].values())!=22:
            raise RuntimeError("synthetic source shape wrong")
        plaintext=w.STAGING/(label+".dump")
        if not w.run_pg(["pg_dump","--format=custom","--schema=jw_dev","--no-owner",
                         "--file",str(plaintext)],dsn,db=name,seconds=90):
            raise RuntimeError("synthetic pg_dump failed")
        key=secrets.token_bytes(32)
        archived=w.STAGING/(label+".jwpgbk")
        enc=encrypt_file(plaintext,archived,key)
        plaintext.unlink()
        manifest={
            "real_source":True, "schema":w.SCHEMA, "project_ref":w.PROJECT,
            "server_major":17,"snapshot_consistent":True,
            "tables":62, "table_row_total":22,
            "source_fingerprint":w.FINGERPRINT,
            "plain_sha256":enc["plain_sha256"],
            "cipher_sha256":enc["cipher_sha256"],
            "container":"PGDMP custom format",
            "source_backup_verdict":"EXPORT_ONLY_NOT_DR_PASS",
            "signature":sig,"roles":roles,
        }
        temporary=w.STAGING/"synthetic_manifest.json"
        temporary.write_text(json.dumps(manifest))
        encrypt_file(temporary,w.STAGING/(label+".manifest.jwpgbk"),key)
        temporary.unlink()
        keyfile=w.STAGING/(label+".key")
        keyfile.write_text(base64.urlsafe_b64encode(key).decode()+"\n")
        keyfile.chmod(0o600)
    finally:
        if created:
            with psycopg.connect(dsn,autocommit=True) as c:
                c.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name)))
                # Force independent restore to reconstruct ACL-only role names:
                # none may remain from the synthetic source setup.
                for role in acl_only:
                    c.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
    # Restore tool MUST recognize marked target and verify semantic parity.
    with psycopg.connect(dsn,autocommit=True) as c:
        verify_ephemeral_target(c,token)
    # Simulate the real Codespaces pause observed during source-free restore.
    # This is only the locally created, marker-verified ephemeral Docker DB.
    stopped=subprocess.run(["docker","stop","-t","1","jw-v223-restore"],
                            text=True,capture_output=True,timeout=15,check=False)
    if stopped.returncode:
        raise RuntimeError("synthetic stopped-container setup failed")
    result=w.verify_restore()
    if result!=0:
        raise RuntimeError("synthetic restore parity failed")
    # A second full restore from protected HOME must pass without re-upload.
    # Includes source-free signature and all four negative tests again.
    repeated=w.verify_restore()
    if repeated!=0:
        raise RuntimeError("private archive replay verification failed")
    print("PASS_PRIVATE_ENCRYPTED_BACKUP_REPEAT_WITHOUT_REUPLOAD")
    print("PASS_SYNTHETIC_PG17_ENCRYPTED_RESTORE_SIGNATURE_AND_NEGATIVE_TESTS")
    print("REAL_SUPABASE_DATA_NOT_USED_NOT_DR_PASS")


if __name__=="__main__":
    main()
