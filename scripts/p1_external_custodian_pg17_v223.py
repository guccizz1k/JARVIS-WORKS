"""External-custodian clean-room full PG17 restoration; NEVER the owner Codespace.

The separate custodian supplies a 32-byte key via an existing OS PIPE and a
pinned private-vault manifest via a second PIPE. It fetches EXACT private Git
blobs independently, validates Git SHA1 + SHA256 and every AES-GCM chunk,
then restores decrypted PG custom archives ONLY into networkless, temporary
PostgreSQL 17. Original source DB, source credential, keys and customer plaintext
are not uploaded, logged or written as dump files.

This tool does not, by itself, prove independent custody, legal WORM retention,
a signed historical source snapshot, or production release readiness.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scripts import p1_cleanroom_key_recovery_v223 as clean
from scripts import p1_owner_offline_restore_v223 as offline
from scripts import pg_backup_v223 as backup
from scripts import jw_independent_equivalence_v223 as equivalence
from scripts import jw_independent_catalog_v223 as catalog
from scripts import naruv_b2_offline_stage as b2stage

B2_ACK = "OWNER_APPROVES_PINNED_B2_OFFLINE_CATALOG_RESTORE"

ACK = "OWNER_APPROVES_EXTERNAL_CUSTODIAN_NETWORKLESS_PG17_RESTORE"
MAX_ARCHIVES = 11
MAX_TOTAL_CIPHER = 128 * 1024 * 1024
MAX_PLAIN_ONE = 32 * 1024 * 1024
MAX_PLAIN_TOTAL = 160 * 1024 * 1024
MAX_RUNTIME_SECONDS = 480
SOURCE_SECRETS = (
    "JW_PG_BACKUP_KEY", "JW_PG_ADMIN_DSN", "JW_PG_SOURCE_DSN",
    "JW_PG_STAGE_DSN", "JW_PG_AUTH_STAGE_DSN", "JW_PG_TARGET_ADMIN_DSN",
    "DATABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "JW_PG_VAULT_READ_TOKEN",
)


class Blocked(RuntimeError):
    pass


def preflight(env=None):
    env=os.environ if env is None else env
    if env.get("JW_PG_SECOND_SITE_ACK") != ACK:
        return "EXPLICIT_SECOND_SITE_APPROVAL_REQUIRED"
    if env.get("CODESPACES","").lower() == "true":
        return "SOURCE_CODESPACE_IS_NOT_AN_INDEPENDENT_SITE"
    if any(env.get(s) for s in SOURCE_SECRETS):
        return "SOURCE_OR_PRODUCTION_CREDENTIAL_PRESENT"
    if env.get("JW_PG_CLEANROOM_ACK") != clean.ACK:
        return "EXTERNAL_KEY_PIPE_APPROVAL_REQUIRED"
    if not clean.SHA1.fullmatch(env.get("JW_PG_CLEANROOM_VAULT_SHA","")):
        return "EXACT_PRIVATE_VAULT_COMMIT_REQUIRED"
    if not clean.SHA256.fullmatch(env.get("JW_WORM_OWNER_SCOPE_SHA256", "")):
        return "INDEPENDENT_OWNER_SCOPE_PIN_REQUIRED"
    if shutil.which("docker") is None:
        return "DOCKER_CLI_UNAVAILABLE"
    if (env.get("DOCKER_HOST") and
            not env["DOCKER_HOST"].startswith("unix://")):
        return "REMOTE_DOCKER_DAEMON_BLOCKED"
    if env.get("DOCKER_TLS_VERIFY"):
        return "REMOTE_DOCKER_DAEMON_BLOCKED"
    try:
        context=offline._docker(["context","inspect","--format",
                                 "{{.Endpoints.docker.Host}}"],timeout=15)
        if context.returncode or not context.stdout.strip().startswith(b"unix://"):
            return "NONLOCAL_DOCKER_CONTEXT_BLOCKED"
        if offline._docker(["info","--format","{{.ServerVersion}}"],
                           timeout=15).returncode:
            return "LOCAL_DOCKER_DAEMON_UNAVAILABLE"
        if offline._docker(["image","inspect",offline.IMAGE],
                           timeout=15).returncode:
            return "PG17_LOCAL_IMAGE_NOT_CACHED"
    except (OSError,subprocess.SubprocessError):
        return "LOCAL_DOCKER_DAEMON_UNAVAILABLE"
    return "PASS"


def _require_owner_scope(pairs, pin):
    """Bind exactly eleven distinct Git blobs to the separate owner approval."""
    if not isinstance(pin, str) or not clean.SHA256.fullmatch(pin):
        raise Blocked("INDEPENDENT_OWNER_SCOPE_PIN_REQUIRED")
    if (len(pairs) != MAX_ARCHIVES or
            any(not isinstance(p, (tuple, list)) or len(p) != 2 or
                not isinstance(p[0], str) or not clean.SHA1.fullmatch(p[0]) or
                not isinstance(p[1], str) or not clean.SHA256.fullmatch(p[1])
                for p in pairs)):
        raise Blocked("OWNER_SCOPE_INVALID_MANIFEST")
    blobs = [p[0] for p in pairs]
    if len(set(blobs)) != MAX_ARCHIVES:
        raise Blocked("OWNER_SCOPE_DUPLICATE_ARCHIVE")
    body = "JW-WORM-OWNER-SCOPE-V1\n" + "\n".join(sorted(blobs)) + "\n"
    actual = hashlib.sha256(body.encode("ascii")).hexdigest()
    if not hmac.compare_digest(actual, pin):
        raise Blocked("OWNER_SCOPE_PIN_MISMATCH")


def decrypt_verified(cipher: bytes, key: bytes) -> bytearray:
    """In-memory bounds and AEAD check across *all* archive chunks."""
    plain=bytearray()
    try:
        if not isinstance(cipher,bytes) or not 24<len(cipher)<=clean.MAX_OBJECT:
            raise Blocked("REMOTE_CIPHERTEXT_SIZE_INVALID")
        magic=cipher[:8]
        if magic not in (backup.MAGIC,backup.MAGIC_LEGACY):
            raise Blocked("CIPHERTEXT_VERSION_UNSUPPORTED")
        offset=8+(8 if magic==backup.MAGIC else 4)
        prefix=cipher[8:offset]
        if len(prefix) not in (4,8):
            raise Blocked("CIPHERTEXT_NONCE_PREFIX_INVALID")
        aes=AESGCM(key)
        pos=offset
        count=0
        while pos<len(cipher):
            if count >= (2**32 if len(prefix)==8 else 2**64):
                raise Blocked("CIPHERTEXT_NONCE_COUNTER_EXHAUSTED")
            if len(cipher)-pos<4:
                raise Blocked("CIPHERTEXT_RECORD_TRUNCATED")
            n=int.from_bytes(cipher[pos:pos+4],"big")
            if not 16<=n<=backup.MAX_CHUNK_CIPHERTEXT:
                raise Blocked("CIPHERTEXT_RECORD_LENGTH_INVALID")
            start=pos+4
            end=start+n
            if end>len(cipher):
                raise Blocked("CIPHERTEXT_RECORD_TRUNCATED")
            final=(end==len(cipher))
            try:
                decrypted=aes.decrypt(backup._nonce(prefix,count),
                                      cipher[start:end],
                                      backup._aad(count,final,magic))
            except (InvalidTag,ValueError):
                raise Blocked("EXTERNAL_KEY_OR_REMOTE_ARCHIVE_AUTH_FAILED") from None
            if len(plain)+len(decrypted)>MAX_PLAIN_ONE:
                raise Blocked("DECRYPTED_ARCHIVE_MEMORY_BUDGET_EXCEEDED")
            plain.extend(decrypted)
            pos=end
            count+=1
        if count==0 or not plain.startswith(b"PGDMP"):
            raise Blocked("DECRYPTED_DATA_NOT_POSTGRES_CUSTOM_ARCHIVE")
        return plain
    except BaseException:
        plain.clear()
        raise


def _staged_inputs(staged):
    """Read the pinned local encrypted set only, before opening a key pipe."""
    if os.environ.get("JW_PG_B2_OFFLINE_ACK") != B2_ACK:
        raise Blocked("B2_OFFLINE_APPROVAL_REQUIRED")
    if any(os.environ.get(k) for k in ("GH_TOKEN","GITHUB_TOKEN","B2_APPLICATION_KEY",
                                      "B2_APPLICATION_KEY_ID","AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY")):
        raise Blocked("B2_OFFLINE_PROVIDER_CREDENTIAL_PRESENT")
    if type(staged) is not tuple or len(staged)!=4:
        raise Blocked("B2_OFFLINE_INPUTS_REQUIRED")
    raw,pin,directory,scope=staged
    try:
        known=b2stage.read_staged(raw,pin,directory,scope)
    except (ValueError,OSError,TypeError):
        raise Blocked("B2_OFFLINE_CIPHERTEXT_SET_INVALID") from None
    if len(known)!=MAX_ARCHIVES:
        raise Blocked("B2_OFFLINE_SCOPE_COUNT")
    return known

def run(reference_raw=None, reference_pin=None, *, catalog_required=False, staged=None) -> dict[str, object]:
    result={
        "external_pg17_restore":"BLOCKED",
        "ciphertext_path":"B2_STAGED_OFFLINE" if staged is not None else "GITHUB_PRIVATE_VAULT",
        "b2_staged_scope_bound":False,
        "owner_scope_pin_checked":False,
        "verified_provider_cipher_count":0,
        "restored_pg17_archive_count":0,
        "restored_65_table_archive_count":0,
        "restore_failures":0,
        "disposable_pg17_removed":"NOT_RUN",
        "decrypted_dump_written_to_host":False,
        "source_codespaces_key_used":False,
        "independent_key_custody":"NOT_ATTESTED",
        "independent_legal_retention":"NOT_ATTESTED",
        "historic_source_signature":"NOT_ATTESTED",
        "production_release_ready":False,
        "overall":"BLOCKED",
    }
    reference_required=catalog_required or reference_raw is not None or reference_pin is not None
    if catalog_required:
        result["normalized_catalog_comparison"]="BLOCKED"
    if reference_required:
        result["normalized_archive_comparison"]="BLOCKED"
    gate=preflight()
    if gate!="PASS":
        result["blocker"]=gate
        return result

    container=None
    key=None
    comparison=None
    try:
        known=None
        if staged is not None:
            if not catalog_required or reference_raw is None or reference_pin is None:
                raise Blocked("B2_OFFLINE_CATALOG_REFERENCE_REQUIRED")
            known=_staged_inputs(staged)
        pin,key,pairs=clean._inputs()
        _require_owner_scope(pairs, os.environ.get("JW_WORM_OWNER_SCOPE_SHA256", ""))
        result["owner_scope_pin_checked"]=True
        if reference_required:
            loader=catalog.load_reference if catalog_required else equivalence.load_reference
            rows=loader(
                reference_raw, expected_reference_sha256=reference_pin,
                expected_vault=pin,
                expected_scope=os.environ.get("JW_WORM_OWNER_SCOPE_SHA256", ""),
                provider_pairs=pairs)
            comparison=catalog.CatalogComparison(*rows) if catalog_required else equivalence.Equivalence(rows)
        if known is None:
            if not set(x[0] for x in pairs)<=clean._head_tree(pin):
                raise Blocked("PINNED_PRIVATE_VAULT_OBJECT_SET_INVALID")
        else:
            if set(known)!={blob for blob,_ in pairs} or any(
                    not hmac.compare_digest(hashlib.sha256(known[blob]).hexdigest(),expected)
                    for blob,expected in pairs):
                raise Blocked("B2_OFFLINE_OWNER_MANIFEST_MISMATCH")
            result["b2_staged_scope_bound"]=True
        name="jw-p1-external-pg17-"+secrets.token_hex(8)
        created=offline._docker([
            "run","--rm","--pull","never","-d","--name",name,
            "--network","none","--publish-all=false",
            "--tmpfs","/var/lib/postgresql/data:rw,size=1073741824",
            "--tmpfs","/var/run/postgresql:rw,size=16777216",
            "-e","POSTGRES_HOST_AUTH_METHOD=trust",
            offline.IMAGE,
        ],timeout=45)
        if created.returncode:
            raise Blocked("NETWORKLESS_DISPOSABLE_PG17_START_FAILED")
        container=created.stdout.decode("ascii","ignore").strip()
        if not offline.SHA_RE.fullmatch(container):
            raise Blocked("DISPOSABLE_PG17_CONTAINER_ID_INVALID")
        for _ in range(60):
            if offline._final_pg17_ready(container):
                break
            time.sleep(0.5)
        else:
            raise Blocked("DISPOSABLE_PG17_NOT_READY")
        version=offline._exec(container,["postgres","--version"],timeout=15)
        if (version.returncode or
                not re.search(rb"PostgreSQL\)\s+17\.",version.stdout)):
            raise Blocked("DISPOSABLE_PG17_VERSION_MISMATCH")

        spent_cipher=0
        spent_plain=0
        begun=time.monotonic()
        for i,(blob,expected) in enumerate(pairs):
            if time.monotonic()-begun > MAX_RUNTIME_SECONDS:
                raise Blocked("SECOND_SITE_TIME_BUDGET_EXCEEDED")
            cipher=clean._download(blob,expected) if known is None else known[blob]
            spent_cipher+=len(cipher)
            if spent_cipher>MAX_TOTAL_CIPHER:
                raise Blocked("SECOND_SITE_CIPHERTEXT_BUDGET_EXCEEDED")
            result["verified_provider_cipher_count"]+=1
            plain=decrypt_verified(cipher,key)
            try:
                spent_plain+=len(plain)
                if spent_plain>MAX_PLAIN_TOTAL:
                    raise Blocked("SECOND_SITE_PLAINTEXT_MEMORY_BUDGET_EXCEEDED")
                if catalog_required:
                    observed=[]
                    def collect(c,db):
                        if c!=container or db!="jw_p1_offline_"+str(i) or observed:
                            raise equivalence.Blocked("CATALOG_CALLBACK_TARGET_OR_REPLAY")
                        observed.append(catalog.probe(offline._exec,c,db))
                    restored=offline._restore_one(container,plain,i,catalog_probe=collect)
                else:
                    restored=offline._restore_one(container,plain,i)
                status,tables,_,row_digest,rows,_,_,_=restored
                if catalog_required:
                    if len(observed)!=1:
                        raise equivalence.Blocked("CATALOG_CALLBACK_MISSING")
                    comparison.compare(blob,hashlib.sha256(cipher).hexdigest(),restored,observed[0])
                elif comparison is not None:
                    comparison.compare(blob,hashlib.sha256(cipher).hexdigest(),restored)
                if (status!="LOCAL_DISPOSABLE_RESTORED"
                        or tables!=65 or rows is None
                        or not isinstance(row_digest,str)):
                    raise Blocked("SECOND_SITE_PG17_RESTORE_MISMATCH_OR_INCOMPLETE")
                result["restored_pg17_archive_count"]+=1
                result["restored_65_table_archive_count"]+=1
            finally:
                plain.clear()
        if (result["verified_provider_cipher_count"]!=MAX_ARCHIVES
                or result["restored_pg17_archive_count"]!=MAX_ARCHIVES):
            raise Blocked("SECOND_SITE_ELEVEN_ARCHIVES_NOT_FULLY_RESTORED")
        result["external_pg17_restore"]="PASS_ELEVEN_PROVIDER_CIPHERS_NETWORKLESS_PG17"
    except (clean.Blocked,Blocked,backup.BackupError,equivalence.Blocked) as exc:
        safe=str(exc)
        result["blocker"]=safe if re.fullmatch(r"[A-Z_]{3,100}",safe) else "SECOND_SITE_RESTORE_FAIL_CLOSED"
        result["restore_failures"]+=1
    except Exception:
        result["blocker"]="SECOND_SITE_RESTORE_FAIL_CLOSED"
        result["restore_failures"]+=1
    finally:
        key=None
        if container and offline.SHA_RE.fullmatch(container):
            try:
                stopped=offline._docker(["rm","-f",container],timeout=30)
                result["disposable_pg17_removed"]="PASS" if stopped.returncode==0 else "BLOCKED_CLEANUP"
            except (OSError,subprocess.SubprocessError):
                result["disposable_pg17_removed"]="BLOCKED_CLEANUP"
            if result["disposable_pg17_removed"]!="PASS":
                result["external_pg17_restore"]="BLOCKED_CLEANUP"
                result["blocker"]="DISPOSABLE_PG17_CLEANUP_FAILED"
    if reference_required:
        if comparison is not None:
            result.update(comparison.receipt(cleanup=result["disposable_pg17_removed"]))
        if (result.get("normalized_archive_comparison")!="PASS_11_ARCHIVE_CHECKPOINTS"
                or result["external_pg17_restore"]!="PASS_ELEVEN_PROVIDER_CIPHERS_NETWORKLESS_PG17"):
            result["normalized_archive_comparison"]="BLOCKED"
            if catalog_required:
                result["normalized_catalog_comparison"]="BLOCKED"
                result["rls_policy_definition_comparison"]="BLOCKED"
    # All necessary raw data and credentials are local to the external custodian.
    # This receipt is *not* an independent signature or source-era provenance.
    return result


def main(argv=None):
    argv=sys.argv[1:] if argv is None else argv
    if argv==["restore-b2-offline-catalog"]:
        # No provider calls in this mode. The custodian supplies independently
        # pinned ciphertext manifest, legacy vault identity/reference and key pipe.
        try:
            if os.environ.get("JW_PG_B2_OFFLINE_ACK") != B2_ACK:
                raise Blocked("B2_OFFLINE_APPROVAL_REQUIRED")
            if preflight()!="PASS":
                raise Blocked("B2_OFFLINE_PREFLIGHT_FAILED")
            import stat
            fd=os.open(os.environ["JW_PG_B2_MANIFEST_PATH"],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,"rb") as f:
                info=os.fstat(f.fileno())
                if not stat.S_ISREG(info.st_mode) or not 0<info.st_size<=65536:
                    raise Blocked("B2_OFFLINE_MANIFEST_FILE")
                manifest=f.read(65537)
            raw=equivalence.read_reference_pipe(os.environ)
            receipt=run(raw,os.environ.get("JW_PG_RESTORE_REFERENCE_SHA256",""),catalog_required=True,
                        staged=(manifest,os.environ.get("JW_PG_B2_MANIFEST_SHA256",""),
                                os.environ["JW_PG_B2_STAGE_DIRECTORY"],os.environ.get("JW_PG_B2_SCOPE","")))
        except Exception:
            receipt={"ciphertext_path":"B2_STAGED_OFFLINE","external_pg17_restore":"BLOCKED",
                     "blocker":"B2_OFFLINE_INPUT_OR_APPROVAL_FAILED","overall":"BLOCKED"}
        print(json.dumps(receipt,sort_keys=True,separators=(",",":")))
        return 0 if (receipt.get("b2_staged_scope_bound") is True and
                     receipt.get("normalized_catalog_comparison")=="PASS_11_SCOPED_CATALOG_CHECKPOINTS" and
                     receipt.get("disposable_pg17_removed")=="PASS") else 1
    if argv in (["restore-external-equivalence"],["restore-external-catalog"]):
        catalog_required=argv==["restore-external-catalog"]
        try:
            raw=equivalence.read_reference_pipe(os.environ)
            receipt=run(raw,os.environ.get("JW_PG_RESTORE_REFERENCE_SHA256", ""),catalog_required=catalog_required)
        except equivalence.Blocked as exc:
            receipt={"normalized_archive_comparison":"BLOCKED","blocker":str(exc),"overall":"BLOCKED"}
        print(json.dumps(receipt,sort_keys=True,separators=(",",":")))
        if catalog_required:
            return 0 if receipt.get("normalized_catalog_comparison")=="PASS_11_SCOPED_CATALOG_CHECKPOINTS" else 1
        return 0 if receipt.get("normalized_archive_comparison")=="PASS_11_ARCHIVE_CHECKPOINTS" else 1
    if argv!=["restore-external"]:
        print("USAGE: python -m scripts.p1_external_custodian_pg17_v223 restore-external",
              file=sys.stderr)
        return 2
    receipt=run()
    print(json.dumps(receipt,sort_keys=True,separators=(",",":")))
    return 0 if (receipt["external_pg17_restore"]==
        "PASS_ELEVEN_PROVIDER_CIPHERS_NETWORKLESS_PG17"
        and receipt["disposable_pg17_removed"]=="PASS") else 1


if __name__=="__main__":
    raise SystemExit(main())
