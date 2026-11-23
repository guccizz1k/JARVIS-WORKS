"""Owner-Codespaces-only encrypted GitHub vault readback. Never upload or decrypt."""
from __future__ import annotations
import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from scripts import p1_owner_one_shot_v223 as owner

VAULT="https://github.com/guccizz1k/jw-backup-vault-261111.git"
ACK="OWNER_APPROVES_CIPHERTEXT_ONLY_PRIVATE_VAULT_READBACK"
SHA=re.compile(r"^[0-9a-f]{40}$")
PATH=re.compile(rb"^(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_.-]+\.jwpgbk$")
MAX=16
MAX_SIZE=128*1024*1024
MAX_TOTAL=512*1024*1024

class Blocked(RuntimeError):
    pass

def git(args:list[str],cwd:Path|None=None,timeout:int=60):
    env=os.environ.copy()
    # Never forward the vault-specific Codespaces secret to general Git
    # operations, including the source-repository credential helper.
    env.pop("JW_VAULT_READ_TOKEN",None)
    env.update(GIT_TERMINAL_PROMPT="0",GIT_LFS_SKIP_SMUDGE="1",
               GIT_TRACE="0",GIT_CURL_VERBOSE="0",GIT_PAGER="cat")
    try:
        return subprocess.run(["git",*args],cwd=cwd,env=env,
              stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
              stderr=subprocess.DEVNULL,timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired):
        raise Blocked("GIT_UNAVAILABLE_OR_TIMEOUT") from None

def local_hash(path:Path)->tuple[str,str]:
    if not owner._private_cipher_file(path):
        raise Blocked("LOCAL_CIPHERTEXT_PERMISSIONS_INVALID")
    try:
        fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
        with os.fdopen(fd,"rb") as f:
            st=os.fstat(f.fileno())
            if (not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode)!=0o600
                or not 0<st.st_size<=MAX_SIZE
                or (hasattr(os,"getuid") and st.st_uid!=os.getuid())):
                raise Blocked("LOCAL_CIPHERTEXT_UNSAFE")
            g=hashlib.sha1(b"blob "+str(st.st_size).encode()+b"\0")
            h=hashlib.sha256()
            while data:=f.read(131072):
                g.update(data);h.update(data)
            return g.hexdigest(),h.hexdigest()
    except OSError:
        raise Blocked("LOCAL_CIPHERTEXT_READ_FAILED") from None

def remote_blobs(raw:bytes)->list[str]:
    if len(raw)>32768 or not raw.endswith(b"\0"):
        raise Blocked("REMOTE_TREE_INVALID")
    out=[]
    seen_names=set()
    for item in raw[:-1].split(b"\0"):
        try:
            meta,name=item.split(b"\t",1)
            mode,kind,sha=meta.split(b" ")
            if (mode!=b"100644" or kind!=b"blob" or
                not PATH.fullmatch(name) or b".." in name.split(b"/") or
                b"." in name.split(b"/")):
                raise ValueError
            token=sha.decode("ascii")
            if not SHA.fullmatch(token) or name in seen_names:raise ValueError
            seen_names.add(name)
        except (ValueError,UnicodeError):
            raise Blocked("REMOTE_TREE_UNSAFE_ENTRY") from None
        out.append(token)
        if len(out)>MAX:raise Blocked("REMOTE_TREE_TOO_MANY_FILES")
    # Distinct Git paths may legitimately contain IDENTICAL encrypted bytes.
    # Reject duplicate paths, NOT repeated Git blob IDs: owner vault currently
    # contains four file paths but only three distinct Git ciphertext blobs.
    if not out:
        raise Blocked("REMOTE_TREE_EMPTY")
    return out

def remote_sha256(repo:Path,sha:str)->tuple[str,int]:
    if not SHA.fullmatch(sha):raise Blocked("GIT_BLOB_SHA_INVALID")
    size=git(["cat-file","-s",sha],repo,30)
    try:n=int(size.stdout.strip())
    except (ValueError,TypeError):raise Blocked("GIT_BLOB_SIZE_UNKNOWN") from None
    if size.returncode or not 0<n<=MAX_SIZE:
        raise Blocked("GIT_BLOB_UNSAFE_SIZE")
    env=os.environ.copy()
    env.update(GIT_TERMINAL_PROMPT="0",GIT_PAGER="cat")
    proc=None;h=hashlib.sha256();read=0
    try:
        proc=subprocess.Popen(["git","cat-file","blob",sha],cwd=repo,env=env,
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        assert proc.stdout is not None
        while part:=proc.stdout.read(131072):
            read+=len(part)
            if read>n:raise Blocked("GIT_BLOB_LENGTH_CHANGED")
            h.update(part)
        if proc.wait(timeout=60) or read!=n:raise Blocked("GIT_BLOB_READBACK_FAILED")
        return h.hexdigest(),n
    except (OSError,subprocess.TimeoutExpired):
        raise Blocked("GIT_BLOB_READBACK_FAILED") from None
    finally:
        if proc and proc.poll() is None:
            proc.kill();proc.wait(timeout=10)

def compare(remote:list[str],local:dict[str,str],repo:Path|None,remote_reader=None)->dict:
    """Verify every remote blob and the distinct local-owner coverage.

    A private vault can contain older/unrelated encrypted objects and multiple
    paths to one blob. Neither is permission to delete files, nor a reason
    to reject 11/11 independently verified CURRENT OWNER backups. All remote
    blob bytes are still read and hashed; any corresponding local mismatch
    fails closed before any positive result.
    """
    matched_entries=0
    matched_objects=set()
    unmatched_entries=0
    total=0
    checked={}
    for obj in remote:
        if obj not in checked:
            actual,n=(remote_reader(obj) if remote_reader is not None
                      else remote_sha256(repo,obj))
            if not (isinstance(actual,str) and re.fullmatch(r"[0-9a-f]{64}",actual)
                    and isinstance(n,int) and not isinstance(n,bool)
                    and 0<n<=MAX_SIZE):
                raise Blocked("REMOTE_READBACK_INVALID_RESULT")
            total+=n
            if total>MAX_TOTAL:raise Blocked("REMOTE_CIPHERTEXT_TOTAL_LIMIT")
            checked[obj]=(actual,n)
        actual,n=checked[obj]
        if obj not in local:
            unmatched_entries+=1
        elif actual!=local[obj]:
            raise Blocked("REMOTE_CIPHERTEXT_SHA256_MISMATCH")
        else:
            matched_entries+=1
            matched_objects.add(obj)
    fully_covered=(len(local)==11 and len(matched_objects)==11)
    # Preserve the existing all-remote-members-local result, but recognize
    # full OWNER coverage independently of unrelated remotely stored blobs.
    if fully_covered:
        status="PASS_ALL_11_OWNER_ARCHIVES_VERIFIED"
    elif matched_entries==len(remote):
        status="PASS_MATCHED_REMOTE_CIPHERTEXT"
    else:
        status="BLOCKED_REMOTE_NOT_LOCAL"
    return {
        "remote_ciphertext_count":len(remote),
        "remote_unique_ciphertext_count":len(checked),
        "remote_duplicate_content_entries":len(remote)-len(checked),
        "remote_downloaded_unique_objects_count":len(checked),
        "remote_full_sha256_readback_matches":matched_entries,
        "remote_unique_full_sha256_matches":len(matched_objects),
        "remote_unmatched_ciphertext_count":unmatched_entries,
        "remote_unique_ciphertexts_not_in_owner":len(set(remote)-set(local)),
        "local_archives_not_offsite":len(local)-len(matched_objects),
        "remote_readback":status,
        "all_11_archives_offsite":fully_covered,
    }


# Read-only alternative when Codespaces GITHUB_TOKEN is scoped to the source
# repository and cannot clone a second PRIVATE repository.
# Manifest mode uses object IDs independently obtained via the connected GitHub
# account. It does NOT download/provider-authenticate bytes from the Codespace.
MANIFEST_ENV="JW_PG_VAULT_TRUSTED_BLOB_IDS"
PINNED_ENV="JW_PG_VAULT_EXPECTED_SHA"


def manifest_diagnostic()->dict:
    report={"manifest_diagnostic":"BLOCKED","overall":"BLOCKED",
            "provider_ciphertext_sha256_readback":"NOT_RUN",
            "remote_immutable_retention":"NOT_VERIFIED",
            "historical_source_signer_verified":False,
            "independent_key_escrow_verified":False}
    if os.environ.get("CODESPACES","").lower()!="true":
        report["blocker"]="OWNER_CODESPACE_REQUIRED";return report
    if os.environ.get("JW_PG_VAULT_READBACK_ACK")!=ACK:
        report["blocker"]="EXPLICIT_READBACK_APPROVAL_REQUIRED";return report
    if not SHA.fullmatch(os.environ.get(PINNED_ENV,"")):
        report["blocker"]="PINNED_REMOTE_COMMIT_REQUIRED";return report
    packed=os.environ.get(MANIFEST_ENV,"")
    ids=packed.split(",")
    if (not 1<=len(ids)<=MAX or any(not SHA.fullmatch(x) for x in ids)
            or packed!=packed.lower()):
        report["blocker"]="TRUSTED_REMOTE_BLOB_LIST_REQUIRED";return report
    archives,discovery=owner.discover_owner_archive()
    report["local_archive_discovery"]=discovery
    report["local_archive_count"]=len(archives)
    if not 1<=len(archives)<=MAX:
        report["blocker"]="LOCAL_PRIVATE_ARCHIVES_MISSING";return report
    try:
        local={}
        for path in archives:
            gh,actual=local_hash(path)
            if gh in local:raise Blocked("LOCAL_ARCHIVE_DUPLICATE_BYTES")
            local[gh]=actual
        unique=set(ids)
        matched=len(unique & local.keys())
        report.update({
          "provider_file_entry_count":len(ids),
          "provider_unique_git_blob_count":len(unique),
          "provider_duplicate_content_entries":len(ids)-len(unique),
          "owner_local_unique_archive_count":len(local),
          "provider_git_blob_id_matched_local_count":matched,
          "provider_unique_blobs_not_found_locally":len(unique)-matched,
          "owner_archives_not_in_provider_manifest":len(local)-matched,
          "manifest_diagnostic":"PASS_LOCAL_HASH_COMPARISON_EXECUTED",
          "provider_manifest_is_independently_signed":False,
        })
    except Blocked as exc:
        report["blocker"]=str(exc)
    return report


def _vault_cli_env()->dict[str,str]:
    """Preserve Codespaces tokens while preventing source-only token shadowing.

    GitHub CLI selects GH_TOKEN then GITHUB_TOKEN over its own stored
    credentials. For this SECOND private repository only, remove the source
    GITHUB_TOKEN from the child process, retaining an explicit GH_TOKEN or
    a previously authorized secure gh login. No credential is logged,
    persisted, elevated or modified. Original process env is unchanged.
    """
    env=os.environ.copy()
    # Existing Codespaces token must remain intact in the user's actual
    # environment. For this VAULT GH CLI child alone, avoid source token
    # precedence, and favor an optional repository-scoped, read-only
    # Codespaces secret without altering other GitHub workflows.
    env.pop("GITHUB_TOKEN",None)
    vault_token=env.pop("JW_VAULT_READ_TOKEN",None)
    if vault_token:
        env["GH_TOKEN"]=vault_token
    env.update(GH_PROMPT_DISABLED="1",GH_NO_UPDATE_NOTIFIER="1",
               GIT_TERMINAL_PROMPT="0")
    return env


def _vault_api_json(endpoint:str,max_bytes:int=65536,timeout:int=45)->dict:
    """Read approved private GitHub REST metadata, reject all untrusted bytes."""
    if (not endpoint.startswith("repos/guccizz1k/jw-backup-vault-261111/")
            or "\n" in endpoint or "\r" in endpoint or len(endpoint)>180):
        raise Blocked("VAULT_API_ENDPOINT_INVALID")
    try:
        call=subprocess.run(["gh","api",endpoint,"--method","GET",
            "--header","Accept: application/vnd.github+json"],
            env=_vault_cli_env(),stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            timeout=timeout,check=False)
        if call.returncode or len(call.stdout)>max_bytes:
            raise Blocked("VAULT_REST_CONTENTS_READ_UNAVAILABLE")
        val=json.loads(call.stdout)
        if not isinstance(val,dict):
            raise ValueError("wrong response type")
        return val
    except (OSError,ValueError,UnicodeError,subprocess.TimeoutExpired):
        raise Blocked("VAULT_REST_CONTENTS_READ_UNAVAILABLE") from None


def _vault_api_tree(data:dict)->list[str]:
    """Only named encrypted regular files; skip actual directory entries."""
    if data.get("truncated") is not False or not isinstance(data.get("tree"),list):
        raise Blocked("VAULT_REMOTE_TREE_TRUNCATED")
    entries=data["tree"]
    if len(entries)>MAX*5 or not entries:
        raise Blocked("VAULT_REMOTE_TREE_UNEXPECTED_SIZE")
    bin_tree=bytearray()
    for obj in entries:
        if not isinstance(obj,dict):
            raise Blocked("VAULT_REMOTE_TREE_UNSAFE")
        typ,mode=obj.get("type"),obj.get("mode")
        if typ=="tree" and mode=="040000":
            continue
        if typ!="blob" or mode!="100644":
            raise Blocked("VAULT_REMOTE_TREE_UNSAFE")
        path,sha,size=obj.get("path"),obj.get("sha"),obj.get("size")
        if (not isinstance(path,str) or not isinstance(sha,str)
                or not isinstance(size,int) or isinstance(size,bool)
                or not 0<size<=MAX_SIZE or not SHA.fullmatch(sha)):
            raise Blocked("VAULT_REMOTE_TREE_UNSAFE")
        try:
            token=path.encode("ascii")
        except UnicodeError:
            raise Blocked("VAULT_REMOTE_TREE_UNSAFE") from None
        if not PATH.fullmatch(token) or b".." in token.split(b"/"):
            raise Blocked("VAULT_REMOTE_TREE_UNSAFE")
        bin_tree.extend(b"100644 blob "+sha.encode()+b"\t"+token+b"\0")
    return remote_blobs(bytes(bin_tree))


def _vault_api_blob_sha256(sha:str)->tuple[str,int]:
    """Use REST base64 response without filesystem plaintext or token logging."""
    if not SHA.fullmatch(sha):
        raise Blocked("VAULT_REMOTE_BLOB_ID_INVALID")
    payload=_vault_api_json(
        "repos/guccizz1k/jw-backup-vault-261111/git/blobs/"+sha,
        max_bytes=MAX_SIZE*2+8192,timeout=90)
    encoded=payload.get("content")
    size=payload.get("size")
    if (payload.get("sha")!=sha or payload.get("encoding")!="base64"
            or not isinstance(encoded,str) or not isinstance(size,int)
            or isinstance(size,bool) or not 0<size<=MAX_SIZE
            or len(encoded)>2*MAX_SIZE):
        raise Blocked("VAULT_REMOTE_BLOB_METADATA_INVALID")
    try:
        content=base64.b64decode("".join(encoded.split()),validate=True)
    except (ValueError,binascii.Error):
        raise Blocked("VAULT_REMOTE_BLOB_BASE64_INVALID") from None
    if len(content)!=size:
        raise Blocked("VAULT_REMOTE_BLOB_LENGTH_INVALID")
    gitid=hashlib.sha1(b"blob "+str(size).encode("ascii")+b"\0"+content).hexdigest()
    if gitid!=sha:
        raise Blocked("VAULT_REMOTE_GIT_BLOB_HASH_MISMATCH")
    return hashlib.sha256(content).hexdigest(),size


def _vault_api_readback(local:dict[str,str],expected_head:str)->dict:
    """Pinned read-only provider API, independent from Git credential helper.

    This is an ALTERNATIVE to Git clone, not a permission bypass: GH_TOKEN or
    a stored gh credential MUST already have Contents:read for this vault.
    """
    if not SHA.fullmatch(expected_head) or not shutil.which("gh"):
        raise Blocked("VAULT_API_AUTH_OR_HEAD_UNAVAILABLE")
    prefix="repos/guccizz1k/jw-backup-vault-261111/"
    ref=_vault_api_json(prefix+"git/ref/heads/main")
    obj=ref.get("object")
    if not isinstance(obj,dict) or obj.get("sha")!=expected_head:
        raise Blocked("VAULT_REMOTE_COMMIT_CHANGED")
    c=_vault_api_json(prefix+"git/commits/"+expected_head)
    tree=c.get("tree")
    if c.get("sha")!=expected_head or not isinstance(tree,dict) or not SHA.fullmatch(tree.get("sha","")):
        raise Blocked("VAULT_REMOTE_COMMIT_TREE_UNVERIFIED")
    items=_vault_api_tree(_vault_api_json(prefix+"git/trees/"+tree["sha"]+"?recursive=1"))
    proof=compare(items,local,None,remote_reader=_vault_api_blob_sha256)
    proof["remote_commit_pinned"]=True
    proof["readback_transport"]="GH_REST_BLOB_BASE64_VERIFIED"
    return proof


def auth_probe()->dict:
    """Differentiates existing Git credential helper from GitHub CLI identity.

    Never emits status, headers, remote URLs, tokens, raw stderr or usernames.
    Does not write a credential helper or change permissions.
    """
    result={"auth_diagnostic":"BLOCKED","overall":"BLOCKED",
            "git_read_only_private_access":"NOT_RUN",
            "gh_cli_private_api_access":"NOT_RUN",
            "gh_token_environment_present":bool(os.environ.get("GH_TOKEN")),
            "vault_read_token_present":bool(os.environ.get("JW_VAULT_READ_TOKEN")),
            "source_github_token_present":bool(os.environ.get("GITHUB_TOKEN"))}
    if os.environ.get("CODESPACES","").lower()!="true":
        result["blocker"]="OWNER_CODESPACE_REQUIRED";return result
    if os.environ.get("JW_PG_VAULT_READBACK_ACK")!=ACK:
        result["blocker"]="EXPLICIT_READBACK_APPROVAL_REQUIRED";return result
    if not shutil.which("git"):
        result["blocker"]="GIT_BINARY_MISSING";return result
    probe=git(["ls-remote","--heads",VAULT,"main"],timeout=30)
    result["git_read_only_private_access"]="PASS" if probe.returncode==0 else "BLOCKED"
    if shutil.which("gh"):
        env=_vault_cli_env()
        try:
            cli=subprocess.run(["gh","api","repos/guccizz1k/jw-backup-vault-261111",
                                "--jq",".private"],env=env,
                               stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL,timeout=30,check=False)
            result["gh_cli_private_api_access"]="PASS" if (
                cli.returncode==0 and cli.stdout.strip()==b"true") else "BLOCKED"
        except (OSError,subprocess.TimeoutExpired):
            result["gh_cli_private_api_access"]="BLOCKED"
    else:
        result["gh_cli_private_api_access"]="GH_NOT_INSTALLED"
    if result["git_read_only_private_access"]=="PASS":
        result["auth_diagnostic"]="PASS_PRIVATE_VAULT_GIT_READ"
    elif result["gh_cli_private_api_access"]=="PASS":
        result["auth_diagnostic"]="GIT_HELPER_USING_DIFFERENT_CREDENTIALS"
    elif result["gh_cli_private_api_access"]=="GH_NOT_INSTALLED":
        result["auth_diagnostic"]="GIT_TOKEN_PRIVATE_REPO_ACCESS_NOT_CONFIRMED"
    else:
        result["auth_diagnostic"]="CODESPACE_CREDENTIAL_CANNOT_READ_PRIVATE_VAULT"
    return result


def _clone_with_approved_credentials(root:Path, checkout:Path):
    """No authorization bypass. Only read via already-authorized GH_TOKEN.

    No tokens in argv/URL, temporary credentials written nowhere.
    """
    first=git(["-c","core.hooksPath=/dev/null",
        "-c","protocol.file.allow=never","clone","--quiet",
        "--no-checkout","--single-branch","--no-tags","--depth=1",
        "--filter=blob:none","--branch=main",VAULT,str(checkout)],timeout=120)
    if first.returncode==0:
        return
    # GitHub Codespaces GITHUB_TOKEN normally covers only its own repository.
    # GH_TOKEN or an existing separately authorized gh login may be used
    # through GitHub CLI without printing or changing a credential.
    if not shutil.which("gh"):
        raise Blocked("CODESPACE_PRIVATE_VAULT_REPO_ACCESS_NOT_AUTHORIZED")
    try:
        if checkout.exists():
            if checkout.is_symlink() or not checkout.is_dir():
                raise Blocked("UNSAFE_TEMPORARY_CHECKOUT")
            shutil.rmtree(checkout)
        probe_env=_vault_cli_env()
        check=subprocess.run(["gh","api","repos/guccizz1k/jw-backup-vault-261111",
                              "--jq",".private"],
             env=probe_env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
             stderr=subprocess.DEVNULL,timeout=30,check=False)
        if check.returncode or check.stdout.strip()!=b"true":
            raise Blocked("GH_TOKEN_MISSING_PRIVATE_VAULT_CONTENTS_READ")
        clone=subprocess.run(["gh","repo","clone",
            "guccizz1k/jw-backup-vault-261111",str(checkout),"--",
            "--no-checkout","--depth=1","--filter=blob:none"],
            env=probe_env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,timeout=120,check=False)
        if clone.returncode:
            raise Blocked("GH_CLI_PRIVATE_REPO_CLONE_FAILED")
    except (OSError,subprocess.TimeoutExpired):
        raise Blocked("GH_CLI_PRIVATE_REPO_CLONE_UNAVAILABLE") from None

def audit()->dict:
    result={
        "remote_readback":"NOT_RUN","temporary_clone_removed":"NOT_STARTED",
        "historical_source_signer_verified":False,
        "independent_key_escrow_verified":False,
        "provider_immutable_retention_verified":False,
        "provider_acl_independent_verification":False,
        "all_11_archives_offsite":False,
        "overall":"BLOCKED",
    }
    if os.environ.get("CODESPACES","").lower()!="true":
        result["blocker"]="OWNER_CODESPACE_REQUIRED";return result
    if os.environ.get("JW_PG_VAULT_READBACK_ACK")!=ACK:
        result["blocker"]="EXPLICIT_READBACK_APPROVAL_REQUIRED";return result
    head=os.environ.get("JW_PG_VAULT_EXPECTED_SHA","")
    if not SHA.fullmatch(head):
        result["blocker"]="EXPECTED_REMOTE_COMMIT_REQUIRED";return result
    if not shutil.which("git"):
        result["blocker"]="GIT_CLI_REQUIRED";return result
    archives,discovery=owner.discover_owner_archive()
    result["owner_discovery"]=discovery
    result["local_archive_count"]=len(archives)
    if not 1<=len(archives)<=MAX:
        result["blocker"]="OWNER_LOCAL_ARCHIVES_NOT_BOUNDED";return result
    try:
        local={};total=0
        for path in archives:
            total+=path.lstat().st_size
            if total>MAX_TOTAL:raise Blocked("LOCAL_CIPHERTEXT_TOTAL_LIMIT")
            gitsha,strong=local_hash(path)
            if gitsha in local:raise Blocked("DUPLICATE_LOCAL_CIPHERTEXT")
            local[gitsha]=strong
        # GitHub CLI may authenticate to the *second* private vault even
        # when the Codespace source-repo git credential helper cannot.
        # A --filter=blob:none clone can therefore SUCCEED but subsequent
        # git cat-file triggers an unauthenticated lazy blob fetch:
        # GIT_BLOB_SIZE_UNKNOWN. Do not take that known-broken transport.
        # Prefer pinned GitHub REST blobs when only gh API auth is proven.
        authorized=auth_probe()
        gh_readable=authorized.get("gh_cli_private_api_access")=="PASS"
        git_readable=authorized.get("git_read_only_private_access")=="PASS"
        with tempfile.TemporaryDirectory(prefix="jw-vault-readback-") as dirname:
            root=Path(dirname);checkout=root/"vault"
            if stat.S_IMODE(root.stat().st_mode)!=0o700:
                raise Blocked("PRIVATE_SCRATCH_PERMISSIONS_INVALID")
            if gh_readable and not git_readable:
                result.update(_vault_api_readback(local,head))
            else:
                try:
                    _clone_with_approved_credentials(root, checkout)
                    remote_head=git(["rev-parse","HEAD"],checkout)
                    if (remote_head.returncode or
                        remote_head.stdout.decode("ascii","ignore").strip()!=head):
                        raise Blocked("REMOTE_COMMIT_CHANGED")
                    tree=git(["ls-tree","-r","-z","--full-tree","HEAD"],checkout)
                    if tree.returncode:raise Blocked("REMOTE_TREE_UNREADABLE")
                    result.update(compare(remote_blobs(tree.stdout),local,checkout))
                    result["remote_commit_pinned"]=True
                    result["readback_transport"]="GIT_PRIVATE_REPOSITORY"
                except Blocked as problem:
                    # Defense in depth: an apparently successful clone may
                    # still lack lazy-fetch permissions. Retry with an
                    # independently authorized REST transport only for these
                    # transport errors, never for ciphertext hash mismatches.
                    if not gh_readable or str(problem) not in (
                        "CODESPACE_PRIVATE_VAULT_REPO_ACCESS_NOT_AUTHORIZED",
                        "GH_TOKEN_MISSING_PRIVATE_VAULT_CONTENTS_READ",
                        "GH_CLI_PRIVATE_REPO_CLONE_FAILED",
                        "GIT_BLOB_SIZE_UNKNOWN",
                        "GIT_BLOB_UNSAFE_SIZE",
                        "GIT_BLOB_READBACK_FAILED"):
                        raise
                    result.update(_vault_api_readback(local,head))
        result["temporary_clone_removed"]="PASS"
    except Blocked as e:
        result["blocker"]=str(e)
    except (OSError,ValueError,TypeError):
        result["blocker"]="SAFE_VAULT_READBACK_ERROR"
    return result

def plan_offsite()->dict:
    """Non-mutating provider gap preflight with no archive names or secret data.

    The proposed copy count is informational; this function never writes to
    GitHub, moves files or changes retention/credentials. Remote object hashes
    must have been independently read back before a plan is considered valid.
    """
    report=audit()
    report["offsite_upload_execution"]="NOT_RUN_REQUIRES_SEPARATE_APPROVAL"
    report["backup_time_attestation"]="NOT_VERIFIED"
    report["key_custody_independent"]="NOT_VERIFIED"
    report["immutable_remote_retention"]="NOT_VERIFIED"
    report["offsite_plan"]="BLOCKED_INCOMPLETE_PROVIDER_EVIDENCE"
    if not (report.get("remote_commit_pinned") is True
            and report.get("temporary_clone_removed")=="PASS"
            and report.get("readback_transport") in (
                "GH_REST_BLOB_BASE64_VERIFIED","GIT_PRIVATE_REPOSITORY")):
        return report
    missing=report.get("local_archives_not_offsite")
    checked=report.get("remote_downloaded_unique_objects_count")
    unique=report.get("remote_unique_ciphertext_count")
    if (not isinstance(missing,int) or isinstance(missing,bool)
            or not 0<=missing<=11
            or not isinstance(unique,int) or unique<1
            or checked!=unique):
        return report
    report["offsite_plan"]="PASS_READ_ONLY_GAP_PREFLIGHT"
    report["missing_unique_archive_upload_candidates"]=missing
    report["predicted_unique_ciphertexts_after_owner_approved_copy"]=unique+missing
    report["predicted_vault_file_entries_after_owner_approved_copy"]=(
        report["remote_ciphertext_count"]+missing)
    report["offsite_upload_execution"]="NOT_RUN_REQUIRES_SEPARATE_APPROVAL"
    report["overall"]="BLOCKED"
    return report


def diagnose_remote()->dict:
    """One-call complete credential classification + authorized readback only.

    This independent owner-only check doesn't need the already-proven
    provider blob metadata input. The CLI exit is a diagnostic completion,
    NEVER a false offsite/retention/origin PASS.
    """
    diagnostic=auth_probe()
    if diagnostic.get("auth_diagnostic") in (
        "PASS_PRIVATE_VAULT_GIT_READ", "GIT_HELPER_USING_DIFFERENT_CREDENTIALS"
    ):
        recovered=audit()
        diagnostic.update(recovered)
    else:
        diagnostic["remote_readback"]="NOT_RUN_AUTHORIZATION_REQUIRED"
    diagnostic["overall"]="BLOCKED"
    return diagnostic


def diagnose_all()->dict:
    """One-shot owner workflow; fail-closed evidence, no token or data printed."""
    report=manifest_diagnostic()
    if report.get("manifest_diagnostic")!="PASS_LOCAL_HASH_COMPARISON_EXECUTED":
        return report
    authorization=auth_probe()
    for key in (
        "auth_diagnostic", "git_read_only_private_access",
        "gh_cli_private_api_access", "gh_token_environment_present",
        "vault_read_token_present", "source_github_token_present",
    ):
        if key in authorization:
            report[key]=authorization[key]
    if authorization.get("auth_diagnostic") in (
        "PASS_PRIVATE_VAULT_GIT_READ", "GIT_HELPER_USING_DIFFERENT_CREDENTIALS"
    ):
        actual=audit()
        for key,value in actual.items():
            if key in ("remote_readback", "remote_ciphertext_count",
                       "remote_unique_ciphertext_count",
                       "remote_duplicate_content_entries",
                       "remote_full_sha256_readback_matches",
                       "remote_unique_full_sha256_matches",
                       "remote_unmatched_ciphertext_count",
                       "local_archives_not_offsite",
                       "all_11_archives_offsite", "temporary_clone_removed",
                       "readback_transport", "blocker", "remote_commit_pinned"):
                report[key]=value
    else:
        report["remote_readback"]="NOT_RUN_AUTHORIZATION_REQUIRED"
    # Never upgrade historical backup origin, key escrow or launch.
    report["overall"]="BLOCKED"
    return report


def main(argv:list[str]|None=None)->int:
    args=sys.argv[1:] if argv is None else argv
    if args not in (["readback"], ["diagnose-manifest"], ["diagnose-auth"], ["diagnose-all"], ["diagnose-remote"], ["plan-offsite"]):
        print("USAGE: python -m scripts.p1_owner_vault_readback_v223 [readback|diagnose-manifest|diagnose-auth|diagnose-all|diagnose-remote|plan-offsite]",file=sys.stderr)
        return 2
    try:
        result=(auth_probe() if args==["diagnose-auth"] else
                manifest_diagnostic() if args==["diagnose-manifest"] else
                diagnose_all() if args==["diagnose-all"] else
                diagnose_remote() if args==["diagnose-remote"] else
                plan_offsite() if args==["plan-offsite"] else audit())
    except Exception:
        print('{"remote_readback":"BLOCKED","overall":"BLOCKED","blocker":"SAFE_FAIL_CLOSED"}')
        return 1
    print(json.dumps(result,sort_keys=True,separators=(",",":")))
    if args==["plan-offsite"]:
        return 0 if result.get("offsite_plan")=="PASS_READ_ONLY_GAP_PREFLIGHT" else 1
    if args==["diagnose-remote"]:
        return 0 if result.get("auth_diagnostic") not in ("BLOCKED",None) else 1
    if args==["diagnose-all"]:
        return 0 if result.get("manifest_diagnostic")=="PASS_LOCAL_HASH_COMPARISON_EXECUTED" else 1
    if args==["diagnose-auth"]:
        return 0 if result.get("auth_diagnostic") not in ("BLOCKED",None) else 1
    if args==["diagnose-manifest"]:
        return 0 if result.get("manifest_diagnostic")=="PASS_LOCAL_HASH_COMPARISON_EXECUTED" else 1
    return 0 if (result.get("remote_readback") in (
                    "PASS_MATCHED_REMOTE_CIPHERTEXT",
                    "PASS_ALL_11_OWNER_ARCHIVES_VERIFIED")
                 and result.get("temporary_clone_removed")=="PASS") else 1

if __name__=="__main__":
    raise SystemExit(main())
