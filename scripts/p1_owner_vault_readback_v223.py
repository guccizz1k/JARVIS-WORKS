"""Owner-Codespaces-only encrypted GitHub vault readback. Never upload or decrypt."""
from __future__ import annotations
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

def compare(remote:list[str],local:dict[str,str],repo:Path)->dict:
    matched=0;unmatched=0;total=0
    for obj in remote:
        sha,n=remote_sha256(repo,obj)
        total+=n
        if total>MAX_TOTAL:raise Blocked("REMOTE_CIPHERTEXT_TOTAL_LIMIT")
        if obj not in local:unmatched+=1
        elif sha!=local[obj]:raise Blocked("REMOTE_CIPHERTEXT_SHA256_MISMATCH")
        else:matched+=1
    return {
        "remote_ciphertext_count":len(remote),
        "remote_full_sha256_readback_matches":matched,
        "remote_unmatched_ciphertext_count":unmatched,
        "local_archives_not_offsite":len(local)-matched,
        "remote_readback":"PASS_MATCHED_REMOTE_CIPHERTEXT" if matched==len(remote)
            else "BLOCKED_REMOTE_NOT_LOCAL",
        "all_11_archives_offsite":matched==len(local)==len(remote)==11,
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


def auth_probe()->dict:
    """Differentiates existing Git credential helper from GitHub CLI identity.

    Never emits status, headers, remote URLs, tokens, raw stderr or usernames.
    Does not write a credential helper or change permissions.
    """
    result={"auth_diagnostic":"BLOCKED","overall":"BLOCKED",
            "git_read_only_private_access":"NOT_RUN",
            "gh_cli_private_api_access":"NOT_RUN",
            "gh_token_environment_present":bool(os.environ.get("GH_TOKEN")),
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
        env=os.environ.copy()
        env.update(GH_PROMPT_DISABLED="1",GH_NO_UPDATE_NOTIFIER="1")
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
    # GH_TOKEN, if separately provisioned with private vault Contents:read,
    # may be used through GitHub CLI without revealing a credential.
    if not os.environ.get("GH_TOKEN") or not shutil.which("gh"):
        raise Blocked("CODESPACE_PRIVATE_VAULT_REPO_ACCESS_NOT_AUTHORIZED")
    try:
        if checkout.exists():
            if checkout.is_symlink() or not checkout.is_dir():
                raise Blocked("UNSAFE_TEMPORARY_CHECKOUT")
            shutil.rmtree(checkout)
        probe_env=os.environ.copy()
        probe_env.update(GH_PROMPT_DISABLED="1",GH_NO_UPDATE_NOTIFIER="1")
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
        with tempfile.TemporaryDirectory(prefix="jw-vault-readback-") as dirname:
            root=Path(dirname);checkout=root/"vault"
            if stat.S_IMODE(root.stat().st_mode)!=0o700:
                raise Blocked("PRIVATE_SCRATCH_PERMISSIONS_INVALID")
            _clone_with_approved_credentials(root, checkout)
            remote_head=git(["rev-parse","HEAD"],checkout)
            if (remote_head.returncode or
                remote_head.stdout.decode("ascii","ignore").strip()!=head):
                raise Blocked("REMOTE_COMMIT_CHANGED")
            tree=git(["ls-tree","-r","-z","--full-tree","HEAD"],checkout)
            if tree.returncode:raise Blocked("REMOTE_TREE_UNREADABLE")
            result.update(compare(remote_blobs(tree.stdout),local,checkout))
            result["remote_commit_pinned"]=True
        result["temporary_clone_removed"]="PASS"
    except Blocked as e:
        result["blocker"]=str(e)
    except (OSError,ValueError,TypeError):
        result["blocker"]="SAFE_VAULT_READBACK_ERROR"
    return result

def main(argv:list[str]|None=None)->int:
    args=sys.argv[1:] if argv is None else argv
    if args not in (["readback"], ["diagnose-manifest"], ["diagnose-auth"]):
        print("USAGE: python -m scripts.p1_owner_vault_readback_v223 [readback|diagnose-manifest|diagnose-auth]",file=sys.stderr)
        return 2
    try:
        result=(auth_probe() if args==["diagnose-auth"] else
                manifest_diagnostic() if args==["diagnose-manifest"] else audit())
    except Exception:
        print('{"remote_readback":"BLOCKED","overall":"BLOCKED","blocker":"SAFE_FAIL_CLOSED"}')
        return 1
    print(json.dumps(result,sort_keys=True,separators=(",",":")))
    if args==["diagnose-auth"]:
        return 0 if result.get("auth_diagnostic") not in ("BLOCKED",None) else 1
    if args==["diagnose-manifest"]:
        return 0 if result.get("manifest_diagnostic")=="PASS_LOCAL_HASH_COMPARISON_EXECUTED" else 1
    return 0 if (result.get("remote_readback")=="PASS_MATCHED_REMOTE_CIPHERTEXT"
                 and result.get("temporary_clone_removed")=="PASS") else 1

if __name__=="__main__":
    raise SystemExit(main())
