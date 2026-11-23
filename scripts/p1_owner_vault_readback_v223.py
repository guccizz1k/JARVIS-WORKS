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
    for item in raw[:-1].split(b"\0"):
        try:
            meta,name=item.split(b"\t",1)
            mode,kind,sha=meta.split(b" ")
            if (mode!=b"100644" or kind!=b"blob" or
                not PATH.fullmatch(name) or b".." in name.split(b"/") or
                b"." in name.split(b"/")):
                raise ValueError
            token=sha.decode("ascii")
            if not SHA.fullmatch(token):raise ValueError
        except (ValueError,UnicodeError):
            raise Blocked("REMOTE_TREE_UNSAFE_ENTRY") from None
        out.append(token)
        if len(out)>MAX:raise Blocked("REMOTE_TREE_TOO_MANY_FILES")
    if not out or len(set(out))!=len(out):
        raise Blocked("REMOTE_TREE_EMPTY_OR_DUPLICATE")
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
            cl=git(["-c","core.hooksPath=/dev/null",
                    "-c","protocol.file.allow=never","clone","--quiet",
                    "--no-checkout","--single-branch","--no-tags","--depth=1",
                    "--filter=blob:none","--branch=main",VAULT,str(checkout)],timeout=120)
            if cl.returncode:raise Blocked("GITHUB_PRIVATE_VAULT_CLONE_AUTH_BLOCKED")
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
    if args!=["readback"]:
        print("USAGE: python -m scripts.p1_owner_vault_readback_v223 readback",file=sys.stderr)
        return 2
    try:result=audit()
    except Exception:
        print('{"remote_readback":"BLOCKED","overall":"BLOCKED","blocker":"SAFE_FAIL_CLOSED"}')
        return 1
    print(json.dumps(result,sort_keys=True,separators=(",",":")))
    return 0 if (result.get("remote_readback")=="PASS_MATCHED_REMOTE_CIPHERTEXT"
                 and result.get("temporary_clone_removed")=="PASS") else 1

if __name__=="__main__":
    raise SystemExit(main())
