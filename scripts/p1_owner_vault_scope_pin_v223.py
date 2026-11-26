"""Owner Codespaces: create a NON-SECRET 11-archive scope digest, no writes.

Only run in owner existing Codespace with 11 encrypted archives still present,
and pinned private vault hash already known. DO NOT print archive names,
Git object SHAs, encryption key, raw bytes, DSNs or a secret.
"""
from __future__ import annotations
import json
import os
import sys
from scripts import p1_owner_vault_upload_v223 as owner
from scripts import p1_external_worm_compliance_v223 as worm


def compute():
    result={"owner_scope_digest":"BLOCKED","selected_cipher_count":0,
            "vault_unique_cipher_count":0,"owner_scope_is_signed":False,
            "source_key_read":False,"source_plaintext_read":False,
            "vault_mutated":False,"overall":"BLOCKED"}
    if os.environ.get("CODESPACES","").lower()!="true":
        result["blocker"]="OWNER_CODESPACE_REQUIRED"
        return result
    pin=os.environ.get("JW_WORM_VAULT_SHA","")
    if not worm.vault.SHA1.fullmatch(pin):
        result["blocker"]="PINNED_PRIVATE_VAULT_COMMIT_REQUIRED"
        return result
    try:
        # Existing 11-file discovery is read-only and checks owner-local
        # encrypted ciphertext sizes, permissions, magic, blob SHA1 + SHA256.
        selected=owner.local_files()
        trusted=worm.vault._head_tree(pin)
        if not set(selected).issubset(trusted):
            result["blocker"]="OWNER_SELECTED_CIPHER_MISSING_FROM_VAULT"
            return result
        for git_sha,(_,strong,_,_) in selected.items():
            remote=worm.vault._download(git_sha,strong)
            if not remote.startswith((b"JWPGBK1\n",b"JWPGBK2\n")):
                result["blocker"]="ORIGINAL_CIPHER_MAGIC_INVALID"
                return result
        result["selected_cipher_count"]=len(selected)
        result["vault_unique_cipher_count"]=len(trusted)
        result["owner_scope_digest"]=worm.owner_scope_fingerprint(selected)
        result["overall"]="PASS_OWNER_LOCAL_SCOPE_PIN_ONLY"
    except Exception:
        result["blocker"]="OWNER_SCOPE_RECONCILIATION_FAIL_CLOSED"
    return result


def main(argv=None):
    args=sys.argv[1:] if argv is None else argv
    if args!=["derive-scope-pin"]:
        print("USAGE: python -m scripts.p1_owner_vault_scope_pin_v223 derive-scope-pin",file=sys.stderr)
        return 2
    result=compute()
    print(json.dumps(result,sort_keys=True,separators=(",",":")))
    return 0 if result["overall"]=="PASS_OWNER_LOCAL_SCOPE_PIN_ONLY" else 1


if __name__=="__main__":
    raise SystemExit(main())
