"""Validate exact upstream skill files and unchanged product source (offline only)."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess

BASE = "9e2b29e7a043b7f1968b6148c640709287bb66fe"
MANIFEST = "docs/agents/JW_V208_FOUR_SKILLS_MANIFEST.json"
PREFIXES = (".agents/skills/security-audit/", ".agents/skills/ponytail/",
            ".agents/skills/change-impact/", ".agents/skills/impeccable/",
            "docs/third_party/licenses/")
EXTRA = {"AGENTS.md", MANIFEST, "docs/agents/JW_V208_FOUR_SKILLS.md",
         "scripts/ci_v208_four_skills.py", "tests/test_v208_four_skills.py",
         ".github/workflows/jw-v208-four-skills.yml",
         ".github/workflows/jw-j1-j6-unified-acceptance.yml"}
PROTECTED = ("app/main.py", "app/static/app.js", "app/static/index.html",
             "app/static/premium_v206.css", "app/static/premium_v206.js",
             "requirements.txt", "requirements-dev.txt")

def git(root, *args):
    return subprocess.check_output(["git","-C",str(root),*args],text=True).strip()

def blob(data):
    return hashlib.sha1(b"blob "+str(len(data)).encode("ascii")+b"\0"+data).hexdigest()

def safe_path(s):
    if not isinstance(s,str) or not s:return False
    p=PurePosixPath(s)
    return bool(p.parts) and not p.is_absolute() and ".." not in p.parts and p.as_posix()==s

def check_sources(root, data):
    if not isinstance(data,dict) or data.get("schema")!="JW_FOUR_SKILLS_PINNED_V1" or data.get("baseline_sha")!=BASE:
        raise AssertionError("Missing trusted baseline manifest")
    if data.get("review_only") is not True or data.get("auto_run_external_tools") is not False or data.get("operational_release")!="BLOCKED":
        raise AssertionError("External skill enabled or release unlocked")
    files=data.get("third_party_files")
    if not isinstance(files,dict) or len(files)<30:raise AssertionError("Insufficient verified sources")
    for path,meta in files.items():
        if not safe_path(path) or not path.startswith(PREFIXES):
            raise AssertionError("Untrusted source destination")
        if not isinstance(meta,dict):raise AssertionError("Malformed source metadata")
        for field in ("commit","git_blob"):
            sha=meta.get(field,"")
            if len(sha)!=40 or any(c not in "0123456789abcdef" for c in sha):
                raise AssertionError("Unpinned upstream "+field)
        p=root/path
        if not p.is_file() or blob(p.read_bytes())!=meta["git_blob"]:
            raise AssertionError("Source content tampered: "+path)
    for pre in PREFIXES[:4]:
        if pre+"SKILL.md" not in files:raise AssertionError("Missing advisory skill "+pre)
    if sum(k.startswith(PREFIXES[-1]) for k in files)!=4:
        raise AssertionError("Expected four license notices")
    return len(files)

def check_scope(root, data):
    changed=set(filter(None,git(root,"diff","--name-only",BASE,"HEAD").splitlines()))
    allowed=set(data["third_party_files"])|EXTRA
    if not changed or changed-allowed:
        raise AssertionError("Unexpected code changes: "+repr(sorted(changed-allowed)))
    for path in PROTECTED:
        if git(root,"rev-parse","HEAD:"+path)!=git(root,"rev-parse",BASE+":"+path):
            raise AssertionError("Protected application file changed: "+path)
    if git(root,"diff","--name-only",BASE,"HEAD","--","app/","db/","migrations/"):
        raise AssertionError("App or DB mutation detected")
    wf=(root/".github/workflows/jw-j1-j6-unified-acceptance.yml").read_text()
    if "review/v208-four-advisory-skills-20261102" not in wf:
        raise AssertionError("Full J1-J6 not enabled for new review branch")
    return len(changed)

def validate(root):
    data=json.loads((root/MANIFEST).read_text(encoding="utf-8"))
    count=check_sources(root,data)
    changed=check_scope(root,data)
    html=(root/"app/static/index.html").read_text()
    css=(root/"app/static/premium_v206.css").read_text()
    if html.index('data-page="imports"')>=html.index('data-page="dashboard"'):
        raise AssertionError("Upload-first business navigation changed")
    if "prefers-reduced-motion" not in css or "data-jw206-theme" not in css:
        raise AssertionError("Existing theme and a11y absent")
    return {"status":"PASS","pinned_files":count,"changed_paths":changed,
            "runtime_mutations":0,"production":"BLOCKED"}

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--repo",type=Path,default=Path("."))
    print(json.dumps(validate(p.parse_args().repo.resolve()),sort_keys=True))
