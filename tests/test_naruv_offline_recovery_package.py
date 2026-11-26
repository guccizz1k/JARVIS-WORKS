import hashlib
import io
import os
import subprocess
import sys
import zipfile
from pathlib import Path
import pytest
from scripts import naruv_offline_recovery_package as p

def test_actual_checkout_package_is_deterministic_and_imports_without_repo(tmp_path):
    root=Path(__file__).resolve().parents[1]
    commit=subprocess.check_output(["git","-C",str(root),"rev-parse","HEAD"],text=True).strip()
    raw=p.from_git(root,commit)
    assert raw==p.from_git(root,commit)
    pin=p.sha(raw)
    assert p.verify(raw,pin,commit)["file_count"]==10
    z=tmp_path/"recovery.zip";z.write_bytes(raw)
    # Python namespace packages need a scripts directory ZIP entry, so use
    # verified explicit allowlist extraction into a fresh private test directory.
    with zipfile.ZipFile(z) as archive:
        for name in p.FILES:
            target=tmp_path/name;target.parent.mkdir(exist_ok=True)
            target.write_bytes(archive.read(name))
    env={k:v for k,v in os.environ.items() if k in ("PATH","SYSTEMROOT","HOME","LANG")}
    code="from scripts import p1_external_custodian_pg17_v223 as e; assert e.B2_ACK; assert e.main(['invalid'])==2"
    r=subprocess.run([sys.executable,"-c",code],cwd=tmp_path,env=env,capture_output=True,timeout=20)
    assert r.returncode==0,r.stderr

def test_rejects_pin_commit_append_and_extra_member():
    files={x:b"pass\n" for x in p.FILES}
    raw=p.build("a"*40,files)
    with pytest.raises(ValueError):p.verify(raw,"0"*64,"a"*40)
    with pytest.raises(ValueError):p.verify(raw,p.sha(raw),"b"*40)
    with pytest.raises(ValueError):p.verify(raw+b"extra",p.sha(raw+b"extra"),"a"*40)
    buf=io.BytesIO(raw)
    with zipfile.ZipFile(buf,"a") as z:z.writestr("../escape","x")
    changed=buf.getvalue()
    with pytest.raises(ValueError):p.verify(changed,p.sha(changed),"a"*40)
    with pytest.raises(ValueError):p.build("a"*40,{**files,"secret":b"x"})
