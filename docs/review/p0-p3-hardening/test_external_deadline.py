"""Simulated final archive latency; no actual provider, Docker or key access."""
import hashlib
from types import SimpleNamespace
import pytest
from scripts import p1_external_custodian_pg17_v223 as e

@pytest.mark.parametrize("elapsed,expected",[(479,"PASS_ELEVEN_PROVIDER_CIPHERS_NETWORKLESS_PG17"),(480,"PASS_ELEVEN_PROVIDER_CIPHERS_NETWORKLESS_PG17"),(481,"BLOCKED")])
def test_final_archive_deadline(monkeypatch,elapsed,expected):
    ids=[f"{i:040x}" for i in range(11)]
    pairs=[(x,"b"*64) for x in ids]
    pin=hashlib.sha256(("JW-WORM-OWNER-SCOPE-V1\n"+"\n".join(ids)+"\n").encode()).hexdigest()
    monkeypatch.setenv("JW_WORM_OWNER_SCOPE_SHA256",pin)
    monkeypatch.setattr(e,"preflight",lambda:"PASS")
    monkeypatch.setattr(e.clean,"_inputs",lambda:("c"*40,b"K"*32,pairs))
    monkeypatch.setattr(e.clean,"_head_tree",lambda _:set(ids))
    monkeypatch.setattr(e.clean,"_download",lambda *_:b"synthetic")
    monkeypatch.setattr(e,"decrypt_verified",lambda *_:bytearray(b"PGDMP-synthetic"))
    ticks=[0]
    monkeypatch.setattr(e.time,"monotonic",lambda:ticks[0])
    commands=[]
    def docker(args,**kwargs):
        commands.append(args[0])
        return SimpleNamespace(returncode=0,stdout=b"a"*64)
    monkeypatch.setattr(e.offline,"_docker",docker)
    monkeypatch.setattr(e.offline,"_final_pg17_ready",lambda _:True)
    monkeypatch.setattr(e.offline,"_exec",lambda *a,**kw:SimpleNamespace(returncode=0,stdout=b"postgres (PostgreSQL) 17.1"))
    def restore(container,plain,i):
        if i==10:ticks[0]=elapsed
        return ("LOCAL_DISPOSABLE_RESTORED",65,None,"d"*64,1,None,None,None)
    monkeypatch.setattr(e.offline,"_restore_one",restore)
    r=e.run()
    assert r["restored_pg17_archive_count"]==11
    assert r["external_pg17_restore"]==expected
    assert r["disposable_pg17_removed"]=="PASS"
    assert r["overall"]=="BLOCKED" and r["production_release_ready"] is False
    assert commands==["run","rm"]
    if elapsed>480:assert r["blocker"]=="SECOND_SITE_TIME_BUDGET_EXCEEDED"
