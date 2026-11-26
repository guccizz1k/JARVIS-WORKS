"""Owner SHA256 scope pin derived from existing 11 synthetic ciphertext references."""
from scripts import p1_owner_vault_scope_pin_v223 as pin
from scripts import p1_external_worm_compliance_v223 as worm


def fake_selected():
    return {f"{i:040x}":(None,f"{i+50:064x}",480000,None)
            for i in range(1,12)}


def test_owner_scope_proof_has_11_ciphertexts_and_a_nonsecret_digest(monkeypatch):
    selected=fake_selected()
    monkeypatch.setenv("CODESPACES","true")
    monkeypatch.setenv("JW_WORM_VAULT_SHA","f"*40)
    monkeypatch.setattr(pin.owner,"local_files",lambda:selected)
    monkeypatch.setattr(pin.worm.vault,"_head_tree",
                        lambda sha:set(selected)|{"a"*40})
    monkeypatch.setattr(pin.worm.vault,"_download",
                        lambda git_sha,digest:b"JWPGBK2\n"+b"X"*24)
    report=pin.compute()
    assert report["overall"]=="PASS_OWNER_LOCAL_SCOPE_PIN_ONLY"
    assert report["owner_scope_digest"]==worm.owner_scope_fingerprint(selected)
    assert report["selected_cipher_count"]==11
    assert report["vault_unique_cipher_count"]==12
    assert report["owner_scope_is_signed"] is False
    assert report["source_key_read"] is False


def test_reject_non_owner_codespace_before_discovery(monkeypatch):
    monkeypatch.setenv("CODESPACES","false")
    monkeypatch.setattr(pin.owner,"local_files",lambda:(_ for _ in ()).throw(
        AssertionError("not allowed to inspect owner-local encrypted files")))
    assert pin.compute()["blocker"]=="OWNER_CODESPACE_REQUIRED"


def test_reject_unpinned_vault_before_discovery(monkeypatch):
    monkeypatch.setenv("CODESPACES","true")
    monkeypatch.setenv("JW_WORM_VAULT_SHA","missing")
    monkeypatch.setattr(pin.owner,"local_files",lambda:(_ for _ in ()).throw(
        AssertionError("untrusted pinned ref")))
    assert pin.compute()["blocker"]=="PINNED_PRIVATE_VAULT_COMMIT_REQUIRED"


def test_selected_cipher_not_on_private_vault_fails_closed(monkeypatch):
    selected=fake_selected()
    monkeypatch.setenv("CODESPACES","true")
    monkeypatch.setenv("JW_WORM_VAULT_SHA","f"*40)
    monkeypatch.setattr(pin.owner,"local_files",lambda:selected)
    monkeypatch.setattr(pin.worm.vault,"_head_tree",
                        lambda _:set(list(selected)[:-1]))
    monkeypatch.setattr(pin.worm.vault,"_download",lambda *args:
                        (_ for _ in ()).throw(AssertionError("not authorized")))
    assert pin.compute()["blocker"]=="OWNER_SELECTED_CIPHER_MISSING_FROM_VAULT"


def test_no_cli_write_actions(monkeypatch):
    monkeypatch.setattr(pin,"compute",lambda:
                        (_ for _ in ()).throw(AssertionError("no compute allowed")))
    assert pin.main(["upload"])==2
