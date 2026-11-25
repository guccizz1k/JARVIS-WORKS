"""F7 follow-up: tests that pin the two properties the F7 helpers exist for.

The F7 tests in tests/test_v223_pg_backup.py check sizes, modes and "decryption fails". Mutation
testing showed two weaker spots they leave open, closed here (a new file, so the audited blob pins
of the backup tool and its main test file stay untouched):
  1. a tampered copy must be rejected because AUTHENTICATION fails on exactly one flipped
     ciphertext byte, not because the magic/header was damaged;
  2. no read of the source may be larger than one CHUNK (the bounded-memory claim itself).
DB-free; needs only ``cryptography``.
"""
import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scripts import pg_backup_v223 as pb

HEADER = len(pb.MAGIC) + 4 + 4        # magic + nonce prefix + first record length


@pytest.fixture()
def key():
    return AESGCM.generate_key(256)


def _plain(tmp_path, size):
    p = tmp_path / "plain.bin"
    p.write_bytes(os.urandom(size))
    return p


@pytest.mark.parametrize("size", [1, pb.CHUNK + 5])
def test_tamper_flips_exactly_one_ciphertext_byte_and_fails_authentication(tmp_path, key, size):
    enc = tmp_path / "enc"
    pb.encrypt_file(_plain(tmp_path, size), enc, key)
    bad = tmp_path / "bad"
    pb.write_negative_cipher_copy(enc, bad, "tamper")
    a, b = enc.read_bytes(), bad.read_bytes()
    assert len(a) == len(b)
    assert a[:HEADER] == b[:HEADER]                                   # header (magic, prefix, length) intact
    assert [i for i in range(len(a)) if a[i] != b[i]] == [HEADER]     # one byte, first ciphertext byte
    assert a[HEADER] ^ b[HEADER] == 1
    with pytest.raises(pb.BackupError, match="AUTH_FAILED"):
        pb.decrypt_file(bad, tmp_path / "out", key)


def test_truncation_copy_is_a_prefix_exactly_40_bytes_shorter(tmp_path, key):
    enc = tmp_path / "enc"
    pb.encrypt_file(_plain(tmp_path, 2 * pb.CHUNK + 9), enc, key)
    cut = tmp_path / "cut"
    pb.write_negative_cipher_copy(enc, cut, "truncation")
    a, c = enc.read_bytes(), cut.read_bytes()
    assert len(c) == len(a) - 40 and a.startswith(c)
    with pytest.raises(pb.BackupError):
        pb.decrypt_file(cut, tmp_path / "out", key)


class _ReadSpy:
    """Wraps a real binary file and records the size argument of every read()."""

    sizes: list = []

    def __init__(self, real):
        self._real = real

    def read(self, n=-1):
        type(self).sizes.append(n)
        return self._real.read(n)

    def __getattr__(self, name):
        return getattr(self._real, name)

    def __enter__(self):
        self._real.__enter__()
        return self

    def __exit__(self, *exc):
        return self._real.__exit__(*exc)


@pytest.fixture()
def spy(monkeypatch):
    _ReadSpy.sizes = []
    real_open = open
    monkeypatch.setattr(pb, "open", lambda *a, **k: _ReadSpy(real_open(*a, **k)), raising=False)
    return _ReadSpy


def test_every_source_read_is_bounded_by_one_chunk(tmp_path, key, spy):
    enc = tmp_path / "enc"
    src = _plain(tmp_path, 3 * pb.CHUNK + 11)
    pb.encrypt_file(src, enc, key)
    spy.sizes.clear()                                     # only the F7 helpers are measured below
    pb.write_negative_cipher_copy(enc, tmp_path / "t", "tamper")
    pb.write_negative_cipher_copy(enc, tmp_path / "c", "truncation")
    pb.write_partial_restore_copy(src, tmp_path / "p")
    assert spy.sizes, "the spy saw no reads: the test would prove nothing"
    assert all(isinstance(n, int) and 0 < n <= pb.CHUNK for n in spy.sizes), spy.sizes
    # a 3 MiB+ source cannot be copied in fewer than 3 reads if reads are bounded
    assert len(spy.sizes) >= 9


def test_failed_partial_copy_removes_only_its_own_file(tmp_path, monkeypatch):
    src = _plain(tmp_path, 100)
    dst = tmp_path / "partial"
    real_open = open

    class Short(_ReadSpy):
        def read(self, n=-1):                              # source "ends" early: simulates a vanished file
            return b""

    monkeypatch.setattr(pb, "open", lambda *a, **k: Short(real_open(*a, **k)), raising=False)
    with pytest.raises(pb.BackupError, match="PARTIAL_DUMP_SOURCE_TRUNCATED"):
        pb.write_partial_restore_copy(src, dst)
    assert not dst.exists()
    assert src.exists()
