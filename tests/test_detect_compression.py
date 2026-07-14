"""Tests for the gzip/zlib layers, including the decompression-bomb guard.

A hostile token must never be able to inflate its way into an OOM: the cap
raises `CapExceeded`, and the engine (tested in test_engine.py) turns that
into a note instead of a crash.
"""

from __future__ import annotations

import zlib

import pytest

from peelback.compression import try_gzip, try_zlib
from peelback.errors import CapExceeded
from tokens import gz

CAP = 1 << 20  # 1 MiB is plenty for these tests


class TestGzip:
    def test_round_trip(self):
        result = try_gzip(gz(b'{"session": "9f8a"}'), CAP)
        assert result is not None
        payload, notes = result
        assert payload == b'{"session": "9f8a"}'
        assert notes == []

    def test_non_gzip_and_magic_only_inputs_are_rejected(self):
        assert try_gzip(b"definitely not gzip", CAP) is None
        # Correct magic, garbage body: must be rejected, not half-decoded.
        assert try_gzip(b"\x1f\x8b" + b"\x00" * 30, CAP) is None

    def test_truncated_stream_is_rejected(self):
        blob = gz(b"x" * 4096)
        assert try_gzip(blob[: len(blob) // 2], CAP) is None

    def test_trailing_bytes_are_tolerated_and_noted(self):
        blob = gz(b"payload") + b"SIGNATUREBYTES"
        result = try_gzip(blob, CAP)
        assert result is not None
        payload, notes = result
        assert payload == b"payload"
        assert any("trailing" in note for note in notes)

    def test_bomb_is_stopped_by_the_cap_but_exactly_at_cap_is_allowed(self):
        bomb = gz(b"\x00" * (CAP * 4))  # tiny input, 4 MiB output
        assert len(bomb) < 8192  # the premise: it really is a bomb
        with pytest.raises(CapExceeded) as excinfo:
            try_gzip(bomb, CAP)
        assert excinfo.value.encoding == "gzip"
        assert excinfo.value.cap == CAP
        # The boundary itself is legal: exactly CAP bytes must decode.
        at_cap = b"\x00" * CAP
        result = try_gzip(gz(at_cap), CAP)
        assert result is not None
        assert result[0] == at_cap


class TestZlib:
    def test_round_trip(self):
        result = try_zlib(zlib.compress(b'{"ok": true}'), CAP)
        assert result is not None
        assert result[0] == b'{"ok": true}'

    def test_header_lookalikes_and_corrupt_bodies_are_rejected(self):
        # 0x78 0x00 fails the RFC 1950 (cmf*256+flg) % 31 check.
        assert try_zlib(b"\x78\x00" + b"data", CAP) is None
        blob = zlib.compress(b"hello hello hello")
        corrupted = blob[:4] + b"\xff\xff\xff\xff" + blob[8:]
        assert try_zlib(corrupted, CAP) is None

    def test_bomb_is_stopped_by_the_cap(self):
        bomb = zlib.compress(b"\x00" * (CAP * 4))
        with pytest.raises(CapExceeded):
            try_zlib(bomb, CAP)
