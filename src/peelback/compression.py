"""gzip and zlib layers with a decompression-bomb guard.

Both decoders stream through :class:`zlib.decompressobj` with a hard output
cap, so a 100-byte token that inflates to gigabytes raises
:class:`~peelback.errors.CapExceeded` instead of exhausting memory.  The
engine catches that and records a note on the node.
"""

from __future__ import annotations

from typing import List, Optional, Tuple
import zlib

from .errors import CapExceeded

GZIP_MAGIC = b"\x1f\x8b"


def _bounded_decompress(data: bytes, wbits: int, cap: int, encoding: str) -> Tuple[bytes, bytes]:
    """Decompress with an output cap; return (payload, trailing bytes).

    Raises :class:`CapExceeded` when the stream would inflate past *cap*,
    and :class:`zlib.error` (propagated to the caller) on corrupt input.
    A truncated stream (no end-of-stream marker) is reported as zlib.error.
    """
    obj = zlib.decompressobj(wbits)
    payload = obj.decompress(data, cap + 1)
    if len(payload) > cap:
        raise CapExceeded(encoding, cap)
    if not obj.eof:
        # The whole input was consumed but the stream never finished:
        # truncated or not actually a complete stream.
        raise zlib.error("incomplete stream")
    return payload, obj.unused_data


def try_gzip(data: bytes, cap: int) -> Optional[Tuple[bytes, List[str]]]:
    """Decode one gzip member, or None when the input is not gzip.

    Returns ``(payload, notes)``.  Trailing bytes after the gzip member are
    tolerated and reported in the notes, because tokens are often built by
    concatenating a compressed body with a checksum or signature.
    """
    if not data.startswith(GZIP_MAGIC) or len(data) < 18:
        # 18 bytes is the size of the smallest valid gzip member.
        return None
    try:
        payload, trailing = _bounded_decompress(data, 16 + zlib.MAX_WBITS, cap, "gzip")
    except zlib.error:
        return None
    notes: List[str] = []
    if trailing:
        notes.append(f"{len(trailing)} trailing byte(s) after gzip stream ignored")
    return payload, notes


def _zlib_header_ok(data: bytes) -> bool:
    """RFC 1950 header check: deflate method, window bits, header checksum."""
    if len(data) < 2:
        return False
    cmf, flg = data[0], data[1]
    if cmf & 0x0F != 8:  # compression method must be deflate
        return False
    if (cmf >> 4) > 7:  # window size beyond 32 KiB is invalid
        return False
    return (cmf * 256 + flg) % 31 == 0


def try_zlib(data: bytes, cap: int) -> Optional[Tuple[bytes, List[str]]]:
    """Decode one zlib (RFC 1950) stream, or None when it is not zlib.

    The two-byte header is weak evidence on its own — plenty of binary
    blobs start with ``0x78`` — so callers should combine this with an
    assessment of the decompressed payload before trusting it.
    """
    if not _zlib_header_ok(data):
        return None
    try:
        payload, trailing = _bounded_decompress(data, zlib.MAX_WBITS, cap, "zlib")
    except zlib.error:
        return None
    notes: List[str] = []
    if trailing:
        notes.append(f"{len(trailing)} trailing byte(s) after zlib stream ignored")
    return payload, notes
