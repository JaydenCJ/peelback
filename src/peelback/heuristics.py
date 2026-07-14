"""Content heuristics shared by detectors and the engine.

Everything in this module is a pure function of bytes: entropy, printability,
UTF-8 validity, JSON shape, magic-byte sniffing, and terminal classification.
These are the signals the engine combines into a confidence score, so they
are deliberately small, deterministic, and unit-tested in isolation.
"""

from __future__ import annotations

import json
import math
import re
from typing import Optional, Tuple

# Printable ASCII plus the whitespace bytes that appear in normal text.
_PRINTABLE_BYTES = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}

# Magic prefixes for common binary containers, checked in order.  The point
# is not to be a full `file(1)` clone — only to label a terminal binary blob
# with something more helpful than "binary".
MAGIC_TYPES: Tuple[Tuple[bytes, str], ...] = (
    (b"\x1f\x8b", "gzip stream"),
    (b"PK\x03\x04", "zip archive"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"%PDF-", "PDF document"),
    (b"\x7fELF", "ELF binary"),
    (b"MZ", "PE/DOS executable"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"\x00asm", "WebAssembly module"),
    (b"BZh", "bzip2 stream"),
    (b"\xfd7zXZ\x00", "xz stream"),
    (b"\x28\xb5\x2f\xfd", "zstd stream"),
    (b"-----BEGIN ", "PEM block"),
)

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# High-entropy threshold in bits per byte.  Random keys, ciphertext and
# signatures sit above ~7.3; text and structured data sit well below.
HIGH_ENTROPY = 7.3


def printable_ratio(data: bytes) -> float:
    """Fraction of bytes that are printable ASCII or common whitespace."""
    if not data:
        return 0.0
    hits = sum(1 for b in data if b in _PRINTABLE_BYTES)
    return hits / len(data)


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 for empty input)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


def is_utf8_text(data: bytes) -> bool:
    """True when the bytes decode as UTF-8 *and* read as text.

    Valid UTF-8 alone is not enough — short random binary often decodes by
    accident — so at least 95% of the decoded characters must be printable
    or whitespace.
    """
    if not data:
        return False
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    ok = sum(1 for ch in text if ch.isprintable() or ch in "\t\n\r ")
    return ok / len(text) >= 0.95


def looks_like_json(data: bytes) -> bool:
    """True when the bytes parse as a JSON object or array.

    Scalars (`5`, `"hi"`, `true`) are technically JSON but classifying every
    number as JSON would be noise, so only containers count.
    """
    stripped = data.strip()
    if not stripped or stripped[0:1] not in (b"{", b"["):
        return False
    try:
        json.loads(stripped)
    except (ValueError, UnicodeDecodeError):
        return False
    return True


def sniff_magic(data: bytes) -> Optional[str]:
    """Return a human label for a known binary container prefix, else None."""
    for prefix, label in MAGIC_TYPES:
        if data.startswith(prefix):
            return label
    return None


def is_uuid(data: bytes) -> bool:
    """True when the bytes are exactly one canonical hyphenated UUID."""
    try:
        text = data.decode("ascii").strip()
    except UnicodeDecodeError:
        return False
    return bool(_UUID_RE.match(text))


def ascii_view(data: bytes) -> Optional[str]:
    """Decode bytes as ASCII for the text-based detectors, or None.

    Every textual encoding peelback understands (base64, hex, percent, JWT)
    is pure ASCII, so a non-ASCII input can skip those detectors entirely.
    """
    try:
        return data.decode("ascii")
    except UnicodeDecodeError:
        return None


def classify_terminal(data: bytes) -> Tuple[str, Optional[str]]:
    """Classify bytes that no detector could peel further.

    Returns ``(kind, detail)`` where *kind* is one of ``empty``, ``json``,
    ``text`` or ``binary`` and *detail* is an optional human note (magic
    type, UUID hint, entropy warning).
    """
    if not data:
        return "empty", None
    if looks_like_json(data):
        return "json", None
    magic = sniff_magic(data)
    if magic is not None:
        return "binary", magic
    if is_utf8_text(data):
        detail = "looks like a UUID" if is_uuid(data) else None
        return "text", detail
    if len(data) >= 16 and shannon_entropy(data) >= HIGH_ENTROPY:
        return "binary", "high entropy — random key, ciphertext, or signature"
    return "binary", None
