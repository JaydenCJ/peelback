"""Layer detectors and the ordered detector registry.

Each detector is a pure function ``(data, ctx) -> Candidate | None``.  It
answers two questions: *can this layer be decoded?* and *how strongly does
the input's shape alone suggest this encoding?*  The second answer is the
``base_confidence``; the engine adds a payload-assessment bonus on top (see
:mod:`peelback.engine`), so a detector never needs to peek more than one
level deep.

Ordering matters only for ties: when two detectors produce the same final
confidence, the earlier one in :data:`REGISTRY` wins, which keeps traces
deterministic.
"""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from . import compression, jwtlayer
from .heuristics import ascii_view, is_uuid


@dataclass
class Context:
    """Per-run knobs a detector may need (currently the bomb-guard cap)."""

    max_bytes: int = 16 * 1024 * 1024


@dataclass
class Child:
    """One decoded product of a layer, with an optional part label."""

    payload: bytes
    label: Optional[str] = None
    notes: List[str] = field(default_factory=list)


@dataclass
class Candidate:
    """A decodable layer proposal made by one detector."""

    detector: str  # registry id, e.g. "base64" (used by --only/--skip)
    encoding: str  # display name, e.g. "base64url" (may be more specific)
    children: List[Child]
    base_confidence: float
    notes: List[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    @property
    def primary_payload(self) -> bytes:
        """The payload the engine assesses for the confidence bonus."""
        return self.children[0].payload


DetectorFn = Callable[[bytes, Context], Optional[Candidate]]

_HEX_BODY_RE = re.compile(r"^[0-9a-fA-F]+$")
_B64_STD_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_B64_URL_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_B32_RE = re.compile(r"^[A-Z2-7]+={0,6}$")
_PCT_ESCAPE_RE = re.compile(r"%[0-9a-fA-F]{2}")
_DATA_URI_RE = re.compile(r"^data:([^,]*),(.*)$", re.DOTALL)


def _strip_ws(text: str) -> Tuple[str, bool]:
    """Remove all whitespace; report whether any was removed."""
    stripped = "".join(text.split())
    return stripped, stripped != text


def detect_jwt(data: bytes, ctx: Context) -> Optional[Candidate]:
    """Compact JWS (peeled fully) or JWE (protected header only)."""
    text = ascii_view(data)
    if text is None or "." not in text:
        return None
    parts = jwtlayer.split_compact(text)
    if parts is None:
        return None
    header = jwtlayer.decode_header(parts[0])
    if header is None:
        return None

    if jwtlayer.looks_like_jws(header, len(parts)):
        try:
            raw_header, payload, signature = jwtlayer.jws_parts(parts)
        except (binascii.Error, ValueError):
            return None
        alg = header.get("alg")
        children = [Child(raw_header, "header")]
        if payload:
            children.append(Child(payload, "payload"))
        else:
            children.append(Child(b"", "payload", notes=["detached payload (empty segment)"]))
        sig_notes = [] if signature else ["empty signature — unsigned token"]
        children.append(Child(signature, "signature", notes=sig_notes))
        notes = [f"alg={alg}" if alg else "no alg in header"]
        return Candidate("jwt", "jwt", children, 0.97, notes, meta={"alg": alg})

    if jwtlayer.looks_like_jwe(header, len(parts)):
        try:
            raw_header = jwtlayer.b64url_decode(parts[0])
        except (binascii.Error, ValueError):
            return None
        notes = [
            f"alg={header.get('alg')} enc={header.get('enc')}",
            "JWE: 4 encrypted segments not peeled (key required)",
        ]
        return Candidate(
            "jwt", "jwe", [Child(raw_header, "protected header")], 0.95, notes,
            meta={"alg": header.get("alg"), "enc": header.get("enc")},
        )
    return None


def detect_data_uri(data: bytes, ctx: Context) -> Optional[Candidate]:
    """RFC 2397 ``data:`` URI — base64 or percent-encoded body."""
    text = ascii_view(data)
    if text is None:
        return None
    match = _DATA_URI_RE.match(text.strip())
    if match is None:
        return None
    mediatype, body = match.group(1), match.group(2)
    notes = [f"media type: {mediatype.split(';')[0] or 'text/plain'}"]
    if mediatype.endswith(";base64"):
        try:
            payload = base64.b64decode(_strip_ws(body)[0], validate=True)
        except (binascii.Error, ValueError):
            return None
        notes.append("base64 body")
    else:
        payload = urllib.parse.unquote_to_bytes(body)
    return Candidate("data-uri", "data-uri", [Child(payload)], 0.95, notes)


def detect_gzip(data: bytes, ctx: Context) -> Optional[Candidate]:
    """gzip member — magic bytes make this near-certain when it inflates."""
    result = compression.try_gzip(data, ctx.max_bytes)
    if result is None:
        return None
    payload, notes = result
    return Candidate("gzip", "gzip", [Child(payload)], 0.97, notes)


def detect_zlib(data: bytes, ctx: Context) -> Optional[Candidate]:
    """zlib stream — weak 2-byte header, so it leans on the payload bonus."""
    result = compression.try_zlib(data, ctx.max_bytes)
    if result is None:
        return None
    payload, notes = result
    return Candidate("zlib", "zlib", [Child(payload)], 0.72, notes)


def detect_url(data: bytes, ctx: Context) -> Optional[Candidate]:
    """Percent-encoding (URL escapes).  Fires only on real ``%XX`` escapes."""
    text = ascii_view(data)
    if text is None:
        return None
    escapes = _PCT_ESCAPE_RE.findall(text)
    if not escapes:
        return None
    payload = urllib.parse.unquote_to_bytes(text)
    if payload == data:
        return None
    confidence = 0.60 + min(0.25, 0.05 * len(escapes))
    notes = [f"{len(escapes)} percent escape(s)"]
    return Candidate("url", "url-encoding", [Child(payload)], confidence, notes)


def detect_hex(data: bytes, ctx: Context) -> Optional[Candidate]:
    """Hexadecimal, tolerating ``0x`` prefixes and ``:``/whitespace separators."""
    text = ascii_view(data)
    if text is None:
        return None
    body = text.strip()
    notes: List[str] = []
    had_prefix = body[:2].lower() == "0x"
    if had_prefix:
        body = body[2:]
    cleaned = re.sub(r"[\s:]+", "", body)
    if cleaned != body:
        notes.append("separators stripped")
    if len(cleaned) < 8 or len(cleaned) % 2 != 0 or not _HEX_BODY_RE.match(cleaned):
        return None
    payload = bytes.fromhex(cleaned)

    confidence = 0.55
    if had_prefix:
        confidence += 0.20
        notes.append("0x prefix")
    if len(cleaned) >= 16:
        confidence += 0.05
    if cleaned.isdigit():
        confidence -= 0.25  # all-digit strings are usually numeric ids
        notes.append("all digits — may be a plain number")
    elif any(c.islower() for c in cleaned) and any(c.isupper() for c in cleaned):
        confidence -= 0.15  # mixed-case hex is rare in the wild
    return Candidate("hex", "hex", [Child(payload)], confidence, notes)


def detect_base64(data: bytes, ctx: Context) -> Optional[Candidate]:
    """base64 (standard and URL-safe alphabets, padded or not)."""
    text = ascii_view(data)
    if text is None:
        return None
    body, had_ws = _strip_ws(text)
    if len(body) < 8 or len(body.rstrip("=")) % 4 == 1:
        return None

    urlsafe = ("-" in body) or ("_" in body)
    standard = ("+" in body) or ("/" in body)
    if urlsafe and standard:
        return None  # mixed alphabets can never be one base64 string
    regex = _B64_URL_RE if urlsafe else _B64_STD_RE
    if not regex.match(body):
        return None

    if is_uuid(body.encode("ascii")):
        # A canonical UUID is valid base64url by charset, but decoding one
        # is never what the user meant.
        return None

    has_pad = "=" in body
    if not has_pad and not urlsafe and not standard and len(body) < 16:
        # A short bare-alphanumeric string is indistinguishable from an
        # ordinary word or identifier; refusing here is what keeps
        # `peelback hello` from "decoding" English.
        return None

    stripped = body.rstrip("=")
    padded = stripped + "=" * (-len(stripped) % 4)
    decoder = base64.urlsafe_b64decode if urlsafe else base64.b64decode
    try:
        payload = decoder(padded)
    except (binascii.Error, ValueError):
        return None
    if not payload:
        return None

    confidence = 0.50
    notes: List[str] = []
    if had_ws:
        notes.append("embedded whitespace ignored")
    if has_pad and len(body) % 4 == 0:
        confidence += 0.15  # correct explicit padding is a strong tell
    if urlsafe or standard:
        confidence += 0.10  # alphabet-specific characters present
    elif not has_pad:
        confidence -= 0.05  # bare alphanumerics: word-shaped, be careful
    if len(body) >= 24:
        confidence += 0.05
    if any(c.islower() for c in body) and any(c.isupper() for c in body):
        confidence += 0.05  # mixed case is typical of base64, rare in words
    if _HEX_BODY_RE.match(body):
        confidence -= 0.20  # pure-hex charset: let the hex detector win
        notes.append("also a valid hex string")
    if body.isdigit():
        confidence -= 0.20
    encoding = "base64url" if urlsafe else "base64"
    return Candidate("base64", encoding, [Child(payload)], confidence, notes)


def detect_base32(data: bytes, ctx: Context) -> Optional[Candidate]:
    """base32 (RFC 4648 upper-case alphabet).  Deliberately timid: its
    alphabet is a subset of base64's, so it must earn its place through the
    payload-assessment bonus."""
    text = ascii_view(data)
    if text is None:
        return None
    body, _ = _strip_ws(text)
    if len(body) < 8 or len(body) % 8 != 0 or not _B32_RE.match(body):
        return None
    try:
        payload = base64.b32decode(body)
    except (binascii.Error, ValueError):
        return None
    if not payload:
        return None
    confidence = 0.42
    if "=" in body:
        confidence += 0.10
    return Candidate("base32", "base32", [Child(payload)], confidence)


#: The ordered registry.  Position breaks confidence ties, so the most
#: structurally specific detectors come first.
REGISTRY: Tuple[Tuple[str, DetectorFn], ...] = (
    ("jwt", detect_jwt),
    ("data-uri", detect_data_uri),
    ("gzip", detect_gzip),
    ("zlib", detect_zlib),
    ("url", detect_url),
    ("hex", detect_hex),
    ("base64", detect_base64),
    ("base32", detect_base32),
)

DETECTOR_IDS: Tuple[str, ...] = tuple(name for name, _ in REGISTRY)

#: One-line description per detector id, used by ``peelback --list-detectors``.
DETECTOR_HELP: Tuple[Tuple[str, str], ...] = (
    ("jwt", "compact JWS (header/payload/signature) and JWE protected headers"),
    ("data-uri", "RFC 2397 data: URIs with base64 or percent-encoded bodies"),
    ("gzip", "gzip members (RFC 1952), bomb-guarded"),
    ("zlib", "zlib streams (RFC 1950), bomb-guarded"),
    ("url", "percent-encoding (%XX escapes)"),
    ("hex", "hexadecimal, with 0x prefixes and :/whitespace separators"),
    ("base64", "base64 and base64url, padded or unpadded"),
    ("base32", "base32 (RFC 4648 upper-case alphabet)"),
)
