"""JWT and JWE structural peeling plus registered-claim annotation.

A JWT is not one encoding layer — it is three base64url segments with JSON
inside two of them.  This module splits a compact JWS/JWE, decodes what can
be decoded without keys, and annotates RFC 7519 registered claims with
human-readable timestamps and expiry state.  No signature verification is
performed and none is claimed; peelback shows structure, it does not vouch
for authenticity.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_-]*$")

#: RFC 7519 registered claim names → human labels.
REGISTERED_CLAIMS: Dict[str, str] = {
    "iss": "issuer",
    "sub": "subject",
    "aud": "audience",
    "exp": "expires at",
    "nbf": "not valid before",
    "iat": "issued at",
    "jti": "token id",
}

_TIME_CLAIMS = ("exp", "nbf", "iat")


def b64url_decode(segment: str) -> bytes:
    """Decode one unpadded base64url segment (padding tolerated)."""
    stripped = segment.rstrip("=")
    pad = -len(stripped) % 4
    if pad == 3:
        raise binascii.Error("invalid base64url length")
    return base64.urlsafe_b64decode(stripped + "=" * pad)


def split_compact(text: str) -> Optional[List[str]]:
    """Split a compact JWS (3 segments) or JWE (5 segments), else None.

    Segments must be base64url charset; only the JWS payload and signature
    may be empty (detached-content JWS, ``alg=none`` tokens).
    """
    parts = text.strip().split(".")
    if len(parts) not in (3, 5):
        return None
    if not parts[0]:  # the protected header is never empty
        return None
    if any(not _SEGMENT_RE.match(p.rstrip("=")) for p in parts):
        return None
    return parts


def decode_header(segment: str) -> Optional[Dict[str, Any]]:
    """Decode a protected header segment into a JSON object, else None."""
    try:
        raw = b64url_decode(segment)
        header = json.loads(raw)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(header, dict):
        return None
    return header


def looks_like_jws(header: Dict[str, Any], n_parts: int) -> bool:
    """A 3-part token whose header carries ``alg`` or ``typ`` is a JWS."""
    return n_parts == 3 and ("alg" in header or "typ" in header)


def looks_like_jwe(header: Dict[str, Any], n_parts: int) -> bool:
    """A 5-part token is a JWE only when the header names an ``enc``."""
    return n_parts == 5 and "enc" in header


def _format_epoch(value: float) -> str:
    """Render a Unix timestamp as compact UTC ISO-8601."""
    dt = datetime.fromtimestamp(value, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _humanize_delta(seconds: float) -> str:
    """Turn a positive number of seconds into '3d', '2h', '45m' or '30s'."""
    seconds = abs(seconds)
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size:
            return f"{int(seconds // size)}{unit}"
    return f"{int(seconds)}s"


def annotate_claims(claims: Dict[str, Any], now: Optional[float] = None) -> List[str]:
    """Produce one annotation line per registered claim found.

    *now* is injectable so callers (and tests) get deterministic expiry
    judgments; when omitted the time-relative suffixes are skipped and only
    absolute ISO timestamps are shown.
    """
    lines: List[str] = []
    for name, label in REGISTERED_CLAIMS.items():
        if name not in claims:
            continue
        value = claims[name]
        if name in _TIME_CLAIMS and isinstance(value, (int, float)) and not isinstance(value, bool):
            rendered = f"{name} ({label}): {value} → {_format_epoch(value)}"
            if now is not None:
                delta = value - now
                if name == "exp":
                    state = f"expires in {_humanize_delta(delta)}" if delta > 0 else f"EXPIRED {_humanize_delta(delta)} ago"
                    rendered += f"  [{state}]"
                elif name == "nbf" and delta > 0:
                    rendered += f"  [not valid for another {_humanize_delta(delta)}]"
                elif name == "iat":
                    rendered += f"  [{_humanize_delta(delta)} ago]" if delta <= 0 else "  [issued in the future]"
            lines.append(rendered)
        else:
            lines.append(f"{name} ({label}): {json.dumps(value, ensure_ascii=False)}")
    return lines


def claims_from_payload(payload: bytes) -> Optional[Dict[str, Any]]:
    """Parse a JWS payload as a claims object, else None (non-JSON payloads
    are legal in JWS — the payload can be anything)."""
    try:
        claims = json.loads(payload)
    except (ValueError, UnicodeDecodeError):
        return None
    return claims if isinstance(claims, dict) else None


def jws_parts(parts: List[str]) -> Tuple[bytes, bytes, bytes]:
    """Decode the three JWS segments to raw bytes (header, payload, sig)."""
    return b64url_decode(parts[0]), b64url_decode(parts[1]), b64url_decode(parts[2])
