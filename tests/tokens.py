"""Deterministic token builders shared by the peelback test suite.

Every helper is reproducible bit-for-bit: fixed keys, fixed timestamps,
gzip with ``mtime=0``.  Nothing here touches the network or the wall clock.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import json
from typing import Any, Dict, Optional

#: Fixed timestamps used across the suite (both far from "now" in either
#: direction, so expiry-state assertions can never flake).
IAT = 1700000000  # 2023-11-14T22:13:20Z
EXP_FUTURE = 32503680000  # 3000-01-01T00:00:00Z
EXP_PAST = 1000000000  # 2001-09-09T01:46:40Z


def b64u(data: bytes) -> str:
    """Unpadded base64url, the JWT segment encoding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def compact_json(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def make_jws(
    claims: Optional[Dict[str, Any]] = None,
    header: Optional[Dict[str, Any]] = None,
    key: bytes = b"test-secret",
) -> str:
    """A real HS256-signed compact JWS with deterministic content."""
    if header is None:
        header = {"alg": "HS256", "typ": "JWT"}
    if claims is None:
        claims = {
            "iss": "https://auth.example.test",
            "sub": "user-4821",
            "iat": IAT,
            "exp": EXP_FUTURE,
        }
    signing_input = f"{b64u(compact_json(header))}.{b64u(compact_json(claims))}"
    signature = hmac.new(key, signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{b64u(signature)}"


def make_unsigned_jws(claims: Optional[Dict[str, Any]] = None) -> str:
    """An ``alg=none`` token: valid structure, empty signature segment."""
    header = {"alg": "none"}
    if claims is None:
        claims = {"sub": "anonymous"}
    return f"{b64u(compact_json(header))}.{b64u(compact_json(claims))}."


def make_jwe() -> str:
    """A structurally valid five-segment JWE (ciphertext is dummy bytes)."""
    header = {"alg": "RSA-OAEP", "enc": "A256GCM"}
    parts = [
        b64u(compact_json(header)),
        b64u(b"\x01" * 32),  # encrypted key
        b64u(b"\x02" * 12),  # IV
        b64u(b"\x03" * 48),  # ciphertext
        b64u(b"\x04" * 16),  # tag
    ]
    return ".".join(parts)


def gz(data: bytes) -> bytes:
    """gzip with a zeroed mtime so output bytes are reproducible."""
    return gzip.compress(data, mtime=0)
