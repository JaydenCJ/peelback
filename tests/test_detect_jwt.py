"""Tests for JWT/JWE structural peeling and claim annotation.

peelback treats a JWT as a branching layer: one decode step that yields a
header, a payload, and a signature.  These tests pin the split logic, the
JWE header-only behavior, and the deterministic claim annotations.
"""

from __future__ import annotations

import json

from peelback.detectors import Context, detect_jwt
from peelback.jwtlayer import annotate_claims, b64url_decode, split_compact
from tokens import EXP_FUTURE, EXP_PAST, IAT, b64u, make_jwe, make_jws, make_unsigned_jws

CTX = Context()


class TestJwsDetection:
    def test_real_hs256_token_splits_into_three_labelled_parts(self):
        cand = detect_jwt(make_jws().encode(), CTX)
        assert cand is not None
        assert cand.encoding == "jwt"
        assert [child.label for child in cand.children] == [
            "header",
            "payload",
            "signature",
        ]
        assert cand.meta["alg"] == "HS256"
        assert any("alg=HS256" in note for note in cand.notes)

    def test_header_and_payload_decode_to_the_original_json(self):
        claims = {"sub": "user-1", "iat": IAT}
        cand = detect_jwt(make_jws(claims=claims).encode(), CTX)
        assert cand is not None
        assert json.loads(cand.children[0].payload) == {"alg": "HS256", "typ": "JWT"}
        assert json.loads(cand.children[1].payload) == claims

    def test_signature_bytes_survive_untouched(self):
        token = make_jws()
        cand = detect_jwt(token.encode(), CTX)
        assert cand is not None
        expected = b64url_decode(token.rsplit(".", 1)[1])
        assert cand.children[2].payload == expected
        assert len(cand.children[2].payload) == 32  # HS256 → 32-byte MAC

    def test_alg_none_token_notes_the_empty_signature(self):
        cand = detect_jwt(make_unsigned_jws().encode(), CTX)
        assert cand is not None
        assert cand.children[2].payload == b""
        assert any("unsigned" in note for note in cand.children[2].notes)

    def test_rejections_shape_alone_is_never_enough(self):
        # Two dots but a non-JSON header.
        assert detect_jwt(b"notjson.payload.signature", CTX) is None
        # Valid JSON header, but neither alg nor typ.
        header = b64u(json.dumps({"foo": "bar"}).encode())
        token = f"{header}.{b64u(b'{}')}.{b64u(b'sig')}"
        assert detect_jwt(token.encode(), CTX) is None
        # Wrong segment counts.
        assert detect_jwt(b"a.b", CTX) is None
        assert detect_jwt(b"a.b.c.d", CTX) is None
        # "1.2.3" has two dots; the header gate must reject version strings.
        assert detect_jwt(b"1.2.3", CTX) is None


class TestJweDetection:
    def test_only_the_protected_header_is_peeled_and_the_rest_is_explained(self):
        cand = detect_jwt(make_jwe().encode(), CTX)
        assert cand is not None
        assert cand.encoding == "jwe"
        assert cand.meta == {"alg": "RSA-OAEP", "enc": "A256GCM"}
        assert len(cand.children) == 1
        assert cand.children[0].label == "protected header"
        assert json.loads(cand.children[0].payload)["enc"] == "A256GCM"
        assert any("key required" in note for note in cand.notes)

    def test_five_segments_without_enc_is_not_a_jwe(self):
        header = b64u(json.dumps({"alg": "HS256"}).encode())
        token = ".".join([header, "AA", "BB", "CC", "DD"])
        assert detect_jwt(token.encode(), CTX) is None


class TestSplitCompact:
    def test_padding_is_tolerated_and_bad_shapes_are_rejected(self):
        assert split_compact("eyJhIjox.eyJiIjoy.c2ln") is not None
        assert split_compact("eyJhIjox==.eyJiIjoy.c2ln") is not None
        assert split_compact(".payload.sig") is None  # empty header
        assert split_compact("a+b.c.d") is None  # invalid charset


class TestClaimAnnotation:
    def test_time_claims_get_iso_timestamps(self):
        lines = annotate_claims({"iat": IAT})
        assert lines == [f"iat (issued at): {IAT} → 2023-11-14T22:13:20Z"]

    def test_expiry_judgments_are_deterministic_given_now(self):
        future = annotate_claims({"exp": EXP_FUTURE}, now=float(EXP_FUTURE - 86400 * 2))
        assert len(future) == 1 and "expires in 2d" in future[0]
        past = annotate_claims({"exp": EXP_PAST}, now=float(EXP_PAST + 3600 * 5))
        assert "EXPIRED 5h ago" in past[0]
        nbf = annotate_claims({"nbf": IAT}, now=float(IAT - 90 * 60))
        assert "not valid for another 1h" in nbf[0]
        # Without an injected now, no relative judgment is made at all.
        bare = annotate_claims({"exp": EXP_PAST})
        assert "EXPIRED" not in bare[0]
        assert "2001-09-09T01:46:40Z" in bare[0]

    def test_odd_claim_values_are_rendered_not_crashed(self):
        # A string exp is rendered verbatim, not treated as a timestamp.
        assert annotate_claims({"exp": "tomorrow"}, now=0.0) == [
            'exp (expires at): "tomorrow"'
        ]
        # Registered string claims get their labels.
        lines = annotate_claims({"iss": "https://auth.example.test", "sub": "u1"})
        assert 'iss (issuer): "https://auth.example.test"' in lines
        assert 'sub (subject): "u1"' in lines
        # Unregistered claims are ignored by the annotator.
        assert annotate_claims({"scope": "read", "custom": 1}) == []
