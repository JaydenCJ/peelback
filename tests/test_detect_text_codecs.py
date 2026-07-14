"""Detector-level tests for the textual codecs: base64, hex, URL, base32,
and data: URIs.

Each detector is called directly so its base-confidence logic is tested
without the engine's assessment bonus on top; the split is what makes the
scoring model debuggable.
"""

from __future__ import annotations

import base64

from peelback.detectors import (
    Context,
    detect_base32,
    detect_base64,
    detect_data_uri,
    detect_hex,
    detect_url,
)

CTX = Context()


class TestBase64:
    def test_standard_padded_base64_decodes_and_padding_boosts_confidence(self):
        padded = detect_base64(b"aGVsbG8gd29ybGQ=", CTX)
        assert padded is not None
        assert padded.encoding == "base64"
        assert padded.primary_payload == b"hello world"
        bare = detect_base64(b"aGVsbG8gd29ybGRz", CTX)  # same length, no '='
        assert bare is not None
        assert padded.base_confidence > bare.base_confidence

    def test_urlsafe_alphabet_is_recognized_and_labelled(self):
        raw = bytes([0xFB, 0xEF, 0xFF, 0x01, 0x02])
        token = base64.urlsafe_b64encode(raw).decode()
        assert "-" in token or "_" in token  # the test premise
        cand = detect_base64(token.encode(), CTX)
        assert cand is not None
        assert cand.encoding == "base64url"
        assert cand.primary_payload == raw

    def test_unpadded_and_line_wrapped_inputs_are_repaired(self):
        token = base64.b64encode(b"a much longer payload").decode().rstrip("=")
        cand = detect_base64(token.encode(), CTX)
        assert cand is not None
        assert cand.primary_payload == b"a much longer payload"

        wrapped_src = base64.b64encode(b"a longer payload that wraps").decode()
        wrapped = "\n".join([wrapped_src[:12], wrapped_src[12:24], wrapped_src[24:]])
        cand = detect_base64(wrapped.encode(), CTX)
        assert cand is not None
        assert cand.primary_payload == b"a longer payload that wraps"
        assert any("whitespace" in note for note in cand.notes)

    def test_structural_refusals(self):
        # Mixed alphabets can never be one base64 string.
        assert detect_base64(b"abc+def_ghi=", CTX) is None
        # Length ≡ 1 (mod 4) is never valid base64.
        assert detect_base64(b"aGVsbG8gd", CTX) is None
        # "peelback" is charset-valid; decoding a bare short word is nonsense.
        assert detect_base64(b"peelback", CTX) is None
        # A UUID is charset-valid base64url; decoding one is never intended.
        assert detect_base64(b"550e8400-e29b-41d4-a716-446655440000", CTX) is None

    def test_pure_hex_charset_is_penalized_below_the_hex_detector(self):
        # 32 hex chars are also valid base64; hex must win the tie.
        token = b"6465616462656566646561646265656b"
        b64 = detect_base64(token, CTX)
        hexc = detect_hex(token, CTX)
        assert b64 is not None and hexc is not None
        assert hexc.base_confidence > b64.base_confidence
        assert any("hex" in note for note in b64.notes)


class TestHex:
    def test_plain_hex_and_colon_separated_fingerprints_decode(self):
        cand = detect_hex(b"7b226f6b223a747275657d", CTX)
        assert cand is not None
        assert cand.primary_payload == b'{"ok":true}'

        cand = detect_hex(b"de:ad:be:ef:ca:fe", CTX)
        assert cand is not None
        assert cand.primary_payload == b"\xde\xad\xbe\xef\xca\xfe"
        assert any("separators" in note for note in cand.notes)

    def test_0x_prefix_boosts_and_all_digits_penalizes(self):
        bare = detect_hex(b"deadbeefcafe", CTX)
        prefixed = detect_hex(b"0xdeadbeefcafe", CTX)
        assert bare is not None and prefixed is not None
        assert prefixed.primary_payload == bare.primary_payload
        assert prefixed.base_confidence > bare.base_confidence

        digits = detect_hex(b"1234567812345678", CTX)
        lettered = detect_hex(b"12345678deadbeef", CTX)
        assert digits is not None and lettered is not None
        assert digits.base_confidence < lettered.base_confidence

    def test_rejections(self):
        assert detect_hex(b"deadbeefc", CTX) is None  # odd length
        assert detect_hex(b"cafe", CTX) is None  # words before hex
        assert detect_hex(b"deadbeefzz", CTX) is None  # non-hex chars


class TestUrl:
    def test_percent_escapes_decode_and_more_escapes_mean_more_confidence(self):
        one = detect_url(b"a%20b%3Dc", CTX)
        assert one is not None
        assert one.primary_payload == b"a b=c"
        many = detect_url(b"%7B%22a%22%3A%201%7D", CTX)
        assert many is not None
        assert many.base_confidence > one.base_confidence

    def test_no_valid_escape_means_no_candidate(self):
        assert detect_url(b"plain-text-no-escapes", CTX) is None
        assert detect_url(b"100% organic", CTX) is None


class TestBase32:
    def test_valid_base32_decodes_but_stays_below_the_default_threshold(self):
        token = base64.b32encode(b"hello base32 layer").decode()
        cand = detect_base32(token.encode(), CTX)
        assert cand is not None
        assert cand.primary_payload == b"hello base32 layer"
        # base32's alphabet is a subset of base64's, so it must never win
        # on shape alone — only with the engine's payload bonus.
        assert cand.base_confidence < 0.55

    def test_rejections(self):
        lower = base64.b32encode(b"hello base32 layer").decode().lower()
        assert detect_base32(lower.encode(), CTX) is None
        assert detect_base32(b"MZXW6YTB1", CTX) is None  # bad block length


class TestDataUri:
    def test_base64_and_percent_bodies_decode(self):
        token = b"data:application/json;base64," + base64.b64encode(b'{"a":1}')
        cand = detect_data_uri(token, CTX)
        assert cand is not None
        assert cand.primary_payload == b'{"a":1}'
        assert any("application/json" in note for note in cand.notes)

        cand = detect_data_uri(b"data:,Hello%2C%20World%21", CTX)
        assert cand is not None
        assert cand.primary_payload == b"Hello, World!"

    def test_rejections(self):
        assert detect_data_uri(b"data:text/plain;base64", CTX) is None  # no comma
        assert detect_data_uri(b"data:text/plain;base64,!!!!", CTX) is None


def test_everyday_strings_produce_no_text_codec_candidates():
    """The false-positive gauntlet: none of these should tempt any codec."""
    probes = [b"hello world", b"peelback", b"1.2.3-beta", b"user@example.test"]
    for probe in probes:
        for detector in (detect_base64, detect_hex, detect_url, detect_base32):
            assert detector(probe, CTX) is None, (probe, detector.__name__)
