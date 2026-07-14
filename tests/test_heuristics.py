"""Unit tests for the content heuristics.

These signals feed the engine's confidence scoring, so each one is pinned
down in isolation: a heuristic that drifts moves every detection decision.
"""

from __future__ import annotations

import json

from peelback import heuristics


class TestPrintableRatio:
    def test_extremes_empty_input_and_proportionality(self):
        assert heuristics.printable_ratio(b"hello, world\n") == 1.0
        assert heuristics.printable_ratio(bytes([0, 1, 2, 3, 255])) == 0.0
        assert heuristics.printable_ratio(b"") == 0.0  # never a ZeroDivisionError
        # 8 printable + 8 control bytes → exactly one half.
        assert heuristics.printable_ratio(b"ABCDEFGH" + bytes(8)) == 0.5


class TestEntropy:
    def test_constant_and_uniform_extremes(self):
        assert heuristics.shannon_entropy(b"\x00" * 64) == 0.0
        assert heuristics.shannon_entropy(bytes(range(256))) == 8.0
        assert heuristics.shannon_entropy(b"") == 0.0

    def test_english_text_sits_well_below_the_random_threshold(self):
        text = b"the quick brown fox jumps over the lazy dog" * 4
        assert heuristics.shannon_entropy(text) < heuristics.HIGH_ENTROPY


class TestUtf8Text:
    def test_ascii_and_multibyte_utf8_are_text(self):
        assert heuristics.is_utf8_text(b"session expired, please log in")
        assert heuristics.is_utf8_text("こんにちは世界".encode("utf-8"))

    def test_invalid_utf8_and_control_soup_are_not_text(self):
        assert not heuristics.is_utf8_text(b"\xff\xfe\x00\x01")
        # Decodes fine, but reads as garbage — must not count as text.
        assert not heuristics.is_utf8_text(bytes(range(0, 32)) * 4)


class TestJsonDetection:
    def test_containers_count_even_with_leading_whitespace(self):
        assert heuristics.looks_like_json(b'{"a": 1}')
        assert heuristics.looks_like_json(b"[1, 2, 3]")
        assert heuristics.looks_like_json(b'  \n {"a": 1}')

    def test_scalars_and_malformed_json_do_not_count(self):
        # `5` parses as JSON, but calling every number JSON would be noise.
        assert not heuristics.looks_like_json(b"5")
        assert not heuristics.looks_like_json(b'"hi"')
        assert not heuristics.looks_like_json(b'{"a": }')


class TestMagicSniffing:
    def test_known_prefixes_are_labelled_and_unknown_is_none(self):
        assert heuristics.sniff_magic(b"\x1f\x8b\x08rest") == "gzip stream"
        assert heuristics.sniff_magic(b"\x89PNG\r\n\x1a\nrest") == "PNG image"
        assert heuristics.sniff_magic(b"%PDF-1.7 blah") == "PDF document"
        assert heuristics.sniff_magic(b"\x00\x00\x00\x00") is None


class TestTerminalClassification:
    def test_empty_json_and_text_kinds(self):
        assert heuristics.classify_terminal(b"") == ("empty", None)
        payload = json.dumps({"k": "v"}).encode()
        assert heuristics.classify_terminal(payload) == ("json", None)
        kind, detail = heuristics.classify_terminal(
            b"550e8400-e29b-41d4-a716-446655440000"
        )
        assert (kind, detail) == ("text", "looks like a UUID")

    def test_binary_kinds_get_magic_names_or_entropy_warnings(self):
        kind, detail = heuristics.classify_terminal(b"\x7fELF\x02\x01\x01" + bytes(16))
        assert (kind, detail) == ("binary", "ELF binary")
        kind, detail = heuristics.classify_terminal(bytes(range(255, 0, -1)))
        assert kind == "binary"
        assert detail is not None and "high entropy" in detail
