"""End-to-end engine tests: multi-layer chains, guards, and options.

These are the tests that prove the tagline — realistic nested tokens peel
all the way down, and inputs that merely *look* encoded do not.
"""

from __future__ import annotations

import base64
import json
import urllib.parse
import zlib

import pytest

from peelback import InputError, peel
from tokens import gz, make_jws


def encodings_path(result):
    """The chain of encodings along the first-child spine."""
    chain = []
    node = result.root
    while node.children:
        node = node.children[0]
        chain.append(node.encoding)
    return chain


class TestChains:
    def test_base64_gzip_json_peels_fully(self, sample_json):
        token = base64.b64encode(gz(sample_json)).decode()
        result = peel(token)
        assert encodings_path(result) == ["base64", "gzip"]
        assert result.layers_peeled == 2
        _, leaf = result.deepest_leaf()
        assert json.loads(leaf.data) == json.loads(sample_json)
        assert leaf.terminal == "json"

    def test_url_base64_gzip_json_the_cookie_from_hell(self, sample_json):
        token = urllib.parse.quote(
            base64.urlsafe_b64encode(gz(sample_json)).decode(), safe=""
        )
        result = peel(token)
        assert result.layers_peeled == 3
        assert result.deepest_leaf()[1].data == sample_json

    def test_hex_zlib_json(self, sample_json):
        token = "0x" + zlib.compress(sample_json).hex()
        result = peel(token)
        assert encodings_path(result) == ["hex", "zlib"]
        assert result.deepest_leaf()[1].data == sample_json

    def test_base64_wrapped_jwt_reaches_the_claims(self):
        token = base64.b64encode(make_jws().encode()).decode()
        result = peel(token)
        # base64 → jwt (3 parts) → claims JSON in the payload leaf
        assert result.layers_peeled == 2
        payload_nodes = [
            n for _, _, n in result.iter_nodes() if n.label == "payload"
        ]
        assert len(payload_nodes) == 1
        assert json.loads(payload_nodes[0].data)["sub"] == "user-4821"

    def test_data_uri_chain(self, sample_json):
        token = "data:application/json;base64," + base64.b64encode(sample_json).decode()
        result = peel(token)
        assert encodings_path(result) == ["data-uri"]
        assert result.deepest_leaf()[1].data == sample_json

    def test_double_base64_peels_twice(self, sample_json):
        once = base64.b64encode(sample_json)
        twice = base64.b64encode(once).decode()
        result = peel(twice)
        assert encodings_path(result) == ["base64", "base64"]

    def test_str_and_bytes_input_produce_identical_traces(self, sample_json):
        token = base64.b64encode(sample_json).decode()
        assert peel(token).to_dict() == peel(token.encode()).to_dict()


class TestRefusals:
    def test_everyday_text_is_left_alone(self):
        probes = [
            "hello world",
            "an ordinary sentence, nothing encoded here",
            "550e8400-e29b-41d4-a716-446655440000",
            "v1.2.3",
        ]
        for probe in probes:
            result = peel(probe)
            assert result.layers_peeled == 0, probe
            assert result.root.terminal == "text", probe

    def test_high_entropy_binary_is_left_alone(self):
        result = peel(bytes(range(256)) * 2)
        assert result.layers_peeled == 0
        assert result.root.terminal == "binary"

    def test_near_miss_is_reported_in_notes(self):
        # "deadbeef" scores as hex but below threshold; the trace must say
        # so instead of silently classifying it as text.
        result = peel("deadbeef")
        assert result.layers_peeled == 0
        assert any("closest candidate: hex" in note for note in result.root.notes)

    def test_same_input_same_trace_every_time(self, sample_json):
        token = urllib.parse.quote(base64.b64encode(gz(sample_json)).decode())
        first = peel(token).to_dict()
        for _ in range(5):
            assert peel(token).to_dict() == first


class TestGuards:
    def test_max_depth_stops_expansion_and_is_flagged(self, sample_json):
        token = base64.b64encode(gz(sample_json)).decode()
        result = peel(token, max_depth=1)
        assert result.max_depth_hit is True
        assert result.layers_peeled == 1
        leaf = result.root.children[0]
        assert leaf.terminal is not None  # still classified, not dangling
        assert any("max depth" in note for note in leaf.notes)

    def test_decompression_bomb_becomes_a_note_not_a_crash(self):
        cap = 4096
        bomb = base64.b64encode(gz(b"\x00" * (cap * 100))).decode()
        result = peel(bomb, max_bytes=cap)
        # The base64 layer peels; the gzip layer refuses and explains why.
        gzip_stop = result.root.children[0]
        assert gzip_stop.encoding == "base64"
        assert not gzip_stop.children
        assert any("exceeds cap" in note for note in gzip_stop.notes)

    def test_min_confidence_moves_the_accept_reject_line_in_both_directions(
        self, sample_json
    ):
        token = base64.b64encode(sample_json).decode()
        assert peel(token).layers_peeled == 1
        # Confidence is capped at 0.99, so a threshold of 1.0 refuses
        # everything — the escape hatch for "just classify, never decode".
        assert peel(token, min_confidence=1.0).layers_peeled == 0
        # And lowering it accepts the ambiguous "deadbeef" as hex.
        loose = peel("deadbeef", min_confidence=0.30)
        assert loose.layers_peeled == 1
        assert loose.root.children[0].encoding == "hex"


class TestDetectorFilters:
    def test_only_and_skip_restrict_the_registry(self, sample_json):
        token = base64.b64encode(gz(sample_json)).decode()
        result = peel(token, only={"base64"})
        assert encodings_path(result) == ["base64"]
        assert result.root.children[0].terminal == "binary"  # gzip was off
        assert peel(token, skip={"base64"}).layers_peeled == 0

    def test_unknown_detector_name_raises_input_error(self):
        with pytest.raises(InputError, match="unknown detector 'rot13'"):
            peel("whatever", only={"rot13"})
