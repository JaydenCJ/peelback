"""Tests for the trace data model: node ids, extraction, JSON shape.

Node ids are part of the CLI contract (`--extract` accepts the ids the tree
prints), so their assignment order is pinned here.
"""

from __future__ import annotations

import base64
import hashlib
import json

from peelback import peel
from tokens import gz, make_jws


class TestNodeIds:
    def test_ids_are_depth_first_preorder(self, sample_json):
        token = base64.b64encode(gz(sample_json)).decode()
        result = peel(token)
        ids = [nid for nid, _, _ in result.iter_nodes()]
        assert ids == [0, 1, 2]
        depths = [depth for _, depth, _ in result.iter_nodes()]
        assert depths == [0, 1, 2]

    def test_jwt_children_get_sequential_ids(self):
        result = peel(make_jws())
        labels = {nid: node.label for nid, _, node in result.iter_nodes()}
        assert labels == {0: None, 1: "header", 2: "payload", 3: "signature"}

    def test_node_by_id_roundtrip_and_out_of_range(self, sample_json):
        token = base64.b64encode(sample_json).decode()
        result = peel(token)
        node = result.node_by_id(1)
        assert node is not None
        assert node.data == sample_json
        assert result.node_by_id(99) is None


class TestDeepestLeaf:
    def test_linear_chain_picks_the_innermost_payload(self, sample_json):
        token = base64.b64encode(gz(sample_json)).decode()
        node_id, node = peel(token).deepest_leaf()
        assert node_id == 2
        assert node.data == sample_json
        # An unpeelable input falls back to the root itself.
        root_id, root = peel("just words").deepest_leaf()
        assert root_id == 0
        assert root.data == b"just words"

    def test_jwt_tie_break_prefers_the_largest_part(self):
        # header/payload/signature share a depth; the payload is the
        # biggest, and that is what a debugger wants by default.
        claims = {"sub": "x" * 64, "scope": "a b c d e f"}
        _, node = peel(make_jws(claims=claims)).deepest_leaf()
        assert node.label == "payload"


class TestToDict:
    def test_shape_ids_and_rounding(self, sample_json):
        token = base64.b64encode(gz(sample_json)).decode()
        payload = peel(token).to_dict()
        assert payload["tool"] == "peelback"
        assert payload["layers_peeled"] == 2
        assert payload["root"]["id"] == 0
        assert payload["root"]["children"][0]["id"] == 1
        assert payload["root"]["children"][0]["children"][0]["id"] == 2
        conf = payload["root"]["children"][0]["confidence"]
        assert conf == round(conf, 3)  # stable, diff-friendly output
        # And per-node digests match the actual bytes at that node.
        flat = peel(base64.b64encode(sample_json).decode()).to_dict()
        leaf = flat["root"]["children"][0]
        assert leaf["sha256"] == hashlib.sha256(sample_json).hexdigest()

    def test_is_json_serializable_and_stable(self, sample_json):
        token = base64.b64encode(gz(sample_json)).decode()
        once = json.dumps(peel(token).to_dict(), sort_keys=True)
        twice = json.dumps(peel(token).to_dict(), sort_keys=True)
        assert once == twice


class TestPreview:
    def test_previews_are_printable_and_truncated(self):
        # Control bytes are replaced, never leaked into terminal output.
        preview = peel(b"\x00\x01binary\x02").root.preview()
        assert "binary" in preview
        assert "\x00" not in preview
        # Long payloads are cut at the preview budget with an ellipsis.
        long_preview = peel(b"x" * 500).root.preview()
        assert len(long_preview) <= 96
        assert long_preview.endswith("…")
