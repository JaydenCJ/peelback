"""Tests for the terminal renderer: tree shape, previews, sizes, color.

The renderer output is a contract too — the ids it prints are the ids
--extract accepts — so its structure is asserted, not just eyeballed.
"""

from __future__ import annotations

import base64
import re

from peelback import peel
from peelback.render import hexdump, humanize_size, render_tree
from tokens import EXP_FUTURE, IAT, gz, make_jws


class TestFormatting:
    def test_humanize_size_units_and_decimals(self):
        assert humanize_size(0) == "0 B"
        assert humanize_size(812) == "812 B"
        assert humanize_size(1450) == "1.4 KiB"
        assert humanize_size(5 * 1024 * 1024) == "5.0 MiB"

    def test_hexdump_rows_are_classic_format_and_truncate_with_a_count(self):
        rows = hexdump(b"\xde\xad\xbe\xefABCD")
        assert len(rows) == 1
        assert rows[0].startswith("00000000  de ad be ef 41 42 43 44")
        assert rows[0].endswith("|....ABCD|")
        rows = hexdump(bytes(200), max_rows=2)
        assert len(rows) == 3
        assert rows[-1] == "… 168 more byte(s)"


class TestTree:
    def test_header_counts_layers_with_correct_grammar(self, sample_json):
        token = base64.b64encode(gz(sample_json)).decode()
        out = render_tree(peel(token))
        assert out.splitlines()[0] == (
            f"peelback · peeled 2 layers · input {len(token)} B"
        )
        single = render_tree(peel(base64.b64encode(sample_json).decode()))
        assert "peeled 1 layer ·" in single

    def test_every_node_id_appears_exactly_once(self):
        out = render_tree(peel(make_jws()))
        for node_id in ("#0", "#1", "#2", "#3"):
            assert out.count(node_id) == 1

    def test_json_leaf_is_pretty_printed_with_sorted_keys(self, sample_json):
        token = base64.b64encode(sample_json).decode()
        out = render_tree(peel(token))
        assert '"user": "amara"' in out
        # sorted: "n" comes before "roles" comes before "user"
        assert out.index('"n": 7') < out.index('"roles"') < out.index('"user"')

    def test_jwt_claims_are_annotated_deterministically(self):
        out = render_tree(peel(make_jws()), now=float(IAT))
        assert "— claims —" in out
        assert f"exp (expires at): {EXP_FUTURE} → 3000-01-01T00:00:00Z" in out
        assert "expires in" in out

    def test_binary_leaf_gets_a_hexdump(self):
        out = render_tree(peel(make_jws()))
        assert "jwt signature" in out
        assert re.search(r"[0-9a-f]{8}  (?:[0-9a-f]{2} )+", out)  # hexdump row

    def test_color_wraps_but_never_changes_the_text(self):
        plain = render_tree(peel(make_jws()), color=False, now=float(IAT))
        assert "\x1b[" not in plain
        colored = render_tree(peel(make_jws()), color=True, now=float(IAT))
        assert "\x1b[36m" in colored
        # Stripping ANSI sequences must recover the plain rendering.
        stripped = re.sub(r"\x1b\[[0-9;]*m", "", colored)
        assert stripped == plain

    def test_note_lines_are_indented_under_their_node(self):
        result = peel("0xdeadbeefcafe", min_confidence=0.5)
        out = render_tree(result)
        assert "· 0x prefix" in out
