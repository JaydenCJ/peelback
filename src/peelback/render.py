"""Terminal rendering of a peel trace.

The tree renderer prints one line per node — id, encoding, size, confidence
— then a short payload preview under each leaf: pretty-printed JSON, quoted
text, or a hexdump for binary.  Node ids shown here are the same ids
``--extract`` accepts, so the tree doubles as a menu.

Color is plain ANSI, disabled when the stream is not a TTY, when
``NO_COLOR`` is set, or with ``--no-color``.
"""

from __future__ import annotations

import json
from typing import List, Optional

from .jwtlayer import annotate_claims
from .model import Node, PeelResult

JSON_PREVIEW_LINES = 14
TEXT_PREVIEW_CHARS = 240
HEXDUMP_ROWS = 4


class Palette:
    """ANSI styles; the disabled palette maps everything to the identity."""

    def __init__(self, enabled: bool) -> None:
        self._on = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self._on else text

    def encoding(self, text: str) -> str:
        return self._wrap("36", text)  # cyan

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def note(self, text: str) -> str:
        return self._wrap("33", text)  # yellow

    def ok(self, text: str) -> str:
        return self._wrap("32", text)  # green

    def head(self, text: str) -> str:
        return self._wrap("1", text)  # bold


def humanize_size(n: int) -> str:
    """812 → '812 B', 1450 → '1.4 KiB' — one decimal above bytes."""
    if n < 1024:
        return f"{n} B"
    value = float(n)
    for unit in ("KiB", "MiB", "GiB"):
        value /= 1024.0
        if value < 1024:
            return f"{value:.1f} {unit}"
    return f"{value:.1f} TiB"


def hexdump(data: bytes, max_rows: int = HEXDUMP_ROWS) -> List[str]:
    """Classic 16-bytes-per-row hexdump, truncated with an ellipsis row."""
    rows: List[str] = []
    limit = max_rows * 16
    for offset in range(0, min(len(data), limit), 16):
        chunk = data[offset : offset + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asciipart = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        rows.append(f"{offset:08x}  {hexpart:<47}  |{asciipart}|")
    if len(data) > limit:
        rows.append(f"… {len(data) - limit} more byte(s)")
    return rows


def _json_preview(data: bytes, max_lines: int = JSON_PREVIEW_LINES) -> List[str]:
    obj = json.loads(data)
    lines = json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=True).splitlines()
    if len(lines) > max_lines:
        lines = lines[: max_lines - 1] + [f"… {len(lines) - max_lines + 1} more line(s)"]
    return lines


def _text_preview(data: bytes, limit: int = TEXT_PREVIEW_CHARS) -> List[str]:
    text = data.decode("utf-8", errors="replace")
    flat = text.replace("\r", "").rstrip("\n")
    if len(flat) > limit:
        flat = flat[: limit - 1] + "…"
    return flat.splitlines() or [""]


def _leaf_preview(node: Node, now: Optional[float]) -> List[str]:
    """Lines describing a leaf payload, without tree prefixes yet."""
    if node.terminal == "empty":
        return []
    if node.terminal == "json":
        lines = _json_preview(node.data)
        claims = node.meta.get("claims")
        if claims:
            annotations = annotate_claims(claims, now)
            if annotations:
                lines += ["— claims —"] + annotations
        return lines
    if node.terminal == "text":
        return _text_preview(node.data)
    return hexdump(node.data)


def _node_line(node_id: int, node: Node, palette: Palette) -> str:
    parts: List[str] = [palette.dim(f"#{node_id}")]
    if node.encoding is None:
        parts.append("input")
    else:
        name = node.encoding if node.label is None else f"{node.encoding} {node.label}"
        parts.append(palette.encoding(name))
    if node.terminal is not None:
        parts.append(palette.ok(node.terminal))
    parts.append(palette.dim(humanize_size(node.size)))
    if node.confidence is not None and node.label in (None, "header"):
        parts.append(palette.dim(f"({node.confidence:.2f})"))
    return " · ".join(parts)


def render_tree(result: PeelResult, color: bool = False, now: Optional[float] = None) -> str:
    """Render the whole trace as an indented tree with previews."""
    palette = Palette(color)
    ids = {id(node): nid for nid, _, node in result.iter_nodes()}
    out: List[str] = []

    layer_word = "layer" if result.layers_peeled == 1 else "layers"
    header = (
        f"peelback · peeled {result.layers_peeled} {layer_word} "
        f"· input {humanize_size(result.root.size)}"
    )
    out.append(palette.head(header))
    if result.max_depth_hit:
        out.append(palette.note("! stopped at the depth cap; raise --max-depth to keep going"))
    out.append("")

    def walk(node: Node, prefix: str, connector: str) -> None:
        line = _node_line(ids[id(node)], node, palette)
        out.append(f"{prefix}{connector}{line}")
        child_prefix = prefix
        if connector:
            child_prefix += "   " if connector.startswith("└") else "│  "
        for note in node.notes:
            out.append(f"{child_prefix}{palette.note('· ' + note)}")
        if not node.children:
            for preview_line in _leaf_preview(node, now):
                out.append(f"{child_prefix}{palette.dim(preview_line)}")
            return
        for i, child in enumerate(node.children):
            last = i == len(node.children) - 1
            walk(child, child_prefix, "└─ " if last else "├─ ")

    walk(result.root, "", "")
    return "\n".join(out)
