"""Data model for a peel trace: nodes, the result tree, JSON serialization.

A trace is a tree because some layers (JWT) split into several parts.  Node
ids are assigned in depth-first preorder, so they are stable for a given
input and options — the ids printed by the tree renderer are the same ids
``--extract`` and the ``--json`` output use.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple

PREVIEW_CHARS = 96


@dataclass
class Node:
    """One blob in the trace, plus how it was produced from its parent."""

    data: bytes
    encoding: Optional[str] = None  # None for the root (raw input)
    detector: Optional[str] = None  # registry id of the detector that fired
    label: Optional[str] = None  # part label for multi-child layers
    confidence: Optional[float] = None
    notes: List[str] = field(default_factory=list)
    children: List["Node"] = field(default_factory=list)
    terminal: Optional[str] = None  # empty|json|text|binary — leaves only
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    def preview(self, limit: int = PREVIEW_CHARS) -> str:
        """A short, always-printable text preview of the node's bytes."""
        head = self.data[: limit * 4]
        try:
            text = head.decode("utf-8")
        except UnicodeDecodeError:
            text = head.decode("latin-1")
        cleaned = "".join(ch if ch.isprintable() else "·" for ch in text)
        if len(cleaned) > limit or len(self.data) > len(head):
            cleaned = cleaned[: limit - 1] + "…"
        return cleaned


@dataclass
class PeelResult:
    """The full trace for one input."""

    root: Node
    layers_peeled: int
    max_depth_hit: bool = False

    def iter_nodes(self) -> Iterator[Tuple[int, int, Node]]:
        """Yield ``(id, depth, node)`` in depth-first preorder."""
        counter = 0
        stack: List[Tuple[int, Node]] = [(0, self.root)]
        while stack:
            depth, node = stack.pop()
            yield counter, depth, node
            counter += 1
            for child in reversed(node.children):
                stack.append((depth + 1, child))

    def node_by_id(self, node_id: int) -> Optional[Node]:
        for nid, _, node in self.iter_nodes():
            if nid == node_id:
                return node
        return None

    def leaves(self) -> List[Tuple[int, int, Node]]:
        return [(nid, depth, node) for nid, depth, node in self.iter_nodes() if not node.children]

    def deepest_leaf(self) -> Tuple[int, Node]:
        """The innermost payload: deepest leaf, largest first on ties.

        For a JWT the header, payload, and signature share a depth; the
        payload is almost always the largest, so size is the tie-breaker,
        and preorder position settles exact ties — fully deterministic.
        """
        best: Optional[Tuple[int, int, int, Node]] = None
        for nid, depth, node in self.leaves():
            key = (depth, node.size, -nid)
            if best is None or key > (best[0], best[1], best[2]):
                best = (depth, node.size, -nid, node)
        assert best is not None  # a trace always has at least the root
        return -best[2], best[3]

    def to_dict(self) -> Dict[str, Any]:
        """A stable, machine-readable rendering of the whole trace."""
        ids: Dict[int, int] = {id(node): nid for nid, _, node in self.iter_nodes()}

        def encode(node: Node) -> Dict[str, Any]:
            return {
                "id": ids[id(node)],
                "encoding": node.encoding,
                "detector": node.detector,
                "label": node.label,
                "confidence": round(node.confidence, 3) if node.confidence is not None else None,
                "size": node.size,
                "sha256": node.sha256,
                "terminal": node.terminal,
                "notes": list(node.notes),
                "preview": node.preview(),
                "children": [encode(child) for child in node.children],
            }

        return {
            "tool": "peelback",
            "input_size": self.root.size,
            "layers_peeled": self.layers_peeled,
            "max_depth_hit": self.max_depth_hit,
            "root": encode(self.root),
        }
