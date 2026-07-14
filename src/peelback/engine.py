"""The recursive peeling engine.

For each blob the engine asks every enabled detector for a candidate, then
scores each candidate as::

    final = base_confidence (input shape)  +  assessment bonus (output shape)

The assessment bonus rewards decodes that *reveal structure* — JSON, another
recognizable layer, readable text — and penalizes decodes that merely turn
one opaque blob into another.  That asymmetry is what lets peelback decode
real base64 aggressively while refusing to "decode" a UUID or an English
word that happens to be valid hex.

Guards, in order of appearance: a depth cap, a cycle check on payload
digests, a decompression-output cap, and the confidence threshold itself.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import FrozenSet, List, Optional, Tuple, Union

from . import heuristics, jwtlayer
from .compression import GZIP_MAGIC, _zlib_header_ok
from .detectors import DETECTOR_IDS, REGISTRY, Candidate, Context
from .errors import CapExceeded, InputError
from .model import Node, PeelResult

DEFAULT_MAX_DEPTH = 16
DEFAULT_MIN_CONFIDENCE = 0.55
DEFAULT_MAX_BYTES = 16 * 1024 * 1024

#: Candidates that lose but score at least this much are worth mentioning.
NEAR_MISS_FLOOR = 0.35


@dataclass
class Options:
    """Engine knobs, all overridable from the CLI."""

    max_depth: int = DEFAULT_MAX_DEPTH
    min_confidence: float = DEFAULT_MIN_CONFIDENCE
    max_bytes: int = DEFAULT_MAX_BYTES
    only: Optional[FrozenSet[str]] = None
    skip: FrozenSet[str] = frozenset()

    def __post_init__(self) -> None:
        for name in (self.only or frozenset()) | self.skip:
            if name not in DETECTOR_IDS:
                raise InputError(
                    f"unknown detector {name!r} (known: {', '.join(DETECTOR_IDS)})"
                )

    def enabled(self, detector_id: str) -> bool:
        if detector_id in self.skip:
            return False
        return self.only is None or detector_id in self.only


def _looks_like_next_layer(payload: bytes) -> bool:
    """Cheap one-level lookahead: does the payload carry its own strong tell?"""
    if payload.startswith(GZIP_MAGIC) or _zlib_header_ok(payload):
        return True
    text = heuristics.ascii_view(payload)
    if text is not None and "." in text:
        parts = jwtlayer.split_compact(text)
        if parts is not None and jwtlayer.decode_header(parts[0]) is not None:
            return True
    return False


def assess_payload(payload: bytes) -> Tuple[float, List[str]]:
    """Score how much *structure* a decoded payload reveals.

    Returns ``(bonus, notes)``.  The bonus is added to the detector's base
    confidence; a negative bonus means the decode produced something less
    structured than we would expect from a correct peel.
    """
    if not payload:
        return 0.0, []
    if heuristics.looks_like_json(payload):
        return 0.30, ["decodes to JSON"]
    if _looks_like_next_layer(payload):
        return 0.30, ["decodes to another recognizable layer"]
    if heuristics.is_utf8_text(payload):
        return 0.20, ["decodes to readable text"]
    if heuristics.printable_ratio(payload) >= 0.85:
        return 0.10, ["decodes to mostly-printable bytes"]
    if len(payload) >= 16 and heuristics.shannon_entropy(payload) >= heuristics.HIGH_ENTROPY:
        return -0.15, ["decodes to high-entropy binary"]
    if len(payload) < 8:
        return -0.10, ["decodes to a very short opaque blob"]
    return 0.0, []


@dataclass
class _Scored:
    candidate: Candidate
    confidence: float
    assessment_notes: List[str] = field(default_factory=list)


def _score(candidate: Candidate) -> _Scored:
    # Structural detectors (jwt/jwe, data URIs) carry their certainty in the
    # input shape itself; assessing their first child would double-count.
    if candidate.detector in ("jwt", "data-uri"):
        return _Scored(candidate, min(candidate.base_confidence, 0.99))
    bonus, notes = assess_payload(candidate.primary_payload)
    return _Scored(candidate, max(0.0, min(candidate.base_confidence + bonus, 0.99)), notes)


class Engine:
    def __init__(self, options: Optional[Options] = None) -> None:
        self.options = options or Options()
        self._ctx = Context(max_bytes=self.options.max_bytes)
        self._layers = 0
        self._depth_hit = False

    def run(self, data: bytes) -> PeelResult:
        self._layers = 0
        self._depth_hit = False
        root = Node(data=data)
        self._expand(root, depth=0, seen=frozenset())
        return PeelResult(root=root, layers_peeled=self._layers, max_depth_hit=self._depth_hit)

    # -- internals ---------------------------------------------------------

    def _candidates(self, data: bytes) -> List[_Scored]:
        scored: List[_Scored] = []
        for detector_id, fn in REGISTRY:
            if not self.options.enabled(detector_id):
                continue
            try:
                candidate = fn(data, self._ctx)
            except CapExceeded as exc:
                placeholder = Candidate(detector_id, exc.encoding, [], 0.0,
                                        [f"not expanded: {exc}"])
                scored.append(_Scored(placeholder, 0.0))
                continue
            if candidate is not None:
                scored.append(_score(candidate))
        return scored

    def _expand(self, node: Node, depth: int, seen: FrozenSet[bytes]) -> None:
        if depth >= self.options.max_depth:
            self._depth_hit = True
            node.notes.append(f"max depth ({self.options.max_depth}) reached; not expanded")
            self._finalize(node)
            return

        scored = self._candidates(node.data)
        capped = [s for s in scored if not s.candidate.children]
        for s in capped:
            node.notes.extend(s.candidate.notes)
        viable = [s for s in scored if s.candidate.children]

        best: Optional[_Scored] = None
        for s in viable:  # registry order; strict > keeps the earliest on ties
            if best is None or s.confidence > best.confidence:
                best = s

        if best is None or best.confidence < self.options.min_confidence:
            self._note_near_miss(node, best)
            self._finalize(node)
            return

        digest = hashlib.sha256(node.data).digest()
        if any(hashlib.sha256(c.payload).digest() in seen | {digest}
               for c in best.candidate.children):
            node.notes.append(f"{best.candidate.encoding} decode would revisit "
                              "an earlier payload; stopped to avoid a cycle")
            self._finalize(node)
            return

        self._layers += 1
        cand = best.candidate
        next_seen = seen | {digest}
        for i, child_spec in enumerate(cand.children):
            # Candidate-level notes describe the decode step as a whole, so
            # they go on the first child only; per-part notes stay per-part.
            layer_notes = list(cand.notes) if i == 0 else []
            child = Node(
                data=child_spec.payload,
                encoding=cand.encoding,
                detector=cand.detector,
                label=child_spec.label,
                confidence=best.confidence,
                notes=layer_notes + list(child_spec.notes),
                meta=dict(cand.meta),
            )
            node.children.append(child)
            self._expand(child, depth + 1, next_seen)

    def _note_near_miss(self, node: Node, best: Optional[_Scored]) -> None:
        if best is not None and best.confidence >= NEAR_MISS_FLOOR:
            reasons = ", ".join(best.assessment_notes) or "weak input shape"
            node.notes.append(
                f"closest candidate: {best.candidate.encoding} "
                f"({best.confidence:.2f} < {self.options.min_confidence:.2f} threshold; {reasons})"
            )

    def _finalize(self, node: Node) -> None:
        kind, detail = heuristics.classify_terminal(node.data)
        node.terminal = kind
        if detail:
            node.notes.append(detail)
        if kind == "json" and node.detector == "jwt" and node.label == "payload":
            claims = jwtlayer.claims_from_payload(node.data)
            if claims is not None:
                node.meta["claims"] = claims


def peel(data: Union[bytes, str], **kwargs: object) -> PeelResult:
    """Peel every recognizable layer off *data* and return the trace.

    Keyword arguments mirror :class:`Options` (``max_depth``,
    ``min_confidence``, ``max_bytes``, ``only``, ``skip``).  ``str`` input is
    encoded as UTF-8 first.

    >>> peel("aGVsbG8gd29ybGQ=").deepest_leaf()[1].data
    b'hello world'
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    only = kwargs.pop("only", None)
    skip = kwargs.pop("skip", frozenset())
    options = Options(
        only=frozenset(only) if only is not None else None,  # type: ignore[arg-type]
        skip=frozenset(skip),  # type: ignore[arg-type]
        **kwargs,  # type: ignore[arg-type]
    )
    return Engine(options).run(data)
