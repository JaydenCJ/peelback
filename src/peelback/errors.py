"""Exception hierarchy for peelback.

Everything raised deliberately by the package derives from
:class:`PeelbackError`, so callers can catch one type at the boundary.
"""

from __future__ import annotations


class PeelbackError(Exception):
    """Base class for all peelback errors."""


class InputError(PeelbackError):
    """The input could not be read or is not usable (empty file, bad path)."""


class ExtractionError(PeelbackError):
    """A requested node id does not exist in the peel trace."""


class CapExceeded(PeelbackError):
    """A decompression layer would exceed the configured output cap.

    Raised inside detectors and caught by the engine, which records a note
    on the node instead of expanding it — a decompression bomb must never
    take the process down.
    """

    def __init__(self, encoding: str, cap: int) -> None:
        super().__init__(f"{encoding}: decompressed output exceeds cap of {cap} bytes")
        self.encoding = encoding
        self.cap = cap
