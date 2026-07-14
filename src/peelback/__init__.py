"""peelback — recursively peel base64, hex, gzip, URL and JWT layers off an
opaque token.

Library entry points::

    from peelback import peel

    result = peel("H4sIAAAA...")          # or bytes
    print(result.layers_peeled)
    node_id, node = result.deepest_leaf()
    print(node.data)                      # the innermost payload
    print(result.to_dict())               # machine-readable trace

The CLI (``peelback`` / ``python -m peelback``) is a thin veneer over the
same :func:`peel` call.
"""

from __future__ import annotations

from .engine import Options, peel
from .errors import (
    CapExceeded,
    ExtractionError,
    InputError,
    PeelbackError,
)
from .model import Node, PeelResult

__version__ = "0.1.0"

__all__ = [
    "peel",
    "Options",
    "Node",
    "PeelResult",
    "PeelbackError",
    "InputError",
    "ExtractionError",
    "CapExceeded",
    "__version__",
]
