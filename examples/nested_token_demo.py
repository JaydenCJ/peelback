"""Library-API demo: build a nasty nested token, then peel it.

Run it from the repository root (no install needed, zero dependencies):

    PYTHONPATH=src python3 examples/nested_token_demo.py

It constructs url( base64url( gzip( JSON ) ) ) with the stdlib, peels it
with :func:`peelback.peel`, walks the trace, and round-trips the innermost
payload — printing DEMO OK when everything matches.
"""

from __future__ import annotations

import base64
import gzip
import json
import urllib.parse

from peelback import peel

SESSION = {
    "user": "amara",
    "roles": ["admin", "ops"],
    "session": "9f8a-77c2",
    # This value keeps the compressed blob's length off a multiple of three,
    # so the base64 layer carries '=' padding and the URL layer has
    # something to escape — three real layers, deterministically.
    "issued": 1700000003,
}


def build_token() -> str:
    """What a middleware stack does to your session before you see it."""
    inner = json.dumps(SESSION, separators=(",", ":")).encode()
    compressed = gzip.compress(inner, mtime=0)
    encoded = base64.urlsafe_b64encode(compressed).decode()
    return urllib.parse.quote(encoded, safe="")


def main() -> None:
    token = build_token()
    print(f"[build] token ({len(token)} chars): {token[:48]}...")

    result = peel(token)
    print(f"[peel]  layers peeled: {result.layers_peeled}")
    for node_id, depth, node in result.iter_nodes():
        name = node.encoding or "input"
        print(f"[peel]  {'  ' * depth}#{node_id} {name}: {node.size} bytes")

    node_id, leaf = result.deepest_leaf()
    recovered = json.loads(leaf.data)
    print(f"[leaf]  node #{node_id} is terminal {leaf.terminal!r}")
    print(f"[leaf]  user={recovered['user']} roles={recovered['roles']}")

    assert recovered == SESSION, "round-trip mismatch"
    assert result.layers_peeled >= 2, "expected at least base64+gzip layers"

    # The same trace, machine-readable — what `peelback --json` prints.
    trace = result.to_dict()
    assert trace["root"]["id"] == 0
    print(f"[json]  trace has input_size={trace['input_size']}")

    print("DEMO OK")


if __name__ == "__main__":
    main()
