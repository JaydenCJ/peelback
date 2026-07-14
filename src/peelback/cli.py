"""The ``peelback`` command-line interface.

Reads a token from an argument, a file, or stdin; peels it; prints either a
human tree, a machine-readable JSON trace, or the raw bytes of one node.

Exit codes: 0 when at least one layer was peeled, 1 when nothing peeled
(the input is already terminal), 2 on usage or input errors — so
``peelback "$TOKEN" >/dev/null`` doubles as an "is this thing encoded?"
predicate in shell scripts.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import List, Optional

from . import __version__
from .detectors import DETECTOR_HELP
from .engine import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MIN_CONFIDENCE,
    peel,
)
from .errors import ExtractionError, InputError, PeelbackError
from .model import PeelResult
from .render import render_tree

EXIT_PEELED = 0
EXIT_NOTHING_TO_PEEL = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="peelback",
        description="Recursively peel base64, hex, gzip, URL and JWT layers "
        "off an opaque token.",
        epilog="exit codes: 0 = peeled at least one layer, "
        "1 = nothing to peel, 2 = error",
    )
    parser.add_argument("token", nargs="?", help="the token to peel (omit to read stdin)")
    parser.add_argument("-f", "--file", metavar="PATH",
                        help="read the input from a file (binary-safe)")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="emit the full trace as JSON instead of a tree")
    parser.add_argument("-x", "--extract", action="store_true",
                        help="write raw payload bytes instead of the tree "
                        "(innermost payload unless --node is given)")
    parser.add_argument("--node", metavar="ID", type=int, default=None,
                        help="with --extract: the node id to write "
                        "(ids are shown in the tree and JSON output)")
    parser.add_argument("-o", "--out", metavar="PATH",
                        help="with --extract: write the bytes to a file")
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH,
                        metavar="N", help=f"layer recursion cap (default {DEFAULT_MAX_DEPTH})")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, metavar="N",
                        help="decompression output cap in bytes "
                        f"(default {DEFAULT_MAX_BYTES})")
    parser.add_argument("--min-confidence", type=float, default=DEFAULT_MIN_CONFIDENCE,
                        metavar="F",
                        help=f"detection threshold 0..1 (default {DEFAULT_MIN_CONFIDENCE})")
    parser.add_argument("--only", metavar="LIST",
                        help="comma-separated detector ids to use exclusively")
    parser.add_argument("--skip", metavar="LIST",
                        help="comma-separated detector ids to disable")
    parser.add_argument("--list-detectors", action="store_true",
                        help="print the detector table and exit")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("-V", "--version", action="version",
                        version=f"peelback {__version__}")
    return parser


def _split_ids(raw: Optional[str]) -> Optional[List[str]]:
    if raw is None:
        return None
    return [part.strip() for part in raw.split(",") if part.strip()]


def _read_input(args: argparse.Namespace) -> bytes:
    if args.token is not None and args.file is not None:
        raise InputError("give a token argument or --file, not both")
    if args.token is not None:
        return args.token.encode("utf-8")
    if args.file is not None:
        try:
            with open(args.file, "rb") as fh:
                return fh.read()
        except OSError as exc:
            raise InputError(f"cannot read {args.file}: {exc.strerror}") from exc
    data = sys.stdin.buffer.read()
    # `echo token | peelback` appends a newline that is not part of the
    # token; trailing CR/LF from a pipe is never meaningful input.
    return data.rstrip(b"\r\n")


def _use_color(args: argparse.Namespace) -> bool:
    if args.no_color or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _do_extract(result: PeelResult, node_id: Optional[int],
                out_path: Optional[str]) -> None:
    if node_id is None:
        node_id, node = result.deepest_leaf()
    else:
        found = result.node_by_id(node_id)
        if found is None:
            raise ExtractionError(f"no node #{node_id} in this trace "
                                  f"(run without --extract to list ids)")
        node = found
    if out_path:
        try:
            with open(out_path, "wb") as fh:
                fh.write(node.data)
        except OSError as exc:
            raise ExtractionError(
                f"cannot write {out_path}: {exc.strerror or exc}") from exc
        print(f"wrote node #{node_id} ({len(node.data)} bytes) to {out_path}",
              file=sys.stderr)
    else:
        sys.stdout.buffer.write(node.data)
        sys.stdout.buffer.flush()


def _print_detectors() -> None:
    width = max(len(name) for name, _ in DETECTOR_HELP)
    for name, description in DETECTOR_HELP:
        print(f"{name:<{width}}  {description}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_detectors:
        _print_detectors()
        return EXIT_PEELED

    try:
        if not args.extract and (args.node is not None or args.out):
            raise InputError("--node and --out only apply with --extract")
        data = _read_input(args)
        if not data:
            raise InputError("empty input — nothing to peel")
        result = peel(
            data,
            max_depth=args.max_depth,
            max_bytes=args.max_bytes,
            min_confidence=args.min_confidence,
            only=_split_ids(args.only),
            skip=_split_ids(args.skip) or frozenset(),
        )
        if args.extract:
            _do_extract(result, args.node, args.out)
        elif args.as_json:
            payload = result.to_dict()
            payload["version"] = __version__
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(render_tree(result, color=_use_color(args), now=time.time()))
    except PeelbackError as exc:
        print(f"peelback: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:
        # Downstream closed the pipe (`peelback … | head`); that is normal
        # shell usage, not an error.  Point stdout at /dev/null so the
        # interpreter's exit-time flush does not print a second traceback.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())

    return EXIT_PEELED if result.layers_peeled > 0 else EXIT_NOTHING_TO_PEEL


if __name__ == "__main__":
    sys.exit(main())
