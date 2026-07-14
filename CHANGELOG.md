# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-13

### Added

- Recursive peeling engine that auto-detects and unwraps encoding layers
  until nothing recognizable remains, with a depth cap, a sha256-based
  cycle guard, and a decompression-output cap.
- Eight detectors behind one ordered registry: compact JWS/JWE (`jwt`),
  RFC 2397 `data:` URIs, gzip, zlib, percent-encoding (`url`), hex
  (with `0x` prefixes and `:`/whitespace separators), base64 +
  base64url (padded or not), and base32.
- Two-part confidence scoring — input-shape base confidence per detector
  plus a payload-assessment bonus that rewards decodes revealing JSON,
  another recognizable layer, or readable text — so real base64 is peeled
  aggressively while UUIDs, numeric ids and English words are refused.
- JWT structural peeling into header/payload/signature nodes with RFC 7519
  registered-claim annotation (ISO timestamps, expiry state) and honest
  JWE handling (protected header only; no keys, no verification).
- Decompression-bomb guard: gzip/zlib streams are inflated through a
  bounded decompressor and reported as capped instead of expanded.
- Terminal classification of leaves (`json` / `text` / `binary` / `empty`)
  with magic-byte sniffing (PNG, zip, PDF, ELF, SQLite, PEM, …) and a
  high-entropy hint for keys, ciphertext and signatures.
- CLI with tree output (payload previews: pretty JSON, quoted text, or a
  hexdump), `--json` machine-readable traces with stable node ids,
  `--extract [--node ID]` for raw payload bytes, `--only`/`--skip`
  detector selection, `--max-depth`/`--max-bytes`/`--min-confidence`
  knobs, `--list-detectors`, and shell-friendly exit codes
  (0 peeled / 1 nothing to peel / 2 error).
- Library API (`peel()`, `PeelResult`, `Node`) mirroring the CLI, plus
  runnable examples (`examples/nested_token_demo.py`,
  `examples/sample-tokens.txt`).
- 93 deterministic offline tests and `scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/peelback/releases/tag/v0.1.0
