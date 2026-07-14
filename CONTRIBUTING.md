# Contributing to peelback

Thanks for your interest in contributing. Issues, discussions, and pull
requests are all welcome.

## Getting started

You need Python 3.9 or newer; nothing else — the package has zero runtime
dependencies.

```bash
git clone https://github.com/JaydenCJ/peelback
cd peelback
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
bash scripts/smoke.sh
```

`scripts/smoke.sh` builds a genuinely nested token with the standard library,
drives the real CLI end-to-end — tree output, `--json`, `--extract`, exit
codes, the decompression-bomb guard — and must print `SMOKE OK`.

## Before you open a pull request

1. Format with `python3 -m black src tests` if you have it (PEP 8 /
   100-column style is enforced by review either way).
2. Lint with `python3 -m ruff check src tests` if you have it; new warnings
   are treated as failures.
3. `pytest` — all tests must pass, offline, with no new flakiness.
4. `bash scripts/smoke.sh` — must print `SMOKE OK`.
5. Add tests for behavior changes; keep logic in pure, unit-testable modules
   (`detectors.py`, `heuristics.py`, `compression.py`, `jwtlayer.py` know
   nothing about files or argv).

## Ground rules

- **No new runtime dependencies.** The package is standard-library only; that
  is the headline feature. Test-only tooling belongs in the `dev` extra.
- **Refusal is a feature.** A detector that fires on ordinary words, UUIDs or
  numeric ids is a bug, even when the decode "succeeds". Every new detector
  needs negative tests proving it stays quiet on plain text.
- **Determinism is a contract.** Same input + same options ⇒ byte-identical
  tree, JSON, and node ids. No wall-clock reads outside the injectable `now`,
  no unsorted iteration, no locale dependence.
- **No network calls, no telemetry.** peelback reads bytes and prints bytes;
  tokens people paste into it are often secrets, which is exactly why it must
  stay fully offline.
- Code comments and doc comments are written in English.
- **Keep the three READMEs aligned.** `README.md`, `README.zh.md`, and
  `README.ja.md` are line-for-line translations; update all three when you
  change one (English is the authoritative version).

## Reporting bugs

Please include `peelback --version`, the exact command line, and a token that
reproduces the issue — if the real token is sensitive, `--json` output with
the `preview` fields redacted, or a synthetic token built the way
`scripts/smoke.sh` builds one, is usually enough to pin down a detector bug.

## Security

Please do not open public issues for suspected vulnerabilities; use GitHub's
private vulnerability reporting on this repository instead.
