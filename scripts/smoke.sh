#!/usr/bin/env bash
# Smoke test for peelback: build a genuinely nasty nested token with the
# stdlib, peel it with the real CLI, and assert on the trace, the JSON
# output, the extracted bytes, and the exit codes.
# Self-contained: pure stdlib, no network, idempotent (works from a clean tree).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
if [ -x "$ROOT/.venv/bin/python" ]; then
  PYTHON="$ROOT/.venv/bin/python"
fi

# The package has zero runtime dependencies, so running from src/ needs no install.
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/peelback-smoke.XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT

fail() { echo "SMOKE FAIL: $1" >&2; exit 1; }

echo "[smoke] python: $("$PYTHON" --version 2>&1)"

# 1. Build a four-layer token: url( base64url( gzip( JSON ) ) ), plus a
#    signed JWT wrapped in base64 — both with the stdlib only.
"$PYTHON" - "$WORKDIR" <<'PYEOF'
import base64, gzip, hashlib, hmac, json, sys, urllib.parse

workdir = sys.argv[1]
# The salt loop guarantees the base64 blob carries '=' padding, so the URL
# layer really has something to escape (a blob whose length is divisible
# by 3 would otherwise pass through urllib.parse.quote unchanged).
for salt in range(16):
    inner = json.dumps({"user": "amara", "roles": ["admin", "ops"],
                        "session": "9f8a-77c2", "salt": salt}).encode()
    blob = base64.urlsafe_b64encode(gzip.compress(inner, mtime=0)).decode()
    token = urllib.parse.quote(blob, safe="")
    if token != blob:
        break
else:
    raise SystemExit("could not build a padded token")
with open(f"{workdir}/nested.txt", "w") as fh:
    fh.write(token)
with open(f"{workdir}/inner.json", "wb") as fh:
    fh.write(inner)

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
header = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
payload = b64u(json.dumps({"iss": "https://auth.example.test", "sub": "user-4821",
                           "iat": 1700000000, "exp": 32503680000},
                          separators=(",", ":")).encode())
signing = f"{header}.{payload}".encode()
sig = b64u(hmac.new(b"smoke-secret", signing, hashlib.sha256).digest())
with open(f"{workdir}/wrapped-jwt.txt", "w") as fh:
    fh.write(base64.b64encode(f"{header}.{payload}.{sig}".encode()).decode())
PYEOF
NESTED="$(cat "$WORKDIR/nested.txt")"

# 2. Peel the nested token: all three layers must be found, exit code 0.
tree_out="$("$PYTHON" -m peelback "$NESTED")" || fail "peeling the nested token exited non-zero"
echo "$tree_out" | sed 's/^/[tree] /'
echo "$tree_out" | grep -q "peeled 3 layers" || fail "expected 3 peeled layers"
for enc in url-encoding base64 gzip; do
  echo "$tree_out" | grep -q "$enc" || fail "tree is missing the $enc layer"
done
echo "$tree_out" | grep -q '"user": "amara"' || fail "tree is missing the decoded JSON"

# 3. Extract the innermost payload and compare byte-for-byte.
"$PYTHON" -m peelback --extract "$NESTED" > "$WORKDIR/extracted.json" \
  || fail "--extract exited non-zero"
cmp -s "$WORKDIR/extracted.json" "$WORKDIR/inner.json" \
  || fail "--extract did not reproduce the original bytes"

# 4. JSON mode: valid JSON with the right layer count and node ids.
"$PYTHON" -m peelback --json "$NESTED" > "$WORKDIR/trace.json" || fail "--json exited non-zero"
"$PYTHON" - "$WORKDIR/trace.json" <<'PYEOF'
import json, sys
trace = json.load(open(sys.argv[1]))
assert trace["tool"] == "peelback", "tool field missing"
assert trace["layers_peeled"] == 3, f"expected 3 layers, got {trace['layers_peeled']}"
assert trace["root"]["id"] == 0, "root id must be 0"
PYEOF
echo "[json] trace validated: 3 layers, ids stable"

# 5. A base64-wrapped JWT: claims must surface, signature must hexdump.
jwt_out="$("$PYTHON" -m peelback --file "$WORKDIR/wrapped-jwt.txt")" \
  || fail "peeling the wrapped JWT exited non-zero"
echo "$jwt_out" | grep -q "jwt payload" || fail "JWT payload node missing"
echo "$jwt_out" | grep -q "iss (issuer)" || fail "claim annotations missing"
echo "$jwt_out" | grep -q "3000-01-01T00:00:00Z" || fail "exp timestamp not rendered"
echo "[jwt] claims annotated"

# 6. Refusals: everyday text exits 1 and is not "decoded".
set +e
"$PYTHON" -m peelback "just some words" > "$WORKDIR/refusal.txt"
refusal_rc=$?
set -e
[ "$refusal_rc" -eq 1 ] || fail "plain text should exit 1, got $refusal_rc"
grep -q "peeled 0 layers" "$WORKDIR/refusal.txt" || fail "plain text was wrongly peeled"

# 7. A decompression bomb is stopped by the cap, not by the OOM killer.
"$PYTHON" - "$WORKDIR" <<'PYEOF'
import base64, gzip, sys
with open(f"{sys.argv[1]}/bomb.txt", "w") as fh:
    fh.write(base64.b64encode(gzip.compress(b"\0" * (1 << 24), mtime=0)).decode())
PYEOF
bomb_out="$("$PYTHON" -m peelback --max-bytes 65536 --file "$WORKDIR/bomb.txt")" \
  || fail "bomb input crashed the CLI"
echo "$bomb_out" | grep -q "exceeds cap" || fail "bomb was not reported as capped"
echo "[bomb] cap held at 64 KiB"

# 8. --version agrees with the package, --help mentions the exit codes.
version_out="$("$PYTHON" -m peelback --version)"
pkg_version="$("$PYTHON" -c 'import peelback; print(peelback.__version__)')"
[ "$version_out" = "peelback $pkg_version" ] \
  || fail "--version mismatch: '$version_out' vs package '$pkg_version'"
"$PYTHON" -m peelback --help | grep -q "exit codes" || fail "--help missing exit codes"

echo "SMOKE OK"
