# peelback examples

Everything here runs offline with the standard library only.

## `nested_token_demo.py`

Builds a four-layer token — `url( base64url( gzip( JSON ) ) )` — the way a
real middleware stack would, then peels it with the library API and
round-trips the innermost payload. Prints `DEMO OK` on success:

```bash
PYTHONPATH=src python3 examples/nested_token_demo.py
```

## `sample-tokens.txt`

Seven hand-checked tokens covering every detector — base64, hex,
URL-encoding, a signed JWT, a `data:` URI, base32, and one plain string that
peelback correctly refuses to "decode" (exit code 1). Feed any line to the
CLI:

```bash
peelback "$(sed -n 6p examples/sample-tokens.txt)"    # the base64 cookie
peelback "$(sed -n 15p examples/sample-tokens.txt)"   # the JWT
```

The JWT in line 15 is signed with the throwaway key `sample-secret` and
carries fixed timestamps, so its output is reproducible anywhere.
