# Live chain tests (optional)

The `live` testsuite is **not** executed by default.

Run it explicitly:

```bash
docker run --rm -v "$PWD":/app -w /app composer:2.7 composer test-live
```

## Environment variables

- `BLACKCAT_TESTING_LIVE_CONFIG`: absolute path to a runtime config JSON file (inside the container).
- `BLACKCAT_TESTING_LIVE_ASSERT_TRUSTED=1` (optional): additionally assert `trusted_now=true` (requires matching local integrity root + manifest).

## Intended usage

Live tests are meant as a smoke layer (read-only unless you explicitly implement tx flows).
They require a runtime config JSON file with a real RPC + a real deployed `InstanceController`.

Recommended approach:

1) Deploy contracts once (outside this repo).
2) Point live tests to that installation to avoid spamming the chain.
