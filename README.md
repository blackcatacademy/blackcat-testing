# blackcat-testing

Security-focused, production-like integration tests and attack-flow simulations for the BlackCat kernel stack:

- `blackcat-core` (TrustKernel, guards, integrity verification)
- `blackcat-config` (secure runtime config loading + validation)

This repo is intentionally **not** part of runtime code. It exists to validate security posture and regression-test
realistic failure/attack scenarios.

## Quick start (Docker)

The host machine does not need PHP installed.

```bash
docker run --rm -v "$PWD":/app -w /app composer:2.7 composer install
docker run --rm -v "$PWD":/app -w /app composer:2.7 composer test
docker run --rm -v "$PWD":/app -w /app composer:2.7 composer stan
```

## Test suites

- Offline (default): deterministic tests using a stub JSON-RPC transport (`tests/Support/StubWeb3Transport.php`).
- Live: optional smoke tests against a real chain (run explicitly with `composer test-live`).

See:
- `docs/ATTACK_FLOWS.md`
- `docs/LIVE_CHAIN.md`

