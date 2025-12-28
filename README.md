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

## Demo dashboard (localhost)

This repo ships a tiny demo site for partners to observe the kernel status in real time.

```bash
docker compose -f docker/minimal-prod/docker-compose.yml up --build
```

Open:
- `http://localhost:8088/` (dashboard)
- `http://localhost:8088/health` (raw JSON)

## Test suites

- Offline (default): deterministic tests using a stub JSON-RPC transport (`tests/Support/StubWeb3Transport.php`).
- Live: optional smoke tests against a real chain (run explicitly with `composer test-live`).
- Workspace: security gate scans for obvious bypass surfaces (run explicitly with `composer test-workspace`).

See:
- `docs/ATTACK_FLOWS.md`
- `docs/LIVE_CHAIN.md`

## Note: `"symlink": false` vs symlink attack tests

`composer.json` uses `path` repositories with `"symlink": false` so the installed code under test is a real copy
(closer to production and friendlier for integrity verification). Separately, the test suite includes explicit
symlink-based attack flows to ensure the kernel rejects symlink files/directories used for tampering or bypasses.
