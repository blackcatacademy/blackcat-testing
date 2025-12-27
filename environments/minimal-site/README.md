# Minimal site (prod-like target)

This directory contains a deliberately small “target application” used by `blackcat-testing` to simulate a production website.

It boots:
- `blackcat-config` runtime config (`/etc/blackcat/config.runtime.json` inside container)
- `blackcat-core` HTTP kernel + TrustKernel (fail-closed by default)

Endpoints (intentionally tiny):

- `GET /health` — JSON status snapshot (sanitized, safe for monitoring).
- `POST /db/write` — tries a DB write via `BlackCat\Core\Database` wrapper.
- `GET /db/read` — tries a DB read via `BlackCat\Core\Database` wrapper.
- `GET /bypass/pdo` — attempts to access raw PDO (must be denied by TrustKernel guard).

This is not a “framework”. It exists only for security testing.

