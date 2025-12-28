# Minimal site (prod-like target)

This directory contains a deliberately small “target application” used by `blackcat-testing` to simulate a production website.

It boots:
- `blackcat-config` runtime config (`/etc/blackcat/config.runtime.json` inside container)
- `blackcat-core` HTTP kernel + TrustKernel (fail-closed by default)

Endpoints (intentionally tiny):

- `GET /health` — JSON status snapshot (sanitized, safe for monitoring).
- `GET /health/debug` — extended JSON payload for local debugging (not for public monitoring).
- `POST /db/write` — tries a DB write via `BlackCat\Core\Database` wrapper.
- `GET /db/read` — tries a DB read via `BlackCat\Core\Database` wrapper.
- `GET /bypass/pdo` — attempts to access raw PDO (must be denied by TrustKernel guard).
- `GET /bypass/keys` — attempts to read a key file directly (must be denied by OS permissions in secrets-agent mode).
- `GET /bypass/agent` — attempts to bypass TrustKernel by calling the secrets-agent socket directly (must be denied when `read_allowed=false`).
- `POST /crypto/roundtrip` — crypto demo (encrypt+decrypt, must still be guarded by TrustKernel `secrets.read`).

This is not a “framework”. It exists only for security testing.
