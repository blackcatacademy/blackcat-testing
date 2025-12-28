# Insecure site (deliberately unprotected target)

This is a **deliberately insecure** "control" site used for demos and comparisons.

It intentionally does **not** bootstrap:
- `blackcat-core` (TrustKernel + guards)
- `blackcat-config` (secure runtime config)
- secrets-agent boundary

It exists to show what a typical PHP app looks like **without** BlackCat protections:
- secrets can be readable by the web runtime
- raw PDO access is possible
- configuration is often reachable via env/files

Endpoints:
- `GET /` — simple UI (unprotected).
- `GET /health` — basic JSON health.
- `GET /leak/key` — reads a local key file (intentionally bad).
- `GET /leak/db` — shows DB credentials (intentionally bad).
- `GET /db/read` — raw PDO read.
- `POST /db/write` — raw PDO write.

Do not copy this into any real app. It is an educational target only.

