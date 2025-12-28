# Presentation demo (partners)

This repo includes a small, production-like demo stack that lets non-developers observe BlackCat’s trust/integrity
model in real time.

## 1) Start the demo

From the `blackcatacademy` root:

```bash
docker compose \
  -f blackcat-testing/docker/minimal-prod/docker-compose.yml \
  -f blackcat-testing/docker/minimal-prod/docker-compose.demo.yml \
  up --build
```

Optional hardened filesystem mode:

```bash
docker compose \
  -f blackcat-testing/docker/minimal-prod/docker-compose.yml \
  -f blackcat-testing/docker/minimal-prod/docker-compose.demo.yml \
  -f blackcat-testing/docker/minimal-prod/docker-compose.hardened-fs.yml \
  up --build
```

Open:
- Protected dashboard: `http://localhost:8088/`
- Unprotected demo (control target): `http://localhost:8089/`
- Raw status (protected): `http://localhost:8088/health`

The dashboard shows:
- `trusted_now`, `read_allowed`, `write_allowed`
- on-chain `active_root` + `active_policy_hash`
- the current failure reason (`error_codes` / `errors`) when the system fails closed

Optional:
- Debug status (not for monitoring): `http://localhost:8088/health/debug`

## 1.1) Optional: show funded demo wallets

If you want the dashboard to display a list of demo wallet addresses and their current balances (via JSON-RPC quorum),
set:

```bash
BLACKCAT_TESTING_DEMO_WALLETS=0xYourAddress1,0xYourAddress2 \
docker compose -f blackcat-testing/docker/minimal-prod/docker-compose.yml up --build
```

The container writes `/etc/blackcat/demo.wallets.public.json` (addresses only). Private keys are never shown.

## 2) What to say (high-level)

- The server does **not** trust local disk or hosting admins by default.
- The installation is “anchored” to an on-chain InstanceController:
  - integrity root (filesystem commitment)
  - security policy hash
  - runtime-config commitment (policy v3)
- If anything important diverges, the kernel fails closed and blocks sensitive operations.

## 3) Run scenarios (live tamper)

Scenarios are just compose overrides; see `docs/SCENARIOS.md`.

### A) Filesystem tamper (default)

The default stack schedules a tamper after `BLACKCAT_TESTING_TAMPER_AFTER_SEC` (default `40s`).
You should see:
- `trusted_now=true` initially
- after tamper: `trusted_now=false`, writes blocked, and errors visible on the dashboard

Note:
- In hardened read-only rootfs mode, “unexpected file in app root” tamper may be blocked by the filesystem.
  Use `BLACKCAT_TESTING_TAMPER_KIND=modify_config` or `modify_manifest` for a reliable demo.

### B) RPC outage → stale reads

```bash
docker compose \
  -f blackcat-testing/docker/minimal-prod/docker-compose.yml \
  -f blackcat-testing/docker/minimal-prod/docker-compose.rpc-outage.yml \
  up --build --abort-on-container-exit attacker
```

Expected:
- `rpc_ok_now=false`
- reads may stay allowed for `max_stale_sec` (stale-mode)
- writes stay blocked

### C) Byzantine RPC endpoint (quorum=2)

```bash
docker compose \
  -f blackcat-testing/docker/minimal-prod/docker-compose.yml \
  -f blackcat-testing/docker/minimal-prod/docker-compose.byzantine-rpc.yml \
  up --build --abort-on-container-exit attacker
```

Note: policy v3 commits to `trust.web3.rpc_endpoints` + `trust.web3.rpc_quorum`. If your InstanceController is locked to
the default config, you need a separate InstanceController for this scenario.

## 3.1) Secrets-agent mode (default)

By default, the demo runs with **secrets-agent mode enabled**:
- crypto key files are **root-owned** and not readable by the web runtime
- the web runtime uses a local UNIX socket (and the agent also enforces TrustKernel)

On the dashboard you can run:
- `Crypto roundtrip` (encrypt+decrypt)
- `Probe key file read` (must be denied by OS permissions)
- (When trust fails) `Probe secrets-agent bypass` (must be denied too)

To disable secrets-agent mode (not recommended), you must use a different InstanceController whose on-chain
runtime-config commitment matches the non-agent config:

```bash
BLACKCAT_TESTING_ENABLE_SECRETS_AGENT=0 \
docker compose \
  -f blackcat-testing/docker/minimal-prod/docker-compose.yml \
  -f blackcat-testing/docker/minimal-prod/docker-compose.demo.yml \
  up --build
```

## 3.2) On-chain “audit + upgrade” demo (operator-driven)

The protected dashboard includes a `On-chain upgrade info` panel (via `GET /demo/upgrade-info`) that prints:
- `component_id`
- the local `integrity_root` + policy hashes
- the runtime-config attestation keys (v1 + v2) and their on-chain values/lock state

Use it as a copy/paste source for Foundry scripts in `blackcat-kernel-contracts`.

Recommended operator runbooks:
- `blackcat-testing/docs/EDGEN_MINIMAL_PROD_RUNBOOK.md` (create a dedicated demo InstanceController)
- `blackcat-testing/docs/EDGEN_EXISTING_INSTANCE_UPGRADE.md` (upgrade an existing InstanceController without new contracts)

Security note:
- Do **not** bake your main authority private key into any image.
- For presentations, use a dedicated funded EOA and a dedicated demo InstanceController (treat it as public/dev).

## 4) Cleanup

```bash
docker compose \
  -f blackcat-testing/docker/minimal-prod/docker-compose.yml \
  -f blackcat-testing/docker/minimal-prod/docker-compose.demo.yml \
  down -v
```
