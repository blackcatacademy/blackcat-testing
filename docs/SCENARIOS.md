# Scenarios

`blackcat-testing` is designed to run **long-running, production-like** checks against a real chain and real services.

This file lists the currently supported harness scenarios.

## A) Filesystem tamper (default)

Uses:
- `BLACKCAT_TESTING_TAMPER_AFTER_SEC` (in `app`)
- `EXPECT_TRUST_FAIL_AFTER_TAMPER=1` (in `attacker`)

Expected outcome:
- before tamper: `trusted_now=true`
- after tamper: `trusted_now=false`, requests start failing (fail-closed)

Run:

```bash
docker compose -f blackcat-testing/docker/minimal-prod/docker-compose.yml up --build --abort-on-container-exit attacker
```

## B) RPC outage → stale reads (override)

This simulates an RPC outage by poisoning `/etc/hosts` in the `app` container after some time.

Override file:
- `docker/minimal-prod/docker-compose.rpc-outage.yml`

Expected outcome:
- after RPC outage: `rpc_ok_now=false`
- during `max_stale_sec`: `read_allowed=true`, `write_allowed=false`

Run:

```bash
docker compose \
  -f blackcat-testing/docker/minimal-prod/docker-compose.yml \
  -f blackcat-testing/docker/minimal-prod/docker-compose.rpc-outage.yml \
  up --build --abort-on-container-exit attacker
```

## C) Runtime config tamper (override)

This simulates runtime-config tampering (editing `config.runtime.json` after boot).

Override file:
- `docker/minimal-prod/docker-compose.config-tamper.yml`

Expected outcome:
- after tamper: `trusted_now=false`, `read_allowed=false`, `write_allowed=false`
- `error_codes` should include `runtime_config_source_changed` (or `runtime_config_source_invalid`)

Run:

```bash
docker compose \
  -f blackcat-testing/docker/minimal-prod/docker-compose.yml \
  -f blackcat-testing/docker/minimal-prod/docker-compose.config-tamper.yml \
  up --build --abort-on-container-exit attacker
```

## D) Runtime config tamper + app restart (override)

This simulates a timed attacker flow:

1) tamper `config.runtime.json`
2) force a runtime restart (to try to load the tampered config)

Override file:
- `docker/minimal-prod/docker-compose.config-tamper-restart.yml`

Expected outcome:
- after restart: TrustKernel still fails closed (policy v3 will mismatch on-chain commitment)
- `trusted_now=false`, `read_allowed=false`, `write_allowed=false`
- `error_codes` should include `runtime_config_commitment_mismatch` (and/or `runtime_config_source_changed`)

Run:

```bash
docker compose \
  -f blackcat-testing/docker/minimal-prod/docker-compose.yml \
  -f blackcat-testing/docker/minimal-prod/docker-compose.config-tamper-restart.yml \
  up --build --abort-on-container-exit attacker
```

## E) Integrity manifest tamper + app restart (override)

This simulates tampering with `integrity.manifest.json` and then restarting the runtime.

Override file:
- `docker/minimal-prod/docker-compose.manifest-tamper-restart.yml`

Expected outcome:
- after restart: `trusted_now=false` (integrity check fails)
- `error_codes` should include `integrity_hash_mismatch` (or `integrity_check_failed`)

Run:

```bash
docker compose \
  -f blackcat-testing/docker/minimal-prod/docker-compose.yml \
  -f blackcat-testing/docker/minimal-prod/docker-compose.manifest-tamper-restart.yml \
  up --build --abort-on-container-exit attacker
```

## F) Runtime config delete + app restart (override)

This simulates an attacker deleting `config.runtime.json` and triggering a restart.

Override file:
- `docker/minimal-prod/docker-compose.config-delete-restart.yml`

Expected outcome:
- after restart: kernel bootstrap fails → `/health` becomes unavailable (503/000) (fail-closed)

Run:

```bash
docker compose \
  -f blackcat-testing/docker/minimal-prod/docker-compose.yml \
  -f blackcat-testing/docker/minimal-prod/docker-compose.config-delete-restart.yml \
  up --build --abort-on-container-exit attacker
```

## G) Runtime config corrupt + app restart (override)

This simulates runtime config corruption (invalid JSON) and a restart.

Override file:
- `docker/minimal-prod/docker-compose.config-corrupt-restart.yml`

Expected outcome:
- after restart: kernel bootstrap fails → `/health` becomes unavailable (503/000) (fail-closed)

Run:

```bash
docker compose \
  -f blackcat-testing/docker/minimal-prod/docker-compose.yml \
  -f blackcat-testing/docker/minimal-prod/docker-compose.config-corrupt-restart.yml \
  up --build --abort-on-container-exit attacker
```

## H) Controller swap + app restart (override)

This simulates an attacker trying to redirect trust to a different `InstanceController` by editing runtime config.

Override file:
- `docker/minimal-prod/docker-compose.controller-swap-restart.yml`

Expected outcome:
- after restart: policy v3 detects `runtime_config_commitment_mismatch` → fail-closed

Run:

```bash
docker compose \
  -f blackcat-testing/docker/minimal-prod/docker-compose.yml \
  -f blackcat-testing/docker/minimal-prod/docker-compose.controller-swap-restart.yml \
  up --build --abort-on-container-exit attacker
```

## I) Byzantine RPC endpoint (quorum=2) (override)

This simulates a “Byzantine” RPC: the second endpoint is a localhost proxy that initially forwards to the real RPC,
then starts mutating JSON-RPC responses after `BLACKCAT_TESTING_RPC_PROXY_SABOTAGE_AFTER_SEC`.

Override file:
- `docker/minimal-prod/docker-compose.byzantine-rpc.yml`

Expected outcome:
- before sabotage: `trusted_now=true`
- after sabotage: `rpc_ok_now=false` (quorum not met), writes blocked, reads may stay allowed until `max_stale_sec`

Important:
- Policy v3 runtime-config attestation commits to `trust.web3.rpc_endpoints` + `trust.web3.rpc_quorum`.
- If your on-chain InstanceController is locked to the default multi-endpoint config, the byzantine-proxy config
  is a different runtime config and must use a separate InstanceController (separate install).

Run:

```bash
docker compose \
  -f blackcat-testing/docker/minimal-prod/docker-compose.yml \
  -f blackcat-testing/docker/minimal-prod/docker-compose.byzantine-rpc.yml \
  up --build --abort-on-container-exit attacker
```

## J) Soak (baseline, no tamper) (override)

This is a long-running stability/performance run with **no tamper** by default.

Override file:
- `docker/minimal-prod/docker-compose.soak.yml`

Expected outcome:
- `trusted_now=true` for the full run (no fail-closed trigger)
- `/health` stays available

Run:

```bash
docker compose \
  -f blackcat-testing/docker/minimal-prod/docker-compose.yml \
  -f blackcat-testing/docker/minimal-prod/docker-compose.soak.yml \
  up --build --abort-on-container-exit attacker
```

## K) Secrets-agent (optional)

This enables a privileged secrets agent that serves crypto keys over a UNIX socket, while key files remain
root-owned and unreadable by the web runtime user.

Enable:

```bash
BLACKCAT_TESTING_ENABLE_SECRETS_AGENT=1 \
docker compose -f blackcat-testing/docker/minimal-prod/docker-compose.yml up --build --abort-on-container-exit attacker
```

Expected outcome (when crypto is configured and trust is OK):
- `/bypass/keys` returns `403` (web runtime cannot read key files directly)
- `/crypto/roundtrip` returns `200` only when TrustKernel `read_allowed=true`

Important:
- Policy v3 commits to the runtime config JSON. Enabling this changes the committed hash, so use an InstanceController
  whose runtime-config attestation matches the secrets-agent-enabled config.

## Notes

- These scenarios require a correctly provisioned on-chain `InstanceController` (see `docs/EDGEN_MINIMAL_PROD_RUNBOOK.md`).
- Increase `ATTACK_DURATION_SEC` to run longer (hours) once the setup is stable.
