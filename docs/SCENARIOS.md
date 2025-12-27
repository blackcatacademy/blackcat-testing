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

## Notes

- These scenarios require a correctly provisioned on-chain `InstanceController` (see `docs/EDGEN_MINIMAL_PROD_RUNBOOK.md`).
- Increase `ATTACK_DURATION_SEC` to run longer (hours) once the setup is stable.

