# Production-like harness (docker + live chain)

`blackcat-testing` is intended to be the **final** system test that simulates production as closely as possible:

- a real web runtime (HTTP entrypoint),
- a real database container,
- a real chain (Edgen, EVM),
- continuous “attacker” traffic + tamper scenarios over time.

This is separate from unit tests inside individual repos. Those should stay in the repo they belong to.

## Directory layout

- `environments/minimal-site/` — the target “website” used for testing.
- `docker/minimal-prod/` — docker-compose stack for the minimal site + DB + attacker.

## Runbooks

- Edgen (chain_id `4207`): `docs/EDGEN_MINIMAL_PROD_RUNBOOK.md`
- Scenarios: `docs/SCENARIOS.md`

## Typical flow (high level)

1) Build/boot the docker stack.
2) Compute the integrity root + policy hash for the current container filesystem.
3) Commit the upgrade + runtime-config attestation on-chain (InstanceController).
4) Run long-running traffic + attack/tamper flows (hours, if needed).

## Logs and reports

The `attacker` container writes:

- JSONL events: `blackcat-testing/var/harness/minimal-prod/logs/events.<run_id>.jsonl`
- JSON summary: `blackcat-testing/var/harness/minimal-prod/logs/summary.<run_id>.json`

## Security note

This harness never commits private keys to git. Broadcast keys must be provided at runtime via env/secret managers.
