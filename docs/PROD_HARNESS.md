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

## Typical flow (high level)

1) Build/boot the docker stack.
2) Compute the integrity root + policy hash for the current container filesystem.
3) Commit the upgrade + runtime-config attestation on-chain (InstanceController).
4) Run long-running traffic + attack/tamper flows (hours, if needed).

## Security note

This harness never commits private keys to git. Broadcast keys must be provided at runtime via env/secret managers.

