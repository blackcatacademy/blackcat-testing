# Edgen Live-chain Minimal Prod Harness Report (NEXT RUN)

This file is a **template for the next live-chain run** after updating on-chain state to match the current `main` of:

- `blackcat-core`
- `blackcat-config`
- `blackcat-testing`

It records the **new computed integrity root** and the **runtime-config attestation value(s)** so the on-chain
`InstanceController` can be provisioned accordingly.

No private keys belong in this repo.

## Pre-flight (computed values)

Computed from:

```bash
docker compose -f blackcat-testing/docker/minimal-prod/docker-compose.yml build app
docker compose -f blackcat-testing/docker/minimal-prod/docker-compose.yml run --rm --no-deps -e BLACKCAT_TESTING_BOOT_MODE=compute app
```

- Network: Edgen Chain (`chain_id=4207`)
- Integrity root (current image): `0xffb8609f3cf778b93f27e06423398876df44b800550b0201c277b647ba34df8e`
- Policy hash (v3 strict): `0x9bfd6b85a20e830ad44702b98f652553b1c0870c3a30b804d9e0ed0303e23cc6`
- Policy hash (v3 warn): `0xa1709103984a9beed0a481c300797eca28f46d9b30d1ec4e944e36e12e2232b4`
- Runtime-config attestation key (v3): `0x09a17e002a8d8186967ccbf26197cc17f053f4a00a10bc7c147eac903b5ed70b`

Runtime-config attestation **values** depend on whether secrets-agent mode is enabled at provision time:

- Default (`BLACKCAT_TESTING_ENABLE_SECRETS_AGENT=1`): `0xe7cb4b4003e09cbf0bf09e22eb6c4a559d2d375d533a45aa3bb03580d2abf173`
- Disabled (`BLACKCAT_TESTING_ENABLE_SECRETS_AGENT=0`): `0x1d8c02f633723a53a62c6b2428870a17da707b171be5f673732b7268c6cbbb50`

Important:

- Policy v3 **requires** the on-chain runtime-config commitment to match the runtime config JSON.
- The attestation key is locked on-chain per install, so treat the config as immutable after locking.

## On-chain setup (to fill)

- ReleaseRegistry: `...`
- InstanceController: `...`
- Genesis root: `0xffb8609f3cf778b93f27e06423398876df44b800550b0201c277b647ba34df8e`
- Genesis policy hash: `0x9bfd6b85a20e830ad44702b98f652553b1c0870c3a30b804d9e0ed0303e23cc6`
- Runtime-config attestation value: `...` (pick one above, depending on your chosen mode)

Tx hashes:
- Publish release: `...`
- Propose upgrade: `...`
- Activate upgrade: `...`
- Set+lock runtime-config attestation: `...`

## Harness run (to fill)

Run IDs + summaries live under:

- `blackcat-testing/var/harness/minimal-prod/logs/summary.<run_id>.json`

Scenarios:

- Baseline tamper: `PASS|FAIL` (run_id: `...`)
- RPC outage + stale reads: `PASS|FAIL` (run_id: `...`)
- Runtime config tamper: `PASS|FAIL` (run_id: `...`)
- Runtime config tamper + restart: `PASS|FAIL` (run_id: `...`)
- Manifest tamper + restart: `PASS|FAIL` (run_id: `...`)
- Byzantine RPC (quorum=2): `PASS|FAIL` (run_id: `...`)
- Soak (no tamper): `PASS|FAIL` (run_id: `...`)

Optional scenarios:

- Secrets-agent mode is default in this harness:
  - `/bypass/keys` must be denied (403) when keys are root-owned.
  - `/bypass/agent` must be denied (403) when TrustKernel `read_allowed=false`.
  - `/crypto/roundtrip` must be denied when TrustKernel `read_allowed=false`.

## Notes / Observations (to fill)

- Any unexpected `error_codes`:
- Any performance notes (RPC latency, CPU, memory):
- Any false positives/negatives from attacker probes:
