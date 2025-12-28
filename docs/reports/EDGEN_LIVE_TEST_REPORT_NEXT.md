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
- Integrity root (current image): `0x1771629ae4e9837bb6c29d6ab1296a35508fbc986c48f3d56a3483add2267ed6`
- Policy hash (v3 strict): `0x9bfd6b85a20e830ad44702b98f652553b1c0870c3a30b804d9e0ed0303e23cc6`
- Policy hash (v3 warn): `0xa1709103984a9beed0a481c300797eca28f46d9b30d1ec4e944e36e12e2232b4`
- Policy hash (v3 strict, v2 attestation key): `0xb69c25723bce4a373f73923211da2f9124cc52a51261c2eb2263d4fea6a3e6ed`
- Policy hash (v3 warn, v2 attestation key): `0xed806a9db43103c16c6a06cf0cd8f59c1b7d7b16d87a41a3680989db9d09a329`
- Runtime-config attestation key (v3, v1): `0x09a17e002a8d8186967ccbf26197cc17f053f4a00a10bc7c147eac903b5ed70b`
- Runtime-config attestation key (v3, v2 rotation): `0xdca04fb7003fcfce49413b5c55aaaef33aad292b414340ebf61ef8bd478a0cec`

Runtime-config attestation values:

- Default (`BLACKCAT_TESTING_ENABLE_SECRETS_AGENT=1`): `0x7f319ccc7879d2750d89d0fee7adfcf3dbd4ccaefd22160b6f252b01616f5de7`

Important:

- Policy v3 requires the on-chain runtime-config commitment to match the runtime config JSON.
- The attestation key is locked on-chain per install, so treat the config as immutable after locking.
  - If `runtime_config_key` (v1) is already locked, rotate to `runtime_config_key_v2` and upgrade the policy hash to
    `policy_hash_v3_strict_v2` (or warn).

## On-chain setup (to fill)

- ReleaseRegistry: `...`
- InstanceController: `...`
- Upgrade target root: `0x1771629ae4e9837bb6c29d6ab1296a35508fbc986c48f3d56a3483add2267ed6`
- Upgrade target policy hash:
  - legacy v3 (v1 key): `0x9bfd6b85a20e830ad44702b98f652553b1c0870c3a30b804d9e0ed0303e23cc6`
  - rotation v3 (v2 key): `0xb69c25723bce4a373f73923211da2f9124cc52a51261c2eb2263d4fea6a3e6ed`
- Runtime-config attestation (rotation v2):
  - key: `0xdca04fb7003fcfce49413b5c55aaaef33aad292b414340ebf61ef8bd478a0cec`
  - value: `0x7f319ccc7879d2750d89d0fee7adfcf3dbd4ccaefd22160b6f252b01616f5de7`

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
