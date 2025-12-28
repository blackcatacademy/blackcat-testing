# Edgen Live-chain Minimal Prod Harness Report (2025-12-28)

This report documents live-chain integration testing on **Edgen Chain** (EVM, `chain_id=4207`) for the **minimal BlackCat security stack**:

- `blackcat-core` TrustKernel (`policy v3`, strict-by-default, fail-closed)
- `blackcat-config` runtime config (file-based, security validation)
- `blackcat-kernel-contracts` on-chain authority (InstanceController + ReleaseRegistry)
- `blackcat-testing` production-like docker harness (traffic + attack probes)

No private keys are included; only public addresses and transaction hashes.

## Chain / Contracts

- Network: Edgen Chain (`chain_id=4207`)
- RPC: `https://rpc.layeredge.io`
- ReleaseRegistry: `0x22681Ee2153B7B25bA6772B44c160BB60f4C333E`
- InstanceController (test installation): `0xae32F6d7BF7C155Cd099BD0Cc0F80048A0275137`
- ComponentId: `0x9772f74df4547efb0d338a9ed09381198a50ae4eb5c38050888baa9da59b9a18`
- Policy hash (v3 strict): `0x9bfd6b85a20e830ad44702b98f652553b1c0870c3a30b804d9e0ed0303e23cc6`
- Runtime-config attestation key (locked on-chain): `0x09a17e002a8d8186967ccbf26197cc17f053f4a00a10bc7c147eac903b5ed70b`
- Active root (after upgrade in this report): `0xb6264415068b7a48be7a1b8d289e7d037d83ffffc6e05e6786eb59e247290b2f`
- Active URI hash: `0x0000000000000000000000000000000000000000000000000000000000000000`

## On-chain actions performed (root alignment)

During this test run, the on-chain `activeRoot` was updated to match the current minimal-prod image content.

- Publish release (version `12`) tx: `0x7daec8f1a8a8aac42e0996600b032155fed1a6391d0236179254cf58f342055c`
- Propose upgrade by release tx: `0x6f8169f6a70e25ac9b457ca5507b529cfb34b8a854223ca97f76a4d0e86091a6`
- Activate upgrade tx: `0xf8a97358c4b9c9d3d4da4d5c43bd0fece9eeffb7d25b9532895167f418cb3ff9`

Explorer (Blockscout / edgenscan):

- `https://edgenscan.io/address/0x22681Ee2153B7B25bA6772B44c160BB60f4C333E`
- `https://edgenscan.io/address/0xae32F6d7BF7C155Cd099BD0Cc0F80048A0275137`
- `https://edgenscan.io/tx/0x7daec8f1a8a8aac42e0996600b032155fed1a6391d0236179254cf58f342055c`
- `https://edgenscan.io/tx/0x6f8169f6a70e25ac9b457ca5507b529cfb34b8a854223ca97f76a4d0e86091a6`
- `https://edgenscan.io/tx/0xf8a97358c4b9c9d3d4da4d5c43bd0fece9eeffb7d25b9532895167f418cb3ff9`

## Test harness (docker/minimal-prod)

Services:

- `db`: MariaDB 11
- `app`: PHP 8.3 built-in server + `BlackCat\Core\Kernel\HttpKernel` (strict gate at request entry)
- `runner`: periodic TrustKernel `check()` loop (health + persists last-known-good snapshot file)
- `attacker`: traffic generator + attack probes; writes logs to `var/harness/minimal-prod/logs`

All scenario logs are stored as:

- `blackcat-testing/var/harness/minimal-prod/logs/meta.<run_id>.json`
- `blackcat-testing/var/harness/minimal-prod/logs/events.<run_id>.jsonl`
- `blackcat-testing/var/harness/minimal-prod/logs/summary.<run_id>.json`

## Scenarios executed (live chain)

### 1) Baseline integrity tamper (unexpected file)

- Compose: `docker-compose.yml` (default tamper: `unexpected_file` at 40s)
- Expected: trust OK at start, then fail after tamper (fail-closed)
- Result: PASS
- Run ID: `20251228T001950Z.622038241d5a`
- Summary: `blackcat-testing/var/harness/minimal-prod/logs/summary.20251228T001950Z.622038241d5a.json`

Observed:

- `/health`: 200 throughout (monitoring endpoint stays available)
- After tamper: request entry is denied (`/db/read` and `/db/write` return 503)

### 2) RPC outage + stale-read window

- Compose: `docker-compose.yml` + `docker-compose.rpc-outage.yml` (poison `rpc.layeredge.io` after 30s)
- Expected: when RPC is down, `rpc_ok_now=false` but `read_allowed=true` within `max_stale_sec`; writes must be denied
- Result: PASS
- Run ID: `20251228T003529Z.45a60c256bac`
- Summary: `blackcat-testing/var/harness/minimal-prod/logs/summary.20251228T003529Z.45a60c256bac.json`

Observed:

- `/db/read`: 200 during outage window
- `/db/write`: 403 during outage window
- Final health: `error_codes=["rpc_error"]`

### 3) Runtime config tamper (modify file)

- Compose: `docker-compose.yml` + `docker-compose.config-tamper.yml`
- Expected: strict mode rejects any runtime-config modification under policy v3
- Result: PASS
- Run ID: `20251228T004651Z.eddeeb252307`
- Summary: `blackcat-testing/var/harness/minimal-prod/logs/summary.20251228T004651Z.eddeeb252307.json`

Observed:

- `error_codes=["runtime_config_commitment_mismatch"]`
- Request entry denied (503) after tamper.

### 4) Runtime config tamper + restart

- Compose: `docker-compose.yml` + `docker-compose.config-tamper-restart.yml` (app restarts after tamper)
- Expected: after restart, the corrupted/modified config remains and the system stays fail-closed
- Result: PASS
- Run ID: `20251228T005814Z.a1a1bd9446dd`
- Summary: `blackcat-testing/var/harness/minimal-prod/logs/summary.20251228T005814Z.a1a1bd9446dd.json`

Observed:

- Temporary downtime during restart (`http_code=0` in the attacker summary), then stable fail-closed (503).

### 5) Integrity manifest tamper + restart

- Compose: `docker-compose.yml` + `docker-compose.manifest-tamper-restart.yml`
- Expected: after restart, integrity verification fails and request entry is denied
- Result: PASS
- Run ID: `20251228T011619Z.a004b5809157`
- Summary: `blackcat-testing/var/harness/minimal-prod/logs/summary.20251228T011619Z.a004b5809157.json`

Observed:

- Deny-by-default after restart (503 on sensitive endpoints).

### 6) Soak test (5 minutes)

- Compose: `docker-compose.yml` + `docker-compose.soak.yml`
- Parameters used: `ATTACK_DURATION_SEC=300`, `ATTACK_RPS=5`, tamper disabled
- Expected: stable trust in strict mode; reads+writes work; PDO bypass always denied
- Result: PASS
- Run ID: `20251228T010729Z.462622197541`
- Summary: `blackcat-testing/var/harness/minimal-prod/logs/summary.20251228T010729Z.462622197541.json`

Observed:

- `/db/read`: 200
- `/db/write`: 200
- `/bypass/pdo`: 403
- `/health`: strict + trusted throughout

## Not executed / special notes

- `docker-compose.byzantine-rpc.yml` cannot be executed on the same `InstanceController` once policy v3 runtime-config attestation is locked, because changing `trust.web3.rpc_endpoints` / `rpc_quorum` changes the committed config hash. To test multi-RPC quorum, create a separate `InstanceController` whose on-chain runtime-config attestation matches the multi-endpoint config.

## Next run

New commits change the integrity root of the minimal-prod image. For the next live-chain run (with updated on-chain
state), use `docs/reports/EDGEN_LIVE_TEST_REPORT_NEXT.md`.
