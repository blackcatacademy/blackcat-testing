# blackcat-testing

Security-focused, production-like integration tests and attack-flow simulations for the BlackCat kernel stack:

- `blackcat-core` (TrustKernel, guards, integrity verification)
- `blackcat-config` (secure runtime config loading + validation)

This repo is intentionally **not** part of runtime code. It exists to validate security posture and regression-test
realistic failure/attack scenarios.

## Quick start (Docker)

The host machine does not need PHP installed.

```bash
docker run --rm -v "$PWD":/app -w /app composer:2.7 composer install
docker run --rm -v "$PWD":/app -w /app composer:2.7 composer test
docker run --rm -v "$PWD":/app -w /app composer:2.7 composer stan
```

### Optional: single “test-suite” image

Build (from `blackcatacademy` root):

```bash
docker build -f blackcat-testing/docker/test-suite/Dockerfile -t blackcat-testing-suite .
```

Run:

```bash
docker run --rm blackcat-testing-suite
```

## Demo dashboard (localhost)

This repo ships a tiny demo site for partners to observe the kernel status in real time, plus an intentionally
unprotected “control” site to compare behavior without BlackCat protections.

```bash
export BLACKCAT_INSTANCE_CONTROLLER=0x...   # required for a trusted-at-start demo
docker compose \
  -f docker/minimal-prod/docker-compose.yml \
  -f docker/minimal-prod/docker-compose.demo.yml \
  up --build
```

Defaults (Edgen, strict):
- RPC endpoints: `https://rpc.layeredge.io` + `https://edgenscan.io/api/eth-rpc`
- Quorum: `2` (fail-closed if any endpoint disagrees or is down; stale reads may apply depending on policy)

Open:
- `http://localhost:8088/` (protected dashboard)
- `http://localhost:8088/presentation.html` (partner/investor view: secure vs unprotected)
- `http://localhost:8089/` (unprotected demo)
- `http://localhost:8088/health` (protected raw JSON)
- `http://localhost:8088/demo/tx-outbox` (tx intents; incident reports, optional check-ins, audit-chain anchors)

Presentation script:
- `docs/PRESENTATION_DEMO.md`
Hardening notes:
- `docs/HARDENING_RECOMMENDATIONS.md`
Threat model:
- `docs/THREAT_MODEL_MATRIX.md`

### Optional: tx-outbox relayer (broadcast to chain)

The demo can optionally run a tx-outbox **relayer** (EOA) that broadcasts allowlisted tx intents.

Recommended production-like flow (no privileged relayer):
- `runner/secrets-agent` queue `sig.*.json` signature requests (`blackcat.sig_request`)
- `signer` signs EIP-712 typed data and converts them into `tx.*.json` (`blackcat.tx_request`)
- `relayer` broadcasts `tx.*.json` to the chain

```bash
SIGNER_PRIVATE_KEY=0x... \
RELAYER_PRIVATE_KEY=0x... \
docker compose \
  -f docker/minimal-prod/docker-compose.yml \
  -f docker/minimal-prod/docker-compose.demo.yml \
  -f docker/minimal-prod/docker-compose.signer.yml \
  -f docker/minimal-prod/docker-compose.relayer.yml \
  up --build
```

### Optional: on-chain watcher (auto-pause safety)

This repo also ships an optional **watcher** that can queue permissionless safety calls:
- `pauseIfStale()` (pauses when check-ins are stale beyond `maxCheckInAgeSec`)
- `pauseIfActiveRootUntrusted()` (pauses when the active root is no longer trusted by `ReleaseRegistry`)

The watcher only **queues tx intents** to the tx-outbox; broadcasting still requires the relayer.
Note: the simplest legacy flow is `BLACKCAT_TRUST_RUNNER_TX_MODE=direct` + relayer configured as `InstanceController.reporterAuthority`
(so `checkIn(...)` does not revert). Recommended flow is `authorized` + signer + `checkInAuthorized(...)`.

```bash
SIGNER_PRIVATE_KEY=0x... \
RELAYER_PRIVATE_KEY=0x... \
docker compose \
  -f docker/minimal-prod/docker-compose.yml \
  -f docker/minimal-prod/docker-compose.demo.yml \
  -f docker/minimal-prod/docker-compose.signer.yml \
  -f docker/minimal-prod/docker-compose.relayer.yml \
  -f docker/minimal-prod/docker-compose.watcher.yml \
  up --build
```

### Optional: hardened filesystem mode

Runs the demo with a read-only container root filesystem and only `/etc/blackcat` + `/var/lib/blackcat` writable:

```bash
docker compose \
  -f docker/minimal-prod/docker-compose.yml \
  -f docker/minimal-prod/docker-compose.demo.yml \
  -f docker/minimal-prod/docker-compose.hardened-fs.yml \
  up --build
```

### Compatibility note (when secrets-agent is not possible)

Some platforms cannot run a local secrets-agent boundary (UNIX sockets / multiple users/processes). The kernel still
provides **policy + integrity + fail-closed**, but without a secrets boundary an RCE-class compromise may still exfiltrate
any DB credentials or key material visible to the web runtime.

Mitigations are documented in:
- `docs/HARDENING_RECOMMENDATIONS.md`

## Test suites

- Offline (default): deterministic tests using a stub JSON-RPC transport (`tests/Support/StubWeb3Transport.php`).
- Live: optional smoke tests against a real chain (run explicitly with `composer test-live`).
- Workspace: security gate scans for obvious bypass surfaces (run explicitly with `composer test-workspace`).

See:
- `docs/ATTACK_FLOWS.md`
- `docs/LIVE_CHAIN.md`

## Note: `"symlink": false` vs symlink attack tests

`composer.json` uses `path` repositories with `"symlink": false` so the installed code under test is a real copy
(closer to production and friendlier for integrity verification). Separately, the test suite includes explicit
symlink-based attack flows to ensure the kernel rejects symlink files/directories used for tampering or bypasses.
