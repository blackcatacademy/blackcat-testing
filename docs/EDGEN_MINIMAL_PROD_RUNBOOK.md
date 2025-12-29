# Edgen minimal production runbook (blackcat-testing)

Goal: run a **production-like**, long-running system test of the minimal BlackCat kernel stack:

- `blackcat-core` (TrustKernel + guards + HTTP kernel)
- `blackcat-config` (secure runtime config)
- `blackcat-kernel-contracts` (InstanceController on Edgen Chain)

This harness spins up:

- `app` (PHP built-in HTTP server, minimal site)
- `db` (MariaDB)
- `attacker` (traffic + attack probes + assertions)

## Prerequisites

1) You have deployed the kernel contracts to Edgen (`chain_id=4207`).
   - See: `blackcat-kernel-contracts/docs/DEPLOY_EDGEN.md`

2) You have an `InstanceFactory` address (from the deployment output).

3) You have a funded test EOA (or Safe / KernelAuthority) for broadcasting.

4) Decide your RPC quorum config (strict recommended).
   - Recommended endpoints: `https://rpc.layeredge.io` and `https://edgenscan.io/api/eth-rpc`
   - Recommended quorum: `2`
   - Note: `trust.web3.rpc_endpoints` and `trust.web3.rpc_quorum` are part of the runtime-config attestation and
     become immutable once locked on-chain for a given installation.

5) Secrets-agent mode is enabled by default.
   - To disable (not recommended), set `BLACKCAT_TESTING_ENABLE_SECRETS_AGENT=0`.
   - Switching secrets-agent on/off changes the runtime config JSON and therefore changes the policy v3 runtime-config
     attestation value. Keep your choice consistent for Steps 1–5 so the on-chain commitment matches.

## Step 1: Compute integrity root + policy hash (docker, local)

From the `blackcatacademy` root:

```bash
docker compose -f blackcat-testing/docker/minimal-prod/docker-compose.yml build app
docker compose -f blackcat-testing/docker/minimal-prod/docker-compose.yml run --rm --no-deps -e BLACKCAT_TESTING_BOOT_MODE=compute app
```

Copy these values from the output:

- `integrity.root` (bytes32)
- recommended: `trust_policy.policy_hash_v4_strict` (bytes32)
  - v4 strict additionally requires on-chain commitments for:
    - `composer.lock` (canonical JSON sha256)
    - PHP fingerprint (v2; multi-SAPI stable)
    - `/etc/blackcat/image.digest` (sha256 bytes32)
  - these attestation keys/values are also printed in the compute output (Step 3).
- alternative (older): `trust_policy.policy_hash_v3_strict` (bytes32)
- If `integrity.uri_hash` is `null`, use `0x0000000000000000000000000000000000000000000000000000000000000000`.

## Step 2: Create a new InstanceController (genesis)

Use Foundry script from `blackcat-kernel-contracts`:

```bash
cd blackcat-kernel-contracts

cat > .env <<'EOF'
PRIVATE_KEY=0x...

BLACKCAT_INSTANCE_FACTORY=0x...

BLACKCAT_ROOT_AUTHORITY=0x...
BLACKCAT_UPGRADE_AUTHORITY=0x...
BLACKCAT_EMERGENCY_AUTHORITY=0x...

BLACKCAT_GENESIS_ROOT=0x...
BLACKCAT_GENESIS_URI_HASH=0x0000000000000000000000000000000000000000000000000000000000000000
BLACKCAT_GENESIS_POLICY_HASH=0x...
EOF

docker run --rm \
  --env-file .env \
  -v "$PWD":/app \
  -w /app \
  --entrypoint forge \
  ghcr.io/foundry-rs/foundry:stable \
  script script/CreateInstance.s.sol:CreateInstance --rpc-url edgen --chain-id 4207 --broadcast -vvvv
```

Record the created `InstanceController` address from the script output / transaction.

## Step 3: Compute runtime-config attestation for the real InstanceController

Set your real controller address for the compose stack (no file edits needed):

```bash
export BLACKCAT_INSTANCE_CONTROLLER=0x...
```

Then run compute again (now the canonical config hash will include the correct controller address):

```bash
docker compose -f blackcat-testing/docker/minimal-prod/docker-compose.yml run --rm --no-deps -e BLACKCAT_TESTING_BOOT_MODE=compute app
```

Copy:

- `attestation.runtime_config_key`
- `attestation.runtime_config_key_v2` (rotation key)
- `attestation.runtime_config_value`

If you selected policy v4 strict (recommended), also copy:

- `attestation.composer_lock_key_v1`
- `attestation.composer_lock_value_v1`
- `attestation.php_fingerprint_key_v2`
- `attestation.php_fingerprint_value_v2`
- `attestation.image_digest_key_v1`
- `attestation.image_digest_value_v1`

## Step 4: Set + lock the runtime-config attestation on-chain

In `blackcat-kernel-contracts`:

```bash
cd blackcat-kernel-contracts

cat > .env.attest <<'EOF'
PRIVATE_KEY=0x...
BLACKCAT_INSTANCE_CONTROLLER=0x...
BLACKCAT_ATTESTATION_KEY=0x...
BLACKCAT_ATTESTATION_VALUE=0x...
EOF

docker run --rm \
  --env-file .env.attest \
  -v "$PWD":/app \
  -w /app \
  --entrypoint forge \
  ghcr.io/foundry-rs/foundry:stable \
  script script/SetAttestationAndLock.s.sol:SetAttestationAndLock --rpc-url edgen --chain-id 4207 --broadcast -vvvv
```

At this point the chain is committed to:

- the integrity root (genesis)
- your chosen policy hash (v3 or v4)
- runtime-config commitment (attested + locked)

### Policy v4: set + lock additional attestations (recommended)

If you selected `trust_policy.policy_hash_v4_strict` (or v4 warn), you must also set+lock the additional keys
*before* you start the runtime (otherwise TrustKernel will fail-closed):

Repeat Step 4 three more times (same script, different key/value):

1) composer.lock

```bash
export BLACKCAT_ATTESTATION_KEY=0x...   # attestation.composer_lock_key_v1
export BLACKCAT_ATTESTATION_VALUE=0x... # attestation.composer_lock_value_v1
```

2) PHP fingerprint (v2)

```bash
export BLACKCAT_ATTESTATION_KEY=0x...   # attestation.php_fingerprint_key_v2
export BLACKCAT_ATTESTATION_VALUE=0x... # attestation.php_fingerprint_value_v2
```

3) image digest

```bash
export BLACKCAT_ATTESTATION_KEY=0x...   # attestation.image_digest_key_v1
export BLACKCAT_ATTESTATION_VALUE=0x... # attestation.image_digest_value_v1
```

Notes:
- This harness auto-writes `/etc/blackcat/image.digest` (derived from the current build) unless you provide
  `BLACKCAT_TESTING_IMAGE_DIGEST` (e.g. an OCI digest like `sha256:<hex>`).
- In a real deployment, treat `image.digest` as an externally verifiable “build artifact” digest (OCI image digest,
  signed release, etc).

### Policy v3 rotation (when v1 key is already locked)

If your installation already locked `attestation.runtime_config_key` on-chain and you later change the runtime config
schema (e.g. moving DB credentials into the secrets boundary), you must **rotate** the commitment key instead of trying
to overwrite the locked key:

- set+lock `attestation.runtime_config_key_v2` to the new `attestation.runtime_config_value`
- upgrade the InstanceController `activePolicyHash` to `trust_policy.policy_hash_v3_strict_v2`

This avoids creating a new InstanceController (no new contracts), while keeping the system fail-closed.

For policy v4, the same idea applies:
- set+lock the rotated runtime-config key `attestation.runtime_config_key_v2`
- upgrade the `activePolicyHash` to `trust_policy.policy_hash_v4_strict_v2`

## Step 5: Run the long-running harness

From the `blackcatacademy` root:

```bash
docker compose -f blackcat-testing/docker/minimal-prod/docker-compose.yml up --build --abort-on-container-exit attacker
```

The default compose config:

- generates load (`ATTACK_RPS`)
- simulates filesystem tamper after `BLACKCAT_TESTING_TAMPER_AFTER_SEC`
- expects trust to fail after tamper

Tune duration/attack rate/tamper knobs in `blackcat-testing/docker/minimal-prod/docker-compose.yml`.

For a **soak** run (hours, no tamper by default), add:

```bash
docker compose \
  -f blackcat-testing/docker/minimal-prod/docker-compose.yml \
  -f blackcat-testing/docker/minimal-prod/docker-compose.soak.yml \
  up --build --abort-on-container-exit attacker
```

Recommended extra assertion (fails fast if provisioning is wrong):

```bash
export EXPECT_TRUST_OK_AT_START=1
```

## Cleanup

```bash
docker compose -f blackcat-testing/docker/minimal-prod/docker-compose.yml down -v
```
