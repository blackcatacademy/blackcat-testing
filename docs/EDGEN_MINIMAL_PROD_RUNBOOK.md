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

## Step 1: Compute integrity root + policy hash (docker, local)

From the `blackcatacademy` root:

```bash
docker compose -f blackcat-testing/docker/minimal-prod/docker-compose.yml build app
docker compose -f blackcat-testing/docker/minimal-prod/docker-compose.yml run --rm --no-deps -e BLACKCAT_TESTING_BOOT_MODE=compute app
```

Copy these values from the output:

- `integrity.root` (bytes32)
- `trust_policy.policy_hash_v3_strict` (bytes32)
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
- `attestation.runtime_config_value`

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
- policy v3 strict (requires runtime-config commitment)
- runtime-config commitment (attested + locked)

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
