# Edgen: upgrade an existing InstanceController (no new contracts)

This runbook upgrades an existing BlackCat installation on **Edgen Chain** (`chain_id=4207`) by:

1) publishing a new release root to `ReleaseRegistry`
2) rotating the runtime-config commitment to a **new attestation key** (v2)
3) upgrading the `InstanceController` to the new `{activeRoot, activePolicyHash}`

No new `InstanceController` contracts are deployed.

## Target (current workspace build)

Computed by:

```bash
BLACKCAT_INSTANCE_CONTROLLER=0xae32F6d7BF7C155Cd099BD0Cc0F80048A0275137 \
docker compose -f blackcat-testing/docker/minimal-prod/docker-compose.yml run --rm --no-deps \
  -e BLACKCAT_TESTING_BOOT_MODE=compute app
```

Values:

- InstanceController: `0xae32F6d7BF7C155Cd099BD0Cc0F80048A0275137`
- ReleaseRegistry: `0x22681Ee2153B7B25bA6772B44c160BB60f4C333E`
- ComponentId: `0x9772f74df4547efb0d338a9ed09381198a50ae4eb5c38050888baa9da59b9a18`
- Current on-chain release version: `12`
- Next release version: `13`
- Upgrade root: `0x1771629ae4e9837bb6c29d6ab1296a35508fbc986c48f3d56a3483add2267ed6`
- Upgrade uriHash: `0x0000000000000000000000000000000000000000000000000000000000000000`
- Upgrade policy hash (strict, v2 commitment key): `0xb69c25723bce4a373f73923211da2f9124cc52a51261c2eb2263d4fea6a3e6ed`
- Runtime-config attestation key (v2): `0xdca04fb7003fcfce49413b5c55aaaef33aad292b414340ebf61ef8bd478a0cec`
- Runtime-config attestation value: `0x7f319ccc7879d2750d89d0fee7adfcf3dbd4ccaefd22160b6f252b01616f5de7`

Why rotation:

- The v1 runtime-config key is already **locked on-chain**.
- If the runtime config schema changes, you must rotate to a new key and upgrade the policy hash accordingly.

## Prerequisites

- You have a funded EOA that is:
  - `ReleaseRegistry.owner()`
  - `InstanceController.rootAuthority()`
  - `InstanceController.upgradeAuthority()`
- Do not commit private keys. Prefer env files that are gitignored.

## 1) Publish release (version 13)

From `blackcatacademy` root:

```bash
cd blackcat-kernel-contracts

export PRIVATE_KEY=0x...
export BLACKCAT_RELEASE_REGISTRY=0x22681Ee2153B7B25bA6772B44c160BB60f4C333E
export BLACKCAT_COMPONENT_ID=0x9772f74df4547efb0d338a9ed09381198a50ae4eb5c38050888baa9da59b9a18
export BLACKCAT_RELEASE_VERSION=13
export BLACKCAT_RELEASE_ROOT=0x1771629ae4e9837bb6c29d6ab1296a35508fbc986c48f3d56a3483add2267ed6
export BLACKCAT_RELEASE_URI_HASH=0x0000000000000000000000000000000000000000000000000000000000000000
export BLACKCAT_RELEASE_META_HASH=0x0000000000000000000000000000000000000000000000000000000000000000

docker run --rm \
  -e PRIVATE_KEY \
  -e BLACKCAT_RELEASE_REGISTRY \
  -e BLACKCAT_COMPONENT_ID \
  -e BLACKCAT_RELEASE_VERSION \
  -e BLACKCAT_RELEASE_ROOT \
  -e BLACKCAT_RELEASE_URI_HASH \
  -e BLACKCAT_RELEASE_META_HASH \
  -v "$PWD":/app -w /app --entrypoint forge \
  ghcr.io/foundry-rs/foundry:stable \
  script script/PublishRelease.s.sol:PublishRelease --rpc-url edgen --chain-id 4207 --broadcast -vvvv
```

## 2) Set + lock runtime-config attestation (v2 key)

```bash
cd blackcat-kernel-contracts

export PRIVATE_KEY=0x...
export BLACKCAT_INSTANCE_CONTROLLER=0xae32F6d7BF7C155Cd099BD0Cc0F80048A0275137
export BLACKCAT_ATTESTATION_KEY=0xdca04fb7003fcfce49413b5c55aaaef33aad292b414340ebf61ef8bd478a0cec
export BLACKCAT_ATTESTATION_VALUE=0x7f319ccc7879d2750d89d0fee7adfcf3dbd4ccaefd22160b6f252b01616f5de7

docker run --rm \
  -e PRIVATE_KEY \
  -e BLACKCAT_INSTANCE_CONTROLLER \
  -e BLACKCAT_ATTESTATION_KEY \
  -e BLACKCAT_ATTESTATION_VALUE \
  -v "$PWD":/app -w /app --entrypoint forge \
  ghcr.io/foundry-rs/foundry:stable \
  script script/SetAttestationAndLock.s.sol:SetAttestationAndLock --rpc-url edgen --chain-id 4207 --broadcast -vvvv
```

Policy v4 note (if you are upgrading to a v4 policy hash):
- you must also set+lock the additional v4 attestations (composer.lock / PHP fingerprint / image digest) before
  activating the upgrade, otherwise the runtime will fail-closed.
- use the same script (`SetAttestationAndLock`) with the corresponding key/value pairs (see
  `blackcat-testing/docs/EDGEN_MINIMAL_PROD_RUNBOOK.md` Step 4).

## 3) Propose upgrade by release

```bash
cd blackcat-kernel-contracts

export PRIVATE_KEY=0x...
export BLACKCAT_INSTANCE_CONTROLLER=0xae32F6d7BF7C155Cd099BD0Cc0F80048A0275137
export BLACKCAT_COMPONENT_ID=0x9772f74df4547efb0d338a9ed09381198a50ae4eb5c38050888baa9da59b9a18
export BLACKCAT_RELEASE_VERSION=13
export BLACKCAT_UPGRADE_POLICY_HASH=0xb69c25723bce4a373f73923211da2f9124cc52a51261c2eb2263d4fea6a3e6ed
export BLACKCAT_UPGRADE_TTL_SEC=3600

docker run --rm \
  -e PRIVATE_KEY \
  -e BLACKCAT_INSTANCE_CONTROLLER \
  -e BLACKCAT_COMPONENT_ID \
  -e BLACKCAT_RELEASE_VERSION \
  -e BLACKCAT_UPGRADE_POLICY_HASH \
  -e BLACKCAT_UPGRADE_TTL_SEC \
  -v "$PWD":/app -w /app --entrypoint forge \
  ghcr.io/foundry-rs/foundry:stable \
  script script/ProposeUpgradeByRelease.s.sol:ProposeUpgradeByRelease --rpc-url edgen --chain-id 4207 --broadcast -vvvv
```

Wait at least `minUpgradeDelaySec` (currently `5s`), then activate.

## 4) Activate upgrade (expected)

```bash
cd blackcat-kernel-contracts

sleep 6

export PRIVATE_KEY=0x...
export BLACKCAT_INSTANCE_CONTROLLER=0xae32F6d7BF7C155Cd099BD0Cc0F80048A0275137
export BLACKCAT_UPGRADE_ROOT=0x1771629ae4e9837bb6c29d6ab1296a35508fbc986c48f3d56a3483add2267ed6
export BLACKCAT_UPGRADE_URI_HASH=0x0000000000000000000000000000000000000000000000000000000000000000
export BLACKCAT_UPGRADE_POLICY_HASH=0xb69c25723bce4a373f73923211da2f9124cc52a51261c2eb2263d4fea6a3e6ed

docker run --rm \
  -e PRIVATE_KEY \
  -e BLACKCAT_INSTANCE_CONTROLLER \
  -e BLACKCAT_UPGRADE_ROOT \
  -e BLACKCAT_UPGRADE_URI_HASH \
  -e BLACKCAT_UPGRADE_POLICY_HASH \
  -v "$PWD":/app -w /app --entrypoint forge \
  ghcr.io/foundry-rs/foundry:stable \
  script script/ActivateUpgradeExpected.s.sol:ActivateUpgradeExpected --rpc-url edgen --chain-id 4207 --broadcast -vvvv
```

## 5) Verify (read-only)

```bash
cd blackcat-kernel-contracts

docker run --rm -v "$PWD":/app -w /app --entrypoint cast ghcr.io/foundry-rs/foundry:stable \
  call --rpc-url edgen 0xae32F6d7BF7C155Cd099BD0Cc0F80048A0275137 "activeRoot()(bytes32)"

docker run --rm -v "$PWD":/app -w /app --entrypoint cast ghcr.io/foundry-rs/foundry:stable \
  call --rpc-url edgen 0xae32F6d7BF7C155Cd099BD0Cc0F80048A0275137 "activePolicyHash()(bytes32)"

docker run --rm -v "$PWD":/app -w /app --entrypoint cast ghcr.io/foundry-rs/foundry:stable \
  call --rpc-url edgen 0xae32F6d7BF7C155Cd099BD0Cc0F80048A0275137 \
  "attestations(bytes32)(bytes32)" 0xdca04fb7003fcfce49413b5c55aaaef33aad292b414340ebf61ef8bd478a0cec
```

## 6) Run the harness (live chain)

```bash
cd ..

BLACKCAT_INSTANCE_CONTROLLER=0xae32F6d7BF7C155Cd099BD0Cc0F80048A0275137 \
docker compose \
  -f blackcat-testing/docker/minimal-prod/docker-compose.yml \
  up --build --abort-on-container-exit attacker
```
