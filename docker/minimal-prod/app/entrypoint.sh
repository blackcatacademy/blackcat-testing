#!/bin/sh
set -eu

BOOT_MODE="${BLACKCAT_TESTING_BOOT_MODE:-run}"
FORCE_PROVISION="${BLACKCAT_TESTING_FORCE_PROVISION:-0}"

TAMPER_AFTER_SEC="${BLACKCAT_TESTING_TAMPER_AFTER_SEC:-0}"
TAMPER_KIND="${BLACKCAT_TESTING_TAMPER_KIND:-unexpected_file}"
RPC_SABOTAGE_AFTER_SEC="${BLACKCAT_TESTING_RPC_SABOTAGE_AFTER_SEC:-0}"

mkdir -p /etc/blackcat
chmod 0750 /etc/blackcat || true

ROOT_DIR="/srv/blackcat"
MANIFEST_PATH="/etc/blackcat/integrity.manifest.json"
CONFIG_PATH="/etc/blackcat/config.runtime.json"

CHAIN_ID="${BLACKCAT_TRUST_CHAIN_ID:-4207}"
RPC_ENDPOINTS="${BLACKCAT_TRUST_RPC_ENDPOINTS:-https://rpc.layeredge.io}"
RPC_QUORUM="${BLACKCAT_TRUST_RPC_QUORUM:-1}"
MODE="${BLACKCAT_TRUST_MODE:-full}"
MAX_STALE_SEC="${BLACKCAT_TRUST_MAX_STALE_SEC:-180}"
TIMEOUT_SEC="${BLACKCAT_TRUST_TIMEOUT_SEC:-5}"
INSTANCE_CONTROLLER="${BLACKCAT_INSTANCE_CONTROLLER:-}"

DB_DSN="${BLACKCAT_DB_DSN:-}"
DB_USER="${BLACKCAT_DB_USER:-}"
DB_PASS="${BLACKCAT_DB_PASS:-}"

if [ -z "$INSTANCE_CONTROLLER" ]; then
  echo "[entrypoint] missing BLACKCAT_INSTANCE_CONTROLLER" >&2
  exit 2
fi

export ROOT_DIR MANIFEST_PATH CONFIG_PATH FORCE_PROVISION
export CHAIN_ID RPC_ENDPOINTS RPC_QUORUM MODE MAX_STALE_SEC TIMEOUT_SEC INSTANCE_CONTROLLER
export DB_DSN DB_USER DB_PASS

php -r '
  $force = getenv("FORCE_PROVISION") === "1";
  $rootDir = getenv("ROOT_DIR");
  $manifestPath = getenv("MANIFEST_PATH");
  $configPath = getenv("CONFIG_PATH");

  require "/srv/blackcat/vendor/autoload.php";

  $rpcEndpointsRaw = (string) getenv("RPC_ENDPOINTS");
  $endpoints = array_values(array_filter(array_map("trim", explode(",", $rpcEndpointsRaw)), fn($v) => $v !== ""));

  $cfg = [
    "trust" => [
      "integrity" => [
        "root_dir" => $rootDir,
        "manifest" => $manifestPath,
      ],
      "web3" => [
        "chain_id" => (int) getenv("CHAIN_ID"),
        "rpc_endpoints" => $endpoints,
        "rpc_quorum" => (int) getenv("RPC_QUORUM"),
        "mode" => (string) getenv("MODE"),
        "max_stale_sec" => (int) getenv("MAX_STALE_SEC"),
        "timeout_sec" => (int) getenv("TIMEOUT_SEC"),
        "contracts" => [
          "instance_controller" => (string) getenv("INSTANCE_CONTROLLER"),
        ],
      ],
    ],
    "db" => [
      "dsn" => (string) getenv("DB_DSN"),
      "user" => (string) getenv("DB_USER"),
      "pass" => (string) getenv("DB_PASS"),
    ],
  ];

  $manifest = \BlackCat\Core\TrustKernel\IntegrityManifestBuilder::build($rootDir, null);
  if ($force || !is_file($manifestPath)) {
    file_put_contents($manifestPath, json_encode($manifest["manifest"], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT) . "\n");
  }

  if ($force || !is_file($configPath)) {
    file_put_contents($configPath, json_encode($cfg, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT) . "\n");
  }

  @chmod($manifestPath, 0644);
  @chmod($configPath, 0640);

  // Owner stays root; allow group-read for www-data (container runtime).
  @chgrp($configPath, "www-data");
  @chgrp(dirname($configPath), "www-data");

  $repo = \BlackCat\Config\Runtime\ConfigRepository::fromJsonFile($configPath);
  $tk = \BlackCat\Core\TrustKernel\TrustKernelConfig::fromRuntimeConfig(new \BlackCat\Core\TrustKernel\BlackCatConfigRepositoryAdapter($repo));
  if ($tk === null) {
    throw new \RuntimeException("trust.web3 not configured");
  }

  $attKey = $tk->runtimeConfigAttestationKey;
  $attVal = $tk->runtimeConfigCanonicalSha256;

  $out = [
    "integrity" => [
      "root_dir" => $rootDir,
      "manifest_path" => $manifestPath,
      "root" => $manifest["root"],
      "uri_hash" => $manifest["uri_hash"],
      "files_count" => $manifest["files_count"],
    ],
    "trust_policy" => [
      "mode" => $tk->mode,
      "max_stale_sec" => $tk->maxStaleSec,
      "policy_hash_v3_strict" => $tk->policyHashV3Strict,
      "policy_hash_v3_warn" => $tk->policyHashV3Warn,
    ],
    "attestation" => [
      "runtime_config_key" => $attKey,
      "runtime_config_value" => $attVal,
      "runtime_config_source_path" => $tk->runtimeConfigSourcePath,
    ],
  ];

  fwrite(STDERR, "[entrypoint] provisioning:\n" . json_encode($out, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES) . "\n");
'

if [ "$BOOT_MODE" = "compute" ]; then
  echo "[entrypoint] compute-only mode; exiting." >&2
  exit 0
fi

if [ "$TAMPER_AFTER_SEC" != "0" ] && [ "$TAMPER_AFTER_SEC" != "" ]; then
  (
    sleep "$TAMPER_AFTER_SEC" || exit 0
    echo "[entrypoint] simulating filesystem tamper (${TAMPER_KIND}) after ${TAMPER_AFTER_SEC}s" >&2

    case "$TAMPER_KIND" in
      unexpected_file)
        echo "tampered $(date -u +%FT%TZ)" > /srv/blackcat/site/public/.bc_tamper.txt || true
        ;;
      modify_file)
        printf "\n/* blackcat-testing tamper: %s */\n" "$(date -u +%FT%TZ)" >> /srv/blackcat/site/public/index.php || true
        ;;
      modify_config)
        php -r '
          $path = getenv("CONFIG_PATH") ?: "/etc/blackcat/config.runtime.json";
          $raw = @file_get_contents($path);
          if (!is_string($raw)) {
            fwrite(STDERR, "[entrypoint] unable to read runtime config: {$path}\n");
            exit(0);
          }
          try {
            $cfg = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
          } catch (Throwable $e) {
            fwrite(STDERR, "[entrypoint] runtime config is invalid JSON already: {$path}\n");
            exit(0);
          }
          if (!is_array($cfg)) {
            fwrite(STDERR, "[entrypoint] runtime config JSON is not an object/array: {$path}\n");
            exit(0);
          }
          $cfg["_blackcat_testing_tamper"] = [
            "at" => gmdate("c"),
            "note" => "simulated runtime-config tamper",
          ];
          file_put_contents($path, json_encode($cfg, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT) . "\n");
        ' || true
        ;;
      *)
        echo "[entrypoint] unknown TAMPER_KIND=${TAMPER_KIND}, skipping tamper" >&2
        ;;
    esac
  ) &
fi

if [ "$RPC_SABOTAGE_AFTER_SEC" != "0" ] && [ "$RPC_SABOTAGE_AFTER_SEC" != "" ]; then
  (
    sleep "$RPC_SABOTAGE_AFTER_SEC" || exit 0
    echo "[entrypoint] simulating RPC outage by poisoning /etc/hosts after ${RPC_SABOTAGE_AFTER_SEC}s" >&2
    if [ -w /etc/hosts ]; then
      echo "127.0.0.1 rpc.layeredge.io" >> /etc/hosts || true
    else
      echo "[entrypoint] /etc/hosts is not writable, cannot sabotage RPC" >&2
    fi
  ) &
fi

exec su -s /bin/sh -c "php -S 0.0.0.0:8080 -t /srv/blackcat/site/public" www-data
