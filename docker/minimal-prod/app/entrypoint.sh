#!/bin/sh
set -eu

BOOT_MODE="${BLACKCAT_TESTING_BOOT_MODE:-run}"
FORCE_PROVISION="${BLACKCAT_TESTING_FORCE_PROVISION:-0}"
EXIT_AFTER_TAMPER="${BLACKCAT_TESTING_EXIT_AFTER_TAMPER:-0}"
ENABLE_SECRETS_AGENT="${BLACKCAT_TESTING_ENABLE_SECRETS_AGENT:-1}"
LOCAL_RPC_PROXY="${BLACKCAT_TESTING_LOCAL_RPC_PROXY:-0}"
RPC_PROXY_PORT="${BLACKCAT_TESTING_RPC_PROXY_PORT:-8545}"
RPC_PROXY_UPSTREAM="${BLACKCAT_TESTING_RPC_PROXY_UPSTREAM:-}"
RPC_PROXY_SABOTAGE_AFTER_SEC="${BLACKCAT_TESTING_RPC_PROXY_SABOTAGE_AFTER_SEC:-0}"

TAMPER_AFTER_SEC="${BLACKCAT_TESTING_TAMPER_AFTER_SEC:-0}"
TAMPER_KIND="${BLACKCAT_TESTING_TAMPER_KIND:-unexpected_file}"
RPC_SABOTAGE_AFTER_SEC="${BLACKCAT_TESTING_RPC_SABOTAGE_AFTER_SEC:-0}"

mkdir -p /etc/blackcat
chmod 0750 /etc/blackcat || true

ROOT_DIR="/srv/blackcat"
MANIFEST_PATH="/etc/blackcat/integrity.manifest.json"
CONFIG_PATH="/etc/blackcat/config.runtime.json"
TAMPER_MARKER="/etc/blackcat/.blackcat_testing_tamper_done"
NO_REPROVISION_MARKER="/etc/blackcat/.blackcat_testing_disable_reprovision"

CHAIN_ID="${BLACKCAT_TRUST_CHAIN_ID:-4207}"
RPC_ENDPOINTS="${BLACKCAT_TRUST_RPC_ENDPOINTS:-https://rpc.layeredge.io,https://edgenscan.io/api/eth-rpc}"
RPC_QUORUM="${BLACKCAT_TRUST_RPC_QUORUM:-2}"
MODE="${BLACKCAT_TRUST_MODE:-full}"
MAX_STALE_SEC="${BLACKCAT_TRUST_MAX_STALE_SEC:-180}"
TIMEOUT_SEC="${BLACKCAT_TRUST_TIMEOUT_SEC:-5}"
INSTANCE_CONTROLLER="${BLACKCAT_INSTANCE_CONTROLLER:-}"

DB_DSN="${BLACKCAT_DB_DSN:-}"
DB_USER="${BLACKCAT_DB_USER:-}"
DB_PASS="${BLACKCAT_DB_PASS:-}"
DB_RO_USER="${BLACKCAT_DB_RO_USER:-blackcat_ro}"
DB_RO_PASS="${BLACKCAT_DB_RO_PASS:-blackcat_ro}"

if [ -z "$INSTANCE_CONTROLLER" ]; then
  echo "[entrypoint] missing BLACKCAT_INSTANCE_CONTROLLER" >&2
  exit 2
fi

export ROOT_DIR MANIFEST_PATH CONFIG_PATH FORCE_PROVISION
export NO_REPROVISION_MARKER
export CHAIN_ID RPC_ENDPOINTS RPC_QUORUM MODE MAX_STALE_SEC TIMEOUT_SEC INSTANCE_CONTROLLER
export DB_DSN DB_USER DB_PASS
export DB_RO_USER DB_RO_PASS
export ENABLE_SECRETS_AGENT

php -r '
  $force = getenv("FORCE_PROVISION") === "1";
  $noReprovisionMarker = getenv("NO_REPROVISION_MARKER") ?: "";
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
  ];

  if (getenv("ENABLE_SECRETS_AGENT") === "1") {
    $cfg["crypto"] = [
      "keys_dir" => "/etc/blackcat/keys",
      "agent" => [
        "socket_path" => "/etc/blackcat/secrets-agent.sock",
      ],
    ];

    $cfg["db"] = [
      "agent" => [
        "socket_path" => "/etc/blackcat/secrets-agent.sock",
      ],
      "credentials_file" => "/etc/blackcat/db.credentials.json",
    ];
  }

  $manifest = \BlackCat\Core\TrustKernel\IntegrityManifestBuilder::build($rootDir, null);
  $noReprovision = !$force && is_string($noReprovisionMarker) && $noReprovisionMarker !== "" && file_exists($noReprovisionMarker);

  if (!$noReprovision && ($force || !is_file($manifestPath))) {
      file_put_contents($manifestPath, json_encode($manifest["manifest"], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT) . "\n");
  }

  if (!$noReprovision && ($force || !is_file($configPath))) {
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

if [ "$ENABLE_SECRETS_AGENT" = "1" ]; then
  echo "[entrypoint] provisioning root-owned crypto key files (secrets-agent mode)" >&2
  php -r '
    $dir = "/etc/blackcat/keys";
    if (!is_dir($dir)) {
      @mkdir($dir, 0700, true);
    }
    @chmod($dir, 0700);
    $path = $dir . "/crypto_key_v1.key";
    if (!is_file($path)) {
      $raw = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);
      file_put_contents($path, $raw);
      @chmod($path, 0400);
    }
  '

  echo "[entrypoint] provisioning root-owned DB credentials file (secrets-agent mode)" >&2
  php -r '
    $path = "/etc/blackcat/db.credentials.json";
    if (is_link($path)) {
      throw new RuntimeException("Refusing symlink db.credentials.json");
    }

    $dsn = (string) getenv("DB_DSN");
    $rwUser = (string) getenv("DB_USER");
    $rwPass = (string) getenv("DB_PASS");
    $roUser = (string) getenv("DB_RO_USER");
    $roPass = (string) getenv("DB_RO_PASS");

    if ($dsn === "" || $rwUser === "" || $rwPass === "" || $roUser === "" || $roPass === "") {
      throw new RuntimeException("Missing DB credential env vars (DB_DSN/DB_USER/DB_PASS/DB_RO_USER/DB_RO_PASS).");
    }

    $payload = [
      "read" => ["dsn" => $dsn, "user" => $roUser, "pass" => $roPass],
      "write" => ["dsn" => $dsn, "user" => $rwUser, "pass" => $rwPass],
      "meta" => ["created_at" => gmdate("c")],
    ];

    $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    if (!is_string($json)) {
      throw new RuntimeException("Unable to encode db.credentials.json");
    }

    $tmp = $path . ".tmp-" . bin2hex(random_bytes(6));
    file_put_contents($tmp, $json . "\n");
    @chmod($tmp, 0600);
    if (!@rename($tmp, $path)) {
      @unlink($tmp);
      throw new RuntimeException("Unable to move db.credentials.json into place");
    }
    @chmod($path, 0600);
  '

  echo "[entrypoint] starting secrets agent (root) on unix socket" >&2
  php /srv/blackcat/site/bin/secrets-agent.php &
  agent_pid="$!"

  # Fail-closed: do not continue boot if the agent is expected but not running.
  i="0"
  while [ "$i" -lt 50 ]; do
    if [ -S "/etc/blackcat/secrets-agent.sock" ]; then
      break
    fi
    i="$((i + 1))"
    sleep 0.1 || true
  done

  if [ ! -S "/etc/blackcat/secrets-agent.sock" ]; then
    echo "[entrypoint] ERROR: secrets-agent did not create its unix socket (pid=${agent_pid})" >&2
    kill "${agent_pid}" >/dev/null 2>&1 || true
    exit 2
  fi
fi

# Provision a minimal schema so read-only endpoints can function during stale-read mode.
# In real deployments schema/migrations are handled out-of-band; this is only for blackcat-testing.
if [ "${BLACKCAT_TESTING_PROVISION_DB_SCHEMA:-1}" = "1" ]; then
  if [ -n "$DB_DSN" ]; then
    php -r '
      $dsn = (string) getenv("DB_DSN");
      $user = getenv("DB_USER");
      $pass = getenv("DB_PASS");
      if ($dsn === "") {
        exit(0);
      }
      $pdo = new PDO($dsn, is_string($user) ? $user : null, is_string($pass) ? $pass : null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => false,
      ]);
      $pdo->exec(
        "CREATE TABLE IF NOT EXISTS bc_test_events (\n"
        . "  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,\n"
        . "  msg VARCHAR(255) NOT NULL,\n"
        . "  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,\n"
        . "  PRIMARY KEY (id)\n"
        . ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
      );
    ' || true
  fi
fi

if [ -f "$TAMPER_MARKER" ]; then
  echo "[entrypoint] tamper marker exists, disabling tamper scheduling: ${TAMPER_MARKER}" >&2
  TAMPER_AFTER_SEC="0"
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
      swap_controller)
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
          $cfg["trust"]["web3"]["contracts"]["instance_controller"] = "0x2222222222222222222222222222222222222222";
          file_put_contents($path, json_encode($cfg, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT) . "\n");
        ' || true
        ;;
      corrupt_config)
        printf '{broken_json' > "$CONFIG_PATH" || true
        ;;
      delete_config)
        rm -f "$CONFIG_PATH" || true
        echo "1" > "$NO_REPROVISION_MARKER" || true
        chmod 0640 "$NO_REPROVISION_MARKER" || true
        ;;
      modify_manifest)
        php -r '
          $path = getenv("MANIFEST_PATH") ?: "/etc/blackcat/integrity.manifest.json";
          $raw = @file_get_contents($path);
          if (!is_string($raw)) {
            fwrite(STDERR, "[entrypoint] unable to read integrity manifest: {$path}\n");
            exit(0);
          }
          try {
            $m = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
          } catch (Throwable $e) {
            fwrite(STDERR, "[entrypoint] integrity manifest is invalid JSON already: {$path}\n");
            exit(0);
          }
          if (!is_array($m) || !isset($m["files"]) || !is_array($m["files"]) || $m["files"] === []) {
            fwrite(STDERR, "[entrypoint] integrity manifest has no files: {$path}\n");
            exit(0);
          }
          $k = array_key_first($m["files"]);
          if (!is_string($k)) {
            exit(0);
          }
          $h = $m["files"][$k] ?? null;
          if (is_string($h) && str_starts_with($h, "0x") && strlen($h) === 66) {
            $last = substr($h, -1);
            $flip = $last === "0" ? "1" : "0";
            $m["files"][$k] = substr($h, 0, -1) . $flip;
          } else {
            $m["files"][$k] = "0x" . str_repeat("00", 32);
          }
          file_put_contents($path, json_encode($m, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT) . "\n");
        ' || true
        ;;
      corrupt_manifest)
        printf '{broken_json' > "$MANIFEST_PATH" || true
        ;;
      delete_manifest)
        rm -f "$MANIFEST_PATH" || true
        echo "1" > "$NO_REPROVISION_MARKER" || true
        chmod 0640 "$NO_REPROVISION_MARKER" || true
        ;;
      *)
        echo "[entrypoint] unknown TAMPER_KIND=${TAMPER_KIND}, skipping tamper" >&2
        ;;
    esac

    echo "tampered $(date -u +%FT%TZ) kind=${TAMPER_KIND}" > "$TAMPER_MARKER" || true
    chmod 0640 "$TAMPER_MARKER" || true

    if [ "$EXIT_AFTER_TAMPER" = "1" ]; then
      echo "[entrypoint] exit-after-tamper enabled; stopping container to simulate reboot/restart" >&2
      kill -TERM 1 || true
      sleep 2 || true
      kill -KILL 1 || true
    fi
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

if [ "$LOCAL_RPC_PROXY" = "1" ]; then
  if [ -z "$RPC_PROXY_UPSTREAM" ]; then
    echo "[entrypoint] missing BLACKCAT_TESTING_RPC_PROXY_UPSTREAM" >&2
    echo "[entrypoint] TIP: set it to one of BLACKCAT_TRUST_RPC_ENDPOINTS (must be https)" >&2
    exit 2
  fi

  case "$RPC_PROXY_UPSTREAM" in
    https://*) ;;
    *)
      echo "[entrypoint] BLACKCAT_TESTING_RPC_PROXY_UPSTREAM must be https (got: ${RPC_PROXY_UPSTREAM})" >&2
      exit 2
      ;;
  esac

  export BLACKCAT_TESTING_RPC_PROXY_UPSTREAM="$RPC_PROXY_UPSTREAM"
  export BLACKCAT_TESTING_RPC_PROXY_SABOTAGE_AFTER_SEC="$RPC_PROXY_SABOTAGE_AFTER_SEC"
  export BLACKCAT_TESTING_RPC_PROXY_STARTED_AT="$(date +%s)"

  echo "[entrypoint] starting local RPC proxy on 127.0.0.1:${RPC_PROXY_PORT} (upstream=${RPC_PROXY_UPSTREAM})" >&2
  php -S "127.0.0.1:${RPC_PROXY_PORT}" -t /srv/blackcat/site/rpc-proxy >/dev/null 2>&1 &
fi

unset BLACKCAT_DB_DSN BLACKCAT_DB_USER BLACKCAT_DB_PASS BLACKCAT_DB_RO_USER BLACKCAT_DB_RO_PASS || true
unset DB_DSN DB_USER DB_PASS DB_RO_USER DB_RO_PASS || true

exec su -s /bin/sh -c "php -S 0.0.0.0:8080 -t /srv/blackcat/site/public" www-data
