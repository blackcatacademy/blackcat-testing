#!/bin/sh
set -eu

DB_DSN="${DB_DSN:-${BLACKCAT_DB_DSN:-}}"
DB_USER="${DB_USER:-${BLACKCAT_DB_USER:-}}"
DB_PASS="${DB_PASS:-${BLACKCAT_DB_PASS:-}}"

export DB_DSN DB_USER DB_PASS

if [ -z "$DB_DSN" ] || [ -z "$DB_USER" ] || [ -z "$DB_PASS" ]; then
  echo "[insecure-entrypoint] missing DB env (DB_DSN/DB_USER/DB_PASS)" >&2
  exit 2
fi

# Intentionally insecure: world-readable key file to illustrate exfiltration risk without a secrets boundary.
KEY_DIR="/srv/insecure/site/keys"
KEY_PATH="${INSECURE_KEYS_FILE:-${KEY_DIR}/crypto_key_v1.key}"

mkdir -p "$KEY_DIR"
chmod 0755 "$KEY_DIR" || true

if [ ! -f "$KEY_PATH" ]; then
  dd if=/dev/urandom of="$KEY_PATH" bs=32 count=1 >/dev/null 2>&1 || true
  chmod 0644 "$KEY_PATH" || true
fi

# Best-effort schema init (for demo buttons).
php -r '
  $dsn = (string) getenv("DB_DSN");
  $user = (string) getenv("DB_USER");
  $pass = (string) getenv("DB_PASS");
  $pdo = new PDO($dsn, $user, $pass, [
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

exec su -s /bin/sh -c "php -S 0.0.0.0:8080 -t /srv/insecure/site/public" www-data
