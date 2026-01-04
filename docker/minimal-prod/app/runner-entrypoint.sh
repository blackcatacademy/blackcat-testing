#!/bin/sh
set -eu

# Runner entrypoint (trust-runner container).
# IMPORTANT: /srv/blackcat is NOT shared between the `app` and `runner` containers.
# If we simulate a "filesystem tamper" only inside `app`, the `runner` would stay trusted
# because it verifies its own container filesystem. This wrapper allows the runner to
# simulate the same tamper so `/health` flips to untrusted as expected.

TAMPER_AFTER_SEC="${BLACKCAT_TESTING_TAMPER_AFTER_SEC:-0}"
TAMPER_KIND="${BLACKCAT_TESTING_TAMPER_KIND:-unexpected_file}"
TAMPER_MARKER="/etc/blackcat/.blackcat_testing_tamper_done"
RPC_SABOTAGE_AFTER_SEC="${BLACKCAT_TESTING_RPC_SABOTAGE_AFTER_SEC:-0}"

is_uint() {
  case "$1" in
    ''|*[!0-9]*)
      return 1
      ;;
    *)
      return 0
      ;;
  esac
}

schedule_filesystem_tamper() {
  if ! is_uint "$TAMPER_AFTER_SEC"; then
    return 0
  fi

  if [ "$TAMPER_AFTER_SEC" = "0" ]; then
    return 0
  fi

  case "$TAMPER_KIND" in
    unexpected_file|modify_file)
      ;;
    *)
      # Not a filesystem tamper that needs to be mirrored into this container.
      return 0
      ;;
  esac

  (
    sleep "$TAMPER_AFTER_SEC" || exit 0
    echo "[runner-entrypoint] simulating filesystem tamper (${TAMPER_KIND}) after ${TAMPER_AFTER_SEC}s" >&2

    case "$TAMPER_KIND" in
      unexpected_file)
        echo "tampered $(date -u +%FT%TZ) (runner)" > /srv/blackcat/site/public/.bc_tamper.txt || true
        ;;
      modify_file)
        printf "\n/* blackcat-testing tamper (runner): %s */\n" "$(date -u +%FT%TZ)" >> /srv/blackcat/site/public/index.php || true
        ;;
    esac

    echo "tampered $(date -u +%FT%TZ) kind=${TAMPER_KIND} (runner)" > "$TAMPER_MARKER" || true
    chmod 0640 "$TAMPER_MARKER" || true
    chgrp www-data "$TAMPER_MARKER" >/dev/null 2>&1 || true
  ) &
}

schedule_filesystem_tamper

schedule_rpc_outage() {
  if ! is_uint "$RPC_SABOTAGE_AFTER_SEC"; then
    return 0
  fi

  if [ "$RPC_SABOTAGE_AFTER_SEC" = "0" ]; then
    return 0
  fi

  (
    sleep "$RPC_SABOTAGE_AFTER_SEC" || exit 0
    echo "[runner-entrypoint] simulating RPC outage by poisoning /etc/hosts after ${RPC_SABOTAGE_AFTER_SEC}s" >&2
    if [ -w /etc/hosts ]; then
      printf '\n127.0.0.1 rpc.layeredge.io\n' >> /etc/hosts || true
      printf '\n::1 rpc.layeredge.io\n' >> /etc/hosts || true
    else
      echo "[runner-entrypoint] WARN: /etc/hosts is not writable; cannot sabotage RPC" >&2
    fi
  ) &
}

schedule_rpc_outage

exec php /srv/blackcat/site/bin/trust-runner.php
