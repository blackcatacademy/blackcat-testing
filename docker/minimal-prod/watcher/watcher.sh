#!/bin/sh
set -eu

umask 007

log() {
  printf '%s %s\n' "[watcher]" "$*" >&2
}

fail() {
  log "ERROR: $*"
  exit 2
}

trim() {
  # shellcheck disable=SC2001
  printf '%s' "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

is_evm_address() {
  case "$1" in
    0x[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]) return 0 ;;
    *) return 1 ;;
  esac
}

is_bytes32() {
  case "$1" in
    0x[0-9a-fA-F]*)
      [ "${#1}" -eq 66 ] || return 1
      printf '%s' "$1" | tr -d '0-9a-fA-Fx' | grep -q . && return 1
      return 0
      ;;
    *) return 1 ;;
  esac
}

is_bool() {
  case "$(trim "$1")" in
    true|false|0|1) return 0 ;;
    *) return 1 ;;
  esac
}

bool_is_true() {
  case "$(trim "$1")" in
    true|1) return 0 ;;
    *) return 1 ;;
  esac
}

is_uint() {
  v="$(trim "$1")"
  [ "$v" != "" ] || return 1
  case "$v" in
    *[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

rand_hex_8() {
  # 8 bytes random as hex (no xxd dependency).
  od -An -N8 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n'
}

CONFIG_PATH="${BLACKCAT_CONFIG_PATH:-/etc/blackcat/config.runtime.json}"
if [ ! -f "$CONFIG_PATH" ]; then
  fail "runtime config is missing: ${CONFIG_PATH}"
fi
if [ -L "$CONFIG_PATH" ]; then
  fail "refusing symlink runtime config: ${CONFIG_PATH}"
fi
if [ ! -r "$CONFIG_PATH" ]; then
  fail "runtime config is not readable: ${CONFIG_PATH}"
fi

OUTBOX_DIR="$(jq -r '.trust.web3.tx_outbox_dir // empty' "$CONFIG_PATH" | head -n 1)"
CHAIN_ID="$(jq -r '.trust.web3.chain_id // empty' "$CONFIG_PATH" | head -n 1)"
CONTROLLER="$(jq -r '.trust.web3.contracts.instance_controller // empty' "$CONFIG_PATH" | head -n 1)"

[ "$(trim "$OUTBOX_DIR")" != "" ] || fail "trust.web3.tx_outbox_dir is missing in runtime config"
[ "$(trim "$CHAIN_ID")" != "" ] || fail "trust.web3.chain_id is missing in runtime config"
[ "$(trim "$CONTROLLER")" != "" ] || fail "trust.web3.contracts.instance_controller is missing in runtime config"

OUTBOX_DIR="$(trim "$OUTBOX_DIR")"
CHAIN_ID="$(trim "$CHAIN_ID")"
CONTROLLER="$(trim "$CONTROLLER")"

case "$OUTBOX_DIR" in
  /var/lib/blackcat/*) ;;
  *) fail "refusing tx_outbox_dir outside /var/lib/blackcat: ${OUTBOX_DIR}" ;;
esac

case "$CHAIN_ID" in
  ''|*[!0-9]*) fail "invalid chain_id (expected integer): ${CHAIN_ID}" ;;
esac

is_evm_address "$CONTROLLER" || fail "invalid instance_controller address: ${CONTROLLER}"

RPC_ENDPOINTS="$(jq -r '.trust.web3.rpc_endpoints[]? // empty' "$CONFIG_PATH")"
[ "$(trim "$RPC_ENDPOINTS")" != "" ] || fail "trust.web3.rpc_endpoints is missing/empty"

# Default: HTTPS-only.
ALLOW_HTTP_LOCAL="${WATCHER_ALLOW_HTTP_LOCALHOST:-0}"
VALID_RPC_ENDPOINTS=""
for rpc in $RPC_ENDPOINTS; do
  rpc="$(trim "$rpc")"
  [ "$rpc" != "" ] || continue
  case "$rpc" in
    https://*)
      VALID_RPC_ENDPOINTS="${VALID_RPC_ENDPOINTS}${rpc}\n"
      ;;
    http://localhost/*|http://127.0.0.1/*|http://[::1]/*)
      if [ "$ALLOW_HTTP_LOCAL" = "1" ]; then
        VALID_RPC_ENDPOINTS="${VALID_RPC_ENDPOINTS}${rpc}\n"
      else
        fail "insecure rpc endpoint refused (set WATCHER_ALLOW_HTTP_LOCALHOST=1 to allow localhost http): ${rpc}"
      fi
      ;;
    *)
      fail "unsupported rpc endpoint scheme (expected https://): ${rpc}"
      ;;
  esac
done

if [ "$(printf '%b' "$VALID_RPC_ENDPOINTS" | wc -l | tr -d ' ')" -lt 1 ]; then
  fail "no valid rpc endpoints after filtering"
fi

POLL_INTERVAL_SEC="${WATCHER_POLL_INTERVAL_SEC:-10}"
case "$POLL_INTERVAL_SEC" in
  ''|*[!0-9]*) fail "invalid WATCHER_POLL_INTERVAL_SEC (expected int)" ;;
esac
if [ "$POLL_INTERVAL_SEC" -lt 1 ]; then
  POLL_INTERVAL_SEC="1"
fi
if [ "$POLL_INTERVAL_SEC" -gt 300 ]; then
  POLL_INTERVAL_SEC="300"
fi

DEBOUNCE_SEC="${WATCHER_DEBOUNCE_SEC:-60}"
case "$DEBOUNCE_SEC" in
  ''|*[!0-9]*) fail "invalid WATCHER_DEBOUNCE_SEC (expected int)" ;;
esac
if [ "$DEBOUNCE_SEC" -lt 5 ]; then
  DEBOUNCE_SEC="5"
fi
if [ "$DEBOUNCE_SEC" -gt 3600 ]; then
  DEBOUNCE_SEC="3600"
fi

DRY_RUN="${WATCHER_DRY_RUN:-0}"
case "$DRY_RUN" in
  0|1) ;;
  *) fail "invalid WATCHER_DRY_RUN (expected 0|1)" ;;
esac

ENABLE_STALE_CHECKIN="${WATCHER_ENABLE_STALE_CHECKIN:-1}"
case "$ENABLE_STALE_CHECKIN" in
  0|1) ;;
  *) fail "invalid WATCHER_ENABLE_STALE_CHECKIN (expected 0|1)" ;;
esac

ENABLE_ACTIVE_ROOT_UNTRUSTED="${WATCHER_ENABLE_ACTIVE_ROOT_UNTRUSTED:-1}"
case "$ENABLE_ACTIVE_ROOT_UNTRUSTED" in
  0|1) ;;
  *) fail "invalid WATCHER_ENABLE_ACTIVE_ROOT_UNTRUSTED (expected 0|1)" ;;
esac

mkdir -p "$OUTBOX_DIR" || true
mkdir -p "$OUTBOX_DIR/processing" "$OUTBOX_DIR/sent" "$OUTBOX_DIR/failed" || true

select_rpc() {
  for rpc in $(printf '%b' "$VALID_RPC_ENDPOINTS"); do
    cid="$(cast chain-id --rpc-url "$rpc" 2>/dev/null || true)"
    cid="$(trim "$cid")"
    if [ "$cid" = "$CHAIN_ID" ]; then
      printf '%s' "$rpc"
      return 0
    fi
  done
  return 1
}

enqueue_tx() {
  method="$1"
  kind="$2"
  metaJson="$3"

  now="$(date +%s)"
  createdAt="$(date -u +%FT%TZ)"
  rand="$(rand_hex_8)"

  tmp="$OUTBOX_DIR/.tx.${now}.${rand}.tmp"
  dst="$OUTBOX_DIR/tx.${now}.${rand}.json"

  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN: would enqueue ${method} (${kind})"
    return 0
  fi

  # metaJson is expected to be a JSON object; fallback to {}.
  metaOk="$(printf '%s' "$metaJson" | jq -c '.' 2>/dev/null || true)"
  if [ "$(trim "$metaOk")" = "" ]; then
    metaOk="{}"
  fi

  jq -n \
    --arg created_at "$createdAt" \
    --arg to "$CONTROLLER" \
    --arg method "$method" \
    --arg kind "$kind" \
    --argjson meta "$metaOk" \
    '{
      schema_version: 1,
      type: "blackcat.tx_request",
      created_at: $created_at,
      to: $to,
      method: $method,
      args: [],
      meta: ({source:"watcher", kind:$kind} + $meta)
    }' > "$tmp"

  mv "$tmp" "$dst"
  log "outbox: queued ${method} (${kind}) -> $(basename "$dst")"
}

lastStaleAt="0"
lastRootUntrustedAt="0"

log "starting (chain_id=${CHAIN_ID} controller=${CONTROLLER} outbox=${OUTBOX_DIR} poll=${POLL_INTERVAL_SEC}s debounce=${DEBOUNCE_SEC}s dry_run=${DRY_RUN})"

while true; do
  rpc="$(select_rpc || true)"
  if [ "$(trim "$rpc")" = "" ]; then
    log "WARN: no healthy rpc endpoint with matching chain_id"
    sleep "$POLL_INTERVAL_SEC" || true
    continue
  fi

  paused="$(cast call --rpc-url "$rpc" "$CONTROLLER" "paused()(bool)" 2>/dev/null || true)"
  paused="$(trim "$paused")"
  if ! is_bool "$paused"; then
    log "WARN: unable to read paused()"
    sleep "$POLL_INTERVAL_SEC" || true
    continue
  fi

  if bool_is_true "$paused"; then
    sleep "$POLL_INTERVAL_SEC" || true
    continue
  fi

  now="$(date +%s)"

  if [ "$ENABLE_STALE_CHECKIN" = "1" ]; then
    since="$((now - lastStaleAt))"
    if [ "$lastStaleAt" -eq 0 ] || [ "$since" -ge "$DEBOUNCE_SEC" ]; then
      maxAge="$(cast call --rpc-url "$rpc" "$CONTROLLER" "maxCheckInAgeSec()(uint64)" 2>/dev/null || true)"
      maxAge="$(trim "$maxAge")"

      if is_uint "$maxAge" && [ "$maxAge" -gt 0 ]; then
        lastAt="$(cast call --rpc-url "$rpc" "$CONTROLLER" "lastCheckInAt()(uint64)" 2>/dev/null || true)"
        lastAt="$(trim "$lastAt")"
        genesisAt="$(cast call --rpc-url "$rpc" "$CONTROLLER" "genesisAt()(uint64)" 2>/dev/null || true)"
        genesisAt="$(trim "$genesisAt")"

        if is_uint "$lastAt" && is_uint "$genesisAt"; then
          base="$genesisAt"
          if [ "$lastAt" -gt 0 ]; then
            base="$lastAt"
          fi
          cutoff="$((base + maxAge))"
          if [ "$now" -gt "$cutoff" ]; then
            enqueue_tx "pauseIfStale()" "stale_checkin" "$(jq -n --argjson now "$now" --argjson cutoff "$cutoff" --argjson base "$base" --argjson max_age "$maxAge" --argjson last_checkin "$lastAt" --argjson genesis "$genesisAt" '{now:$now,cutoff:$cutoff,base:$base,max_checkin_age_sec:$max_age,last_checkin_at:$last_checkin,genesis_at:$genesis}')"
            lastStaleAt="$now"
          fi
        fi
      fi
    fi
  fi

  if [ "$ENABLE_ACTIVE_ROOT_UNTRUSTED" = "1" ]; then
    since="$((now - lastRootUntrustedAt))"
    if [ "$lastRootUntrustedAt" -eq 0 ] || [ "$since" -ge "$DEBOUNCE_SEC" ]; then
      registry="$(cast call --rpc-url "$rpc" "$CONTROLLER" "releaseRegistry()(address)" 2>/dev/null || true)"
      registry="$(trim "$registry")"
      # normalize address casing
      if is_evm_address "$registry"; then
        regLower="$(printf '%s' "$registry" | tr 'A-F' 'a-f')"
        if [ "$regLower" != "0x0000000000000000000000000000000000000000" ]; then
          root="$(cast call --rpc-url "$rpc" "$CONTROLLER" "activeRoot()(bytes32)" 2>/dev/null || true)"
          root="$(trim "$root")"
          if is_bytes32 "$root"; then
            trusted="$(cast call --rpc-url "$rpc" "$registry" "isTrustedRoot(bytes32)(bool)" "$root" 2>/dev/null || true)"
            trusted="$(trim "$trusted")"
            if is_bool "$trusted" && ! bool_is_true "$trusted"; then
              enqueue_tx "pauseIfActiveRootUntrusted()" "active_root_untrusted" "$(jq -n --arg registry "$registry" --arg root "$root" '{release_registry:$registry,active_root:$root}')"
              lastRootUntrustedAt="$now"
            fi
          fi
        fi
      fi
    fi
  fi

  sleep "$POLL_INTERVAL_SEC" || true
done

