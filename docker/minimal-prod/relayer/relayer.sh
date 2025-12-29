#!/bin/sh
set -eu

umask 007

log() {
  printf '%s %s\n' "[relayer]" "$*" >&2
}

fail() {
  log "ERROR: $*"
  exit 2
}

is_evm_address() {
  case "$1" in
    0x[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]) return 0 ;;
    *) return 1 ;;
  esac
}

is_bytes32() {
  case "$1" in
    0x[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]*)
      [ "${#1}" -eq 66 ] || return 1
      printf '%s' "$1" | tr -d '0-9a-fA-Fx' | grep -q . && return 1
      return 0
      ;;
    *) return 1 ;;
  esac
}

is_hex_bytes() {
  case "$1" in
    0x[0-9a-fA-F]*)
      printf '%s' "$1" | tr -d '0-9a-fA-Fx' | grep -q . && return 1
      n="$(( ${#1} - 2 ))"
      [ "$n" -ge 0 ] || return 1
      [ $((n % 2)) -eq 0 ] || return 1
      return 0
      ;;
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

trim() {
  # shellcheck disable=SC2001
  printf '%s' "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
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
ALLOW_HTTP_LOCAL="${RELAYER_ALLOW_HTTP_LOCALHOST:-0}"
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
        fail "insecure rpc endpoint refused (set RELAYER_ALLOW_HTTP_LOCALHOST=1 to allow localhost http): ${rpc}"
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

PK=""
if [ -n "${RELAYER_PRIVATE_KEY_FILE:-}" ]; then
  keyFile="$(trim "$RELAYER_PRIVATE_KEY_FILE")"
  [ "$keyFile" != "" ] || fail "RELAYER_PRIVATE_KEY_FILE is empty"
  [ -f "$keyFile" ] || fail "RELAYER_PRIVATE_KEY_FILE does not exist: ${keyFile}"
  [ ! -L "$keyFile" ] || fail "refusing symlink key file: ${keyFile}"
  PK="$(cat "$keyFile" | tr -d '\r\n' | tr -d ' ')"
else
  PK="${RELAYER_PRIVATE_KEY:-}"
fi

PK="$(trim "$PK")"
[ "$PK" != "" ] || fail "missing relayer key (set RELAYER_PRIVATE_KEY or RELAYER_PRIVATE_KEY_FILE)"

case "$PK" in
  0x*) ;;
  *) PK="0x${PK}" ;;
esac

case "$PK" in
  0x[0-9a-fA-F]*)
    [ "${#PK}" -eq 66 ] || fail "invalid private key length (expected 32 bytes hex)"
    ;;
  *) fail "invalid private key format" ;;
esac

POLL_INTERVAL_SEC="${RELAYER_POLL_INTERVAL_SEC:-2}"
case "$POLL_INTERVAL_SEC" in
  ''|*[!0-9]*) fail "invalid RELAYER_POLL_INTERVAL_SEC (expected int)" ;;
esac
if [ "$POLL_INTERVAL_SEC" -lt 1 ]; then
  POLL_INTERVAL_SEC="1"
fi
if [ "$POLL_INTERVAL_SEC" -gt 60 ]; then
  POLL_INTERVAL_SEC="60"
fi

MAX_PER_TICK="${RELAYER_MAX_TX_PER_TICK:-3}"
case "$MAX_PER_TICK" in
  ''|*[!0-9]*) fail "invalid RELAYER_MAX_TX_PER_TICK (expected int)" ;;
esac
if [ "$MAX_PER_TICK" -lt 1 ]; then
  MAX_PER_TICK="1"
fi
if [ "$MAX_PER_TICK" -gt 100 ]; then
  MAX_PER_TICK="100"
fi

DRY_RUN="${RELAYER_DRY_RUN:-0}"
case "$DRY_RUN" in
  0|1) ;;
  *) fail "invalid RELAYER_DRY_RUN (expected 0|1)" ;;
esac

ALLOWED_METHODS_RAW="${RELAYER_ALLOWED_METHODS:-reportIncidentAuthorized(bytes32,uint256,bytes),checkInAuthorized(bytes32,bytes32,bytes32,uint256,bytes),pauseIfStale(),pauseIfActiveRootUntrusted()}"
ALLOWED_METHODS="$(printf '%s' "$ALLOWED_METHODS_RAW" | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed '/^$/d')"
if [ "$(printf '%s\n' "$ALLOWED_METHODS" | wc -l | tr -d ' ')" -lt 1 ]; then
  fail "no allowed methods configured"
fi

allowed_method() {
  m="$1"
  printf '%s\n' "$ALLOWED_METHODS" | grep -Fxq -- "$m"
}

mkdir -p "$OUTBOX_DIR" || true
mkdir -p "$OUTBOX_DIR/processing" "$OUTBOX_DIR/sent" "$OUTBOX_DIR/failed"

log "starting (chain_id=${CHAIN_ID} controller=${CONTROLLER} outbox=${OUTBOX_DIR} poll=${POLL_INTERVAL_SEC}s dry_run=${DRY_RUN})"
if [ "$DRY_RUN" = "1" ]; then
  log "DRY-RUN: will not broadcast transactions"
fi

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

while true; do
  processed="0"

  # shellcheck disable=SC2012
  for file in $(ls -1 "$OUTBOX_DIR"/tx.*.json 2>/dev/null | sort 2>/dev/null); do
    if [ "$processed" -ge "$MAX_PER_TICK" ]; then
      break
    fi

    [ -f "$file" ] || continue
    [ ! -L "$file" ] || continue

    base="$(basename "$file")"
    stem="${base%.json}"
    claimed="$OUTBOX_DIR/processing/${stem}.json"

    if ! mv "$file" "$claimed" 2>/dev/null; then
      continue
    fi

    schema="$(jq -r '.schema_version // empty' "$claimed" | head -n 1)"
    typ="$(jq -r '.type // empty' "$claimed" | head -n 1)"
    to="$(jq -r '.to // empty' "$claimed" | head -n 1)"
    method="$(jq -r '.method // empty' "$claimed" | head -n 1)"
    args="$(jq -r '.args[]? // empty' "$claimed")"

    schema="$(trim "$schema")"
    typ="$(trim "$typ")"
    to="$(trim "$to")"
    method="$(trim "$method")"

    err=""
    if [ "$schema" != "1" ]; then
      err="unsupported schema_version: ${schema}"
    elif [ "$typ" != "blackcat.tx_request" ]; then
      err="unsupported type: ${typ}"
    elif ! is_evm_address "$to"; then
      err="invalid to address: ${to}"
    elif [ "$(printf '%s' "$to" | tr 'A-F' 'a-f')" != "$(printf '%s' "$CONTROLLER" | tr 'A-F' 'a-f')" ]; then
      err="to address mismatch (refusing non-controller): ${to}"
    elif ! allowed_method "$method"; then
      err="method not allowlisted: ${method}"
    else
      case "$method" in
        reportIncident(bytes32))
          c="$(printf '%s\n' "$args" | sed '/^$/d' | wc -l | tr -d ' ')"
          if [ "$c" -ne 1 ]; then
            err="invalid args count for reportIncident: ${c}"
          else
            a1="$(printf '%s\n' "$args" | sed -n '1p')"
            is_bytes32 "$a1" || err="invalid bytes32 arg"
          fi
          ;;
        reportIncidentAuthorized(bytes32,uint256,bytes))
          c="$(printf '%s\n' "$args" | sed '/^$/d' | wc -l | tr -d ' ')"
          if [ "$c" -ne 3 ]; then
            err="invalid args count for reportIncidentAuthorized: ${c}"
          else
            a1="$(printf '%s\n' "$args" | sed -n '1p')"
            a2="$(printf '%s\n' "$args" | sed -n '2p')"
            a3="$(printf '%s\n' "$args" | sed -n '3p')"
            is_bytes32 "$a1" || err="invalid bytes32 arg #1"
            is_uint "$a2" || err="invalid uint256 arg #2"
            is_hex_bytes "$a3" || err="invalid bytes arg #3"
          fi
          ;;
        checkIn(bytes32,bytes32,bytes32))
          c="$(printf '%s\n' "$args" | sed '/^$/d' | wc -l | tr -d ' ')"
          if [ "$c" -ne 3 ]; then
            err="invalid args count for checkIn: ${c}"
          else
            a1="$(printf '%s\n' "$args" | sed -n '1p')"
            a2="$(printf '%s\n' "$args" | sed -n '2p')"
            a3="$(printf '%s\n' "$args" | sed -n '3p')"
            is_bytes32 "$a1" || err="invalid bytes32 arg #1"
            is_bytes32 "$a2" || err="invalid bytes32 arg #2"
            is_bytes32 "$a3" || err="invalid bytes32 arg #3"
          fi
          ;;
        checkInAuthorized(bytes32,bytes32,bytes32,uint256,bytes))
          c="$(printf '%s\n' "$args" | sed '/^$/d' | wc -l | tr -d ' ')"
          if [ "$c" -ne 5 ]; then
            err="invalid args count for checkInAuthorized: ${c}"
          else
            a1="$(printf '%s\n' "$args" | sed -n '1p')"
            a2="$(printf '%s\n' "$args" | sed -n '2p')"
            a3="$(printf '%s\n' "$args" | sed -n '3p')"
            a4="$(printf '%s\n' "$args" | sed -n '4p')"
            a5="$(printf '%s\n' "$args" | sed -n '5p')"
            is_bytes32 "$a1" || err="invalid bytes32 arg #1"
            is_bytes32 "$a2" || err="invalid bytes32 arg #2"
            is_bytes32 "$a3" || err="invalid bytes32 arg #3"
            is_uint "$a4" || err="invalid uint256 arg #4"
            is_hex_bytes "$a5" || err="invalid bytes arg #5"
          fi
          ;;
        pauseIfStale())
          c="$(printf '%s\n' "$args" | sed '/^$/d' | wc -l | tr -d ' ')"
          if [ "$c" -ne 0 ]; then
            err="invalid args count for pauseIfStale: ${c}"
          fi
          ;;
        pauseIfActiveRootUntrusted())
          c="$(printf '%s\n' "$args" | sed '/^$/d' | wc -l | tr -d ' ')"
          if [ "$c" -ne 0 ]; then
            err="invalid args count for pauseIfActiveRootUntrusted: ${c}"
          fi
          ;;
        *)
          err="unsupported allowlisted method validation: ${method}"
          ;;
      esac
    fi

    if [ "$err" != "" ]; then
      log "FAILED ${base}: ${err}"
      printf '%s\n' "$err" > "$OUTBOX_DIR/failed/${stem}.error.txt" || true
      mv "$claimed" "$OUTBOX_DIR/failed/${base}" || true
      processed="$((processed + 1))"
      continue
    fi

    rpc="$(select_rpc || true)"
    if [ "$(trim "$rpc")" = "" ]; then
      log "FAILED ${base}: no healthy rpc endpoint with matching chain_id"
      printf '%s\n' "no_healthy_rpc" > "$OUTBOX_DIR/failed/${stem}.error.txt" || true
      mv "$claimed" "$OUTBOX_DIR/failed/${base}" || true
      processed="$((processed + 1))"
      continue
    fi

    if [ "$DRY_RUN" = "1" ]; then
      log "DRY-RUN ${base}: would send ${method} to ${to} via ${rpc}"
      printf '%s\n' "{\"dry_run\":true,\"to\":\"${to}\",\"method\":\"${method}\",\"rpc\":\"${rpc}\",\"chain_id\":${CHAIN_ID}}" > "$OUTBOX_DIR/sent/${stem}.receipt.json" || true
      mv "$claimed" "$OUTBOX_DIR/sent/${base}" || true
      processed="$((processed + 1))"
      continue
    fi

    # Build cast args array (avoid word-splitting issues for args by using newline->positional loop).
    castArgs=""
    for a in $(printf '%s\n' "$args" | sed '/^$/d'); do
      castArgs="${castArgs} ${a}"
    done

    # Send async (tx hash only), then fetch JSON receipt.
    txHash="$(cast send --async --rpc-url "$rpc" --chain "$CHAIN_ID" --private-key "$PK" "$to" "$method" $castArgs 2>/dev/null || true)"
    txHash="$(trim "$txHash")"
    if [ "${#txHash}" -ne 66 ]; then
      log "FAILED ${base}: cast send did not return tx hash"
      printf '%s\n' "cast_send_failed" > "$OUTBOX_DIR/failed/${stem}.error.txt" || true
      mv "$claimed" "$OUTBOX_DIR/failed/${base}" || true
      processed="$((processed + 1))"
      continue
    fi

    receipt="$(cast receipt --json --rpc-url "$rpc" "$txHash" 2>/dev/null || true)"
    if [ "$(trim "$receipt")" = "" ]; then
      log "SENT ${base}: ${txHash} (receipt not available yet)"
      printf '%s\n' "{\"tx_hash\":\"${txHash}\",\"rpc\":\"${rpc}\",\"chain_id\":${CHAIN_ID},\"receipt\":\"pending\"}" > "$OUTBOX_DIR/sent/${stem}.receipt.json" || true
      mv "$claimed" "$OUTBOX_DIR/sent/${base}" || true
      processed="$((processed + 1))"
      continue
    fi

    printf '%s\n' "$receipt" > "$OUTBOX_DIR/sent/${stem}.receipt.json" || true
    mv "$claimed" "$OUTBOX_DIR/sent/${base}" || true
    log "SENT ${base}: ${txHash}"
    processed="$((processed + 1))"
  done

  sleep "$POLL_INTERVAL_SEC" || true
done
