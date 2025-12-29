#!/bin/sh
set -eu

umask 007

log() {
  printf '%s %s\n' "[signer]" "$*" >&2
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

is_uint() {
  v="$(trim "$1")"
  [ "$v" != "" ] || return 1
  case "$v" in
    *[!0-9]*) return 1 ;;
    *) return 0 ;;
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
ALLOW_HTTP_LOCAL="${SIGNER_ALLOW_HTTP_LOCALHOST:-0}"
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
        fail "insecure rpc endpoint refused (set SIGNER_ALLOW_HTTP_LOCALHOST=1 to allow localhost http): ${rpc}"
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
if [ -n "${SIGNER_PRIVATE_KEY_FILE:-}" ]; then
  keyFile="$(trim "$SIGNER_PRIVATE_KEY_FILE")"
  [ "$keyFile" != "" ] || fail "SIGNER_PRIVATE_KEY_FILE is empty"
  [ -f "$keyFile" ] || fail "SIGNER_PRIVATE_KEY_FILE does not exist: ${keyFile}"
  [ ! -L "$keyFile" ] || fail "refusing symlink key file: ${keyFile}"
  PK="$(cat "$keyFile" | tr -d '\r\n' | tr -d ' ')"
else
  PK="${SIGNER_PRIVATE_KEY:-}"
fi

PK="$(trim "$PK")"
[ "$PK" != "" ] || fail "missing signer key (set SIGNER_PRIVATE_KEY or SIGNER_PRIVATE_KEY_FILE)"

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

SIGNER_ADDR="$(cast wallet address --private-key "$PK" 2>/dev/null || true)"
SIGNER_ADDR="$(trim "$SIGNER_ADDR")"
if ! is_evm_address "$SIGNER_ADDR"; then
  fail "unable to derive signer address"
fi

POLL_INTERVAL_SEC="${SIGNER_POLL_INTERVAL_SEC:-2}"
case "$POLL_INTERVAL_SEC" in
  ''|*[!0-9]*) fail "invalid SIGNER_POLL_INTERVAL_SEC (expected int)" ;;
esac
if [ "$POLL_INTERVAL_SEC" -lt 1 ]; then
  POLL_INTERVAL_SEC="1"
fi
if [ "$POLL_INTERVAL_SEC" -gt 60 ]; then
  POLL_INTERVAL_SEC="60"
fi

MAX_PER_TICK="${SIGNER_MAX_PER_TICK:-5}"
case "$MAX_PER_TICK" in
  ''|*[!0-9]*) fail "invalid SIGNER_MAX_PER_TICK (expected int)" ;;
esac
if [ "$MAX_PER_TICK" -lt 1 ]; then
  MAX_PER_TICK="1"
fi
if [ "$MAX_PER_TICK" -gt 100 ]; then
  MAX_PER_TICK="100"
fi

DEFAULT_TTL_SEC="${SIGNER_DEFAULT_TTL_SEC:-300}"
case "$DEFAULT_TTL_SEC" in
  ''|*[!0-9]*) fail "invalid SIGNER_DEFAULT_TTL_SEC (expected int)" ;;
esac
if [ "$DEFAULT_TTL_SEC" -lt 30 ]; then
  DEFAULT_TTL_SEC="30"
fi
if [ "$DEFAULT_TTL_SEC" -gt 3600 ]; then
  DEFAULT_TTL_SEC="3600"
fi

DRY_RUN="${SIGNER_DRY_RUN:-0}"
case "$DRY_RUN" in
  0|1) ;;
  *) fail "invalid SIGNER_DRY_RUN (expected 0|1)" ;;
esac

mkdir -p "$OUTBOX_DIR" || true
mkdir -p "$OUTBOX_DIR/processing" "$OUTBOX_DIR/signed" "$OUTBOX_DIR/failed" || true

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

mk_typed_file_checkin() {
  dst="$1"
  observedRoot="$2"
  observedUriHash="$3"
  observedPolicyHash="$4"
  nonce="$5"
  deadline="$6"

  jq -n \
    --arg name "BlackCatInstanceController" \
    --arg version "1" \
    --arg controller "$CONTROLLER" \
    --arg observedRoot "$observedRoot" \
    --arg observedUriHash "$observedUriHash" \
    --arg observedPolicyHash "$observedPolicyHash" \
    --argjson chainId "$CHAIN_ID" \
    --argjson nonce "$nonce" \
    --argjson deadline "$deadline" \
    '{
      types: {
        EIP712Domain: [
          {name:"name", type:"string"},
          {name:"version", type:"string"},
          {name:"chainId", type:"uint256"},
          {name:"verifyingContract", type:"address"}
        ],
        CheckIn: [
          {name:"observedRoot", type:"bytes32"},
          {name:"observedUriHash", type:"bytes32"},
          {name:"observedPolicyHash", type:"bytes32"},
          {name:"nonce", type:"uint256"},
          {name:"deadline", type:"uint256"}
        ]
      },
      primaryType: "CheckIn",
      domain: {name:$name, version:$version, chainId:$chainId, verifyingContract:$controller},
      message: {observedRoot:$observedRoot, observedUriHash:$observedUriHash, observedPolicyHash:$observedPolicyHash, nonce:$nonce, deadline:$deadline}
    }' > "$dst"
}

mk_typed_file_incident() {
  dst="$1"
  incidentHash="$2"
  nonce="$3"
  deadline="$4"

  jq -n \
    --arg name "BlackCatInstanceController" \
    --arg version "1" \
    --arg controller "$CONTROLLER" \
    --arg incidentHash "$incidentHash" \
    --argjson chainId "$CHAIN_ID" \
    --argjson nonce "$nonce" \
    --argjson deadline "$deadline" \
    '{
      types: {
        EIP712Domain: [
          {name:"name", type:"string"},
          {name:"version", type:"string"},
          {name:"chainId", type:"uint256"},
          {name:"verifyingContract", type:"address"}
        ],
        ReportIncident: [
          {name:"incidentHash", type:"bytes32"},
          {name:"nonce", type:"uint256"},
          {name:"deadline", type:"uint256"}
        ]
      },
      primaryType: "ReportIncident",
      domain: {name:$name, version:$version, chainId:$chainId, verifyingContract:$controller},
      message: {incidentHash:$incidentHash, nonce:$nonce, deadline:$deadline}
    }' > "$dst"
}

enqueue_tx() {
  method="$1"
  argsJson="$2"
  metaJson="$3"

  now="$(date +%s)"
  createdAt="$(date -u +%FT%TZ)"
  rand="$(rand_hex_8)"

  tmp="$OUTBOX_DIR/.tx.${now}.${rand}.tmp"
  dst="$OUTBOX_DIR/tx.${now}.${rand}.json"

  # metaJson is expected to be a JSON object; fallback to {}.
  metaOk="$(printf '%s' "$metaJson" | jq -c '.' 2>/dev/null || true)"
  if [ "$(trim "$metaOk")" = "" ]; then
    metaOk="{}"
  fi

  jq -n \
    --arg created_at "$createdAt" \
    --arg to "$CONTROLLER" \
    --arg method "$method" \
    --arg signer "$SIGNER_ADDR" \
    --argjson args "$argsJson" \
    --argjson meta "$metaOk" \
    '{
      schema_version: 1,
      type: "blackcat.tx_request",
      created_at: $created_at,
      to: $to,
      method: $method,
      args: $args,
      meta: ({source:"signer", signer:$signer} + $meta)
    }' > "$tmp"

  mv "$tmp" "$dst"
  log "outbox: queued tx -> $(basename "$dst") (${method})"
}

log "starting (chain_id=${CHAIN_ID} controller=${CONTROLLER} outbox=${OUTBOX_DIR} poll=${POLL_INTERVAL_SEC}s dry_run=${DRY_RUN} signer=${SIGNER_ADDR})"
if [ "$DRY_RUN" = "1" ]; then
  log "DRY-RUN: will not enqueue tx requests"
fi

while true; do
  processed="0"

  # shellcheck disable=SC2012
  for file in $(ls -1 "$OUTBOX_DIR"/sig.*.json 2>/dev/null | sort 2>/dev/null); do
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
    kind="$(jq -r '.kind // empty' "$claimed" | head -n 1)"
    to="$(jq -r '.to // empty' "$claimed" | head -n 1)"
    ttlSec="$(jq -r '.ttl_sec // empty' "$claimed" | head -n 1)"
    metaJson="$(jq -c '.meta // {}' "$claimed" 2>/dev/null || true)"

    schema="$(trim "$schema")"
    typ="$(trim "$typ")"
    kind="$(trim "$kind")"
    to="$(trim "$to")"
    ttlSec="$(trim "$ttlSec")"

    err=""
    if [ "$schema" != "1" ]; then
      err="unsupported schema_version: ${schema}"
    elif [ "$typ" != "blackcat.sig_request" ]; then
      err="unsupported type: ${typ}"
    elif ! is_evm_address "$to"; then
      err="invalid to address: ${to}"
    elif [ "$(printf '%s' "$to" | tr 'A-F' 'a-f')" != "$(printf '%s' "$CONTROLLER" | tr 'A-F' 'a-f')" ]; then
      err="to address mismatch (refusing non-controller): ${to}"
    fi

    if [ "$err" != "" ]; then
      log "FAILED ${base}: ${err}"
      printf '%s\n' "$err" > "$OUTBOX_DIR/failed/${stem}.error.txt" || true
      mv "$claimed" "$OUTBOX_DIR/failed/${base}" || true
      processed="$((processed + 1))"
      continue
    fi

    if [ "$ttlSec" = "" ]; then
      ttlSec="$DEFAULT_TTL_SEC"
    fi
    if ! is_uint "$ttlSec"; then
      ttlSec="$DEFAULT_TTL_SEC"
    fi
    if [ "$ttlSec" -lt 30 ]; then
      ttlSec="30"
    fi
    if [ "$ttlSec" -gt 3600 ]; then
      ttlSec="3600"
    fi

    rpc="$(select_rpc || true)"
    if [ "$(trim "$rpc")" = "" ]; then
      log "FAILED ${base}: no healthy rpc endpoint with matching chain_id"
      printf '%s\n' "no_healthy_rpc" > "$OUTBOX_DIR/failed/${stem}.error.txt" || true
      mv "$claimed" "$OUTBOX_DIR/failed/${base}" || true
      processed="$((processed + 1))"
      continue
    fi

    now="$(date +%s)"
    deadline="$((now + ttlSec))"

    if [ "$DRY_RUN" = "1" ]; then
      log "DRY-RUN ${base}: would sign kind=${kind} ttl_sec=${ttlSec}"
      mv "$claimed" "$OUTBOX_DIR/signed/${base}" || true
      processed="$((processed + 1))"
      continue
    fi

    tmpTyped="/tmp/${stem}.typed.json"
    sig=""

    case "$kind" in
      check_in)
        observedRoot="$(jq -r '.observed_root // empty' "$claimed" | head -n 1)"
        observedUriHash="$(jq -r '.observed_uri_hash // empty' "$claimed" | head -n 1)"
        observedPolicyHash="$(jq -r '.observed_policy_hash // empty' "$claimed" | head -n 1)"
        observedRoot="$(trim "$observedRoot")"
        observedUriHash="$(trim "$observedUriHash")"
        observedPolicyHash="$(trim "$observedPolicyHash")"

        if ! is_bytes32 "$observedRoot" || ! is_bytes32 "$observedUriHash" || ! is_bytes32 "$observedPolicyHash"; then
          err="invalid bytes32 in check_in request"
          ;;
        fi

        nonce="$(cast call --rpc-url "$rpc" "$CONTROLLER" "reporterNonce()(uint256)" 2>/dev/null || true)"
        nonce="$(trim "$nonce")"
        if ! is_uint "$nonce"; then
          err="unable to read reporterNonce()"
          ;;
        fi

        mk_typed_file_checkin "$tmpTyped" "$observedRoot" "$observedUriHash" "$observedPolicyHash" "$nonce" "$deadline"
        sig="$(cast wallet sign --data --from-file --private-key "$PK" "$tmpTyped" 2>/dev/null || true)"
        sig="$(trim "$sig")"

        if ! is_hex_bytes "$sig"; then
          err="signature invalid"
          ;;
        fi

        # signature must be 64 or 65 bytes (EIP-2098 or standard).
        sigLen="$(( (${#sig} - 2) / 2 ))"
        if [ "$sigLen" -ne 64 ] && [ "$sigLen" -ne 65 ]; then
          err="signature length invalid: ${sigLen} bytes"
          ;;
        fi

        argsJson="$(jq -cn --arg a1 "$observedRoot" --arg a2 "$observedUriHash" --arg a3 "$observedPolicyHash" --argjson d "$deadline" --arg s "$sig" '[$a1,$a2,$a3,$d,$s]')"
        enqueue_tx "checkInAuthorized(bytes32,bytes32,bytes32,uint256,bytes)" "$argsJson" "$metaJson"
        ;;

      report_incident)
        incidentHash="$(jq -r '.incident_hash // empty' "$claimed" | head -n 1)"
        incidentHash="$(trim "$incidentHash")"
        if ! is_bytes32 "$incidentHash"; then
          err="invalid bytes32 incident_hash"
          ;;
        fi

        nonce="$(cast call --rpc-url "$rpc" "$CONTROLLER" "incidentNonce()(uint256)" 2>/dev/null || true)"
        nonce="$(trim "$nonce")"
        if ! is_uint "$nonce"; then
          err="unable to read incidentNonce()"
          ;;
        fi

        mk_typed_file_incident "$tmpTyped" "$incidentHash" "$nonce" "$deadline"
        sig="$(cast wallet sign --data --from-file --private-key "$PK" "$tmpTyped" 2>/dev/null || true)"
        sig="$(trim "$sig")"

        if ! is_hex_bytes "$sig"; then
          err="signature invalid"
          ;;
        fi

        sigLen="$(( (${#sig} - 2) / 2 ))"
        if [ "$sigLen" -ne 64 ] && [ "$sigLen" -ne 65 ]; then
          err="signature length invalid: ${sigLen} bytes"
          ;;
        fi

        argsJson="$(jq -cn --arg a1 "$incidentHash" --argjson d "$deadline" --arg s "$sig" '[$a1,$d,$s]')"
        enqueue_tx "reportIncidentAuthorized(bytes32,uint256,bytes)" "$argsJson" "$metaJson"
        ;;

      *)
        err="unsupported kind: ${kind}"
        ;;
    esac

    rm -f "$tmpTyped" 2>/dev/null || true

    if [ "$err" != "" ]; then
      log "FAILED ${base}: ${err}"
      printf '%s\n' "$err" > "$OUTBOX_DIR/failed/${stem}.error.txt" || true
      mv "$claimed" "$OUTBOX_DIR/failed/${base}" || true
      processed="$((processed + 1))"
      continue
    fi

    mv "$claimed" "$OUTBOX_DIR/signed/${base}" || true
    processed="$((processed + 1))"
  done

  sleep "$POLL_INTERVAL_SEC" || true
done

