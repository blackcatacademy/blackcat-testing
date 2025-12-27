#!/usr/bin/env bash
set -euo pipefail

TARGET_BASE_URL="${TARGET_BASE_URL:-http://app:8080}"
ATTACK_DURATION_SEC="${ATTACK_DURATION_SEC:-120}"
ATTACK_RPS="${ATTACK_RPS:-5}"
TAMPER_AFTER_SEC="${TAMPER_AFTER_SEC:-40}"
EXPECT_TRUST_FAIL_AFTER_TAMPER="${EXPECT_TRUST_FAIL_AFTER_TAMPER:-1}"
EXPECT_STALE_READS_ON_RPC_OUTAGE="${EXPECT_STALE_READS_ON_RPC_OUTAGE:-0}"

echo "[attacker] target=${TARGET_BASE_URL}"
echo "[attacker] duration_sec=${ATTACK_DURATION_SEC} rps=${ATTACK_RPS} tamper_after_sec=${TAMPER_AFTER_SEC} expect_trust_fail_after_tamper=${EXPECT_TRUST_FAIL_AFTER_TAMPER} expect_stale_reads_on_rpc_outage=${EXPECT_STALE_READS_ON_RPC_OUTAGE}"

start_ts="$(date +%s)"
tampered="0"

req_code() {
  local method="$1"
  local path="$2"
  local url="${TARGET_BASE_URL}${path}"

  if [[ "$method" == "POST" ]]; then
    curl -sS -o /dev/null -w "%{http_code}" -X POST "$url" || echo "000"
    return
  fi

  curl -sS -o /dev/null -w "%{http_code}" "$url" || echo "000"
}

attack_invalid_methods() {
  curl -sS -o /dev/null -w "%{http_code}\n" -X TRACE "${TARGET_BASE_URL}/health" || true
  curl -sS -o /dev/null -w "%{http_code}\n" -X PUT "${TARGET_BASE_URL}/health" || true
}

attack_path_traversal() {
  curl -sS -o /dev/null -w "%{http_code}\n" "${TARGET_BASE_URL}/..%2f..%2fetc%2fpasswd" || true
  curl -sS -o /dev/null -w "%{http_code}\n" "${TARGET_BASE_URL}/php://filter" || true
}

health_json() {
  curl -fsS "${TARGET_BASE_URL}/health" | jq -c '{trusted_now:.trust.trusted_now,rpc_ok_now:.trust.rpc_ok_now,read_allowed:.trust.read_allowed,write_allowed:.trust.write_allowed,paused:.trust.paused,error_codes:.trust.error_codes}'
}

echo "[attacker] initial health=$(health_json || echo '{}')"

while true; do
  now="$(date +%s)"
  elapsed="$((now - start_ts))"
  if (( elapsed >= ATTACK_DURATION_SEC )); then
    break
  fi

if (( tampered == 0 && elapsed >= TAMPER_AFTER_SEC )); then
    tampered="1"
    echo "[attacker] NOTE: this harness expects tamper + restart to be orchestrated by the host (docker exec)."
    echo "[attacker] trusted_now_before_tamper=$(health_json || echo '?')"
  fi

  health="$(health_json || echo '{}')"
  trusted_now="$(echo "$health" | jq -r '.trusted_now // "null"' || echo "null")"
  rpc_ok_now="$(echo "$health" | jq -r '.rpc_ok_now // "null"' || echo "null")"
  read_allowed="$(echo "$health" | jq -r '.read_allowed // "null"' || echo "null")"
  write_allowed="$(echo "$health" | jq -r '.write_allowed // "null"' || echo "null")"

  # Normal traffic
  code_health="$(req_code GET /health)"
  code_db_read="$(req_code GET /db/read)"
  code_db_write="$(req_code POST /db/write)"
  code_bypass_pdo="$(req_code GET /bypass/pdo)"

  # Attack probes
  attack_invalid_methods
  attack_path_traversal

  if (( elapsed % 10 == 0 )); then
    echo "[attacker] t=${elapsed}s health=${code_health} trusted_now=${trusted_now} rpc_ok_now=${rpc_ok_now} read_allowed=${read_allowed} write_allowed=${write_allowed} | db_read=${code_db_read} db_write=${code_db_write} bypass_pdo=${code_bypass_pdo}"
  fi

  if (( EXPECT_TRUST_FAIL_AFTER_TAMPER == 1 && elapsed > (TAMPER_AFTER_SEC + 10) )); then
    if [[ "$trusted_now" == "true" ]]; then
      echo "[attacker] FAIL: expected trust to fail after tamper window but trusted_now=true" >&2
      exit 2
    fi
  fi

  if (( EXPECT_STALE_READS_ON_RPC_OUTAGE == 1 )); then
    # If RPC is down but read_allowed should remain true during max_stale_sec.
    if [[ "$rpc_ok_now" == "false" && "$read_allowed" != "true" ]]; then
      echo "[attacker] FAIL: rpc_ok_now=false but read_allowed is not true (stale reads not working)" >&2
      exit 3
    fi
  fi

  sleep "$(awk "BEGIN {print 1/${ATTACK_RPS}}")"
done

echo "[attacker] done"
echo "[attacker] final health=$(health_json || echo '{}')"
