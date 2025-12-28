#!/usr/bin/env bash
set -euo pipefail

TARGET_BASE_URL="${TARGET_BASE_URL:-http://app:8080}"
ATTACK_DURATION_SEC="${ATTACK_DURATION_SEC:-120}"
ATTACK_RPS="${ATTACK_RPS:-5}"
TAMPER_AFTER_SEC="${TAMPER_AFTER_SEC:-40}"
EXPECT_TRUST_FAIL_AFTER_TAMPER="${EXPECT_TRUST_FAIL_AFTER_TAMPER:-1}"
EXPECT_STALE_READS_ON_RPC_OUTAGE="${EXPECT_STALE_READS_ON_RPC_OUTAGE:-0}"
EXPECT_TRUST_OK_AT_START="${EXPECT_TRUST_OK_AT_START:-0}"
EXPECT_HEALTH_DOWN_AFTER_TAMPER="${EXPECT_HEALTH_DOWN_AFTER_TAMPER:-0}"
ATTACK_LOG_DIR="${ATTACK_LOG_DIR:-/var/log/blackcat-testing}"
ATTACK_LOG_EVERY_SEC="${ATTACK_LOG_EVERY_SEC:-1}"
ATTACK_READY_TIMEOUT_SEC="${ATTACK_READY_TIMEOUT_SEC:-60}"
ATTACK_MAX_CONSECUTIVE_HEALTH_FAILS="${ATTACK_MAX_CONSECUTIVE_HEALTH_FAILS:-30}"
ATTACK_HEALTH_TIMEOUT_SEC="${ATTACK_HEALTH_TIMEOUT_SEC:-20}"
ATTACK_HTTP_TIMEOUT_SEC="${ATTACK_HTTP_TIMEOUT_SEC:-20}"

echo "[attacker] target=${TARGET_BASE_URL}"
echo "[attacker] duration_sec=${ATTACK_DURATION_SEC} rps=${ATTACK_RPS} tamper_after_sec=${TAMPER_AFTER_SEC} expect_trust_fail_after_tamper=${EXPECT_TRUST_FAIL_AFTER_TAMPER} expect_stale_reads_on_rpc_outage=${EXPECT_STALE_READS_ON_RPC_OUTAGE}"
echo "[attacker] expect_health_down_after_tamper=${EXPECT_HEALTH_DOWN_AFTER_TAMPER}"
echo "[attacker] log_dir=${ATTACK_LOG_DIR} log_every_sec=${ATTACK_LOG_EVERY_SEC} ready_timeout_sec=${ATTACK_READY_TIMEOUT_SEC} max_consecutive_health_fails=${ATTACK_MAX_CONSECUTIVE_HEALTH_FAILS}"
echo "[attacker] timeouts: health=${ATTACK_HEALTH_TIMEOUT_SEC}s other_http=${ATTACK_HTTP_TIMEOUT_SEC}s"

start_ts="$(date +%s)"
tampered="0"
consecutive_health_fails="0"

run_id="$(date -u +%Y%m%dT%H%M%SZ).$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
mkdir -p "${ATTACK_LOG_DIR}"
events_file="${ATTACK_LOG_DIR}/events.${run_id}.jsonl"
summary_file="${ATTACK_LOG_DIR}/summary.${run_id}.json"
meta_file="${ATTACK_LOG_DIR}/meta.${run_id}.json"

jq -n \
  --arg run_id "${run_id}" \
  --arg started_at "$(date -u +%FT%TZ)" \
  --arg target "${TARGET_BASE_URL}" \
  --arg duration_sec "${ATTACK_DURATION_SEC}" \
  --arg rps "${ATTACK_RPS}" \
  --arg tamper_after_sec "${TAMPER_AFTER_SEC}" \
  --arg expect_trust_ok_at_start "${EXPECT_TRUST_OK_AT_START}" \
  --arg expect_trust_fail_after_tamper "${EXPECT_TRUST_FAIL_AFTER_TAMPER}" \
  --arg expect_stale_reads_on_rpc_outage "${EXPECT_STALE_READS_ON_RPC_OUTAGE}" \
  --arg expect_health_down_after_tamper "${EXPECT_HEALTH_DOWN_AFTER_TAMPER}" \
  '{
    run_id:$run_id,
    started_at:$started_at,
    target:$target,
    duration_sec:($duration_sec|tonumber),
    rps:($rps|tonumber),
    tamper_after_sec:($tamper_after_sec|tonumber),
    expectations:{
      trust_ok_at_start:($expect_trust_ok_at_start|tonumber == 1),
      trust_fail_after_tamper:($expect_trust_fail_after_tamper|tonumber == 1),
      stale_reads_on_rpc_outage:($expect_stale_reads_on_rpc_outage|tonumber == 1),
      health_down_after_tamper:($expect_health_down_after_tamper|tonumber == 1)
    }
  }' > "${meta_file}"

req_code() {
  local method="$1"
  local path="$2"
  local url="${TARGET_BASE_URL}${path}"
  local timeout="${ATTACK_HTTP_TIMEOUT_SEC}"
  if [[ "${path}" == "/health" ]]; then
    timeout="${ATTACK_HEALTH_TIMEOUT_SEC}"
  fi

  curl -sS -m "${timeout}" -o /dev/null -w "%{http_code}" -X "$method" "$url" || echo "000"
}

attack_invalid_methods() {
  local _c
  _c="$(req_code TRACE /health)" || true
  _c="$(req_code PUT /health)" || true
}

attack_path_traversal() {
  local _c
  _c="$(req_code GET /..%2f..%2fetc%2fpasswd)" || true
  _c="$(req_code GET /php://filter)" || true
}

fetch_health() {
  local url="${TARGET_BASE_URL}/health"
  local out
  out="$(curl -sS -m "${ATTACK_HEALTH_TIMEOUT_SEC}" -w '\n%{http_code}' "$url" || true)"
  HEALTH_CODE="$(printf '%s' "$out" | tail -n 1 | tr -d '\r')"
  HEALTH_BODY="$(printf '%s' "$out" | sed '$d')"
}

health_compact() {
  if [[ "${HEALTH_CODE}" == "200" ]]; then
    echo "${HEALTH_BODY}" | jq -c '{ok:true,http_code:200,enforcement:.trust.enforcement,trusted_now:.trust.trusted_now,rpc_ok_now:.trust.rpc_ok_now,read_allowed:.trust.read_allowed,write_allowed:.trust.write_allowed,paused:.trust.paused,checked_at:.trust.checked_at,last_ok_at:.trust.last_ok_at,error_codes:(.trust.error_codes//[])}' 2>/dev/null \
      || jq -nc --arg code "${HEALTH_CODE}" '{ok:false,http_code:($code|tonumber? // 0),parse_error:true}'
    return
  fi

  jq -nc --arg code "${HEALTH_CODE}" '{ok:false,http_code:($code|tonumber? // 0)}'
}

wait_for_ready() {
  local timeout_sec="$1"
  local expect_trust_ok="$2"
  local start
  start="$(date +%s)"

  while true; do
    fetch_health
    local now
    now="$(date +%s)"
    local elapsed
    elapsed="$((now - start))"

    if (( elapsed > timeout_sec )); then
      echo "[attacker] FAIL: readiness timeout after ${timeout_sec}s (last health_code=${HEALTH_CODE})" >&2
      return 1
    fi

    if [[ "${HEALTH_CODE}" != "200" ]]; then
      sleep 1
      continue
    fi

    local compact
    compact="$(health_compact || echo '{}')"
    if [[ "${expect_trust_ok}" == "1" ]]; then
      if [[ "$(echo "$compact" | jq -r '.trusted_now' || echo "null")" == "true" ]]; then
        echo "[attacker] ready: trusted_now=true"
        return 0
      fi
      sleep 1
      continue
    fi

    echo "[attacker] ready: health endpoint reachable"
    return 0
  done
}

wait_for_ready "${ATTACK_READY_TIMEOUT_SEC}" "${EXPECT_TRUST_OK_AT_START}"

fetch_health
initial_health="$(health_compact || echo '{}')"
echo "[attacker] initial health=${initial_health}"

if (( EXPECT_TRUST_OK_AT_START == 1 )); then
  if [[ "$(echo "$initial_health" | jq -r '.trusted_now' || echo "null")" != "true" ]]; then
    echo "[attacker] FAIL: expected trusted_now=true at start (chain/config not provisioned?)" >&2
    exit 10
  fi
fi

while true; do
  now="$(date +%s)"
  elapsed="$((now - start_ts))"
  if (( elapsed >= ATTACK_DURATION_SEC )); then
    break
  fi

  if (( TAMPER_AFTER_SEC > 0 && tampered == 0 && elapsed >= TAMPER_AFTER_SEC )); then
    tampered="1"
    echo "[attacker] NOTE: filesystem/config tamper is expected to be performed by the app container (entrypoint.sh) based on BLACKCAT_TESTING_TAMPER_*."
    fetch_health
    echo "[attacker] health_before_tamper=$(health_compact || echo '?')"
  fi

  fetch_health
  health="$(health_compact || echo '{}')"
  ok="$(echo "$health" | jq -r '.ok // false' 2>/dev/null || echo "false")"
  enforcement="$(echo "$health" | jq -r '.enforcement // "null"' 2>/dev/null || echo "null")"
  trusted_now="$(echo "$health" | jq -r '.trusted_now' 2>/dev/null || echo "null")"
  rpc_ok_now="$(echo "$health" | jq -r '.rpc_ok_now' 2>/dev/null || echo "null")"
  read_allowed="$(echo "$health" | jq -r '.read_allowed' 2>/dev/null || echo "null")"
  write_allowed="$(echo "$health" | jq -r '.write_allowed' 2>/dev/null || echo "null")"

  # Normal traffic
  code_health="$(req_code GET /health)"
  code_db_read="$(req_code GET /db/read)"
  code_db_write="$(req_code POST /db/write)"
  code_bypass_pdo="$(req_code GET /bypass/pdo)"
  code_bypass_keys="000"
  code_crypto_roundtrip="000"
  if (( elapsed % 5 == 0 )); then
    code_bypass_keys="$(req_code GET /bypass/keys)"
    code_crypto_roundtrip="$(req_code POST /crypto/roundtrip)"
  fi

  # Attack probes
  attack_invalid_methods
  attack_path_traversal

  if (( elapsed % 10 == 0 )); then
    echo "[attacker] t=${elapsed}s health=${code_health} enforcement=${enforcement} trusted_now=${trusted_now} rpc_ok_now=${rpc_ok_now} read_allowed=${read_allowed} write_allowed=${write_allowed} | db_read=${code_db_read} db_write=${code_db_write} bypass_pdo=${code_bypass_pdo}"
  fi

  if [[ "${code_health}" != "200" ]]; then
    consecutive_health_fails="$((consecutive_health_fails + 1))"
    if (( EXPECT_HEALTH_DOWN_AFTER_TAMPER == 1 && elapsed > (TAMPER_AFTER_SEC + 15) )); then
      true
    else
      if (( consecutive_health_fails >= ATTACK_MAX_CONSECUTIVE_HEALTH_FAILS )); then
        echo "[attacker] FAIL: /health unavailable for too long (consecutive=${consecutive_health_fails}, last_code=${code_health})" >&2
        exit 20
      fi
    fi
  else
    consecutive_health_fails="0"
  fi

  if [[ "$enforcement" == "strict" && "${ok}" == "true" ]]; then
    if [[ "$write_allowed" != "true" && "$code_db_write" == "200" ]]; then
      fetch_health
      health2="$(health_compact || echo '{}')"
      write_allowed2="$(echo "$health2" | jq -r '.write_allowed' 2>/dev/null || echo "null")"

      if [[ "$write_allowed2" != "true" ]]; then
        echo "[attacker] FAIL: write_allowed=false but /db/write returned 200 (write must be denied in strict mode)" >&2
        exit 11
      fi
    fi

    if [[ "$read_allowed" != "true" && "$code_db_read" == "200" ]]; then
      fetch_health
      health2="$(health_compact || echo '{}')"
      read_allowed2="$(echo "$health2" | jq -r '.read_allowed' 2>/dev/null || echo "null")"

      if [[ "$read_allowed2" != "true" ]]; then
        echo "[attacker] FAIL: read_allowed=false but /db/read returned 200 (read must be denied in strict mode)" >&2
        exit 12
      fi
    fi

    if [[ "$read_allowed" == "true" && "$code_bypass_pdo" != "403" ]]; then
      # Avoid false positives when trust state changes between the health poll and the bypass probe
      # (e.g., right when a tamper event happens).
      fetch_health
      health2="$(health_compact || echo '{}')"
      read_allowed2="$(echo "$health2" | jq -r '.read_allowed' 2>/dev/null || echo "null")"
      trusted_now2="$(echo "$health2" | jq -r '.trusted_now' 2>/dev/null || echo "null")"

      if [[ "$read_allowed2" == "true" && "$trusted_now2" == "true" ]]; then
        echo "[attacker] FAIL: /bypass/pdo must be denied (403) when requests are allowed (raw PDO bypass must never be allowed). got=${code_bypass_pdo}" >&2
        exit 13
      fi
    fi

    if [[ "$read_allowed" == "true" && "$code_bypass_keys" == "500" ]]; then
      echo "[attacker] FAIL: /bypass/keys returned 500 (possible key file read bypass or endpoint bug)" >&2
      exit 16
    fi

    if [[ "$read_allowed" != "true" && "$code_crypto_roundtrip" == "200" ]]; then
      fetch_health
      health2="$(health_compact || echo '{}')"
      read_allowed2="$(echo "$health2" | jq -r '.read_allowed' 2>/dev/null || echo "null")"

      if [[ "$read_allowed2" != "true" ]]; then
        echo "[attacker] FAIL: read_allowed=false but /crypto/roundtrip returned 200 (secrets.read must be denied in strict mode)" >&2
        exit 17
      fi
    fi
  fi

  if [[ "${ok}" == "true" ]]; then
    if [[ "$read_allowed" == "true" && "$code_db_read" != "200" ]]; then
      # Avoid false positives if trust flips between the health poll and the DB call.
      fetch_health
      health2="$(health_compact || echo '{}')"
      read_allowed2="$(echo "$health2" | jq -r '.read_allowed' 2>/dev/null || echo "null")"
      if [[ "$read_allowed2" == "true" ]]; then
        echo "[attacker] FAIL: read_allowed=true but /db/read did not return 200 (got=${code_db_read})" >&2
        exit 14
      fi
    fi

    if [[ "$write_allowed" == "true" && "$code_db_write" != "200" ]]; then
      fetch_health
      health2="$(health_compact || echo '{}')"
      write_allowed2="$(echo "$health2" | jq -r '.write_allowed' 2>/dev/null || echo "null")"
      if [[ "$write_allowed2" == "true" ]]; then
        echo "[attacker] FAIL: write_allowed=true but /db/write did not return 200 (got=${code_db_write})" >&2
        exit 15
      fi
    fi
  fi

  if (( EXPECT_TRUST_FAIL_AFTER_TAMPER == 1 && elapsed > (TAMPER_AFTER_SEC + 10) )); then
    if [[ "$trusted_now" == "true" ]]; then
      echo "[attacker] FAIL: expected trust to fail after tamper window but trusted_now=true" >&2
      exit 2
    fi
  fi

  if (( EXPECT_HEALTH_DOWN_AFTER_TAMPER == 1 && elapsed > (TAMPER_AFTER_SEC + 15) )); then
    if [[ "${code_health}" == "200" ]]; then
      echo "[attacker] FAIL: expected /health to be unavailable after tamper+restart but got 200" >&2
      exit 21
    fi
  fi

  if (( EXPECT_STALE_READS_ON_RPC_OUTAGE == 1 )); then
    # If RPC is down but read_allowed should remain true during max_stale_sec.
    if [[ "$rpc_ok_now" == "false" && "$read_allowed" != "true" ]]; then
      echo "[attacker] FAIL: rpc_ok_now=false but read_allowed is not true (stale reads not working)" >&2
      exit 3
    fi
  fi

  if (( ATTACK_LOG_EVERY_SEC > 0 && elapsed % ATTACK_LOG_EVERY_SEC == 0 )); then
    jq -nc \
      --arg run_id "${run_id}" \
      --arg ts "$(date -u +%FT%TZ)" \
      --argjson t "${elapsed}" \
      --arg code_health "${code_health}" \
      --arg code_db_read "${code_db_read}" \
      --arg code_db_write "${code_db_write}" \
      --arg code_bypass_pdo "${code_bypass_pdo}" \
      --arg code_bypass_keys "${code_bypass_keys}" \
      --arg code_crypto_roundtrip "${code_crypto_roundtrip}" \
      --argjson health "${health}" \
      '{
        run_id:$run_id,
        ts:$ts,
        t_sec:$t,
        http:{
          health:($code_health|tonumber? // 0),
          db_read:($code_db_read|tonumber? // 0),
          db_write:($code_db_write|tonumber? // 0),
          bypass_pdo:($code_bypass_pdo|tonumber? // 0),
          bypass_keys:($code_bypass_keys|tonumber? // 0),
          crypto_roundtrip:($code_crypto_roundtrip|tonumber? // 0)
        },
        health:$health
      }' >> "${events_file}"
  fi

  sleep "$(awk "BEGIN {print 1/${ATTACK_RPS}}")"
done

echo "[attacker] done"
fetch_health
final_health="$(health_compact || echo '{}')"
echo "[attacker] final health=${final_health}"

if [[ -f "${events_file}" ]]; then
  jq -s \
    --arg run_id "${run_id}" \
    --arg started_at "$(jq -r '.started_at // null' "${meta_file}" 2>/dev/null || echo null)" \
    --arg ended_at "$(date -u +%FT%TZ)" \
    '{
      run_id:$run_id,
      started_at:$started_at,
      ended_at:$ended_at,
      ticks:length,
      health_http_codes:(map(.http.health)|group_by(.)|map({code:.[0],count:length})),
      db_write_http_codes:(map(.http.db_write)|group_by(.)|map({code:.[0],count:length})),
      db_read_http_codes:(map(.http.db_read)|group_by(.)|map({code:.[0],count:length})),
      bypass_keys_http_codes:(map(.http.bypass_keys)|group_by(.)|map({code:.[0],count:length})),
      crypto_roundtrip_http_codes:(map(.http.crypto_roundtrip)|group_by(.)|map({code:.[0],count:length})),
      trust_true:(map(select(.health.trusted_now==true))|length),
      rpc_ok_true:(map(select(.health.rpc_ok_now==true))|length),
      read_allowed_true:(map(select(.health.read_allowed==true))|length),
      write_allowed_true:(map(select(.health.write_allowed==true))|length)
    }' "${events_file}" > "${summary_file}" || true
  echo "[attacker] wrote events=${events_file}"
  echo "[attacker] wrote summary=${summary_file}"
fi
