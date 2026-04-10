#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODULE_PATH="${ROOT}/modules/kislayphp_gateway.so"
UPSTREAM_A_PORT="${KISLAY_NATIVE_TEST_UPSTREAM_A_PORT:-19291}"
UPSTREAM_B_PORT="${KISLAY_NATIVE_TEST_UPSTREAM_B_PORT:-19292}"
GATEWAY_PORT="${KISLAY_NATIVE_TEST_GATEWAY_PORT:-19290}"
DISCOVERY_PATH="${KISLAY_NATIVE_TEST_DISCOVERY_PATH:-/tmp/kislay_native_discovery.txt}"
ENGINE="${KISLAY_GATEWAY_ENGINE:-auto}"
THREADS="${KISLAY_NATIVE_TEST_THREADS:-1}"
POLL_MS="${KISLAY_NATIVE_TEST_DISCOVERY_POLL_MS:-100}"

UP_A_PID=""
UP_B_PID=""
GW_PID=""
cleanup() {
  if [[ -n "${GW_PID}" ]]; then kill "${GW_PID}" 2>/dev/null || true; fi
  if [[ -n "${UP_A_PID}" ]]; then kill "${UP_A_PID}" 2>/dev/null || true; fi
  if [[ -n "${UP_B_PID}" ]]; then kill "${UP_B_PID}" 2>/dev/null || true; fi
}
trap cleanup EXIT

printf 'native-service=http://127.0.0.1:%s\n' "${UPSTREAM_A_PORT}" > "${DISCOVERY_PATH}"

python3 "${ROOT}/tests/native/asyncio_upstream.py" --port "${UPSTREAM_A_PORT}" --label-prefix A >/tmp/kislay_native_discovery_up_a.log 2>&1 &
UP_A_PID=$!
python3 "${ROOT}/tests/native/asyncio_upstream.py" --port "${UPSTREAM_B_PORT}" --label-prefix B >/tmp/kislay_native_discovery_up_b.log 2>&1 &
UP_B_PID=$!
sleep 1

env \
  KISLAY_GATEWAY_ENGINE="${ENGINE}" \
  KISLAY_NATIVE_TEST_THREADS="${THREADS}" \
  KISLAY_NATIVE_TEST_UPSTREAM_PORT="${UPSTREAM_A_PORT}" \
  KISLAY_NATIVE_TEST_GATEWAY_PORT="${GATEWAY_PORT}" \
  KISLAY_NATIVE_TEST_DISCOVERY_PATH="${DISCOVERY_PATH}" \
  KISLAY_NATIVE_TEST_DISCOVERY_POLL_MS="${POLL_MS}" \
  php -n -d extension="${MODULE_PATH}" "${ROOT}/tests/native/native_discovery_driver.php" >/tmp/kislay_native_discovery_gateway.log 2>&1 &
GW_PID=$!
sleep 2

python3 "${ROOT}/tests/native/native_probe.py" \
  --port "${GATEWAY_PORT}" \
  --path /service \
  --expect-body "A:/service" \
  --clients 10 \
  --rounds 2

printf 'native-service=http://127.0.0.1:%s\n' "${UPSTREAM_B_PORT}" > "${DISCOVERY_PATH}"
sleep 2

python3 "${ROOT}/tests/native/native_probe.py" \
  --port "${GATEWAY_PORT}" \
  --path /service \
  --expect-body "B:/service" \
  --clients 10 \
  --rounds 2

ps -p "${GW_PID}" -o pid,ppid,stat,command
