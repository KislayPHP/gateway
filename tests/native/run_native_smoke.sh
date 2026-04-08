#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODULE_PATH="${ROOT}/modules/kislayphp_gateway.so"
UPSTREAM_PORT="${KISLAY_NATIVE_TEST_UPSTREAM_PORT:-19091}"
GATEWAY_PORT="${KISLAY_NATIVE_TEST_GATEWAY_PORT:-19090}"
ENGINE="${KISLAY_GATEWAY_ENGINE:-auto}"
MODE="${KISLAY_NATIVE_TEST_MODE:-direct}"
THREADS="${KISLAY_NATIVE_TEST_THREADS:-0}"

UP_PID=""
GW_PID=""
cleanup() {
  if [[ -n "${GW_PID}" ]]; then kill "${GW_PID}" 2>/dev/null || true; fi
  if [[ -n "${UP_PID}" ]]; then kill "${UP_PID}" 2>/dev/null || true; fi
}
trap cleanup EXIT

python3 "${ROOT}/tests/native/asyncio_upstream.py" --port "${UPSTREAM_PORT}" >/tmp/kislay_native_upstream.log 2>&1 &
UP_PID=$!
sleep 1

env \
  KISLAY_GATEWAY_ENGINE="${ENGINE}" \
  KISLAY_NATIVE_TEST_MODE="${MODE}" \
  KISLAY_NATIVE_TEST_THREADS="${THREADS}" \
  KISLAY_NATIVE_TEST_UPSTREAM_PORT="${UPSTREAM_PORT}" \
  KISLAY_NATIVE_TEST_GATEWAY_PORT="${GATEWAY_PORT}" \
  php -n -d extension="${MODULE_PATH}" "${ROOT}/tests/native/native_gateway_driver.php" >/tmp/kislay_native_gateway.log 2>&1 &
GW_PID=$!
sleep 2

python3 "${ROOT}/tests/native/native_probe.py" \
  --port "${GATEWAY_PORT}" \
  --path /direct \
  --expect-body "upstream-ok:/direct" \
  --clients 50 \
  --rounds 20

python3 "${ROOT}/tests/native/native_probe.py" \
  --port "${GATEWAY_PORT}" \
  --path /slow \
  --expect-body "upstream-ok:/slow" \
  --clients 10 \
  --rounds 5

if [[ "${MODE}" == "service" ]]; then
  python3 "${ROOT}/tests/native/native_probe.py" \
    --port "${GATEWAY_PORT}" \
    --path /service \
    --expect-body "upstream-ok:/service" \
    --clients 50 \
    --rounds 20
fi

ps -p "${GW_PID}" -o pid,ppid,stat,command
