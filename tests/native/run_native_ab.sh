#!/usr/bin/env bash
set -euo pipefail

if ! command -v ab >/dev/null 2>&1; then
  echo "ab not installed"
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODULE_PATH="${ROOT}/modules/kislayphp_gateway.so"
UPSTREAM_PORT="${KISLAY_NATIVE_TEST_UPSTREAM_PORT:-19091}"
GATEWAY_PORT="${KISLAY_NATIVE_TEST_GATEWAY_PORT:-19090}"
ENGINE="${KISLAY_GATEWAY_ENGINE:-auto}"
MODE="${KISLAY_NATIVE_TEST_MODE:-direct}"
THREADS="${KISLAY_NATIVE_TEST_THREADS:-0}"
REQUESTS="${KISLAY_NATIVE_TEST_REQUESTS:-2000}"
CONCURRENCY="${KISLAY_NATIVE_TEST_CONCURRENCY:-100}"

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

ab -k -n "${REQUESTS}" -c "${CONCURRENCY}" "http://127.0.0.1:${UPSTREAM_PORT}/direct" >/tmp/kislay_native_ab_upstream.txt 2>&1 || true
ab -k -n "${REQUESTS}" -c "${CONCURRENCY}" "http://127.0.0.1:${GATEWAY_PORT}/direct" >/tmp/kislay_native_ab_gateway.txt 2>&1 || true
if [[ "${MODE}" == "service" ]]; then
  ab -k -n "${REQUESTS}" -c "${CONCURRENCY}" "http://127.0.0.1:${GATEWAY_PORT}/service" >/tmp/kislay_native_ab_service.txt 2>&1 || true
fi

echo "UPSTREAM"
cat /tmp/kislay_native_ab_upstream.txt
echo
echo "GATEWAY_DIRECT"
cat /tmp/kislay_native_ab_gateway.txt
if [[ "${MODE}" == "service" ]]; then
  echo
  echo "GATEWAY_SERVICE"
  cat /tmp/kislay_native_ab_service.txt
fi
