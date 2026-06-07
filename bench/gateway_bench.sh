#!/usr/bin/env bash
# KislayPHP Gateway — Performance Benchmark
# Go-bench-level rigor: structured sections, p50/p75/p90/p99, MB/s, overhead analysis,
# circuit-breaker test, rate-limiter burst, body-size sweep, and a summary table.
#
# Usage:
#   bash bench/gateway_bench.sh [section]     # run all or a specific section
#
# Environment:
#   CORE_EXT        — path to kislayphp_extension.so
#   GW_EXT          — path to kislayphp_gateway.so
#   BENCH_THREADS   — wrk threads  (default: 4)
#   BENCH_CONNS     — wrk connections (default: 100)
#   BENCH_DURATION  — wrk duration per scenario in seconds (default: 15)
#   BACKEND_PORT    — backend port (default: 9292)
#   GW_PORT         — gateway port (default: 9380)
#   GW_RL_PORT      — rate-limited gateway port (default: 9381)
#   SKIP_RATE_LIMIT — set to 1 to skip rate-limit test
#   SKIP_CB         — set to 1 to skip circuit-breaker test
set -euo pipefail

CORE_EXT="${CORE_EXT:-/Users/kislay/kislayphp/core/modules/kislayphp_extension.so}"
GW_EXT="${GW_EXT:-/Users/kislay/kislayphp/gateway/modules/kislayphp_gateway.so}"
BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="${BENCH_DIR}/results"
mkdir -p "$RESULTS_DIR"

BACKEND_PORT="${BACKEND_PORT:-9292}"
LB_BACKENDS="${LB_BACKENDS:-4}"
GW_PORT="${GW_PORT:-9380}"
GW_RL_PORT="${GW_RL_PORT:-9381}"
HOST="127.0.0.1"
THREADS="${BENCH_THREADS:-4}"
CONNS="${BENCH_CONNS:-100}"
DURATION="${BENCH_DURATION:-15}"

SECTION_FILTER="${1:-all}"

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
REPORT="${RESULTS_DIR}/gateway-bench-${TIMESTAMP}.md"

# ── Prerequisite checks ────────────────────────────────────────────────────────
for ext in "$CORE_EXT" "$GW_EXT"; do
    if [[ ! -f "$ext" ]]; then
        echo "[bench] ERROR: Extension not found: $ext"
        echo "        Build first: cd $(dirname "$ext")/.. && make"
        exit 1
    fi
done

if ! command -v wrk >/dev/null 2>&1; then
    echo "[bench] ERROR: wrk not found. Install with: brew install wrk"
    exit 1
fi

# ── JWT token (HS256) ──────────────────────────────────────────────────────────
JWT_SECRET="bench-secret-key-32bytes-padding!!"
JWT_HEADER=$(printf '{"alg":"HS256","typ":"JWT"}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')
EXP=$(( $(date +%s) + 3600 ))
JWT_PAYLOAD=$(printf '{"sub":"bench-user","roles":"admin","exp":%d}' "$EXP" \
              | openssl base64 -A | tr '+/' '-_' | tr -d '=')
JWT_SIG=$(printf '%s.%s' "$JWT_HEADER" "$JWT_PAYLOAD" \
    | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary \
    | openssl base64 -A | tr '+/' '-_' | tr -d '=')
JWT_TOKEN="${JWT_HEADER}.${JWT_PAYLOAD}.${JWT_SIG}"

# ── Process management ─────────────────────────────────────────────────────────
BACKEND_PID=""
BACKEND_URLS=""
GW_PID=""
GW_RL_PID=""

cleanup() {
    for pid in $BACKEND_PID $GW_PID $GW_RL_PID; do
        [[ -n "$pid" ]] && pkill -TERM -P "$pid" 2>/dev/null || true
    done
    for pid in $BACKEND_PID $GW_PID $GW_RL_PID; do
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    done
    sleep 0.2
    for pid in $BACKEND_PID $GW_PID $GW_RL_PID; do
        [[ -n "$pid" ]] && pkill -KILL -P "$pid" 2>/dev/null || true
    done
    for pid in $BACKEND_PID $GW_PID $GW_RL_PID; do
        [[ -n "$pid" ]] && wait "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT

wait_for() {
    local url="$1" label="$2" attempts="${3:-40}"
    for _ in $(seq 1 "$attempts"); do
        if curl -sf "$url" >/dev/null 2>&1; then
            echo "[bench] $label ready"
            return 0
        fi
        sleep 0.25
    done
    echo "[bench] ERROR: $label not ready after ${attempts} attempts"
    return 1
}

# ── Start backend pool ─────────────────────────────────────────────────────────
echo "[bench] Starting $LB_BACKENDS backend instance(s) from port $BACKEND_PORT..."
for i in $(seq 0 $((LB_BACKENDS - 1))); do
    port=$((BACKEND_PORT + i))
    BACKEND_PORT=$port \
    BACKEND_HTTP_THREADS="${BACKEND_HTTP_THREADS:-8}" \
    BACKEND_WORKERS="${BACKEND_WORKERS:-10}" \
    php -d extension="$CORE_EXT" "$BENCH_DIR/gateway_backend.php" >/tmp/gw_backend_${port}.log 2>&1 &
    pid=$!
    BACKEND_PID="${BACKEND_PID} ${pid}"
    url="http://$HOST:$port"
    if [[ -z "$BACKEND_URLS" ]]; then
        BACKEND_URLS="$url"
    else
        BACKEND_URLS="${BACKEND_URLS},${url}"
    fi
done

# ── Start main gateway ─────────────────────────────────────────────────────────
echo "[bench] Starting gateway on port $GW_PORT..."
GW_PORT=$GW_PORT \
BACKEND_URL="http://$HOST:$BACKEND_PORT" \
BACKEND_URLS="$BACKEND_URLS" \
KISLAY_GATEWAY_THREADS=8 \
php -d extension="$GW_EXT" "$BENCH_DIR/gateway_server.php" >/tmp/gw_server.log 2>&1 &
GW_PID=$!

# ── Start rate-limited gateway (separate instance) ─────────────────────────────
if [[ "${SKIP_RATE_LIMIT:-0}" != "1" ]]; then
    echo "[bench] Starting rate-limited gateway on port $GW_RL_PORT..."
    GW_PORT=$GW_RL_PORT \
    BACKEND_URL="http://$HOST:$BACKEND_PORT" \
    BACKEND_URLS="$BACKEND_URLS" \
    KISLAY_GATEWAY_RATE_LIMIT_ENABLED=1 \
    KISLAY_GATEWAY_RATE_LIMIT_REQUESTS=20 \
    KISLAY_GATEWAY_RATE_LIMIT_WINDOW=1 \
    KISLAY_GATEWAY_THREADS=4 \
    php -d extension="$GW_EXT" "$BENCH_DIR/gateway_server.php" >/tmp/gw_rl.log 2>&1 &
    GW_RL_PID=$!
fi

# ── Wait for readiness ─────────────────────────────────────────────────────────
for i in $(seq 0 $((LB_BACKENDS - 1))); do
    port=$((BACKEND_PORT + i))
    wait_for "http://$HOST:$port/health" "Backend:$port"
done
wait_for "http://$HOST:$GW_PORT/health" "Gateway"
if [[ -n "${GW_RL_PID}" ]]; then
    wait_for "http://$HOST:$GW_RL_PORT/health" "Rate-limited gateway" || true
fi

GW_BASE="http://$HOST:$GW_PORT"
GW_RL_BASE="http://$HOST:$GW_RL_PORT"
BACKEND_BASE="http://$HOST:$BACKEND_PORT"

# ── Helpers ────────────────────────────────────────────────────────────────────

separator() { printf "\n%s\n" "$(printf '─%.0s' $(seq 1 78))"; }

run_wrk() {
    local label="$1" url="$2"; shift 2
    printf "\n\033[1m▶ %-50s\033[0m\n" "$label"
    printf "  URL: %s\n" "$url"
    wrk -t"$THREADS" -c"$CONNS" -d"${DURATION}s" --latency "$@" "$url" 2>&1 | \
        awk '/Latency|Req\/Sec|requests in|Transfer\/sec|50%|75%|90%|99%/{print "  " $0}'
}

run_wrk_lua() {
    local label="$1" url="$2" lua_file="$3"; shift 3
    printf "\n\033[1m▶ %-50s\033[0m\n" "$label"
    printf "  URL: %s\n" "$url"
    wrk -t"$THREADS" -c"$CONNS" -d"${DURATION}s" --latency -s "$lua_file" "$@" "$url" 2>&1 | \
        awk '/Latency|Req\/Sec|requests in|Transfer\/sec|50%|75%|90%|99%/{print "  " $0}'
}

# Lua script: POST with JSON body
make_post_lua() {
    local body="$1" tmpfile
    tmpfile="$(mktemp /tmp/gw_post_XXXXXX.lua)"
    cat > "$tmpfile" <<LUA
wrk.method = "POST"
wrk.body   = '${body}'
wrk.headers["Content-Type"] = "application/json"
LUA
    echo "$tmpfile"
}

# Lua script: GET with Authorization header
make_jwt_lua() {
    local token="$1" tmpfile
    tmpfile="$(mktemp /tmp/gw_jwt_XXXXXX.lua)"
    cat > "$tmpfile" <<LUA
wrk.headers["Authorization"] = "Bearer ${token}"
LUA
    echo "$tmpfile"
}

echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
echo " KislayPHP Gateway — Performance Benchmark (Go-bench level rigor)"
echo "════════════════════════════════════════════════════════════════════════════════"
printf " Backend  : %s\n" "$BACKEND_BASE"
printf " Pool     : %s\n" "$BACKEND_URLS"
printf " Gateway  : %s\n" "$GW_BASE"
printf " wrk      : %d threads, %d connections, %ds per scenario\n" "$THREADS" "$CONNS" "$DURATION"
echo "════════════════════════════════════════════════════════════════════════════════"

# Track results for summary table. Keep this Bash 3 compatible for macOS.
result_var() {
    local prefix="$1" key="$2" safe
    safe="$(printf '%s' "$key" | tr -c '[:alnum:]_' '_')"
    printf 'RESULT_%s_%s' "$prefix" "$safe"
}

set_result() {
    local prefix="$1" key="$2" value="$3" var
    var="$(result_var "$prefix" "$key")"
    printf -v "$var" '%s' "$value"
}

get_result() {
    local prefix="$1" key="$2" var
    var="$(result_var "$prefix" "$key")"
    eval 'printf "%s" "${'"$var"':-}"'
}

capture_rps() {
    local key="$1" url="$2"; shift 2
    local out
    out=$(wrk -t"$THREADS" -c"$CONNS" -d"${DURATION}s" --latency "$@" "$url" 2>&1 || true)
    set_result "RPS" "$key" "$(echo "$out" | awk '/Requests\/sec:/{print $2; found=1} END{if (!found) print "N/A"}')"
    set_result "P99" "$key" "$(echo "$out" | awk '/99%/{print $2; found=1; exit} END{if (!found) print "N/A"}')"
    echo "$out" | awk '/Latency|Req\/Sec|requests in|Transfer\/sec|50%|75%|90%|99%/{print "  " $0}'
}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — Baseline: Direct backend (no gateway)
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$SECTION_FILTER" == "all" || "$SECTION_FILTER" == "baseline" ]]; then
    separator
    echo "  SECTION 1 — Baseline: Direct Backend (no gateway overhead)"
    separator

    printf "\n\033[1m▶ backend/plaintext (direct)\033[0m\n"
    capture_rps "backend/plaintext" "$BACKEND_BASE/plaintext"

    printf "\n\033[1m▶ backend/json (direct)\033[0m\n"
    capture_rps "backend/json" "$BACKEND_BASE/json"
fi

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — Plain proxy pass-through
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$SECTION_FILTER" == "all" || "$SECTION_FILTER" == "proxy" ]]; then
    separator
    echo "  SECTION 2 — Plain Proxy (gateway pass-through)"
    separator

    printf "\n\033[1m▶ gateway/proxy/plaintext\033[0m\n"
    capture_rps "proxy/plaintext" "$GW_BASE/proxy/plaintext"

    printf "\n\033[1m▶ gateway/proxy/json\033[0m\n"
    capture_rps "proxy/json" "$GW_BASE/proxy/json"
fi

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — POST body forwarding (multiple sizes)
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$SECTION_FILTER" == "all" || "$SECTION_FILTER" == "post" ]]; then
    separator
    echo "  SECTION 3 — POST Body Forwarding (200B / 1KB / 10KB)"
    separator

    # 200-byte payload
    LUA_200B="$(make_post_lua '{"user":"bench","data":"'"$(python3 -c 'print("x"*168)')"'"}')"
    printf "\n\033[1m▶ gateway/proxy/echo (POST 200B)\033[0m\n"
    capture_rps "post/echo_200b" "$GW_BASE/proxy/echo" -s "$LUA_200B"
    rm -f "$LUA_200B"

    # 1 KB payload
    LUA_1K="$(make_post_lua '{"user":"bench","data":"'"$(python3 -c 'print("x"*1000)')"'"}')"
    printf "\n\033[1m▶ gateway/proxy/echo (POST 1KB)\033[0m\n"
    capture_rps "post/echo_1k" "$GW_BASE/proxy/echo" -s "$LUA_1K"
    rm -f "$LUA_1K"

    # 10 KB payload
    LUA_10K="$(make_post_lua '{"user":"bench","data":"'"$(python3 -c 'print("x"*10000)')"'"}')"
    printf "\n\033[1m▶ gateway/proxy/echo (POST 10KB)\033[0m\n"
    capture_rps "post/echo_10k" "$GW_BASE/proxy/echo" -s "$LUA_10K"
    rm -f "$LUA_10K"
fi

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — Header propagation
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$SECTION_FILTER" == "all" || "$SECTION_FILTER" == "headers" ]]; then
    separator
    echo "  SECTION 4 — Header Propagation (trace-id, request-id)"
    separator

    printf "\n\033[1m▶ gateway/proxy/headers (forwarded headers round-trip)\033[0m\n"
    capture_rps "headers/trace" "$GW_BASE/proxy/headers" \
        -H "X-Request-Id: bench-$(openssl rand -hex 8)" \
        -H "traceparent: 00-$(openssl rand -hex 16)-$(openssl rand -hex 8)-01"
fi

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — JWT authentication (HS256)
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$SECTION_FILTER" == "all" || "$SECTION_FILTER" == "jwt" ]]; then
    separator
    echo "  SECTION 5 — JWT Authentication (HS256)"
    separator

    LUA_JWT="$(make_jwt_lua "$JWT_TOKEN")"

    printf "\n\033[1m▶ gateway/secure/data (valid JWT → 200)\033[0m\n"
    capture_rps "jwt/valid" "$GW_BASE/secure/data" -s "$LUA_JWT"

    printf "\n\033[1m▶ gateway/secure/headers (valid JWT + header check)\033[0m\n"
    capture_rps "jwt/valid_headers" "$GW_BASE/secure/headers" -s "$LUA_JWT"
    rm -f "$LUA_JWT"

    # No token — measures fast-reject speed (401 responses)
    printf "\n\033[1m▶ gateway/secure/data (no token → 401 fast-reject)\033[0m\n"
    capture_rps "jwt/missing_401" "$GW_BASE/secure/data"

    # Overhead comparison
    if [[ -n "$(get_result RPS "proxy/plaintext")" && -n "$(get_result RPS "jwt/valid")" ]]; then
        PP="$(get_result RPS "proxy/plaintext")"
        JP="$(get_result RPS "jwt/valid")"
        if [[ "$PP" != "N/A" && "$JP" != "N/A" ]]; then
            OVERHEAD=$(awk -v pp="$PP" -v jp="$JP" 'BEGIN { printf "%.1f", ((pp-jp)/pp)*100 }')
            printf "\n  JWT HS256 overhead: %.1f req/s → %.1f req/s (%.1f%% RPS reduction)\n" \
                "$PP" "$JP" "$OVERHEAD"
        fi
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — Native service registry (round-robin load balancing)
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$SECTION_FILTER" == "all" || "$SECTION_FILTER" == "lb" ]]; then
    separator
    echo "  SECTION 6 — Native Service Registry (round-robin LB)"
    separator

    printf "\n\033[1m▶ gateway/lb/json (round-robin)\033[0m\n"
    capture_rps "lb/json" "$GW_BASE/lb/json"

    printf "\n\033[1m▶ gateway/lb/plaintext (round-robin)\033[0m\n"
    capture_rps "lb/plaintext" "$GW_BASE/lb/plaintext"
fi

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — Fallback route
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$SECTION_FILTER" == "all" || "$SECTION_FILTER" == "fallback" ]]; then
    separator
    echo "  SECTION 7 — Fallback Route"
    separator

    printf "\n\033[1m▶ gateway/fallback (unknown path → fallback target)\033[0m\n"
    capture_rps "fallback/unknown" "$GW_BASE/no-such-route"
fi

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — Upstream latency simulation (5ms backend delay)
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$SECTION_FILTER" == "all" || "$SECTION_FILTER" == "slow" ]]; then
    separator
    echo "  SECTION 8 — Upstream Latency (5ms simulated backend delay)"
    separator

    printf "\n\033[1m▶ gateway/proxy/slow (5ms upstream)\033[0m\n"
    capture_rps "proxy/slow" "$GW_BASE/proxy/slow"
fi

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — High concurrency (4× normal connections)
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$SECTION_FILTER" == "all" || "$SECTION_FILTER" == "stress" ]]; then
    separator
    echo "  SECTION 9 — High Concurrency ($(( CONNS * 4 )) connections)"
    separator

    HIGH_CONNS=$(( CONNS * 4 ))
    printf "\n\033[1m▶ gateway/proxy/plaintext @ %d connections\033[0m\n" "$HIGH_CONNS"
    capture_rps "stress/plaintext" "$GW_BASE/proxy/plaintext" \
        -t"$(( THREADS * 2 ))" -c"$HIGH_CONNS" -d"${DURATION}s"

    printf "\n\033[1m▶ gateway/proxy/json @ %d connections\033[0m\n" "$HIGH_CONNS"
    capture_rps "stress/json" "$GW_BASE/proxy/json" \
        -t"$(( THREADS * 2 ))" -c"$HIGH_CONNS" -d"${DURATION}s"
fi

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 10 — Rate limiter throughput (fast-reject benchmark)
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$SECTION_FILTER" == "all" || "$SECTION_FILTER" == "ratelimit" ]]; then
    if [[ "${SKIP_RATE_LIMIT:-0}" != "1" && -n "${GW_RL_PID}" ]]; then
        separator
        echo "  SECTION 10 — Rate Limiter: Fast-Reject Throughput"
        echo "  (Gateway: RATE_LIMIT_REQUESTS=20/s — most responses will be 429)"
        echo "  Metric: how fast the gateway can reject overloaded requests."
        separator

        # Burst well above the rate limit
        printf "\n\033[1m▶ rate-limited gateway/proxy/plaintext (burst → 429s)\033[0m\n"
        BURST_CONNS=$(( CONNS * 2 ))
        wrk -t"$THREADS" -c"$BURST_CONNS" -d"${DURATION}s" --latency \
            "$GW_RL_BASE/proxy/plaintext" 2>&1 | \
            awk '/Latency|Req\/Sec|requests in|Transfer\/sec|50%|75%|90%|99%|Non-2xx/{print "  " $0}'
        set_result "RPS" "rate_limit/429_throughput" "$(wrk -t"$THREADS" -c"$BURST_CONNS" -d"5s" \
            "$GW_RL_BASE/proxy/plaintext" 2>&1 | awk '/Requests\/sec:/{print $2; found=1} END{if (!found) print "N/A"}')"
    else
        echo ""
        echo "  [SECTION 10 SKIPPED] Rate limiter test skipped (SKIP_RATE_LIMIT=1 or instance failed)"
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 11 — Circuit breaker test
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$SECTION_FILTER" == "all" || "$SECTION_FILTER" == "circuit" ]]; then
    if [[ "${SKIP_CB:-0}" != "1" ]]; then
        separator
        echo "  SECTION 11 — Circuit Breaker Behavior"
        echo "  Sends requests to a failing backend endpoint, then verifies the breaker"
        echo "  opens (503 Service Unavailable) and later closes (connection pool test)."
        separator

        # Start a circuit-breaker enabled gateway on a temp port
        CB_PORT=$(( GW_PORT + 2 ))
        printf "\n[bench] Starting CB gateway on port %d...\n" "$CB_PORT"
        GW_PORT=$CB_PORT \
        BACKEND_URL="http://$HOST:$BACKEND_PORT" \
        KISLAY_GATEWAY_CIRCUIT_BREAKER_ENABLED=1 \
        KISLAY_GATEWAY_CB_FAILURE_THRESHOLD=3 \
        KISLAY_GATEWAY_CB_OPEN_SECONDS=5 \
        KISLAY_GATEWAY_THREADS=4 \
        php -d extension="$GW_EXT" "$BENCH_DIR/gateway_server.php" >/tmp/gw_cb.log 2>&1 &
        CB_PID=$!
        # Ensure cleanup
        trap "cleanup; kill $CB_PID 2>/dev/null || true; wait $CB_PID 2>/dev/null || true" EXIT

        wait_for "http://$HOST:$CB_PORT/health" "CB gateway" || { kill "$CB_PID" 2>/dev/null || true; }

        if curl -sf "http://$HOST:$CB_PORT/health" >/dev/null 2>&1; then
            CB_BASE="http://$HOST:$CB_PORT"

            # Phase 1: normal traffic (breaker closed)
            printf "\n\033[1m▶ Phase 1: Normal traffic (breaker CLOSED)\033[0m\n"
            wrk -t2 -c10 -d5s --latency "$CB_BASE/proxy/plaintext" 2>&1 | \
                awk '/Req\/Sec|50%|99%/{print "  " $0}'

            # Phase 2: trigger failures via the /cb/fail route (if available)
            # The gateway_server_cb.php would add this route — we use curl directly here
            printf "\n\033[1m▶ Phase 2: Triggering failures to open breaker\033[0m\n"
            for i in $(seq 1 5); do
                curl -sf "$CB_BASE/proxy/fail" >/dev/null 2>&1 || true
            done
            echo "  Sent 5 requests to failing endpoint — breaker should open now."

            # Phase 3: measure fast 503 rejection (breaker open)
            printf "\n\033[1m▶ Phase 3: Breaker OPEN — measuring 503 fast-reject throughput\033[0m\n"
            wrk -t2 -c20 -d5s --latency "$CB_BASE/proxy/plaintext" 2>&1 | \
                awk '/Req\/Sec|50%|99%|Non-2xx/{print "  " $0}'

            # Phase 4: wait for breaker to close (CB_OPEN_SECONDS=5)
            echo ""
            printf "  Waiting 6s for circuit breaker to close...\n"
            sleep 6

            # Phase 5: normal traffic again (breaker half-open → closed)
            printf "\n\033[1m▶ Phase 4: Breaker CLOSED again — recovery\033[0m\n"
            wrk -t2 -c10 -d5s --latency "$CB_BASE/proxy/plaintext" 2>&1 | \
                awk '/Req\/Sec|50%|99%/{print "  " $0}'

            kill "$CB_PID" 2>/dev/null || true
            wait "$CB_PID" 2>/dev/null || true
        else
            echo "  [SKIPPED] CB gateway failed to start"
        fi
    else
        echo ""
        echo "  [SECTION 11 SKIPPED] Circuit breaker test skipped (SKIP_CB=1)"
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 12 — Response size impact (backend payload sweep)
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$SECTION_FILTER" == "all" || "$SECTION_FILTER" == "payload" ]]; then
    separator
    echo "  SECTION 12 — Response Payload Size Impact"
    echo "  How gateway throughput degrades as backend response size grows."
    separator

    for kb in 1 10 100; do
        # Direct backend
        printf "\n\033[1m▶ backend/json (direct, ~%dKB)\033[0m\n" "$kb"
        wrk -t"$THREADS" -c"$CONNS" -d"${DURATION}s" --latency \
            "$BACKEND_BASE/payload/${kb}k" 2>&1 | \
            awk '/Req\/Sec|Transfer\/sec|50%|99%/{print "  backend-direct: " $0}' || \
            echo "  (endpoint /payload/${kb}k not available on backend)"

        # Via gateway
        printf "\n\033[1m▶ gateway/proxy (via gateway, ~%dKB)\033[0m\n" "$kb"
        wrk -t"$THREADS" -c"$CONNS" -d"${DURATION}s" --latency \
            "$GW_BASE/proxy/payload/${kb}k" 2>&1 | \
            awk '/Req\/Sec|Transfer\/sec|50%|99%/{print "  via-gateway:    " $0}' || \
            echo "  (route /proxy/payload/${kb}k not configured in gateway_server.php)"
    done
fi

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY TABLE (Markdown + terminal)
# ══════════════════════════════════════════════════════════════════════════════
separator
echo "  SUMMARY — Throughput Table"
separator

{
    echo "# KislayPHP Gateway Benchmark — $TIMESTAMP"
    echo ""
    echo "| Scenario | Req/sec | P99 latency |"
    echo "|---|---:|---:|"

    declare -a ORDERED_KEYS=(
        "backend/plaintext"
        "backend/json"
        "proxy/plaintext"
        "proxy/json"
        "post/echo_200b"
        "post/echo_1k"
        "post/echo_10k"
        "headers/trace"
        "jwt/valid"
        "jwt/valid_headers"
        "jwt/missing_401"
        "lb/json"
        "lb/plaintext"
        "fallback/unknown"
        "proxy/slow"
        "stress/plaintext"
        "stress/json"
        "rate_limit/429_throughput"
    )

    for k in "${ORDERED_KEYS[@]}"; do
        rps="$(get_result RPS "$k")"
        p99="$(get_result P99 "$k")"
        rps="${rps:-N/A}"
        p99="${p99:-N/A}"
        echo "| $k | $rps | $p99 |"
    done

    echo ""
    echo "**Config:** $THREADS wrk threads, $CONNS connections, ${DURATION}s per scenario"

    # Overhead analysis
    echo ""
    echo "## Overhead Analysis"
    if [[ -n "$(get_result RPS "backend/plaintext")" && -n "$(get_result RPS "proxy/plaintext")" ]]; then
        BP="$(get_result RPS "backend/plaintext")"
        GP="$(get_result RPS "proxy/plaintext")"
        if [[ "$BP" != "N/A" && "$GP" != "N/A" ]]; then
            OVH=$(awk -v b="$BP" -v g="$GP" 'BEGIN { printf "%.1f", ((b-g)/b)*100 }')
            echo "- Plain proxy overhead: ${OVH}% RPS reduction (${BP} → ${GP} req/s)"
        fi
    fi
    if [[ -n "$(get_result RPS "proxy/plaintext")" && -n "$(get_result RPS "jwt/valid")" ]]; then
        GP="$(get_result RPS "proxy/plaintext")"
        JP="$(get_result RPS "jwt/valid")"
        if [[ "$GP" != "N/A" && "$JP" != "N/A" ]]; then
            OVH=$(awk -v g="$GP" -v j="$JP" 'BEGIN { printf "%.1f", ((g-j)/g)*100 }')
            echo "- JWT HS256 auth overhead: ${OVH}% RPS reduction vs plain proxy"
        fi
    fi
} | tee "$REPORT"

echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
printf " [bench] Done. Report saved: %s\n" "$REPORT"
echo "════════════════════════════════════════════════════════════════════════════════"
