<?php
/**
 * KislayPHP Gateway – Performance Benchmark Client
 *
 * Go-bench-style HTTP benchmarking for the gateway extension.
 * Measures gateway overhead by comparing direct backend vs. gateway proxy,
 * and benchmarks all gateway features: JWT auth, load balancing, fallback,
 * header propagation, POST body forwarding, rate limiting, circuit breaker.
 *
 * Usage:
 *   # Start servers first:
 *   #   Backend : php bench/gateway_backend.php   (port 9292)
 *   #   Gateway : php bench/gateway_server.php    (port 9380)
 *
 *   php bench/perf_client.php [backend_host] [backend_port] [gw_host] [gw_port] \
 *                              [concurrency] [requests] [filter] [runs]
 *
 * Environment:
 *   BENCH_JWT_SECRET   — HS256 secret (default: bench-secret-key-32bytes-padding!!)
 *   BENCH_DURATION_MS  — run each scenario for N ms instead of fixed request count
 *   BENCH_GOBENCH=1    — emit Go-bench text lines (benchstat-compatible)
 *   BENCH_JSON=1       — emit JSON results after table
 *   BENCH_RUNS=3       — number of runs per scenario for CV stability check
 *   BENCH_CV_WARN=5    — warn if RPS coefficient of variation exceeds this %
 */

$backendHost = $argv[1] ?? '127.0.0.1';
$backendPort = (int)($argv[2] ?? 9292);
$gwHost      = $argv[3] ?? '127.0.0.1';
$gwPort      = (int)($argv[4] ?? 9380);
$concurrency = (int)($argv[5] ?? 20);
$requests    = (int)($argv[6] ?? 1000);
$only        = $argv[7] ?? null;
$runs        = (int)($argv[8] ?? (int)(getenv('BENCH_RUNS') ?: 1));

$backendUrl  = "http://{$backendHost}:{$backendPort}";
$gwUrl       = "http://{$gwHost}:{$gwPort}";
$durationMs  = (int)(getenv('BENCH_DURATION_MS') ?: 0);
$emitGoBench = (bool)(getenv('BENCH_GOBENCH') ?: false);
$emitJson    = (bool)(getenv('BENCH_JSON') ?: false);
$cvWarnPct   = (float)(getenv('BENCH_CV_WARN') ?: 5.0);

// ── JWT token generation ──────────────────────────────────────────────────────
$jwtSecret  = getenv('BENCH_JWT_SECRET') ?: 'bench-secret-key-32bytes-padding!!';
$jwtHeader  = rtrim(strtr(base64_encode('{"alg":"HS256","typ":"JWT"}'), '+/', '-_'), '=');
$jwtPayload = rtrim(strtr(base64_encode(json_encode([
    'sub'   => 'bench-user',
    'roles' => 'admin',
    'exp'   => time() + 3600,
])), '+/', '-_'), '=');
$jwtSigRaw  = hash_hmac('sha256', "$jwtHeader.$jwtPayload", $jwtSecret, true);
$jwtSig     = rtrim(strtr(base64_encode($jwtSigRaw), '+/', '-_'), '=');
$jwtToken   = "$jwtHeader.$jwtPayload.$jwtSig";

// ── Core HTTP helpers (same engine as core/bench/perf_client.php) ─────────────

function bench_run_scenario(
    string $url,
    int $concurrency,
    int $totalRequests,
    string $method = 'GET',
    string $body = '',
    array $extraHeaders = [],
    bool $allow4xx = false,
    bool $allow5xx = false,
    int $durationMs = 0
): array {
    $latencies = [];
    $byteSizes = [];
    $errors    = 0;
    $completed = 0;

    $mh         = curl_multi_init();
    $handles    = [];
    $startTimes = [];
    $deadline   = $durationMs > 0 ? (microtime(true) + $durationMs / 1000.0) : null;

    $addHandle = function () use (
        $mh, $url, $method, $body, $extraHeaders, &$handles, &$startTimes
    ) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        if ($method === 'POST' || $method === 'PUT') {
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
            $extraHeaders[] = 'Content-Type: application/json';
        }
        if ($extraHeaders) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $extraHeaders);
        }
        $id = (int)$ch;
        $startTimes[$id] = microtime(true);
        $handles[$id]    = $ch;
        curl_multi_add_handle($mh, $ch);
    };

    $toSend = $durationMs > 0 ? $concurrency : min($concurrency, $totalRequests);
    for ($i = 0; $i < $toSend; $i++) {
        $addHandle();
    }

    $wallStart = microtime(true);
    $active    = null;

    do {
        while (($s = curl_multi_exec($mh, $active)) === CURLM_CALL_MULTI_PERFORM) {}
        if ($s !== CURLM_OK) break;

        while ($info = curl_multi_info_read($mh)) {
            $ch        = $info['handle'];
            $id        = (int)$ch;
            $lat       = (microtime(true) - ($startTimes[$id] ?? microtime(true))) * 1000.0;
            $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $size      = (float)curl_getinfo($ch, CURLINFO_SIZE_DOWNLOAD);

            $isError = $info['result'] !== CURLE_OK
                || (!$allow4xx && $http_code >= 400 && $http_code < 500)
                || (!$allow5xx && $http_code >= 500);

            if ($isError) {
                $errors++;
            } else {
                $latencies[] = $lat;
                $byteSizes[] = $size;
            }

            $completed++;
            curl_multi_remove_handle($mh, $ch);
            @curl_close($ch);
            unset($handles[$id], $startTimes[$id]);

            $needMore = $durationMs > 0
                ? (microtime(true) < $deadline)
                : (($completed + count($handles)) < $totalRequests);
            if ($needMore) $addHandle();
        }

        if ($active) curl_multi_select($mh, 0.005);
        if ($deadline !== null && microtime(true) >= $deadline && !$active && empty($handles)) break;
    } while ($active || $handles);

    $wallElapsed = microtime(true) - $wallStart;
    curl_multi_close($mh);

    sort($latencies);
    $n = count($latencies);

    if ($n === 0) {
        return [
            'rps' => 0.0, 'ns_op' => INF, 'avg_ms' => 0.0,
            'p50_ms' => 0.0, 'p95_ms' => 0.0, 'p99_ms' => 0.0, 'p999_ms' => 0.0,
            'min_ms' => 0.0, 'max_ms' => 0.0, 'stddev_ms' => 0.0,
            'bytes_op' => 0.0, 'errors' => $errors, 'total' => $completed,
            'elapsed_s' => $wallElapsed, 'cv_pct' => 0.0, 'runs' => 1, 'unstable' => false,
        ];
    }

    $sum  = array_sum($latencies);
    $mean = $sum / $n;
    $var  = 0.0;
    foreach ($latencies as $v) { $var += ($v - $mean) ** 2; }
    $stddev = sqrt($var / $n);

    $pct = function (float $p) use ($latencies, $n): float {
        return $latencies[max(0, min((int)ceil($p * $n) - 1, $n - 1))];
    };

    $rps = $wallElapsed > 0 ? ($n / $wallElapsed) : 0.0;

    return [
        'rps'       => $rps,
        'ns_op'     => $rps > 0 ? 1.0e9 / $rps : INF,
        'avg_ms'    => $mean,
        'p50_ms'    => $pct(0.50),
        'p95_ms'    => $pct(0.95),
        'p99_ms'    => $pct(0.99),
        'p999_ms'   => $pct(0.999),
        'min_ms'    => $latencies[0],
        'max_ms'    => $latencies[$n - 1],
        'stddev_ms' => $stddev,
        'bytes_op'  => array_sum($byteSizes) / $n,
        'errors'    => $errors,
        'total'     => $completed,
        'elapsed_s' => $wallElapsed,
        'cv_pct'    => 0.0,
        'runs'      => 1,
        'unstable'  => false,
    ];
}

function bench_run(
    string $url,
    int $concurrency,
    int $requests,
    string $method = 'GET',
    string $body = '',
    array $extraHeaders = [],
    bool $allow4xx = false,
    bool $allow5xx = false,
    int $durationMs = 0,
    int $runs = 1,
    float $cvWarnPct = 5.0
): array {
    $allResults = [];
    $allRps     = [];
    for ($i = 0; $i < $runs; $i++) {
        $r = bench_run_scenario($url, $concurrency, $requests, $method, $body, $extraHeaders, $allow4xx, $allow5xx, $durationMs);
        $allResults[] = $r;
        $allRps[]     = $r['rps'];
    }
    if ($runs === 1) {
        $allResults[0]['cv_pct'] = 0.0;
        $allResults[0]['runs']   = 1;
        $allResults[0]['unstable'] = false;
        return $allResults[0];
    }
    $meanRps = array_sum($allRps) / $runs;
    $varRps  = 0.0;
    foreach ($allRps as $r) { $varRps += ($r - $meanRps) ** 2; }
    $cvPct = $meanRps > 0 ? (sqrt($varRps / $runs) / $meanRps) * 100.0 : 0.0;

    sort($allRps);
    $medRps  = $allRps[(int)($runs / 2)];
    $best    = $allResults[0];
    $bestDiff = INF;
    foreach ($allResults as $r) {
        $d = abs($r['rps'] - $medRps);
        if ($d < $bestDiff) { $bestDiff = $d; $best = $r; }
    }
    $best['cv_pct']  = $cvPct;
    $best['runs']    = $runs;
    $best['unstable'] = $cvPct > $cvWarnPct;
    return $best;
}

function bench_warmup(string $url, int $n = 50, string $method = 'GET', string $body = '', array $headers = []): void
{
    $mh = curl_multi_init();
    $hs = [];
    for ($i = 0; $i < $n; $i++) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }
        if ($headers) curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        $hs[] = $ch;
        curl_multi_add_handle($mh, $ch);
    }
    $active = null;
    do {
        while (curl_multi_exec($mh, $active) === CURLM_CALL_MULTI_PERFORM) {}
        if ($active) curl_multi_select($mh, 0.005);
    } while ($active);
    foreach ($hs as $ch) { curl_multi_remove_handle($mh, $ch); @curl_close($ch); }
    curl_multi_close($mh);
}

// ── Display helpers ───────────────────────────────────────────────────────────

function gw_fmt_lat(float $ms): string
{
    if ($ms < 1.0)  return sprintf('%.1fµs', $ms * 1000);
    if ($ms < 1000) return sprintf('%.2fms', $ms);
    return sprintf('%.2fs', $ms / 1000);
}

function gw_fmt_bytes(float $b): string
{
    if ($b < 1024)    return sprintf('%.0f B', $b);
    if ($b < 1048576) return sprintf('%.1f KB', $b / 1024);
    return sprintf('%.2f MB', $b / 1048576);
}

function gw_print_header(): void
{
    printf(
        "  %-38s | %9s | %8s | %8s | %8s | %8s | %9s | %6s\n",
        'Scenario', 'req/s', 'ns/op', 'p50', 'p95', 'p99', 'bytes/op', 'errors'
    );
    echo '  ' . str_repeat('-', 110) . "\n";
}

function gw_print_result(string $label, array $r, string $note = ''): void
{
    $cv = '';
    if (($r['runs'] ?? 1) > 1) {
        $cv = ($r['unstable'] ?? false)
            ? sprintf(' ⚠CV=%.1f%%', $r['cv_pct'])
            : sprintf(' ✓CV=%.1f%%', $r['cv_pct']);
    }
    $errTag = $r['errors'] > 0 ? sprintf('!%d', $r['errors']) : '0';
    printf(
        "  %-38s | %9.1f | %8.0f | %8s | %8s | %8s | %9s | %6s%s%s\n",
        $label,
        $r['rps'],
        $r['ns_op'],
        gw_fmt_lat($r['p50_ms']),
        gw_fmt_lat($r['p95_ms']),
        gw_fmt_lat($r['p99_ms']),
        gw_fmt_bytes($r['bytes_op']),
        $errTag,
        $cv,
        $note ? "  ← $note" : ''
    );
}

function gw_overhead_note(array $direct, array $gw): string
{
    if ($direct['rps'] <= 0) return '';
    $overhead_pct = (($direct['rps'] - $gw['rps']) / $direct['rps']) * 100.0;
    $lat_add_ms   = $gw['p50_ms'] - $direct['p50_ms'];
    return sprintf('+%.2fms p50, %.1f%% rps overhead', $lat_add_ms, $overhead_pct);
}

// ── Verify both services are up ───────────────────────────────────────────────
foreach ([['Backend', $backendUrl], ['Gateway', $gwUrl]] as [$label, $base]) {
    $ch = curl_init("$base/health");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    $resp = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    @curl_close($ch);
    if ($code !== 200 || trim($resp) !== 'ok') {
        fwrite(STDERR, "[perf_client] ERROR: $label not reachable at $base/health (HTTP $code)\n");
        exit(1);
    }
}

// ── Banner ────────────────────────────────────────────────────────────────────
echo "\n════════════════════════════════════════════════════════════════════════════════\n";
echo " KislayPHP Gateway – Performance Benchmark  (Go-bench style)\n";
echo "════════════════════════════════════════════════════════════════════════════════\n";
printf(" Backend     : %s\n", $backendUrl);
printf(" Gateway     : %s\n", $gwUrl);
printf(" JWT         : %s...%s\n", substr($jwtToken, 0, 20), substr($jwtToken, -8));
printf(" Concurrency : %d\n", $concurrency);
if ($durationMs > 0) {
    printf(" Duration    : %d ms per scenario\n", $durationMs);
} else {
    printf(" Requests    : %d per scenario\n", $requests);
}
printf(" Runs        : %d%s\n", $runs, $runs > 1 ? " (CV stability check)" : "");
echo " Columns     : req/s | ns/op | p50 | p95 | p99 | bytes/op | errors\n";
echo "════════════════════════════════════════════════════════════════════════════════\n";

$summary      = [];
$gobenchLines = [];
$ncpus        = (int)(shell_exec('nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 1') ?: 1);

$jwthdr = ["Authorization: Bearer $jwtToken"];

// ── Shared small benchmark runner ─────────────────────────────────────────────
$bench = function (string $url, string $method = 'GET', string $body = '', array $headers = [],
                   bool $allow4xx = false, bool $allow5xx = false) use (
    $concurrency, $requests, $durationMs, $runs, $cvWarnPct
): array {
    return bench_run($url, $concurrency, $requests, $method, $body, $headers,
                     $allow4xx, $allow5xx, $durationMs, $runs, $cvWarnPct);
};

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 1 — Baseline: Direct backend (no gateway)
// ══════════════════════════════════════════════════════════════════════════════
if (!$only || str_contains($only, 'baseline') || str_contains($only, 'direct')) {
    echo "\n  ▶ Section 1 — Baseline: Direct Backend (no gateway overhead)\n";
    gw_print_header();

    bench_warmup("$backendUrl/plaintext");
    $d_plain = $bench("$backendUrl/plaintext");
    gw_print_result('  direct/plaintext', $d_plain);
    $summary['direct/plaintext'] = $d_plain;

    bench_warmup("$backendUrl/json");
    $d_json = $bench("$backendUrl/json");
    gw_print_result('  direct/json', $d_json);
    $summary['direct/json'] = $d_json;
}

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 2 — Plain proxy (gateway → backend)
// ══════════════════════════════════════════════════════════════════════════════
if (!$only || str_contains($only, 'proxy')) {
    echo "\n  ▶ Section 2 — Plain Proxy (gateway pass-through overhead)\n";
    gw_print_header();

    bench_warmup("$gwUrl/proxy/plaintext");
    $g_plain = $bench("$gwUrl/proxy/plaintext");
    $note = isset($d_plain) ? gw_overhead_note($d_plain, $g_plain) : '';
    gw_print_result('  gateway/proxy/plaintext', $g_plain, $note);
    $summary['proxy/plaintext'] = $g_plain;

    bench_warmup("$gwUrl/proxy/json");
    $g_json = $bench("$gwUrl/proxy/json");
    $note = isset($d_json) ? gw_overhead_note($d_json, $g_json) : '';
    gw_print_result('  gateway/proxy/json', $g_json, $note);
    $summary['proxy/json'] = $g_json;
}

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 3 — POST body forwarding
// ══════════════════════════════════════════════════════════════════════════════
if (!$only || str_contains($only, 'post') || str_contains($only, 'body')) {
    echo "\n  ▶ Section 3 — POST Body Forwarding\n";
    gw_print_header();

    $bodies = [
        'echo_small (200 B)'   => str_repeat('x', 200),
        'echo_medium (1 KB)'   => str_repeat('x', 1024),
        'echo_large (10 KB)'   => str_repeat('x', 10240),
    ];
    foreach ($bodies as $label => $payload) {
        $bodyJson = json_encode(['user' => 'bench', 'data' => $payload]);
        bench_warmup("$gwUrl/proxy/echo", 20, 'POST', $bodyJson);
        $r = $bench("$gwUrl/proxy/echo", 'POST', $bodyJson);
        gw_print_result("  $label", $r);
        $key = 'post/' . preg_replace('/[^a-z0-9]/', '_', strtolower($label));
        $summary[$key] = $r;
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 4 — Header propagation
// ══════════════════════════════════════════════════════════════════════════════
if (!$only || str_contains($only, 'header')) {
    echo "\n  ▶ Section 4 — Header Propagation\n";
    gw_print_header();

    $traceHeaders = [
        'X-Request-Id: bench-' . bin2hex(random_bytes(8)),
        'traceparent: 00-' . bin2hex(random_bytes(16)) . '-' . bin2hex(random_bytes(8)) . '-01',
    ];
    bench_warmup("$gwUrl/proxy/headers", 50, 'GET', '', $traceHeaders);
    $r = $bench("$gwUrl/proxy/headers", 'GET', '', $traceHeaders);
    gw_print_result('  headers/trace+request-id', $r);
    $summary['headers/trace'] = $r;
}

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 5 — JWT authentication
// ══════════════════════════════════════════════════════════════════════════════
if (!$only || str_contains($only, 'jwt') || str_contains($only, 'auth')) {
    echo "\n  ▶ Section 5 — JWT Authentication (HS256)\n";
    gw_print_header();

    // Valid JWT — measures full JWT verify + proxy overhead
    bench_warmup("$gwUrl/secure/data", 50, 'GET', '', $jwthdr);
    $r_valid = $bench("$gwUrl/secure/data", 'GET', '', $jwthdr);
    gw_print_result('  jwt/valid → 200', $r_valid);
    $summary['jwt/valid'] = $r_valid;

    // Valid JWT, header-heavy endpoint
    bench_warmup("$gwUrl/secure/headers", 50, 'GET', '', $jwthdr);
    $r_hdrs = $bench("$gwUrl/secure/headers", 'GET', '', $jwthdr);
    gw_print_result('  jwt/valid+headers → 200', $r_hdrs);
    $summary['jwt/valid_headers'] = $r_hdrs;

    // No token → 401 fast-path (measures how fast gateway rejects)
    bench_warmup("$gwUrl/secure/data", 50);
    $r_no = $bench("$gwUrl/secure/data", 'GET', '', [], true);
    gw_print_result('  jwt/missing → 401', $r_no, 'fast-reject path');
    $summary['jwt/missing_401'] = $r_no;

    // Malformed token → 401
    $badHeaders = ['Authorization: Bearer this.is.not.a.valid.jwt'];
    bench_warmup("$gwUrl/secure/data", 20, 'GET', '', $badHeaders);
    $r_bad = $bench("$gwUrl/secure/data", 'GET', '', $badHeaders, true);
    gw_print_result('  jwt/invalid → 401', $r_bad, 'fast-reject path');
    $summary['jwt/invalid_401'] = $r_bad;

    if (isset($r_valid, $g_plain)) {
        $jwtOverhead_ms = $r_valid['p50_ms'] - $g_plain['p50_ms'];
        printf("\n  JWT verify overhead vs plain proxy: +%.2fms p50\n", $jwtOverhead_ms);
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 6 — Native service registry (round-robin load balancing)
// ══════════════════════════════════════════════════════════════════════════════
if (!$only || str_contains($only, 'lb') || str_contains($only, 'service')) {
    echo "\n  ▶ Section 6 — Native Service Registry (round-robin LB)\n";
    gw_print_header();

    bench_warmup("$gwUrl/lb/json");
    $r_lb_json = $bench("$gwUrl/lb/json");
    gw_print_result('  lb/json (round-robin)', $r_lb_json);
    $summary['lb/json'] = $r_lb_json;

    bench_warmup("$gwUrl/lb/plaintext");
    $r_lb_plain = $bench("$gwUrl/lb/plaintext");
    gw_print_result('  lb/plaintext (round-robin)', $r_lb_plain);
    $summary['lb/plaintext'] = $r_lb_plain;
}

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 7 — Fallback route
// ══════════════════════════════════════════════════════════════════════════════
if (!$only || str_contains($only, 'fallback')) {
    echo "\n  ▶ Section 7 — Fallback Route\n";
    gw_print_header();

    bench_warmup("$gwUrl/this-route-does-not-exist");
    $r_fb = $bench("$gwUrl/this-route-does-not-exist");
    gw_print_result('  fallback/unknown-path', $r_fb);
    $summary['fallback/unknown'] = $r_fb;
}

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 8 — Upstream latency impact (simulated 5ms backend delay)
// ══════════════════════════════════════════════════════════════════════════════
if (!$only || str_contains($only, 'slow') || str_contains($only, 'latency')) {
    echo "\n  ▶ Section 8 — Upstream Latency (5ms simulated backend delay)\n";
    gw_print_header();

    bench_warmup("$gwUrl/proxy/slow", 10);
    $r_slow = $bench("$gwUrl/proxy/slow");
    gw_print_result('  proxy/slow (5ms upstream)', $r_slow);
    $summary['proxy/slow'] = $r_slow;
}

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 9 — High concurrency stress
// ══════════════════════════════════════════════════════════════════════════════
if (!$only || str_contains($only, 'stress') || str_contains($only, 'concurrency')) {
    echo "\n  ▶ Section 9 — High Concurrency Stress (4× normal concurrency)\n";
    gw_print_header();

    $highConc = $concurrency * 4;
    $highReqs = $requests * 2;
    foreach (['plaintext', 'json'] as $ep) {
        bench_warmup("$gwUrl/proxy/$ep");
        $r = bench_run("$gwUrl/proxy/$ep", $highConc, $highReqs, 'GET', '', [], false, false, $durationMs, $runs, $cvWarnPct);
        gw_print_result("  proxy/$ep @{$highConc}c", $r);
        $summary["stress/proxy/$ep"] = $r;
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 10 — Rate limiter fast-reject throughput
// ══════════════════════════════════════════════════════════════════════════════
if (!$only || str_contains($only, 'rate') || str_contains($only, 'limit')) {
    echo "\n  ▶ Section 10 — Rate Limiter (burst test — expect 429s)\n";
    gw_print_header();
    echo "  Note: Gateway must be configured with KISLAY_GATEWAY_RATE_LIMIT_ENABLED=1\n";
    echo "        and a small limit (e.g. KISLAY_GATEWAY_RATE_LIMIT_REQUESTS=5).\n";
    echo "        429 responses count as success here (we're measuring fast-reject perf).\n\n";

    // Fire a burst that will exceed any reasonable rate limit
    // allow4xx=true so 429s are counted as valid (we're measuring fast-reject speed)
    bench_warmup("$gwUrl/proxy/plaintext", 5);
    $r_burst = bench_run("$gwUrl/proxy/plaintext", min($concurrency, 50), min($requests, 500),
                         'GET', '', [], true, false, 0, 1, 100.0);
    $rateHit = $r_burst['total'] > 0 ? round($r_burst['errors'] / $r_burst['total'] * 100, 1) : 0;
    gw_print_result('  rate_limit/burst', $r_burst, "$rateHit% got through (rest 429'd)");
    $summary['rate_limit/burst'] = $r_burst;
}

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 11 — Summary + overhead analysis
// ══════════════════════════════════════════════════════════════════════════════
echo "\n════════════════════════════════════════════════════════════════════════════════\n";
echo " Summary — sorted by throughput (highest req/s first)\n";
echo "════════════════════════════════════════════════════════════════════════════════\n";
gw_print_header();

uasort($summary, fn($a, $b) => $b['rps'] <=> $a['rps']);
$rank = 1;
foreach ($summary as $k => $r) {
    gw_print_result(sprintf("  #%-2d %-34s", $rank++, $k), $r);
}

// Gateway overhead analysis
if (isset($summary['direct/plaintext'], $summary['proxy/plaintext'])) {
    $dp = $summary['direct/plaintext'];
    $gp = $summary['proxy/plaintext'];
    $rpsOverhead = $dp['rps'] > 0 ? (($dp['rps'] - $gp['rps']) / $dp['rps']) * 100 : 0;
    $latOverhead = $gp['p50_ms'] - $dp['p50_ms'];
    echo "\n  Gateway proxy overhead (plaintext):\n";
    printf("    RPS: %.1f → %.1f (%.1f%% reduction)\n", $dp['rps'], $gp['rps'], $rpsOverhead);
    printf("    p50 latency: +%.2fms (%.2fms → %.2fms)\n", $latOverhead, $dp['p50_ms'], $gp['p50_ms']);
}

if (isset($summary['proxy/plaintext'], $summary['jwt/valid'])) {
    $gp  = $summary['proxy/plaintext'];
    $jwt = $summary['jwt/valid'];
    $jwtRpsOverhead = $gp['rps'] > 0 ? (($gp['rps'] - $jwt['rps']) / $gp['rps']) * 100 : 0;
    $jwtLatOverhead = $jwt['p50_ms'] - $gp['p50_ms'];
    echo "\n  JWT auth overhead (on top of proxy):\n";
    printf("    RPS: %.1f → %.1f (%.1f%% reduction)\n", $gp['rps'], $jwt['rps'], $jwtRpsOverhead);
    printf("    p50 latency: +%.2fms (%.2fms → %.2fms)\n", $jwtLatOverhead, $gp['p50_ms'], $jwt['p50_ms']);
}

// ── Go-bench output ───────────────────────────────────────────────────────────
if ($emitGoBench) {
    echo "\n# Go-bench format (compatible with benchstat)\n";
    foreach ($summary as $k => $r) {
        $safe = 'Gateway_' . preg_replace('/[^A-Za-z0-9_]/', '_', $k);
        $iters = max(1, $r['total'] - $r['errors']);
        printf("Benchmark%s-%d\t%d\t%.0f ns/op\t%.0f B/op\n",
               $safe, $ncpus, $iters, $r['ns_op'], $r['bytes_op']);
    }
}

// ── JSON output ───────────────────────────────────────────────────────────────
if ($emitJson) {
    echo "\n# JSON\n";
    echo json_encode([
        'meta' => [
            'backend'     => $backendUrl,
            'gateway'     => $gwUrl,
            'concurrency' => $concurrency,
            'requests'    => $requests,
            'duration_ms' => $durationMs,
            'runs'        => $runs,
            'timestamp'   => date('c'),
        ],
        'results' => $summary,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
}

echo "\n[perf_client] Done.\n";
