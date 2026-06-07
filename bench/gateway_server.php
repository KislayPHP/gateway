<?php
/**
 * Gateway benchmark — gateway layer
 *
 * Configures all route types needed for Go-bench-level performance testing:
 *   - Plain proxy (pass-through)
 *   - JWT authentication (HS256)
 *   - Native service registry (round-robin LB)
 *   - Fallback route
 *   - Payload-size proxy routes (1KB / 10KB / 100KB)
 *   - Circuit-breaker-enabled failing route
 *
 * Rate limiting and circuit breaker are driven by env vars so the same script
 * can be launched multiple times with different configurations (see gateway_bench.sh).
 *
 * Environment:
 *   GW_HOST          — listen host   (default: 127.0.0.1)
 *   GW_PORT          — listen port   (default: 9380)
 *   BACKEND_URL      — upstream base (default: http://127.0.0.1:9292)
 *   BACKEND_URLS     — comma-separated upstream pool for load-balancer routes
 *   KISLAY_GATEWAY_* — all gateway env vars are passed through to the extension
 */

if (!extension_loaded('kislayphp_gateway')) {
    fwrite(STDERR, "[gateway] kislayphp_gateway not loaded\n");
    exit(1);
}

$gwHost     = getenv('GW_HOST')     ?: '127.0.0.1';
$gwPort     = (int)(getenv('GW_PORT') ?: 9380);
$backendUrl = getenv('BACKEND_URL') ?: 'http://127.0.0.1:9292';
$backendUrlsRaw = getenv('BACKEND_URLS') ?: $backendUrl;
$backendUrls = array_values(array_filter(array_map('trim', explode(',', $backendUrlsRaw))));
if (!$backendUrls) {
    $backendUrls = [$backendUrl];
}

$gw = new Kislay\Gateway\Gateway();

// ── Thread count ───────────────────────────────────────────────────────────────
$threads = (int)(getenv('KISLAY_GATEWAY_THREADS') ?: 8);
if ($threads > 1) {
    $gw->setThreads($threads);
}

// ── Plain proxy routes ────────────────────────────────────────────────────────
$gw->addRoute('GET',  '/proxy/plaintext',   $backendUrl);
$gw->addRoute('GET',  '/proxy/json',        $backendUrl);
$gw->addRoute('POST', '/proxy/echo',        $backendUrl);
$gw->addRoute('GET',  '/proxy/headers',     $backendUrl);
$gw->addRoute('GET',  '/proxy/slow',        $backendUrl);
$gw->addRoute('GET',  '/health',            $backendUrl);

// Payload-size proxy routes (section 12 — response size impact)
$gw->addRoute('GET', '/proxy/payload/1k',   $backendUrl);
$gw->addRoute('GET', '/proxy/payload/10k',  $backendUrl);
$gw->addRoute('GET', '/proxy/payload/100k', $backendUrl);

// Circuit-breaker test: proxy to the always-failing backend endpoint
$gw->addRoute('GET', '/proxy/fail', $backendUrl);

// ── JWT-protected routes ──────────────────────────────────────────────────────
$jwtSecret = getenv('KISLAY_GATEWAY_JWT_SECRET') ?: 'bench-secret-key-32bytes-padding!!';
$gw->requireAuth($jwtSecret, [
    'exclude' => [
        '/health',
        '/proxy/',          // all /proxy/* routes are public for baseline comparison
        '/lb/',             // load-balancer benchmark routes are public baseline paths
        '/no-auth',
    ],
]);
$gw->addRoute('GET', '/secure/data',    $backendUrl);
$gw->addRoute('GET', '/secure/headers', $backendUrl);

// ── Native service registry (round-robin load balancing) ─────────────────────
$gw->addServiceRoute('GET', '/lb/json',      'backend-pool');
$gw->addServiceRoute('GET', '/lb/plaintext', 'backend-pool');
$gw->registerService('backend-pool', $backendUrls);

// ── Fallback route ────────────────────────────────────────────────────────────
$gw->setFallbackTarget($backendUrl);

// ── Start ─────────────────────────────────────────────────────────────────────
fwrite(STDOUT, "[gateway] Listening on http://{$gwHost}:{$gwPort}\n");
fwrite(STDOUT, "[gateway] Backend: {$backendUrl}\n");
fwrite(STDOUT, "[gateway] Backend pool: " . implode(', ', $backendUrls) . "\n");
fwrite(STDOUT, "[gateway] Threads: {$threads}\n");

$gw->listen($gwHost, $gwPort);

// listen() is non-blocking — keep alive until SIGTERM/SIGINT
if (function_exists('pcntl_signal')) {
    pcntl_signal(SIGTERM, function () use ($gw) { $gw->stop(); exit(0); });
    pcntl_signal(SIGINT,  function () use ($gw) { $gw->stop(); exit(0); });
    while (true) {
        pcntl_signal_dispatch();
        usleep(100000);
    }
} else {
    // Fallback when pcntl is not available
    while (true) {
        sleep(1);
    }
}
