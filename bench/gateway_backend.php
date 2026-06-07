<?php
/**
 * Gateway benchmark — backend service
 *
 * Simulates real upstream services the gateway proxies to.
 * Provides all endpoints needed for Go-bench-level gateway performance testing:
 *   - Plaintext / JSON baseline
 *   - Header echo (verifies gateway header propagation)
 *   - POST echo (body forwarding)
 *   - Simulated slow endpoint (upstream latency impact)
 *   - Always-failing endpoint (circuit breaker testing)
 *   - Payload size endpoints (1KB / 10KB / 100KB response — size impact test)
 */

if (!extension_loaded('kislayphp_extension')) {
    fwrite(STDERR, "[backend] kislayphp_extension not loaded\n");
    exit(1);
}

$host = getenv('BACKEND_HOST') ?: '127.0.0.1';
$port = (int)(getenv('BACKEND_PORT') ?: 9292);

$app = new Kislay\Core\App();
$app->setOption('log', false);

// ── Baseline ──────────────────────────────────────────────────────────────────
$app->get('/health', function ($req, $res) {
    $res->send('ok');
});

$app->get('/plaintext', function ($req, $res) {
    $res->send('hello from backend');
});
$app->get('/proxy/plaintext', function ($req, $res) {
    $res->send('hello from backend');
});
$app->get('/lb/plaintext', function ($req, $res) {
    $res->send('hello from backend');
});
$app->get('/no-such-route', function ($req, $res) {
    $res->send('hello from backend');
});

$app->get('/json', function ($req, $res) {
    static $payload = '{"status":"ok","service":"backend"}';
    $res->setHeader('Content-Type', 'application/json');
    $res->send($payload);
});
$app->get('/proxy/json', function ($req, $res) {
    static $payload = '{"status":"ok","service":"backend"}';
    $res->setHeader('Content-Type', 'application/json');
    $res->send($payload);
});
$app->get('/secure/data', function ($req, $res) {
    static $payload = '{"status":"ok","service":"backend"}';
    $res->setHeader('Content-Type', 'application/json');
    $res->send($payload);
});
$app->get('/lb/json', function ($req, $res) {
    static $payload = '{"status":"ok","service":"backend"}';
    $res->setHeader('Content-Type', 'application/json');
    $res->send($payload);
});

// ── Header propagation echo ───────────────────────────────────────────────────
$app->get('/headers/echo', function ($req, $res) {
    $res->json([
        'x-request-id'  => $req->header('X-Request-Id', ''),
        'traceparent'   => $req->header('traceparent', ''),
        'x-auth-user'   => $req->header('X-Authenticated-User', ''),
        'x-auth-roles'  => $req->header('X-Auth-Roles', ''),
        'x-forwarded-for' => $req->header('X-Forwarded-For', ''),
    ]);
});
$app->get('/proxy/headers', function ($req, $res) {
    $res->json([
        'x-request-id'  => $req->header('X-Request-Id', ''),
        'traceparent'   => $req->header('traceparent', ''),
        'x-auth-user'   => $req->header('X-Authenticated-User', ''),
        'x-auth-roles'  => $req->header('X-Auth-Roles', ''),
        'x-forwarded-for' => $req->header('X-Forwarded-For', ''),
    ]);
});
$app->get('/secure/headers', function ($req, $res) {
    $res->json([
        'x-request-id'  => $req->header('X-Request-Id', ''),
        'traceparent'   => $req->header('traceparent', ''),
        'x-auth-user'   => $req->header('X-Authenticated-User', ''),
        'x-auth-roles'  => $req->header('X-Auth-Roles', ''),
        'x-forwarded-for' => $req->header('X-Forwarded-For', ''),
    ]);
});

// ── POST body forwarding ──────────────────────────────────────────────────────
$app->post('/echo', function ($req, $res) {
    $body = $req->json();
    $res->json(['received' => is_array($body) ? count($body) : (is_object($body) ? count((array)$body) : 0)]);
});
$app->post('/proxy/echo', function ($req, $res) {
    $body = $req->json();
    $res->json(['received' => is_array($body) ? count($body) : (is_object($body) ? count((array)$body) : 0)]);
});

// ── Upstream latency simulation ───────────────────────────────────────────────
$app->get('/slow', function ($req, $res) {
    usleep(5000);   // 5 ms — simulates a real database query or slow microservice
    $res->send('slow-ok');
});
$app->get('/proxy/slow', function ($req, $res) {
    usleep(5000);   // 5 ms — simulates a real database query or slow microservice
    $res->send('slow-ok');
});

// ── Circuit breaker target — always fails ─────────────────────────────────────
$app->get('/fail', function ($req, $res) {
    $res->status(500)->send('upstream error');
});
$app->get('/proxy/fail', function ($req, $res) {
    $res->status(500)->send('upstream error');
});

// ── Payload size endpoints (section 12 — response size impact) ───────────────
// Pre-built at startup to avoid per-request allocation overhead.
$payloads = [];
foreach ([1, 10, 100] as $kb) {
    $payloads[$kb] = json_encode([
        'status' => 'ok',
        'size'   => "{$kb}kb",
        'data'   => str_repeat('x', $kb * 1024 - 40),   // -40 for JSON overhead
    ]);
}

$app->get('/payload/1k', function ($req, $res) use ($payloads) {
    $res->setHeader('Content-Type', 'application/json');
    $res->send($payloads[1]);
});
$app->get('/proxy/payload/1k', function ($req, $res) use ($payloads) {
    $res->setHeader('Content-Type', 'application/json');
    $res->send($payloads[1]);
});

$app->get('/payload/10k', function ($req, $res) use ($payloads) {
    $res->setHeader('Content-Type', 'application/json');
    $res->send($payloads[10]);
});
$app->get('/proxy/payload/10k', function ($req, $res) use ($payloads) {
    $res->setHeader('Content-Type', 'application/json');
    $res->send($payloads[10]);
});

$app->get('/payload/100k', function ($req, $res) use ($payloads) {
    $res->setHeader('Content-Type', 'application/json');
    $res->send($payloads[100]);
});
$app->get('/proxy/payload/100k', function ($req, $res) use ($payloads) {
    $res->setHeader('Content-Type', 'application/json');
    $res->send($payloads[100]);
});

// ── Start ─────────────────────────────────────────────────────────────────────
fwrite(STDOUT, "[backend] Listening on http://{$host}:{$port}\n");
$app->listen($host, $port);
