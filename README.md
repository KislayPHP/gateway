# KislayGateway

> Edge-only HTTP gateway for KislayPHP services. Route, apply lightweight edge policy, and forward requests without duplicating Core runtime behavior.

[![PHP Version](https://img.shields.io/badge/PHP-8.2+-blue.svg)](https://php.net)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Release](https://img.shields.io/badge/Release-1.0.1-orange.svg)]()

## Installation

**Via PIE (recommended):**
```bash
pie install kislayphp/gateway:1.0.1
```

Add to `php.ini`:
```ini
extension=kislayphp_gateway.so
```

## New in 1.0.0

- **Fixed a crash bug**: concurrent requests through service-registry/native-service routes could abort the whole process (Zend memory-manager corruption from calling PHP error-reporting APIs on a raw worker thread). Warning logging now goes straight to stderr instead.
- **Fixed a Host-header bug**: `registerService()` and `setFallbackTarget()` routes sent a blank `Host:` header upstream and never reused pooled connections — both now correctly compute their routing keys at registration time.
- Hot-path allocation reductions across the proxy request path (thread-local buffers for headers, method casing, and route lookups; a fast path for the common no-rewrite route case).
- In cross-language benchmarks, KislayPHP Gateway now beats Go's `httputil.ReverseProxy`, Node.js, and Spring Cloud Gateway on both throughput and tail latency for plain-proxy and JWT scenarios.
- **Multi-host round-robin fixed (2026-08-01)**: real multi-host load balancing (2+ genuinely distinct backends behind one `registerService()` pool) previously collapsed to near-zero throughput under concurrency — root cause was civetweb defaulting to Nagle's algorithm (no `tcp_nodelay`) on client-facing sockets, not a deadlock. Fixed by enabling `tcp_nodelay` in `listen()`. See the Performance section below for current real numbers — this scenario is a genuine, honest mixed result (not a clean win), unlike plain-proxy and JWT where KislayPHP leads outright.

## Performance

Plain proxy pass-through, wrk (2 threads, 20 connections, 3s + 5s warmup), 10-core reference machine, all gateways proxying to the same Node.js backend. Produced by `compare/run_gateway_compare.sh proxy`:

| Gateway | req/s | p50 | p99 | vs KislayPHP |
|---|---:|---:|---:|---:|
| **KislayPHP Gateway** | **80,306** | **119.5µs** | **236µs** | — |
| Node.js (native, cluster) | 54,073 | 325µs | 2.76ms | -32.7% |
| Spring Cloud Gateway | 50,357 | 347µs | 1.75ms | -37.3% |
| Go (httputil.ReverseProxy) | 45,903 | 416µs | 1.14ms | -42.8% |
| Node.js (native, single process) | 35,433 | 543µs | 1.08ms | -55.9% |

Direct backend, no gateway in front (baseline): 130,591 req/s.

KislayPHP Gateway wins on both throughput and tail latency against every reverse proxy in the comparison, including Spring Cloud Gateway and Go's own `net/http/httputil.ReverseProxy`, for plain-proxy and JWT scenarios. Reproduce with `../compare/run_gateway_compare.sh` from the repo root, or the quick `../perf_smoke_test.sh` for a faster (and less statistically rigorous) sanity check.

**Round-robin load balancing** (`../compare/run_gateway_compare.sh lb`), 2-node backend pool, same wrk parameters:

| Gateway | req/s | p50 | p99 | vs KislayPHP |
|---|---:|---:|---:|---:|
| Go (httputil.ReverseProxy) | 7,874 | 9.78ms | 113.40ms | +20.2% req/s |
| **KislayPHP Gateway** | **6,548** | **412µs** | **28.07ms** | — |
| Node.js (native, cluster) | 6,197 | 12.82ms | 149.43ms | -5.4% |
| Node.js (native, single process) | 3,786 | 17.97ms | 186.32ms | -42.2% |

Honest read: Go's `ReverseProxy` edges out KislayPHP on raw req/s here, but KislayPHP's p50 is ~24x tighter and p99 is ~4x tighter than Go's — round-robin across distinct hosts inherently costs some throughput for all four gateways compared to the single-backend numbers above (each request pays a cold-connect or pool-miss tax more often), but KislayPHP holds its latency advantage even here. This is a real, current result (2026-08-31), not the pre-fix catastrophic collapse (~8 req/s) described in earlier notes.

## Role In The Stack

Gateway is the edge layer only.

- Gateway: route, optional edge auth, rate limit, circuit break, forward
- Core: request lifecycle, JWT state, tracing, async HTTP, business logic
- Discovery: resolve service name to healthy instance URL

Gateway does **not** reimplement Core's JWT state model or async HTTP engine.

## Quick Start

```php
<?php

$gateway = new Kislay\Gateway\Gateway();
$gateway->addRoute('GET', '/health', 'http://127.0.0.1:9008');
$gateway->listen('0.0.0.0', 9009);

while (true) {
    sleep(1);
}
```

`addRoute()` path patterns support three shapes: an exact literal path (`/health`), a trailing `*` wildcard prefix (`/api/*` matches any path starting with `/api/`), or `:name`-style named segments matching Core's own router syntax (`/api/tasks/:id` matches `/api/tasks/42` but not `/api/tasks` or `/api/tasks/42/sub` — segment count must match exactly). Named segments are match-only here — Gateway doesn't expose the captured value to anything, it only decides which upstream a request forwards to.

## Discovery Integration

```php
<?php

$gateway = new Kislay\Gateway\Gateway();
$gateway->addServiceRoute('GET', '/api/users', 'user-service');
$gateway->registerService('user-service', [
    'http://127.0.0.1:9001',
    'http://127.0.0.1:9002',
]);
$gateway->listen('0.0.0.0', 9009);

while (true) {
    sleep(1);
}
```

Service route resolution order is:

1. native C++ service registry via `registerService()`
2. PHP `setResolver()` callback if configured
3. Discovery RPC when `KISLAYPHP_RPC_ENABLED=1`

For production, prefer `registerService()` so request threads stay on the native path.

## Runtime Behavior

### Request forwarding

Gateway forwards:
- method
- path and query string
- headers
- body
- `Authorization`
- `X-Request-ID`
- `traceparent`
- `tracestate`

Gateway generates `X-Request-ID` only when the incoming request does not provide one.
Gateway preserves upstream `X-Forwarded-For` chains, forwards the incoming host, and derives `X-Forwarded-Proto` from the actual client-facing scheme.

### Auth alignment

Gateway can do optional edge validation:
- shared bearer token via `KISLAY_GATEWAY_AUTH_TOKEN`
- JWT signature/expiry validation via `KISLAY_GATEWAY_JWT_SECRET`

In both cases, Gateway forwards the original `Authorization` header downstream and leaves `jwt_valid` / `jwt_payload` ownership to Core.

### Resilience

Gateway keeps resilience lightweight:
- read timeout on upstream responses
- retry only for idempotent methods and only on pre-response upstream failures
- simple per-upstream circuit breaker with `CLOSED / OPEN / HALF_OPEN`
- thread-local upstream connection reuse for direct routes

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KISLAY_GATEWAY_THREADS` | `1` | CivetWeb worker threads |
| `KISLAY_GATEWAY_MAX_BODY` | `0` | Max request body bytes, `0` = unlimited |
| `KISLAY_GATEWAY_AUTH_REQUIRED` | `0` | Enable edge auth checks |
| `KISLAY_GATEWAY_AUTH_TOKEN` | empty | Expected bearer token in simple auth mode |
| `KISLAY_GATEWAY_JWT_SECRET` | empty | Enable lightweight HS256 JWT validation |
| `KISLAY_GATEWAY_AUTH_EXCLUDE` | `/health,/ready,/metrics` | Auth-exempt path prefixes |
| `KISLAY_GATEWAY_READ_TIMEOUT_MS` | `10000` | Upstream response timeout |
| `KISLAY_GATEWAY_RETRY_IDEMPOTENT` | `1` | Retry count for idempotent methods |
| `KISLAY_GATEWAY_RATE_LIMIT_ENABLED` | `0` | Enable in-memory rate limiting |
| `KISLAY_GATEWAY_RATE_LIMIT_REQUESTS` | `120` | Requests per window |
| `KISLAY_GATEWAY_RATE_LIMIT_WINDOW` | `60` | Rate-limit window in seconds |
| `KISLAY_GATEWAY_CIRCUIT_BREAKER_ENABLED` | `0` | Enable circuit breaker |
| `KISLAY_GATEWAY_CB_FAILURE_THRESHOLD` | `5` | Failures before open |
| `KISLAY_GATEWAY_CB_OPEN_SECONDS` | `30` | Open duration |

## Notes

- `listen()` starts the server and returns; keep the process alive explicitly.
- Retry is intentionally narrow. Gateway is not a replacement for Core's async execution layer.
- `registerService()` is the recommended production service discovery path. It publishes a native registry snapshot and avoids PHP callbacks on the request path.
- On ZTS builds, PHP resolvers are rejected at `listen()` time. Use Discovery RPC or direct targets there.
- Rate limiting currently uses in-memory storage.
- **Do not load `gateway`, `core`, and `socket` together in the same PHP process.** All three vendor their own copy of civetweb and export non-static symbols like `mg_start`; on platforms linking extensions with `-flat_namespace` (notably macOS), combining any two of them risks one's compiled civetweb code silently shadowing another's, with no error - just undefined behavior up to and including crashes. Run gateway as its own process in front of separate core/socket processes rather than combining them via `-d extension=` flags.

## License

Licensed under the [Apache License 2.0](LICENSE).
