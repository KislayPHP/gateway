# KislayGateway

> Edge-only HTTP gateway for KislayPHP services. Route, apply lightweight edge policy, and forward requests without duplicating Core runtime behavior.

[![PHP Version](https://img.shields.io/badge/PHP-8.2+-blue.svg)](https://php.net)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

## Installation

**Via PIE (recommended):**
```bash
pie install kislayphp/gateway:0.0.9
```

Add to `php.ini`:
```ini
extension=kislayphp_gateway.so
```

## Engine Selection

Gateway now has two runtime engines:

- default CivetWeb control/data plane path
- native event-loop data plane enabled with:

```bash
export KISLAY_GATEWAY_ENGINE=auto
```

The native engine selects the best loop for the platform:

- Linux: `epoll`
- macOS: `kqueue`

Explicit overrides are also supported:

```bash
export KISLAY_GATEWAY_ENGINE=epoll   # Linux only
export KISLAY_GATEWAY_ENGINE=kqueue  # macOS only
```

If `KISLAY_GATEWAY_ENGINE` is unset, Gateway falls back to the existing CivetWeb path.

Worker count behavior on the native path:

- if you do not set `KISLAY_GATEWAY_THREADS`, Gateway defaults to `CPU * 2`
- `setThreads(0)` also means “auto”
- CivetWeb still requires an explicit positive thread count internally and falls back to `1`

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

Gateway's production API remains `addRoute()` / `addServiceRoute()` / `registerService()` plus `listen(host, port)` / `stop()`.

Important runtime rule:

- treat route, service, auth, and fallback methods as startup configuration only
- `listen()` freezes that configuration into the active runtime
- configuration methods reject changes after `listen()` starts the gateway

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

### Native data plane

With `KISLAY_GATEWAY_ENGINE=auto` or an explicit native loop, the native data plane provides:

- per-worker `SO_REUSEPORT` listener processes
- non-blocking upstream proxying
- progress-based timeout enforcement
- raw upstream header passthrough on eligible responses
- gated `splice()` body streaming for large, fixed-length responses on Linux
- per-worker counters with no global locks

Current native-path scope is intentionally narrower than the legacy path:

- direct target routes only
- HTTP/1.1 only
- no HTTP/2 or HTTP/3
- no TLS upstream optimization yet
- no PHP resolver execution in the event loop

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KISLAY_GATEWAY_THREADS` | native: auto (`CPU * 2`), CivetWeb: `1` | Worker count. Unset uses native auto-scaling; `setThreads(0)` also selects auto for the native engine. |
| `KISLAY_GATEWAY_MAX_BODY` | `0` | Max request body bytes, `0` = unlimited |
| `KISLAY_GATEWAY_AUTH_REQUIRED` | `0` | Enable edge auth checks |
| `KISLAY_GATEWAY_AUTH_TOKEN` | empty | Expected bearer token in simple auth mode |
| `KISLAY_GATEWAY_JWT_SECRET` | empty | Enable lightweight HS256 JWT validation |
| `KISLAY_GATEWAY_AUTH_EXCLUDE` | `/health,/ready,/metrics` | Auth-exempt path prefixes |
| `KISLAY_GATEWAY_READ_TIMEOUT_MS` | `10000` | Upstream response timeout |
| `KISLAY_GATEWAY_ENGINE` | empty | Set to `auto`, `epoll`, or `kqueue` to enable the native data plane |
| `KISLAY_GATEWAY_EPOLL_STATS` | `0` | Emit per-worker epoll counters to stderr |
| `KISLAY_GATEWAY_RETRY_IDEMPOTENT` | `1` | Retry count for idempotent methods |
| `KISLAY_GATEWAY_RATE_LIMIT_ENABLED` | `0` | Enable in-memory rate limiting |
| `KISLAY_GATEWAY_RATE_LIMIT_REQUESTS` | `120` | Requests per window |
| `KISLAY_GATEWAY_RATE_LIMIT_WINDOW` | `60` | Rate-limit window in seconds |
| `KISLAY_GATEWAY_CIRCUIT_BREAKER_ENABLED` | `0` | Enable circuit breaker |
| `KISLAY_GATEWAY_CB_FAILURE_THRESHOLD` | `5` | Failures before open |
| `KISLAY_GATEWAY_CB_OPEN_SECONDS` | `30` | Open duration |

## Notes

- `listen()` starts the server and returns; keep the process alive explicitly.
- `listen()` is the configuration freeze point. After startup, runtime workers use the native snapshot and config mutation APIs reject changes.
- Retry is intentionally narrow. Gateway is not a replacement for Core's async execution layer.
- `registerService()` is the recommended production service discovery path. It publishes a native registry snapshot and avoids PHP callbacks on the request path.
- On ZTS builds, PHP resolvers are rejected at `listen()` time. Use Discovery RPC or direct targets there.
- Rate limiting currently uses in-memory storage.
- Do not position Gateway as an NGINX replacement. Position it as a programmable high-performance gateway with a native event-loop data plane.

## License

Licensed under the [Apache License 2.0](LICENSE).
