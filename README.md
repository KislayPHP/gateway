# KislayGateway

> Edge-only HTTP gateway for KislayPHP services. Route, apply lightweight edge policy, and forward requests without duplicating Core runtime behavior.

[![PHP Version](https://img.shields.io/badge/PHP-8.2+-blue.svg)](https://php.net)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

## Installation

**Via PIE (recommended):**
```bash
pie install kislayphp/gateway:0.0.5
```

Add to `php.ini`:
```ini
extension=kislayphp_gateway.so
```

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

## Discovery Integration

```php
<?php

$registry = new Kislay\Discovery\ServiceRegistry('http://127.0.0.1:9010');
$gateway  = new Kislay\Gateway\Gateway();

$gateway->addServiceRoute('GET', '/api/users', 'user-service');
$gateway->setResolver(function (string $service, string $method, string $path) use ($registry): string {
    $url = $registry->resolve($service);
    if ($url === null) {
        throw new RuntimeException("No healthy instance for {$service}");
    }
    return $url;
});

$gateway->listen('0.0.0.0', 9009);
while (true) {
    sleep(1);
}
```

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

### Auth alignment

Gateway can do optional edge validation:
- shared bearer token via `KISLAY_GATEWAY_AUTH_TOKEN`
- JWT signature/expiry validation via `KISLAY_GATEWAY_JWT_SECRET`

In both cases, Gateway forwards the original `Authorization` header downstream and leaves `jwt_valid` / `jwt_payload` ownership to Core.

### Resilience

Gateway keeps resilience lightweight:
- read timeout on upstream responses
- retry only for idempotent methods and only on pre-response upstream failures
- simple per-upstream circuit breaker

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
- Rate limiting currently uses in-memory storage.

## License

Licensed under the [Apache License 2.0](LICENSE).
