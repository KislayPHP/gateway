# kislayphp_gateway Documentation

## Overview

`kislayphp_gateway` is the edge layer for KislayPHP deployments.

Use it to:
- match HTTP routes
- resolve service targets
- apply lightweight edge auth
- rate limit
- trip a simple circuit breaker
- forward requests to Core services or upstream HTTP targets

Do not use it to duplicate:
- Core JWT state
- Core tracing state
- Core async HTTP execution
- business logic

## Namespace

- Primary: `Kislay\Gateway\Gateway`
- Legacy alias: `KislayPHP\Gateway\Gateway`

## Public API

### `addRoute(string $method, string $path, string $target): bool`
Direct upstream route.

### `addServiceRoute(string $method, string $path, string $service): bool`
Logical service route resolved at request time.

### `setResolver(callable $resolver): bool`
Resolver signature:

```php
function (string $service, string $method, string $path): string
```

### `listen(string $host, int $port): bool`
Starts the gateway listener and returns after startup.

### `stop(): bool`
Stops the listener.

## Request / Trace / Auth Flow

Gateway preserves the Core contract.

### Request ID
- forwards incoming `X-Request-ID`
- generates one only if missing
- returns the same request ID in the response path

### Trace context
- forwards incoming `traceparent`
- forwards incoming `tracestate`
- does not invent new tracing state when none exists

### Authorization
- forwards `Authorization` unchanged
- optional edge validation can reject invalid requests early
- Core remains responsible for `jwt_valid` and `jwt_payload`

## Edge Auth Modes

### Simple bearer token
- `KISLAY_GATEWAY_AUTH_REQUIRED=1`
- `KISLAY_GATEWAY_AUTH_TOKEN=<token>`

### Lightweight JWT validation
- `KISLAY_GATEWAY_AUTH_REQUIRED=1`
- `KISLAY_GATEWAY_JWT_SECRET=<hs256-secret>`

Validation is intentionally narrow:
- verify token format
- verify HS256 signature
- verify `exp` if present

Gateway does not synthesize user or role headers from JWT claims.

## Resilience

### Timeouts
- `KISLAY_GATEWAY_READ_TIMEOUT_MS`

### Retries
- `KISLAY_GATEWAY_RETRY_IDEMPOTENT`
- applies only to idempotent methods
- applies only when the gateway fails before receiving a usable upstream response

### Circuit breaker
- per upstream `host:port`
- states are effectively `closed -> open -> closed on success`
- simple and edge-local by design

## Rate limiting

Current backend:
- in-memory

Client identity:
- first IP from `X-Forwarded-For`
- otherwise `remote_addr`

## Operational limits

- On NTS builds, thread count is forced to `1`.
- Gateway remains synchronous in its proxy path by design; Core owns the async execution engine.

## Example

```php
<?php

$registry = new Kislay\Discovery\ServiceRegistry('http://127.0.0.1:9010');
$gateway = new Kislay\Gateway\Gateway();

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
