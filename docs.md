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

### `registerService(string $service, array $targets): bool`
Registers a native C++ service target list for production service routing.

Example:

```php
$gateway->registerService('user-service', [
    'http://127.0.0.1:9001',
    'http://127.0.0.1:9002',
]);
```

### `setResolver(callable $resolver): bool`
Resolver signature:

```php
function (string $service, string $method, string $path): string
```

This is supported on NTS builds only. ZTS builds reject PHP resolvers at `listen()` time because request threads do not execute userland resolvers safely.

Resolution order for service routes is:

1. native service registry via `registerService()`
2. PHP resolver via `setResolver()`
3. Discovery RPC when enabled

For production, prefer `registerService()` because it keeps service routing off the Zend callback path.

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

### Forwarded headers
- appends the current client IP to `X-Forwarded-For`
- preserves incoming `X-Forwarded-Host` or falls back to `Host`
- preserves incoming `X-Forwarded-Proto` or derives it from the client-facing TLS state

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
- states are `CLOSED -> OPEN -> HALF_OPEN -> CLOSED on success`
- one probe request is allowed after the open window expires
- a failed probe immediately reopens the circuit
- simple and edge-local by design

## Rate limiting

Current backend:
- in-memory

Client identity:
- first IP from `X-Forwarded-For`
- otherwise `remote_addr`

## Operational limits

- On NTS builds, thread count is forced to `1`.
- On ZTS builds, direct target routes can use request threads, but PHP resolvers are rejected.
- Gateway remains synchronous in its proxy path by design; Core owns the async execution engine.
- Direct upstream targets reuse thread-local upstream connections when the upstream response is safely framed.

## Example

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
