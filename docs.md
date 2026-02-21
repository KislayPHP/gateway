# kislayphp_gateway Documentation

## Overview

`kislayphp_gateway` exposes a single gateway server class implemented in C++.

Namespace:

- Primary: `Kislay\Gateway\Gateway`
- Legacy alias: `KislayPHP\Gateway\Gateway`

## Class: `Kislay\Gateway\Gateway`

### Constructor

```php
new Kislay\Gateway\Gateway()
```

Loads runtime defaults from environment variables.

### `addRoute`

```php
addRoute(string $method, string $path, string $target): bool
```

Adds a direct upstream route.

- `method` is normalized to uppercase.
- `path` may be exact (`/health`) or wildcard suffix (`/api/*`).
- `target` must be `http(s)://host[:port][/base]`.
- Throws exception on invalid target.

### `addServiceRoute`

```php
addServiceRoute(string $method, string $path, string $service): bool
```

Adds a service-name route. Service name must be resolved later by:

- `setResolver(callable)`; or
- optional RPC resolver mode (`KISLAY_RPC_ENABLED=1`, if compiled with RPC support).

### `routes`

```php
routes(): array
```

Returns configured routes. Each item includes:

- direct route: `method`, `path`, `target`
- service route: `method`, `path`, `service`

### `setThreads`

```php
setThreads(int $count): bool
```

Sets CivetWeb worker thread count before `listen()`.

- Throws if gateway is already running.
- `count < 1` is sanitized to `1` with warning.
- On NTS PHP builds (Thread Safety disabled), values `>1` are forced to `1` with warning.

### `setResolver`

```php
setResolver(callable $resolver): bool
```

Sets PHP callback for service routes.

Callback signature:

```php
function (string $service, string $method, string $path): string
```

Return must be an upstream target string (`http://...` or `https://...`).

### `setFallbackTarget`

```php
setFallbackTarget(string $target): bool
```

Sets default upstream used when no route matches.

### `setFallbackService`

```php
setFallbackService(string $service): bool
```

Sets default service used when no route matches. Requires resolver path (PHP callable or RPC).

### `listen`

```php
listen(string $host, int $port): bool
```

Starts CivetWeb listener on `host:port`.

- Throws on invalid port.
- Throws if already running.
- Applies NTS safety fallback for thread count.
- Initializes HTTP handling and reverse proxy behavior.

### `stop`

```php
stop(): bool
```

Stops listener if running.

## Route Matching Rules

- Request method is matched exactly after uppercasing.
- Exact path match has normal string equality.
- Wildcard is supported only as trailing `*` and acts as prefix match.
  - Example: `/api/*` matches `/api/users` and `/api/users/1`.
- First matching route (in add order) is used.
- If no route matches and fallback exists, fallback is used.
- If no route and no fallback, returns `404 Not Found`.

## Upstream Target Parsing

Accepted forms:

- `http://backend`
- `http://backend:9001`
- `http://backend:9001/base`
- `https://backend`
- `https://backend:9443/base`

Defaults:

- `http` -> port `80`
- `https` -> port `443`
- missing path -> `/`

Invalid target format causes route-registration exception.

## Request Handling Features

### Reverse Proxy

Gateway forwards:

- request method
- request URI + query string
- most headers (hop-by-hop headers removed)
- request body

Gateway returns upstream status/headers/body back to client.

### Body Size Limit

`KISLAY_GATEWAY_MAX_BODY` limits request body size in bytes.

- `0` means unlimited.
- Exceeded payload returns `413 Payload Too Large`.

### Optional Auth Guard

Controlled by env vars:

- `KISLAY_GATEWAY_AUTH_REQUIRED=1`
- `KISLAY_GATEWAY_AUTH_TOKEN=<token>`
- `KISLAY_GATEWAY_AUTH_EXCLUDE=/health,/ready,/metrics`

Behavior:

- If required and token missing in config -> `503`.
- Missing/invalid `Authorization: Bearer <token>` -> `401`.
- Excluded path prefixes bypass auth.

### Optional Rate Limiting

Controlled by:

- `KISLAY_GATEWAY_RATE_LIMIT_ENABLED=1`
- `KISLAY_GATEWAY_RATE_LIMIT_REQUESTS` (default `120`)
- `KISLAY_GATEWAY_RATE_LIMIT_WINDOW` seconds (default `60`)

Keyed by client IP and HTTP method. Exceeding limit returns `429`.

### Optional Circuit Breaker

Controlled by:

- `KISLAY_GATEWAY_CIRCUIT_BREAKER_ENABLED=1`
- `KISLAY_GATEWAY_CB_FAILURE_THRESHOLD` (default `5`)
- `KISLAY_GATEWAY_CB_OPEN_SECONDS` (default `30`)

Per upstream host:port:

- repeated failures open circuit
- open circuit returns `503 Circuit breaker open`
- successful responses reset failure counter

## Service Resolution Modes

### PHP Resolver Callback

Set using `setResolver()`.

- If callback throws, returns non-string, or fails: gateway returns `502 Service resolver failed`.
- Resolver failures are logged via PHP warnings.

### RPC Resolver (Optional Build)

If compiled with RPC support and callback not set:

- `KISLAY_RPC_ENABLED=1`
- `KISLAY_RPC_DISCOVERY_ENDPOINT` (default `127.0.0.1:9090`)
- `KISLAY_RPC_TIMEOUT_MS` (default `200`)

If neither callback nor RPC resolution is available, service routes return `502 Service resolver not configured`.

## Thread Safety Notes

### ZTS Enabled

- Multi-thread worker counts are honored.

### NTS (Thread Safety Disabled)

- Thread count is forced to `1` with warning whenever count would be greater than `1`.
- This allows safe operation on default Linux NTS PHP builds.

## Errors and Status Codes

Common responses emitted by gateway:

- `401` unauthorized token issues
- `404` no route
- `413` payload too large
- `429` rate limit exceeded
- `502` upstream/service resolution failures
- `503` auth misconfiguration or circuit open

## Quick Example

```php
<?php

$gateway = new Kislay\Gateway\Gateway();
$gateway->setThreads(4); // forced to 1 on NTS

$gateway->addRoute('GET', '/public/*', 'https://httpbin.org');
$gateway->addServiceRoute('GET', '/api/users/*', 'user-service');

$gateway->setResolver(function (string $service, string $method, string $path): string {
    if ($service === 'user-service') {
        return 'http://127.0.0.1:9010';
    }
    return 'http://127.0.0.1:9001';
});

$gateway->setFallbackTarget('http://127.0.0.1:9000');
$gateway->listen('0.0.0.0', 9008);

while (true) {
    sleep(1);
}
```

## Build and Test

```bash
phpize
./configure --enable-kislayphp_gateway
make
make test
```
