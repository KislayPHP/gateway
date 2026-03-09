# KislayGateway

> Lightweight API gateway and reverse proxy PHP extension — routes HTTP traffic to upstream services with built-in auth, rate limiting, and circuit breaking.

[![PHP Version](https://img.shields.io/badge/PHP-8.2+-blue.svg)](https://php.net)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

## Installation

**Via PIE (recommended):**
```bash
pie install kislayphp/gateway:0.0.3
```

Add to `php.ini`:
```ini
extension=kislayphp_gateway.so
```

**Build from source:**
```bash
git clone https://github.com/KislayPHP/gateway.git
cd gateway && phpize && ./configure --enable-kislayphp_gateway && make && sudo make install
```

## Requirements

- PHP 8.2+
- PHP ZTS build recommended for `threads > 1` (NTS auto-clamps to 1 thread)
- kislayphp/core for service discovery integration (optional)

## Quick Start

```php
<?php
$gateway = new Kislay\Gateway\Gateway();

$gateway->addRoute('GET',  '/api/users',  'http://127.0.0.1:9001');
$gateway->addRoute('POST', '/api/users',  'http://127.0.0.1:9001');
$gateway->addRoute('GET',  '/api/orders', 'http://127.0.0.1:9002');

$gateway->listen('0.0.0.0', 8080);
```

## API Reference

### `Gateway`

#### `__construct()`
Creates a new Gateway instance. Thread count defaults to `KISLAY_GATEWAY_THREADS` env var or `1`.

#### `addRoute(string $method, string $path, string $target): bool`
Registers a direct-target route. Route matching is first-match; `*` suffix enables prefix matching.
- `$method` — HTTP verb, e.g. `'GET'`, `'POST'`, `'*'` for any
- `$path` — URL path; use `*` suffix for prefix match: `'/api/*'`
- `$target` — Upstream URL: `http://host`, `http://host:port`, `http://host:port/base`, or `https://…`
- Returns `true` on success

```php
$gateway->addRoute('*', '/static/*', 'http://127.0.0.1:9010/files');
```

#### `addServiceRoute(string $method, string $path, string $service): bool`
Registers a named-service route. The gateway resolves the actual URL via the configured resolver callable.
- `$service` — Logical service name passed to the resolver
- Returns `true` on success

```php
$gateway->addServiceRoute('GET', '/api/users/*', 'user-service');
```

#### `setResolver(callable $resolver): bool`
Sets the service-name-to-URL resolver. Called on every request matched by `addServiceRoute()`.
- Signature: `function(string $service, string $method, string $path): string`
- Must return a full upstream URL string

```php
$gateway->setResolver(function (string $service, string $method, string $path): string {
    $registry = new Kislay\Discovery\ServiceRegistry();
    return $registry->resolve($service) ?? 'http://127.0.0.1:9001';
});
```

#### `setFallbackTarget(string $target): bool`
Sets a catch-all upstream for unmatched routes.

#### `setFallbackService(string $service): bool`
Sets a named-service fallback; resolved via the configured resolver.

#### `routes(): array`
Returns all registered routes as an array.

#### `setThreads(int $count): bool`
Sets the number of IO threads. Values > 1 are clamped to 1 on NTS PHP.

#### `listen(string $host, int $port): bool`
Starts the gateway and blocks until stopped.
- `$host` — bind address
- `$port` — TCP port
- Returns `true` on clean shutdown

#### `stop(): bool`
Gracefully stops the gateway.

## Configuration

### Environment Variables

| Variable | Description |
|----------|-------------|
| `KISLAY_GATEWAY_THREADS` | Number of IO threads |
| `KISLAY_GATEWAY_MAX_BODY` | Max request body bytes (`0` = unlimited) |
| `KISLAY_GATEWAY_AUTH_REQUIRED` | `1` to enable bearer token auth |
| `KISLAY_GATEWAY_AUTH_TOKEN` | Expected bearer token value |
| `KISLAY_GATEWAY_AUTH_EXCLUDE` | Comma-separated path prefixes to exclude from auth |
| `KISLAY_GATEWAY_RATE_LIMIT_ENABLED` | `1` to enable rate limiting |
| `KISLAY_GATEWAY_RATE_LIMIT_REQUESTS` | Max requests per window |
| `KISLAY_GATEWAY_RATE_LIMIT_WINDOW` | Rate limit window in seconds |
| `KISLAY_GATEWAY_CIRCUIT_BREAKER_ENABLED` | `1` to enable circuit breaker |
| `KISLAY_GATEWAY_CB_FAILURE_THRESHOLD` | Consecutive failures before circuit opens |
| `KISLAY_GATEWAY_CB_OPEN_SECONDS` | Seconds circuit stays open before half-open retry |

### RPC-based Discovery (optional build feature)

| Variable | Description |
|----------|-------------|
| `KISLAY_RPC_ENABLED` | `1` to enable RPC-based service resolution |
| `KISLAY_RPC_TIMEOUT_MS` | RPC call timeout in milliseconds |
| `KISLAY_RPC_DISCOVERY_ENDPOINT` | Discovery server endpoint |

## Examples

### Service Mesh with Discovery

```php
<?php
$registry = new Kislay\Discovery\ServiceRegistry();
$gateway  = new Kislay\Gateway\Gateway();

$gateway->addServiceRoute('GET',  '/api/users/*',  'user-service');
$gateway->addServiceRoute('POST', '/api/users',    'user-service');
$gateway->addServiceRoute('*',    '/api/orders/*', 'order-service');

$gateway->setResolver(function (string $service) use ($registry): string {
    return $registry->resolve($service) ?? throw new \RuntimeException("No healthy instance for $service");
});

$gateway->listen('0.0.0.0', 8080);
```

### Fallback Proxy

```php
<?php
$gateway = new Kislay\Gateway\Gateway();
$gateway->setFallbackTarget('https://httpbin.org');
$gateway->listen('0.0.0.0', 8080);
```

### Auth + Rate Limiting via Environment

```bash
KISLAY_GATEWAY_AUTH_REQUIRED=1 \
KISLAY_GATEWAY_AUTH_TOKEN=secret-token \
KISLAY_GATEWAY_AUTH_EXCLUDE=/health,/metrics \
KISLAY_GATEWAY_RATE_LIMIT_ENABLED=1 \
KISLAY_GATEWAY_RATE_LIMIT_REQUESTS=100 \
KISLAY_GATEWAY_RATE_LIMIT_WINDOW=60 \
php gateway.php
```

## Related Extensions

| Extension | Use Case |
|-----------|----------|
| [kislayphp/core](https://github.com/KislayPHP/core) | HTTP server powering the upstream microservices |
| [kislayphp/discovery](https://github.com/KislayPHP/discovery) | Service registry for dynamic upstream resolution |

## License

Licensed under the [Apache License 2.0](LICENSE).
