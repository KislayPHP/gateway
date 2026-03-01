# kislayphp_gateway

PHP extension for lightweight API gateway and reverse proxy features.

## Version

Current package line: `v0.0.3`.

## Namespace

- Primary: `Kislay\Gateway\Gateway`
- Legacy alias: `KislayPHP\Gateway\Gateway`

Both names map to the same class.

## Installation

Via PIE:

```bash
pie install kislayphp/gateway:0.0.3
```

Enable in `php.ini`:

```ini
extension=kislayphp_gateway.so
```

Build from source:

```bash
phpize
./configure --enable-kislayphp_gateway
make
sudo make install
```

## Quick Start

```php
<?php

$gateway = new Kislay\Gateway\Gateway();
$gateway->addRoute('GET', '/health', 'http://127.0.0.1:9001');
$gateway->listen('0.0.0.0', 9008);
```

## Documentation

- Basic docs remain in this repository.
- Full detailed docs are maintained on the site: [https://skelves.com/docs](https://skelves.com/docs)
- Local docs route: `http://localhost:5180/docs`

Supported upstream target formats:

- `http://host`
- `http://host:port`
- `http://host:port/base/path`
- `https://host`
- `https://host:port/base/path`

## Service Route Example

```php
<?php

$gateway = new Kislay\Gateway\Gateway();

$gateway->addServiceRoute('GET', '/api/users/*', 'user-service');

$gateway->setResolver(function (string $service, string $method, string $path): string {
    if ($service === 'user-service') {
        return 'http://127.0.0.1:9010';
    }
    return 'http://127.0.0.1:9001';
});

$gateway->listen('0.0.0.0', 9008);
```

Resolver callable contract:

- Input: `(service, method, path)`
- Output: target URL string (`http://...` or `https://...`)

## Fallback Route Example

```php
<?php

$gateway = new Kislay\Gateway\Gateway();
$gateway->setFallbackTarget('https://httpbin.org');
$gateway->listen('0.0.0.0', 9008);
```

## Thread Safety Behavior (ZTS vs NTS)

- If PHP is ZTS-enabled, `setThreads(n)` uses the requested thread count.
- If PHP is NTS (Thread Safety disabled), counts above `1` are automatically forced to `1` with a warning.
- This check is applied at construction (env-based default), `setThreads()`, and `listen()`.

This keeps the gateway usable on common Linux NTS builds without crashing on multi-thread configuration.

## Public API

`Kislay\Gateway\Gateway` methods:

- `__construct()`
- `addRoute(string $method, string $path, string $target): bool`
- `addServiceRoute(string $method, string $path, string $service): bool`
- `routes(): array`
- `setThreads(int $count): bool`
- `setResolver(callable $resolver): bool`
- `setFallbackTarget(string $target): bool`
- `setFallbackService(string $service): bool`
- `listen(string $host, int $port): bool`
- `stop(): bool`

## Runtime Controls (Environment)

- `KISLAY_GATEWAY_MAX_BODY` (bytes, `0` = unlimited)
- `KISLAY_GATEWAY_THREADS`
- `KISLAY_GATEWAY_AUTH_REQUIRED`
- `KISLAY_GATEWAY_AUTH_TOKEN`
- `KISLAY_GATEWAY_AUTH_EXCLUDE` (CSV path prefixes)
- `KISLAY_GATEWAY_RATE_LIMIT_ENABLED`
- `KISLAY_GATEWAY_RATE_LIMIT_REQUESTS`
- `KISLAY_GATEWAY_RATE_LIMIT_WINDOW`
- `KISLAY_GATEWAY_CIRCUIT_BREAKER_ENABLED`
- `KISLAY_GATEWAY_CB_FAILURE_THRESHOLD`
- `KISLAY_GATEWAY_CB_OPEN_SECONDS`

Optional RPC-based service resolution (when extension is built with RPC stubs):

- `KISLAY_RPC_ENABLED`
- `KISLAY_RPC_TIMEOUT_MS`
- `KISLAY_RPC_DISCOVERY_ENDPOINT`

## Test

```bash
cd kislayphp_gateway
make test
```

## Notes

- Route matching is insertion-order and first-match wins.
- Wildcard path matching is suffix `*` prefix matching (example: `/api/*`).
- `listen()` is non-blocking; keep your script alive if needed.

## End-to-End Example

A complete distributed content backend example (registry + gateway + docs/blog/community/auth services) is available in:

- `../kislayphp_discovery/examples/website_backend/README.md`
