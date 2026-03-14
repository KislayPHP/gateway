# KislayGateway

> Lightweight API gateway and reverse proxy PHP extension for direct routes and service-name routing.

[![PHP Version](https://img.shields.io/badge/PHP-8.2+-blue.svg)](https://php.net)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

## Installation

**Via PIE (recommended):**
```bash
pie install kislayphp/gateway:0.0.4
```

Add to `php.ini`:
```ini
extension=kislayphp_gateway.so
```

**Build from source:**
```bash
git clone https://github.com/KislayPHP/gateway.git
cd gateway
phpize
./configure --enable-kislayphp_gateway
make
sudo make install
```

## Requirements

- PHP 8.2+
- `kislayphp/discovery` for service-based routing

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

## API Reference

### `Gateway`

#### `__construct()`
Creates a new gateway instance.

#### `addRoute(string $method, string $path, string $target): bool`
Registers a direct-target route.

#### `addServiceRoute(string $method, string $path, string $service): bool`
Registers a named-service route. The gateway resolves the real upstream URL through the configured resolver callable.

#### `setResolver(callable $resolver): bool`
Sets the resolver callback.
- Signature: `function(string $service, string $method, string $path): string`
- Return a full upstream base URL such as `http://127.0.0.1:9008`

#### `setFallbackTarget(string $target): bool`
Sets a catch-all upstream target.

#### `setFallbackService(string $service): bool`
Sets a catch-all service name resolved through the resolver.

#### `routes(): array`
Returns all configured routes.

#### `setThreads(int $count): bool`
Sets the IO thread count. On NTS builds, values above `1` are clamped to `1`.

#### `listen(string $host, int $port): bool`
Starts the gateway server and returns after startup. Keep the PHP process alive with a loop, supervisor, systemd, or a container entrypoint.

#### `stop(): bool`
Stops the running gateway.

## Discovery Integration

```php
<?php

$registry = new Kislay\Discovery\ServiceRegistry('http://127.0.0.1:9010');
$gateway  = new Kislay\Gateway\Gateway();

$gateway->addServiceRoute('GET', '/health', 'sample-service');
$gateway->addServiceRoute('GET', '/api/users', 'sample-service');

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

## Runtime Notes

- Resolver callbacks are invoked on matched service routes.
- Resolver output must be a full URL.
- Route matching is first-match.
- Use `*` suffix for prefix routing, for example `/api/*`.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `KISLAY_GATEWAY_THREADS` | Number of IO threads |
| `KISLAY_GATEWAY_MAX_BODY` | Maximum request body size |
| `KISLAY_GATEWAY_AUTH_REQUIRED` | Enable bearer token auth |
| `KISLAY_GATEWAY_AUTH_TOKEN` | Expected bearer token |
| `KISLAY_GATEWAY_AUTH_EXCLUDE` | Comma-separated path prefixes excluded from auth |
| `KISLAY_GATEWAY_RATE_LIMIT_ENABLED` | Enable rate limiting |
| `KISLAY_GATEWAY_RATE_LIMIT_REQUESTS` | Requests per window |
| `KISLAY_GATEWAY_RATE_LIMIT_WINDOW` | Rate limit window in seconds |
| `KISLAY_GATEWAY_CIRCUIT_BREAKER_ENABLED` | Enable circuit breaker |
| `KISLAY_GATEWAY_CB_FAILURE_THRESHOLD` | Failures before opening circuit |
| `KISLAY_GATEWAY_CB_OPEN_SECONDS` | Seconds before half-open retry |

## Common Mistakes

- Returning a path instead of a full URL from the resolver.
- Starting the gateway before discovery has a healthy instance.
- Expecting `listen()` to keep the script alive by itself.
- Using high thread counts on NTS PHP and expecting parallel execution.

## Troubleshooting

**Gateway exits immediately**
- `listen()` starts the server and returns.
- Keep the process alive after startup.

**Gateway returns `502 Service resolver failed`**
- Check that discovery is reachable.
- Check that the service is registered and healthy.
- Check that the resolver returns a valid URL.

## License

Licensed under the [Apache License 2.0](LICENSE).
