# KislayPHP Gateway

[![PHP Version](https://img.shields.io/badge/PHP-8.2%2B-blue.svg)](https://php.net)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/KislayPHP/gateway/ci.yml?branch=main&label=CI)](https://github.com/KislayPHP/gateway/actions)
[![API Docs](https://img.shields.io/github/actions/workflow/status/KislayPHP/gateway/docs.yml?branch=main&label=Docs)](https://github.com/KislayPHP/gateway/actions)
[![PIE](https://img.shields.io/badge/install-pie-blueviolet)](https://github.com/php/pie)
[![Version](https://img.shields.io/badge/version-0.0.3-orange.svg)](RELEASE.md)

> **Production API gateway and reverse proxy as a PHP extension.** Dynamic service routing, rate limiting, circuit breaker, JWT auth — all at C++ speed.

Part of the [KislayPHP ecosystem](https://skelves.com/kislayphp/docs) — PHP extensions for production microservices.

---

## ✨ What It Does

`kislayphp/gateway` is a PHP C++ extension that turns any PHP process into a high-performance API gateway. It handles reverse proxy, service routing, auth, and resilience patterns without any external server configuration.

```php
<?php
$gateway = new Kislay\Gateway\Gateway();
$gateway->addRoute('GET', '/health', 'http://127.0.0.1:9001');
$gateway->listen('0.0.0.0', 9008);
```

That's a production-ready reverse proxy in 3 lines of PHP.

---

## ⚡ Key Features

| Feature | Details |
|---|---|
| **Reverse Proxy** | Proxy HTTP/HTTPS upstream targets with path rewriting |
| **Service Routing** | Route by service name; resolve dynamically via callback |
| **Rate Limiting** | Per-IP request rate limiting with configurable window |
| **Circuit Breaker** | Automatic upstream failure detection and recovery |
| **JWT Auth** | Token authentication with path exclusions |
| **Fallback Targets** | Default upstream for unmatched routes |
| **Multi-threaded** | Event-driven concurrency (ZTS PHP) or single-thread (NTS PHP) |
| **PHP 8.2–8.4** | Tested across all supported PHP versions |

---

## 📦 Installation

**Via PIE (recommended):**
```bash
pie install kislayphp/gateway:0.0.3
```

**Enable in `php.ini`:**
```ini
extension=kislayphp_gateway.so
```

**Build from source:**
```bash
git clone https://github.com/KislayPHP/gateway.git
cd gateway
phpize
./configure --enable-kislayphp_gateway
make && sudo make install
```

---

## 🚀 Quick Start

### Basic Proxy

```php
<?php
$gateway = new Kislay\Gateway\Gateway();

// Static route → upstream target
$gateway->addRoute('GET',  '/api/users', 'http://user-service:9001');
$gateway->addRoute('POST', '/api/users', 'http://user-service:9001');

// Wildcard path matching (prefix *)
$gateway->addRoute('GET', '/static/*', 'http://cdn:9002');

$gateway->listen('0.0.0.0', 9008);
```

### Service-Name Routing

Route by logical service name, resolve the address dynamically — perfect for service discovery integration:

```php
<?php
$gateway = new Kislay\Gateway\Gateway();

$gateway->addServiceRoute('GET',  '/api/users/*',   'user-service');
$gateway->addServiceRoute('POST', '/api/orders',    'order-service');
$gateway->addServiceRoute('GET',  '/api/products/*','catalog-service');

$gateway->setResolver(function (string $service, string $method, string $path): string {
    // Integrate with kislayphp/discovery, a database, env vars, etc.
    return match($service) {
        'user-service'    => 'http://127.0.0.1:9001',
        'order-service'   => 'http://127.0.0.1:9002',
        'catalog-service' => 'http://127.0.0.1:9003',
        default           => 'http://127.0.0.1:9000',
    };
});

$gateway->listen('0.0.0.0', 9008);
```

### Fallback Target

Catch all unmatched requests and forward them to a default upstream:

```php
<?php
$gateway = new Kislay\Gateway\Gateway();
$gateway->setFallbackTarget('https://httpbin.org');
$gateway->listen('0.0.0.0', 9008);
```

---

## 🔒 Authentication & Security

Enable JWT bearer token authentication via environment variables:

```bash
KISLAY_GATEWAY_AUTH_REQUIRED=1
KISLAY_GATEWAY_AUTH_TOKEN=your-secret-token

# Exclude specific path prefixes from auth
KISLAY_GATEWAY_AUTH_EXCLUDE=/health,/public
```

---

## 🛡️ Resilience Patterns

### Rate Limiting

```bash
KISLAY_GATEWAY_RATE_LIMIT_ENABLED=1
KISLAY_GATEWAY_RATE_LIMIT_REQUESTS=100    # max requests
KISLAY_GATEWAY_RATE_LIMIT_WINDOW=60       # per N seconds
```

### Circuit Breaker

Automatically stops forwarding to failed upstreams and retries after a configurable timeout:

```bash
KISLAY_GATEWAY_CIRCUIT_BREAKER_ENABLED=1
KISLAY_GATEWAY_CB_FAILURE_THRESHOLD=5     # failures before opening
KISLAY_GATEWAY_CB_OPEN_SECONDS=30         # cooldown before half-open retry
```

---

## 🌐 Supported Upstream Formats

| Format | Example |
|---|---|
| `http://host` | `http://backend` |
| `http://host:port` | `http://backend:9001` |
| `http://host:port/base` | `http://backend:9001/v1` |
| `https://host` | `https://api.example.com` |
| `https://host:port/path` | `https://secure:443/service` |

---

## 📋 Full Environment Reference

| Variable | Type | Default | Description |
|---|---|---|---|
| `KISLAY_GATEWAY_THREADS` | int | 1 | IO threads (ZTS only) |
| `KISLAY_GATEWAY_MAX_BODY` | bytes | 0 (unlimited) | Max request body size |
| `KISLAY_GATEWAY_AUTH_REQUIRED` | bool | 0 | Enable JWT auth |
| `KISLAY_GATEWAY_AUTH_TOKEN` | string | — | JWT bearer token |
| `KISLAY_GATEWAY_AUTH_EXCLUDE` | CSV | — | Paths excluded from auth |
| `KISLAY_GATEWAY_RATE_LIMIT_ENABLED` | bool | 0 | Enable rate limiter |
| `KISLAY_GATEWAY_RATE_LIMIT_REQUESTS` | int | 100 | Max requests per window |
| `KISLAY_GATEWAY_RATE_LIMIT_WINDOW` | int | 60 | Rate limit window (s) |
| `KISLAY_GATEWAY_CIRCUIT_BREAKER_ENABLED` | bool | 0 | Enable circuit breaker |
| `KISLAY_GATEWAY_CB_FAILURE_THRESHOLD` | int | 5 | Failures before open |
| `KISLAY_GATEWAY_CB_OPEN_SECONDS` | int | 30 | Cooldown before retry |
| `KISLAY_RPC_ENABLED` | bool | 0 | Enable RPC discovery |
| `KISLAY_RPC_TIMEOUT_MS` | int | 1000 | RPC timeout |
| `KISLAY_RPC_DISCOVERY_ENDPOINT` | string | — | Discovery endpoint URL |

---

## 🧵 Thread Safety (ZTS vs NTS)

- **ZTS (Thread Safe)**: `setThreads(n)` uses the full requested count. Multi-threaded event-driven proxying.
- **NTS (non-thread-safe)**: Thread counts above `1` are automatically forced to `1` with a warning. Gateway still fully functional — just single-threaded.

Most Linux production PHP builds use NTS. The gateway handles this transparently.

---

## 📖 Public API

```php
namespace Kislay\Gateway;

class Gateway {
    public function __construct();
    public function addRoute(string $method, string $path, string $target): bool;
    public function addServiceRoute(string $method, string $path, string $service): bool;
    public function routes(): array;
    public function setThreads(int $count): bool;
    public function setResolver(callable $resolver): bool;
    public function setFallbackTarget(string $target): bool;
    public function setFallbackService(string $service): bool;
    public function listen(string $host, int $port): bool;
    public function stop(): bool;
}
```

---

## 🧪 Testing

```bash
cd kislayphp_gateway
make test
```

---

## 🏗️ Full Microservice Example

Combine gateway with discovery for a complete service mesh:

```php
<?php
// gateway.php — the entry point for all traffic

$gateway = new Kislay\Gateway\Gateway();

// Route by service name — discovery resolves addresses
$gateway->addServiceRoute('*', '/api/*', 'api-backend');

$gateway->setResolver(function(string $service, string $method, string $path): string {
    $discovery = new Kislay\Discovery\Registry();
    $instance  = $discovery->resolve($service);   // returns host:port
    return "http://{$instance}";
});

// Security layer
putenv('KISLAY_GATEWAY_AUTH_REQUIRED=1');
putenv('KISLAY_GATEWAY_AUTH_TOKEN=' . getenv('API_SECRET'));
putenv('KISLAY_GATEWAY_RATE_LIMIT_ENABLED=1');
putenv('KISLAY_GATEWAY_CIRCUIT_BREAKER_ENABLED=1');

$gateway->listen('0.0.0.0', 80);
```

---

## 🔗 Ecosystem

| Extension | Purpose | Install |
|---|---|---|
| [core](https://github.com/KislayPHP/core) | HTTP server + async | `pie install kislayphp/core` |
| **gateway** | API gateway (this) | `pie install kislayphp/gateway` |
| [discovery](https://github.com/KislayPHP/discovery) | Service registry | `pie install kislayphp/discovery` |
| [metrics](https://github.com/KislayPHP/metrics) | Prometheus metrics | `pie install kislayphp/metrics` |
| [queue](https://github.com/KislayPHP/queue) | Message queue | `pie install kislayphp/queue` |
| [eventbus](https://github.com/KislayPHP/eventbus) | Realtime events | `pie install kislayphp/eventbus` |
| [persistence](https://github.com/KislayPHP/persistence) | Data layer | `pie install kislayphp/persistence` |
| [config](https://github.com/KislayPHP/config) | Configuration | `pie install kislayphp/config` |

---

## 📄 License

[Apache License 2.0](LICENSE) · © 2026 KislayPHP

---

**[Full Documentation](https://skelves.com/kislayphp/docs) · [Issues](https://github.com/KislayPHP/gateway/issues) · [Discussions](https://github.com/KislayPHP/gateway/discussions)**
