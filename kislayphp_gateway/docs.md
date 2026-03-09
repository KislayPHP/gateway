# KislayPHP Gateway - Technical Reference

A high-performance reverse proxy extension for PHP built on embedded civetweb with circuit breaking, rate limiting, authentication, and flexible routing for microservice architectures.

**Version**: 1.0 | **Stability**: Production-Ready

---

## 1. Architecture

### System Design

KislayPHP Gateway is a single-process reverse proxy implemented as a PHP extension (C++). It embeds civetweb HTTP server in-process and proxies requests to upstream services synchronously.

```
Client → civetweb → Rate Limiter → Auth → Router → Circuit Breaker → Upstream
                                                           ↓
                                                   Header Injection
                                                    (8KB streaming)
```

### Core Characteristics

- **Synchronous Processing**: Requests block until upstream responds
- **Single Upstream per Route**: No built-in load balancing (implement in resolver)
- **8KB Chunk Streaming**: Memory-efficient response streaming
- **Connection Management**: `Connection: close` upstream, `keep-alive` clients
- **Thread Pool**: Configurable (default 1), handles concurrent requests
- **Per-Upstream Circuit Breaker**: Separate 2-state machine per host:port
- **Per-Client Rate Limiting**: Sliding window by IP + HTTP method

### Request Processing Pipeline

1. **Accept** - civetweb accepts client connection
2. **Parse** - Extract method, path, headers, body
3. **Rate Limit** - Check sliding window (429 if exceeded)
4. **Authenticate** - Bearer token validation (401 if invalid)
5. **Route Match** - Find route (exact → wildcard → fallback)
6. **Circuit Check** - Check upstream state (503 if open)
7. **Headers** - Inject X-Forwarded-*, strip hop headers
8. **Upstream** - Stream request with 8KB chunks
9. **Response** - Stream response back to client
10. **Failure Track** - Update circuit breaker state
11. **Close** - Connection handling (keep-alive or close)

### Circuit Breaker State Machine

Two-state machine per upstream host:

```
CLOSED (healthy)              OPEN (unhealthy)
├─ Forward all requests       ├─ Return 503 immediately
├─ Count failures             ├─ Hold open_until timestamp
├─ Reset on success           ├─ Check time elapsed
└─ Transition: failures >= T  └─ Transition: now >= open_until
```

**Failure Definition**: HTTP 5xx status or connection error  
**Success Definition**: HTTP < 500 (all 2xx, 3xx, 4xx reset counter)  
**Thread Safety**: Mutex protected per upstream

### Rate Limiting with Sliding Window

Per-client implementation:

```
Key = "{client_ip}|{HTTP_METHOD}"
Window = [now - window_seconds, now]

Logic:
- Window Reset: when now - window_start >= window_seconds
- Limit Check: if request_count >= limit → return 429
- Increment: on each request
- Client IP: X-Forwarded-For first, fallback remote_addr
```

**Thread Safe**: Protected by std::mutex

### Bearer Token Authentication

Simple exact-match validation:

- **Header Format**: `Authorization: Bearer {token}`
- **Comparison**: Exact string match (case-sensitive)
- **Exclusion List**: Path prefixes (CSV, default: `/health,/ready,/metrics`)
- **Responses**:
  - `401 Unauthorized`: Missing or incorrect token
  - `503 Service Unavailable`: Token required but not configured

### Header Management

**Added to Upstream Request**:
- `X-Forwarded-For`: Original client IP (comma-separated)
- `X-Forwarded-Proto`: Original protocol (http/https)
- `X-Forwarded-Host`: Original Host header
- `X-Real-IP`: Original client IP

**Stripped from Request** (hop-by-hop headers):
- Connection, Keep-Alive, TE, Trailer, Transfer-Encoding, Upgrade, Proxy-Connection

### Path Matching Algorithm

Routes matched in definition order:

1. **Exact Match**: `path == route_path`
2. **Wildcard Match**: `route ends with *` and `path starts with route_prefix`
3. **Fallback**: Default route (if set)

First match wins. No regex support.

---

## 2. Configuration Reference

### Environment Variables

All configuration through environment (no config files):

#### Gateway Core

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KISLAY_GATEWAY_MAX_BODY` | long | 0 | Max request body bytes (0=unlimited) |
| `KISLAY_GATEWAY_THREADS` | int | 1 | Thread pool size (1-256) |

#### Authentication

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KISLAY_GATEWAY_AUTH_REQUIRED` | bool | false | Enforce auth on all routes |
| `KISLAY_GATEWAY_AUTH_TOKEN` | string | "" | Bearer token value |
| `KISLAY_GATEWAY_AUTH_EXCLUDE` | CSV | /health,/ready,/metrics | Auth-excluded paths |

#### Rate Limiting

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KISLAY_GATEWAY_RATE_LIMIT_ENABLED` | bool | false | Enable rate limiting |
| `KISLAY_GATEWAY_RATE_LIMIT_REQUESTS` | long | 120 | Max requests per window |
| `KISLAY_GATEWAY_RATE_LIMIT_WINDOW` | long | 60 | Window duration (seconds) |

#### Circuit Breaker

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KISLAY_GATEWAY_CIRCUIT_BREAKER_ENABLED` | bool | false | Enable circuit breaker |
| `KISLAY_GATEWAY_CB_FAILURE_THRESHOLD` | long | 5 | Failures before open |
| `KISLAY_GATEWAY_CB_OPEN_SECONDS` | long | 30 | Duration to keep open |

#### RPC Service Discovery (Optional)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KISLAY_RPC_ENABLED` | bool | false | Enable RPC discovery |
| `KISLAY_RPC_TIMEOUT_MS` | long | 200 | RPC timeout ms |
| `KISLAY_RPC_DISCOVERY_ENDPOINT` | string | 127.0.0.1:9090 | RPC server address |

### Configuration Examples

**Basic Setup**:
```bash
export KISLAY_GATEWAY_THREADS=4
export KISLAY_GATEWAY_MAX_BODY=5242880  # 5MB
```

**Production with Security**:
```bash
export KISLAY_GATEWAY_THREADS=16
export KISLAY_GATEWAY_MAX_BODY=10485760  # 10MB
export KISLAY_GATEWAY_AUTH_REQUIRED=true
export KISLAY_GATEWAY_AUTH_TOKEN="your-secret-token"
export KISLAY_GATEWAY_AUTH_EXCLUDE="/health,/ready,/metrics,/status"
```

**With Resilience**:
```bash
export KISLAY_GATEWAY_THREADS=8
export KISLAY_GATEWAY_CIRCUIT_BREAKER_ENABLED=true
export KISLAY_GATEWAY_CB_FAILURE_THRESHOLD=3
export KISLAY_GATEWAY_CB_OPEN_SECONDS=60
export KISLAY_GATEWAY_RATE_LIMIT_ENABLED=true
export KISLAY_GATEWAY_RATE_LIMIT_REQUESTS=1000
export KISLAY_GATEWAY_RATE_LIMIT_WINDOW=60
```

---

## 3. API Reference

### Class: Kislay\Gateway

#### Constructor
```php
$gateway = new Kislay\Gateway();
```
Creates independent gateway instance.

#### addRoute(method, path, target): bool
```php
$gateway->addRoute('GET', '/users/123', '127.0.0.1:3000');
$gateway->addRoute('GET', '/api/v1/*', '127.0.0.1:3000');
$gateway->addRoute('POST', '/*', '127.0.0.1:8000');
```
- `method`: HTTP verb (GET, POST, PUT, DELETE, PATCH, etc.)
- `path`: Exact path or prefix with `*`
- `target`: `host:port`

#### addServiceRoute(method, path, service): bool
```php
$gateway->addServiceRoute('GET', '/users/*', 'user-service');
```
Add route with service discovery (requires `setResolver()`).

#### routes(): array
```php
$routes = $gateway->routes();
// [
//   ['method' => 'GET', 'path' => '/api/*', 'target' => '127.0.0.1:3000'],
//   ...
// ]
```

#### setThreads(count): bool
```php
$gateway->setThreads(16);  // 16 concurrent requests
```

#### setResolver(callable): bool
```php
$gateway->setResolver(function($service, $method, $path) {
    static $services = [
        'user-service' => '127.0.0.1:3001',
        'order-service' => '127.0.0.1:3002',
    ];
    return $services[$service] ?? '127.0.0.1:9000';
});
```

#### setFallbackTarget(target): bool
```php
$gateway->setFallbackTarget('127.0.0.1:9000');
```

#### setFallbackService(service): bool
```php
$gateway->setFallbackService('default-service');
```

#### listen(host, port): bool
```php
if (!$gateway->listen('0.0.0.0', 8080)) {
    die('Failed to start');
}
// Blocks until stop() called or signal
```

#### listenAsync(host, port): bool
```php
if (!$gateway->listenAsync('0.0.0.0', 8080)) {
    die('Failed to start');
}
// Server runs in background
// Continue execution...
```

#### wait(ms = -1): bool
```php
$gateway->listenAsync('0.0.0.0', 8080);
// Do other work...
$gateway->wait(-1);  // Wait indefinitely
```

#### stop(): bool
```php
$gateway->stop();  // Graceful shutdown
```

#### isRunning(): bool
```php
if ($gateway->isRunning()) {
    echo "Gateway is active";
}
```

---

## 4. Patterns and Recipes

### Pattern 1: API Gateway with Central Auth

Route all microservices through unified entry point:

```php
<?php
$gateway = new Kislay\Gateway();

putenv('KISLAY_GATEWAY_AUTH_REQUIRED=true');
putenv('KISLAY_GATEWAY_AUTH_TOKEN=secret-api-key-123');
putenv('KISLAY_GATEWAY_RATE_LIMIT_ENABLED=true');
putenv('KISLAY_GATEWAY_RATE_LIMIT_REQUESTS=1000');
putenv('KISLAY_GATEWAY_CIRCUIT_BREAKER_ENABLED=true');

$gateway->addRoute('GET', '/users/*', '127.0.0.1:3001');
$gateway->addRoute('POST', '/users', '127.0.0.1:3001');
$gateway->addRoute('GET', '/orders/*', '127.0.0.1:3002');
$gateway->addRoute('POST', '/orders', '127.0.0.1:3002');
$gateway->addRoute('GET', '/products/*', '127.0.0.1:3003');

// Health endpoints excluded from auth
$gateway->addRoute('GET', '/health', '127.0.0.1:3001');
$gateway->addRoute('GET', '/ready', '127.0.0.1:3001');

$gateway->setFallbackTarget('127.0.0.1:9000');
$gateway->listen('0.0.0.0', 8080);
?>
```

Usage:
```bash
# Client must include auth
curl -H "Authorization: Bearer secret-api-key-123" http://localhost:8080/users/123
# No auth needed for health
curl http://localhost:8080/health
```

### Pattern 2: Backend for Frontend (BFF)

Dedicated gateways per frontend with service resolution:

```php
<?php
$gateway = new Kislay\Gateway();

$gateway->setResolver(function($service, $method, $path) {
    static $instances = [
        'auth-service' => '127.0.0.1:3001',
        'user-service' => '127.0.0.1:3002',
        'profile-service' => '127.0.0.1:3003',
        'notification-service' => '127.0.0.1:3004',
    ];
    return $instances[$service] ?? '127.0.0.1:9000';
});

// Mobile BFF - more aggressive rate limiting
putenv('KISLAY_GATEWAY_RATE_LIMIT_ENABLED=true');
putenv('KISLAY_GATEWAY_RATE_LIMIT_REQUESTS=500');

$gateway->addServiceRoute('POST', '/auth/login', 'auth-service');
$gateway->addServiceRoute('GET', '/profile', 'profile-service');
$gateway->addServiceRoute('GET', '/notifications', 'notification-service');

$gateway->listenAsync('0.0.0.0', 8081);
$gateway->wait();
?>
```

### Pattern 3: Service Mesh Ingress

High-concurrency service-to-service communication:

```php
<?php
$gateway = new Kislay\Gateway();

putenv('KISLAY_GATEWAY_CIRCUIT_BREAKER_ENABLED=true');
putenv('KISLAY_GATEWAY_CB_FAILURE_THRESHOLD=3');
putenv('KISLAY_GATEWAY_CB_OPEN_SECONDS=30');

$gateway->setResolver(function($service, $method, $path) {
    // Load from environment (Kubernetes DNS or service registry)
    $registry = [
        'user-service' => getenv('USER_SERVICE_ADDR') ?: '127.0.0.1:3001',
        'order-service' => getenv('ORDER_SERVICE_ADDR') ?: '127.0.0.1:3002',
        'payment-service' => getenv('PAYMENT_SERVICE_ADDR') ?: '127.0.0.1:3003',
    ];
    return $registry[$service] ?? '127.0.0.1:9000';
});

$gateway->addServiceRoute('GET', '/users/*', 'user-service');
$gateway->addServiceRoute('POST', '/orders', 'order-service');
$gateway->addServiceRoute('POST', '/payments', 'payment-service');

$gateway->setThreads(32);  // High concurrency
$gateway->listen('127.0.0.1', 8080);
?>
```

### Pattern 4: Circuit Breaker Demonstration

Testing circuit breaker state transitions:

```php
<?php
$gateway = new Kislay\Gateway();

putenv('KISLAY_GATEWAY_CIRCUIT_BREAKER_ENABLED=true');
putenv('KISLAY_GATEWAY_CB_FAILURE_THRESHOLD=2');
putenv('KISLAY_GATEWAY_CB_OPEN_SECONDS=10');

$gateway->addRoute('GET', '/api/*', '127.0.0.1:5000');

// Admin status endpoint
if ($_SERVER['REQUEST_URI'] === '/admin/status') {
    header('Content-Type: application/json');
    echo json_encode([
        'running' => $gateway->isRunning(),
        'routes' => $gateway->routes(),
        'timestamp' => time(),
    ]);
    exit;
}

$gateway->listen('0.0.0.0', 8080);
?>
```

Test:
```bash
# Upstream fails (return 500)
for i in {1..5}; do
    curl http://localhost:8080/api/test
    sleep 1
done
# After 2 failures → 503 Service Unavailable
# After 10 seconds → circuit closes, retries resume
```

### Pattern 5: Rate Limit Testing

```php
<?php
$gateway = new Kislay\Gateway();

putenv('KISLAY_GATEWAY_RATE_LIMIT_ENABLED=true');
putenv('KISLAY_GATEWAY_RATE_LIMIT_REQUESTS=10');
putenv('KISLAY_GATEWAY_RATE_LIMIT_WINDOW=60');

$gateway->addRoute('GET', '/*', '127.0.0.1:3000');
$gateway->listen('0.0.0.0', 8080);
?>
```

Load test:
```bash
ab -n 20 -c 10 http://localhost:8080/
# First 10 requests → 200 OK
# Requests 11-20 → 429 Too Many Requests
```

### Pattern 6: Versioned API Routing

```php
<?php
$gateway = new Kislay\Gateway();

$gateway->setResolver(function($service, $method, $path) {
    // Extract version from path
    if (preg_match('/^\\/v(\\d+)\\//', $path, $m)) {
        $version = $m[1];
        return "127.0.0.1:" . (3000 + $version);
    }
    return '127.0.0.1:3000';
});

$gateway->addServiceRoute('GET', '/v1/*', 'api');
$gateway->addServiceRoute('GET', '/v2/*', 'api');
$gateway->addServiceRoute('GET', '/v3/*', 'api');

$gateway->listen('0.0.0.0', 8080);
?>
```

---

## 5. Performance Notes

### Throughput Characteristics

- **Synchronous Model**: Throughput = 1 / (upstream_latency / threads)
- **Streaming**: 8KB chunks for memory efficiency
- **CPU-Bound**: Header parsing, rate limit checks
- **Memory**: ~1-2MB per thread + base overhead

### Benchmark Reference

With 16 threads:
- **Latency**: +1-3ms overhead vs direct
- **Throughput**: ~5000 req/s (varies with CPU and upstream latency)
- **Memory**: ~50MB base + ~20MB per 10 threads

### Optimization

1. **Thread Sizing**: Start with `2 × CPU_CORES`
2. **Rate Limit Window**: 60s optimal (balance overhead vs precision)
3. **Circuit Breaker**: Threshold 5 typical
4. **Body Limits**: Set reasonable max (5-10MB)
5. **Connections**: Use connection pooling if upstream has limits

### Monitoring

```php
$gateway->listenAsync('0.0.0.0', 8080);

$stats = [
    'start' => time(),
    'requests' => 0,
    'rate_limit_hits' => 0,
    'circuit_trips' => 0,
];

$gateway->wait();
```

### Scaling

- **Horizontal**: Multiple instances + load balancer
- **Vertical**: Increase threads, optimize upstream
- **Caching**: Cache responses in services

---

## 6. Troubleshooting

### Gateway Won't Start
```bash
# Port in use?
lsof -i :8080
kill -9 <PID>

# Try different port
$gateway->listen('0.0.0.0', 8081);
```

### 429 Rate Limit Errors
```bash
# Increase limit
export KISLAY_GATEWAY_RATE_LIMIT_REQUESTS=500

# Or disable
export KISLAY_GATEWAY_RATE_LIMIT_ENABLED=false
```

### 401 Unauthorized
```bash
# Token must match exactly
export KISLAY_GATEWAY_AUTH_TOKEN="exact-token"
curl -H "Authorization: Bearer exact-token" http://localhost:8080/

# Exclude paths
export KISLAY_GATEWAY_AUTH_EXCLUDE="/health,/ready,/metrics,/status"
```

### 503 Service Unavailable
```bash
# Circuit breaker? Wait or disable
export KISLAY_GATEWAY_CIRCUIT_BREAKER_ENABLED=false

# Test upstream
curl http://127.0.0.1:3000/
```

### Timeout/Hanging
```bash
# Increase threads
export KISLAY_GATEWAY_THREADS=32

# Check upstream
curl -v http://127.0.0.1:3000/
```

### Memory Growing
```bash
# Limit body, reduce threads
export KISLAY_GATEWAY_MAX_BODY=5242880
export KISLAY_GATEWAY_THREADS=4
```

### High CPU
```bash
# Optimize resolver with cache
$gateway->setResolver(function($s, $m, $p) {
    static $cache = [];
    return $cache[$s] ?? ($cache[$s] = resolve($s));
});

# Disable unused features
export KISLAY_GATEWAY_RATE_LIMIT_ENABLED=false
```

### Debug Checklist

1. Running? `if (!$gateway->isRunning()) exit;`
2. Routes? `print_r($gateway->routes());`
3. Upstream? `curl http://upstream/`
4. Proxies? `curl http://localhost/`
5. Rate limit? Burst 120 requests
6. Auth? No token → 401
7. Circuit breaker? Upstream failures → 503

---

## Summary

KislayPHP Gateway provides lightweight reverse proxy for microservices with built-in resilience (circuit breaker, rate limiting), authentication, and routing. Synchronous streaming design prioritizes low latency and predictable resources.

For production: combine with load balancers, monitoring, and graceful shutdown.
