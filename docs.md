# KislayPHP Gateway Extension Documentation

## Overview

The KislayPHP Gateway extension provides high-performance API gateway functionality with load balancing, routing, rate limiting, and service discovery integration. It supports reverse proxy capabilities, circuit breaking, and pluggable middleware architecture.

## Architecture

### Core Components
- **Router**: HTTP request routing and path matching
- **Load Balancer**: Multiple load balancing algorithms (round-robin, least connections, IP hash)
- **Rate Limiter**: Request throttling and quota management
- **Circuit Breaker**: Fault tolerance and service degradation
- **Middleware Chain**: Pluggable request/response processing pipeline

### Supported Protocols
- HTTP/1.1 and HTTP/2
- WebSocket proxying
- gRPC transcoding (planned)
- Custom protocol handlers

## Installation

### Via PIE
```bash
pie install kislayphp/gateway
```

### Manual Build
```bash
cd kislayphp_gateway/
phpize && ./configure --enable-kislayphp_gateway && make && make install
```

### php.ini Configuration
```ini
extension=kislayphp_gateway.so
```

## API Reference

### KislayPHP\\Gateway\\Gateway Class

The main gateway server class.

#### Constructor
```php
$gateway = new KislayPHP\\Gateway\\Gateway(array $config = []);
```

#### Server Control
```php
$gateway->start(): void
$gateway->stop(): void
$gateway->restart(): void
$gateway->isRunning(): bool
```

#### Route Management
```php
$gateway->addRoute(KislayPHP\\Gateway\\Route $route): bool
$gateway->removeRoute(string $routeId): bool
$gateway->getRoutes(): array
```

#### Middleware Management
```php
$gateway->addMiddleware(KislayPHP\\Gateway\\MiddlewareInterface $middleware): bool
$gateway->removeMiddleware(string $middlewareId): bool
```

### KislayPHP\\Gateway\\Route Class

Route configuration class.

#### Constructor
```php
$route = new KislayPHP\\Gateway\\Route(string $path, array $backends, array $options = []);
```

#### Route Configuration
```php
$route->setMethods(array $methods): Route
$route->setHeaders(array $headers): Route
$route->addBackend(string $backendUrl): Route
$route->setLoadBalancer(KislayPHP\\Gateway\\LoadBalancerInterface $lb): Route
$route->setRateLimit(int $requests, int $window): Route
```

### KislayPHP\\Gateway\\LoadBalancerInterface

Load balancing interface.

```php
interface LoadBalancerInterface {
    public function selectBackend(array $backends, Request $request): string;
    public function reportSuccess(string $backend): void;
    public function reportFailure(string $backend): void;
}
```

### KislayPHP\\Gateway\\MiddlewareInterface

Middleware interface for request processing.

```php
interface MiddlewareInterface {
    public function process(Request $request, Response $response, callable $next): Response;
}
```

## Usage Examples

### Basic Reverse Proxy
```php
<?php
use KislayPHP\\Gateway\\Gateway;
use KislayPHP\\Gateway\\Route;

$gateway = new Gateway([
    'host' => '0.0.0.0',
    'port' => 8080,
    'workers' => 4
]);

// Route API requests to backend service
$apiRoute = new Route('/api/*', [
    'http://api-server-1:3000',
    'http://api-server-2:3000',
    'http://api-server-3:3000'
]);

$gateway->addRoute($apiRoute);

// Route web requests to frontend service
$webRoute = new Route('/*', [
    'http://web-server-1:8080',
    'http://web-server-2:8080'
]);

$gateway->addRoute($webRoute);

// Start the gateway
$gateway->start();
```

### Load Balancing Strategies
```php
<?php
use KislayPHP\\Gateway\\Route;
use KislayPHP\\Gateway\\LoadBalancer\\RoundRobinLoadBalancer;
use KislayPHP\\Gateway\\LoadBalancer\\LeastConnectionsLoadBalancer;
use KislayPHP\\Gateway\\LoadBalancer\\IPHashLoadBalancer;

// Round-robin load balancing
$roundRobinRoute = new Route('/api/v1/*', [
    'http://service-a-1:8080',
    'http://service-a-2:8080',
    'http://service-a-3:8080'
]);
$roundRobinRoute->setLoadBalancer(new RoundRobinLoadBalancer());
$gateway->addRoute($roundRobinRoute);

// Least connections load balancing
$leastConnRoute = new Route('/api/v2/*', [
    'http://service-b-1:8080',
    'http://service-b-2:8080'
]);
$leastConnRoute->setLoadBalancer(new LeastConnectionsLoadBalancer());
$gateway->addRoute($leastConnRoute);

// IP hash load balancing (sticky sessions)
$ipHashRoute = new Route('/session/*', [
    'http://session-service-1:8080',
    'http://session-service-2:8080'
]);
$ipHashRoute->setLoadBalancer(new IPHashLoadBalancer());
$gateway->addRoute($ipHashRoute);
```

### Rate Limiting
```php
<?php
use KislayPHP\\Gateway\\Route;

// API rate limiting - 100 requests per minute per IP
$apiRoute = new Route('/api/*', ['http://api-service:8080']);
$apiRoute->setRateLimit(100, 60); // 100 requests per 60 seconds
$gateway->addRoute($apiRoute);

// Strict rate limiting for auth endpoints
$authRoute = new Route('/auth/*', ['http://auth-service:8080']);
$authRoute->setRateLimit(10, 60); // 10 requests per minute
$gateway->addRoute($authRoute);

// No rate limiting for health checks
$healthRoute = new Route('/health', ['http://health-service:8080']);
$gateway->addRoute($healthRoute);
```

### Circuit Breaker Pattern
```php
<?php
use KislayPHP\\Gateway\\Route;
use KislayPHP\\Gateway\\Middleware\\CircuitBreakerMiddleware;

$circuitBreaker = new CircuitBreakerMiddleware([
    'failure_threshold' => 5,      // Open circuit after 5 failures
    'recovery_timeout' => 60,      // Try to close after 60 seconds
    'success_threshold' => 3       // Close after 3 successful requests
]);

$gateway->addMiddleware($circuitBreaker);

// Route with circuit breaker protection
$protectedRoute = new Route('/api/external/*', [
    'http://unreliable-service:8080'
]);
$gateway->addRoute($protectedRoute);
```

### Custom Middleware
```php
<?php
use KislayPHP\\Gateway\\MiddlewareInterface;
use KislayPHP\\Gateway\\Request;
use KislayPHP\\Gateway\\Response;

class AuthenticationMiddleware implements MiddlewareInterface {
    public function process(Request $request, Response $response, callable $next): Response {
        $authHeader = $request->getHeader('Authorization');

        if (!$authHeader) {
            return $response->withStatus(401)->withBody('Unauthorized');
        }

        // Validate JWT token
        if (!$this->validateToken($authHeader)) {
            return $response->withStatus(403)->withBody('Invalid token');
        }

        // Add user info to request headers
        $request->setHeader('X-User-ID', $this->getUserId($authHeader));

        return $next($request, $response);
    }

    private function validateToken(string $token): bool {
        // JWT validation logic
        return true; // Simplified
    }

    private function getUserId(string $token): string {
        // Extract user ID from token
        return '12345'; // Simplified
    }
}

class LoggingMiddleware implements MiddlewareInterface {
    public function process(Request $request, Response $response, callable $next): Response {
        $start = microtime(true);

        // Log request
        error_log(sprintf(
            '[%s] %s %s',
            date('Y-m-d H:i:s'),
            $request->getMethod(),
            $request->getPath()
        ));

        $response = $next($request, $response);

        $duration = microtime(true) - $start;

        // Log response
        error_log(sprintf(
            '[%s] Response: %d in %.3fs',
            date('Y-m-d H:i:s'),
            $response->getStatusCode(),
            $duration
        ));

        return $response;
    }
}

class CORSHeadersMiddleware implements MiddlewareInterface {
    public function process(Request $request, Response $response, callable $next): Response {
        $response = $next($request, $response);

        // Add CORS headers
        $response->setHeader('Access-Control-Allow-Origin', '*');
        $response->setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        $response->setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

        return $response;
    }
}

// Add middleware to gateway
$gateway->addMiddleware(new AuthenticationMiddleware());
$gateway->addMiddleware(new LoggingMiddleware());
$gateway->addMiddleware(new CORSHeadersMiddleware());
```

### Service Discovery Integration
```php
<?php
use KislayPHP\\Gateway\\Route;
use KislayPHP\\Discovery\\ServiceRegistry;

class ServiceDiscoveryRoute extends Route {
    private $serviceRegistry;
    private $serviceName;

    public function __construct(string $path, string $serviceName, ServiceRegistry $registry) {
        $this->serviceName = $serviceName;
        $this->serviceRegistry = $registry;

        // Get initial backends from service discovery
        $backends = $this->getBackendsFromDiscovery();
        parent::__construct($path, $backends);
    }

    private function getBackendsFromDiscovery(): array {
        $services = $this->serviceRegistry->getServiceInstances($this->serviceName);
        return array_map(function($service) {
            return "http://{$service['host']}:{$service['port']}";
        }, $services);
    }

    public function refreshBackends(): void {
        $newBackends = $this->getBackendsFromDiscovery();
        $this->setBackends($newBackends);
    }
}

// Usage with service discovery
$serviceRegistry = new ServiceRegistry(); // From discovery extension

$apiRoute = new ServiceDiscoveryRoute('/api/*', 'api-service', $serviceRegistry);
$gateway->addRoute($apiRoute);

// Refresh backends periodically
$app->get('/refresh-routes', function($req, $res) use ($apiRoute) {
    $apiRoute->refreshBackends();
    $res->json(['status' => 'routes refreshed']);
});
```

### WebSocket Proxying
```php
<?php
use KislayPHP\\Gateway\\Route;
use KislayPHP\\Gateway\\WebSocketRoute;

class WebSocketProxyRoute extends Route {
    public function __construct(string $path, array $backends) {
        parent::__construct($path, $backends, [
            'protocol' => 'websocket',
            'upgrade_header' => 'websocket'
        ]);
    }

    public function handleWebSocket(Request $request): Response {
        // WebSocket upgrade logic
        $backend = $this->getLoadBalancer()->selectBackend($this->getBackends(), $request);

        // Proxy WebSocket connection to backend
        return $this->proxyWebSocket($request, $backend);
    }

    private function proxyWebSocket(Request $request, string $backend): Response {
        // WebSocket proxying implementation
        // This would handle the WebSocket handshake and bidirectional communication
        return new Response(101, [], 'Switching Protocols');
    }
}

// WebSocket chat service
$chatRoute = new WebSocketProxyRoute('/ws/chat', [
    'ws://chat-service-1:8080',
    'ws://chat-service-2:8080'
]);
$gateway->addRoute($chatRoute);

// Real-time notifications
$notificationRoute = new WebSocketProxyRoute('/ws/notifications', [
    'ws://notification-service:8080'
]);
$gateway->addRoute($notificationRoute);
```

## Advanced Usage

### API Gateway with Microservices
```php
<?php
class MicroserviceGateway {
    private $gateway;
    private $serviceRegistry;

    public function __construct() {
        $this->gateway = new Gateway([
            'host' => '0.0.0.0',
            'port' => 8080,
            'workers' => 8,
            'max_connections' => 10000
        ]);

        $this->serviceRegistry = new ServiceRegistry();
        $this->setupRoutes();
        $this->setupMiddleware();
    }

    private function setupRoutes(): void {
        // User service
        $userRoute = new ServiceDiscoveryRoute('/api/users/*', 'user-service', $this->serviceRegistry);
        $userRoute->setRateLimit(1000, 60);
        $this->gateway->addRoute($userRoute);

        // Order service
        $orderRoute = new ServiceDiscoveryRoute('/api/orders/*', 'order-service', $this->serviceRegistry);
        $orderRoute->setRateLimit(500, 60);
        $this->gateway->addRoute($orderRoute);

        // Payment service (strict rate limiting)
        $paymentRoute = new ServiceDiscoveryRoute('/api/payments/*', 'payment-service', $this->serviceRegistry);
        $paymentRoute->setRateLimit(100, 60);
        $this->gateway->addRoute($paymentRoute);

        // Notification service (WebSocket)
        $notificationRoute = new WebSocketProxyRoute('/ws/notifications', [
            'ws://notification-service-1:8080',
            'ws://notification-service-2:8080'
        ]);
        $this->gateway->addRoute($notificationRoute);

        // Admin service (IP restriction)
        $adminRoute = new Route('/api/admin/*', ['http://admin-service:8080']);
        $adminRoute->setMiddleware(new IPRestrictionMiddleware(['192.168.1.0/24']));
        $this->gateway->addRoute($adminRoute);

        // Health check (no auth required)
        $healthRoute = new Route('/health', ['http://health-service:8080']);
        $this->gateway->addRoute($healthRoute);
    }

    private function setupMiddleware(): void {
        // Global middleware chain
        $this->gateway->addMiddleware(new LoggingMiddleware());
        $this->gateway->addMiddleware(new CORSHeadersMiddleware());
        $this->gateway->addMiddleware(new AuthenticationMiddleware());
        $this->gateway->addMiddleware(new CircuitBreakerMiddleware([
            'failure_threshold' => 10,
            'recovery_timeout' => 30,
            'success_threshold' => 5
        ]));
    }

    public function start(): void {
        $this->gateway->start();
    }

    public function getMetrics(): array {
        return [
            'active_connections' => $this->gateway->getActiveConnections(),
            'total_requests' => $this->gateway->getTotalRequests(),
            'routes' => count($this->gateway->getRoutes()),
            'uptime' => $this->gateway->getUptime()
        ];
    }
}

// Usage
$microserviceGateway = new MicroserviceGateway();
$microserviceGateway->start();

// Metrics endpoint
$app->get('/gateway/metrics', function($req, $res) use ($microserviceGateway) {
    $metrics = $microserviceGateway->getMetrics();
    $res->json($metrics);
});
```

### Custom Load Balancers
```php
<?php
use KislayPHP\\Gateway\\LoadBalancerInterface;
use KislayPHP\\Gateway\\Request;

class WeightedRoundRobinLoadBalancer implements LoadBalancerInterface {
    private $weights = [];
    private $currentWeights = [];
    private $currentIndex = 0;

    public function __construct(array $weights) {
        $this->weights = $weights;
        $this->currentWeights = $weights;
    }

    public function selectBackend(array $backends, Request $request): string {
        if (empty($backends)) {
            throw new Exception('No backends available');
        }

        $totalWeight = array_sum($this->currentWeights);
        if ($totalWeight <= 0) {
            return $backends[array_rand($backends)];
        }

        $randomWeight = rand(1, $totalWeight);

        foreach ($backends as $index => $backend) {
            $randomWeight -= $this->currentWeights[$index];
            if ($randomWeight <= 0) {
                $this->currentWeights[$index] -= 1;
                if ($this->currentWeights[$index] <= 0) {
                    $this->currentWeights[$index] = $this->weights[$index];
                }
                return $backend;
            }
        }

        return $backends[0];
    }

    public function reportSuccess(string $backend): void {
        // Could adjust weights based on success/failure
    }

    public function reportFailure(string $backend): void {
        // Could reduce weight for failed backend
    }
}

class GeoLoadBalancer implements LoadBalancerInterface {
    private $geoMapping = [];

    public function __construct(array $geoMapping) {
        $this->geoMapping = $geoMapping; // ['us-east' => 'backend1', 'eu-west' => 'backend2']
    }

    public function selectBackend(array $backends, Request $request): string {
        $clientIP = $request->getClientIP();
        $region = $this->getRegionFromIP($clientIP);

        if (isset($this->geoMapping[$region])) {
            $preferredBackend = $this->geoMapping[$region];
            if (in_array($preferredBackend, $backends)) {
                return $preferredBackend;
            }
        }

        // Fallback to round-robin
        return $backends[array_rand($backends)];
    }

    private function getRegionFromIP(string $ip): string {
        // GeoIP lookup logic
        // This would use a GeoIP database or service
        return 'us-east'; // Simplified
    }

    public function reportSuccess(string $backend): void {}
    public function reportFailure(string $backend): void {}
}

// Usage
$weightedLB = new WeightedRoundRobinLoadBalancer([
    'http://service-1:8080' => 3,  // 3x weight
    'http://service-2:8080' => 1,  // 1x weight
    'http://service-3:8080' => 2   // 2x weight
]);

$geoLB = new GeoLoadBalancer([
    'us-east' => 'http://us-service:8080',
    'eu-west' => 'http://eu-service:8080',
    'asia' => 'http://asia-service:8080'
]);
```

### Request Transformation Middleware
```php
<?php
class RequestTransformationMiddleware implements MiddlewareInterface {
    private $transformations = [];

    public function addTransformation(string $path, callable $transformer): void {
        $this->transformations[$path] = $transformer;
    }

    public function process(Request $request, Response $response, callable $next): Response {
        $path = $request->getPath();

        foreach ($this->transformations as $pattern => $transformer) {
            if (fnmatch($pattern, $path)) {
                $request = $transformer($request);
                break;
            }
        }

        return $next($request, $response);
    }
}

class ResponseTransformationMiddleware implements MiddlewareInterface {
    private $transformations = [];

    public function addTransformation(string $path, callable $transformer): void {
        $this->transformations[$path] = $transformer;
    }

    public function process(Request $request, Response $response, callable $next): Response {
        $response = $next($request, $response);

        $path = $request->getPath();

        foreach ($this->transformations as $pattern => $transformer) {
            if (fnmatch($pattern, $path)) {
                $response = $transformer($response);
                break;
            }
        }

        return $response;
    }
}

// Usage
$requestTransformer = new RequestTransformationMiddleware();
$responseTransformer = new ResponseTransformationMiddleware();

// Transform legacy API calls
$requestTransformer->addTransformation('/api/v1/*', function($request) {
    // Transform v1 API calls to v2 format
    $path = str_replace('/api/v1/', '/api/v2/', $request->getPath());
    $request->setPath($path);

    // Add version header
    $request->setHeader('X-API-Version', 'v2');

    return $request;
});

// Transform responses for mobile clients
$responseTransformer->addTransformation('/api/mobile/*', function($response) {
    // Compress response for mobile
    $body = $response->getBody();
    $compressed = gzcompress($body);
    $response->setBody($compressed);
    $response->setHeader('Content-Encoding', 'gzip');

    return $response;
});

$gateway->addMiddleware($requestTransformer);
$gateway->addMiddleware($responseTransformer);
```

### Health Checks and Service Discovery
```php
<?php
class HealthCheckService {
    private $serviceRegistry;
    private $healthChecks = [];

    public function __construct(ServiceRegistry $serviceRegistry) {
        $this->serviceRegistry = $serviceRegistry;
    }

    public function addHealthCheck(string $serviceName, callable $check): void {
        $this->healthChecks[$serviceName] = $check;
    }

    public function performHealthChecks(): array {
        $results = [];

        foreach ($this->healthChecks as $serviceName => $check) {
            try {
                $healthy = $check();
                $results[$serviceName] = $healthy;

                // Update service registry
                if ($healthy) {
                    $this->serviceRegistry->registerService($serviceName, /* service info */);
                } else {
                    $this->serviceRegistry->deregisterService($serviceName);
                }
            } catch (Exception $e) {
                $results[$serviceName] = false;
                error_log("Health check failed for {$serviceName}: " . $e->getMessage());
            }
        }

        return $results;
    }

    public function getHealthyServices(string $serviceName): array {
        return $this->serviceRegistry->getHealthyInstances($serviceName);
    }
}

class HTTPHealthCheck {
    private $httpClient;

    public function __construct() {
        $this->httpClient = new GuzzleHttp\\Client(['timeout' => 5]);
    }

    public function check(string $url): bool {
        try {
            $response = $this->httpClient->get($url . '/health');
            return $response->getStatusCode() === 200;
        } catch (Exception $e) {
            return false;
        }
    }
}

// Usage
$healthCheckService = new HealthCheckService($serviceRegistry);
$httpHealthCheck = new HTTPHealthCheck();

// Add health checks for services
$healthCheckService->addHealthCheck('user-service', function() use ($httpHealthCheck) {
    return $httpHealthCheck->check('http://user-service-1:8080');
});

$healthCheckService->addHealthCheck('order-service', function() use ($httpHealthCheck) {
    return $httpHealthCheck->check('http://order-service-1:8080');
});

// Perform health checks periodically
$app->get('/health-check', function($req, $res) use ($healthCheckService) {
    $results = $healthCheckService->performHealthChecks();
    $res->json($results);
});

// Get healthy backends for routing
$healthyUserServices = $healthCheckService->getHealthyServices('user-service');
$userRoute = new Route('/api/users/*', $healthyUserServices);
$gateway->addRoute($userRoute);
```

## Integration Examples

### Kubernetes Ingress Integration
```php
<?php
class KubernetesGateway extends Gateway {
    private $kubeClient;

    public function __construct(array $config = []) {
        parent::__construct($config);
        $this->kubeClient = new KubernetesClient();
        $this->setupFromIngress();
    }

    private function setupFromIngress(): void {
        $ingresses = $this->kubeClient->getIngresses();

        foreach ($ingresses as $ingress) {
            $routes = $this->convertIngressToRoutes($ingress);
            foreach ($routes as $route) {
                $this->addRoute($route);
            }
        }
    }

    private function convertIngressToRoutes(array $ingress): array {
        $routes = [];

        foreach ($ingress['rules'] as $rule) {
            foreach ($rule['http']['paths'] as $path) {
                $backends = $this->getServiceEndpoints($path['backend']['service']['name']);

                $route = new Route($path['path'], $backends, [
                    'host' => $rule['host'],
                    'path_type' => $path['pathType']
                ]);

                $routes[] = $route;
            }
        }

        return $routes;
    }

    private function getServiceEndpoints(string $serviceName): array {
        $endpoints = $this->kubeClient->getEndpoints($serviceName);
        return array_map(function($endpoint) {
            return "http://{$endpoint['ip']}:{$endpoint['port']}";
        }, $endpoints['subsets'][0]['addresses'] ?? []);
    }

    public function watchIngressChanges(): void {
        $this->kubeClient->watchIngresses(function($event) {
            if ($event['type'] === 'MODIFIED' || $event['type'] === 'ADDED') {
                $this->updateRoutesFromIngress($event['object']);
            } elseif ($event['type'] === 'DELETED') {
                $this->removeRoutesFromIngress($event['object']);
            }
        });
    }
}

// Usage
$kubeGateway = new KubernetesGateway([
    'host' => '0.0.0.0',
    'port' => 80
]);

// Watch for Ingress changes
$kubeGateway->watchIngressChanges();
$kubeGateway->start();
```

### AWS API Gateway Integration
```php
<?php
class AWSGateway extends Gateway {
    private $apiGatewayClient;

    public function __construct(array $config = []) {
        parent::__construct($config);
        $this->apiGatewayClient = new Aws\\ApiGateway\\ApiGatewayClient([
            'version' => '2015-07-09',
            'region' => getenv('AWS_REGION'),
            'credentials' => [
                'key' => getenv('AWS_ACCESS_KEY_ID'),
                'secret' => getenv('AWS_SECRET_ACCESS_KEY')
            ]
        ]);

        $this->setupFromAPIGateway();
    }

    private function setupFromAPIGateway(): void {
        $apis = $this->apiGatewayClient->getRestApis();

        foreach ($apis['items'] as $api) {
            $resources = $this->apiGatewayClient->getResources([
                'restApiId' => $api['id']
            ]);

            foreach ($resources['items'] as $resource) {
                if (isset($resource['resourceMethods'])) {
                    $route = $this->convertResourceToRoute($api['id'], $resource);
                    if ($route) {
                        $this->addRoute($route);
                    }
                }
            }
        }
    }

    private function convertResourceToRoute(string $apiId, array $resource): ?Route {
        // Get integration details
        $integration = $this->apiGatewayClient->getIntegration([
            'restApiId' => $apiId,
            'resourceId' => $resource['id'],
            'httpMethod' => 'GET' // Primary method
        ]);

        if (!isset($integration['uri'])) {
            return null;
        }

        // Extract backend URL from integration URI
        $backendUrl = $this->extractBackendUrl($integration['uri']);

        return new Route($resource['path'], [$backendUrl], [
            'methods' => array_keys($resource['resourceMethods']),
            'api_id' => $apiId,
            'resource_id' => $resource['id']
        ]);
    }

    private function extractBackendUrl(string $uri): string {
        // Extract URL from AWS integration URI format
        // Format: arn:aws:apigateway:region:lambda:path/2015-03-31/functions/...
        if (preg_match('/functions\/([^\/]+)\//', $uri, $matches)) {
            return "https://{$matches[1]}.execute-api.{$this->region}.amazonaws.com/prod";
        }

        // For HTTP integrations
        if (preg_match('/https?:\/\/[^\/]+/', $uri, $matches)) {
            return $matches[0];
        }

        return $uri;
    }
}

// Usage
$awsGateway = new AWSGateway([
    'host' => '0.0.0.0',
    'port' => 443,
    'ssl_cert' => '/path/to/ssl/cert.pem',
    'ssl_key' => '/path/to/ssl/private.key'
]);

$awsGateway->start();
```

## Testing

### Unit Testing
```php
<?php
use PHPUnit\\Framework\\TestCase;
use KislayPHP\\Gateway\\Route;
use KislayPHP\\Gateway\\LoadBalancer\\RoundRobinLoadBalancer;

class GatewayTest extends TestCase {
    public function testRouteCreation() {
        $route = new Route('/api/*', ['http://backend1:8080', 'http://backend2:8080']);

        $this->assertEquals('/api/*', $route->getPath());
        $this->assertCount(2, $route->getBackends());
    }

    public function testLoadBalancerSelection() {
        $backends = ['http://backend1:8080', 'http://backend2:8080'];
        $lb = new RoundRobinLoadBalancer();

        $request = $this->createMock(Request::class);

        $selected1 = $lb->selectBackend($backends, $request);
        $selected2 = $lb->selectBackend($backends, $request);

        $this->assertContains($selected1, $backends);
        $this->assertContains($selected2, $backends);
        $this->assertNotEquals($selected1, $selected2);
    }

    public function testMiddlewareChain() {
        $middleware1 = $this->createMock(MiddlewareInterface::class);
        $middleware2 = $this->createMock(MiddlewareInterface::class);

        $middleware1->expects($this->once())
            ->method('process')
            ->willReturnCallback(function($req, $res, $next) {
                return $next($req, $res);
            });

        $middleware2->expects($this->once())
            ->method('process')
            ->willReturnCallback(function($req, $res, $next) {
                $res->setHeader('X-Test', 'processed');
                return $res;
            });

        $gateway = new Gateway();
        $gateway->addMiddleware($middleware1);
        $gateway->addMiddleware($middleware2);

        $request = new Request('GET', '/test');
        $response = new Response();

        $result = $gateway->processRequest($request, $response);

        $this->assertEquals('processed', $result->getHeader('X-Test'));
    }
}
```

### Integration Testing
```php
<?php
class GatewayIntegrationTest extends PHPUnit\\Framework\\TestCase {
    private static $gateway;
    private static $backendServer;

    public static function setUpBeforeClass(): void {
        // Start mock backend server
        self::$backendServer = self::startMockBackend();

        // Start gateway
        self::$gateway = new Gateway([
            'host' => '127.0.0.1',
            'port' => 8081
        ]);

        $route = new Route('/api/*', ['http://127.0.0.1:8082']);
        self::$gateway->addRoute($route);

        self::$gateway->start();
        sleep(1); // Allow server to start
    }

    private static function startMockBackend() {
        $server = proc_open(
            'php -S 127.0.0.1:8082 -t ' . __DIR__ . '/fixtures/backend',
            [],
            $pipes
        );
        sleep(1);
        return $server;
    }

    public static function tearDownAfterClass(): void {
        if (self::$gateway) {
            self::$gateway->stop();
        }
        if (self::$backendServer) {
            proc_terminate(self::$backendServer);
            proc_close(self::$backendServer);
        }
    }

    public function testGatewayProxy() {
        $httpClient = new GuzzleHttp\\Client();

        // Test proxy request
        $response = $httpClient->get('http://127.0.0.1:8081/api/test');

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('Hello from backend', (string)$response->getBody());
    }

    public function testLoadBalancing() {
        $httpClient = new GuzzleHttp\\Client();

        // Make multiple requests to test load balancing
        $responses = [];
        for ($i = 0; $i < 10; $i++) {
            $response = $httpClient->get('http://127.0.0.1:8081/api/balance');
            $responses[] = (string)$response->getBody();
        }

        // Should see responses from different backends
        $uniqueResponses = array_unique($responses);
        $this->assertGreaterThan(1, count($uniqueResponses));
    }

    public function testRateLimiting() {
        $httpClient = new GuzzleHttp\\Client();

        // Make requests up to the limit
        for ($i = 0; $i < 100; $i++) {
            try {
                $httpClient->get('http://127.0.0.1:8081/api/limited');
            } catch (GuzzleHttp\\Exception\\ClientException $e) {
                if ($e->getResponse()->getStatusCode() === 429) {
                    // Rate limit exceeded
                    $this->assertGreaterThanOrEqual(100, $i);
                    return;
                }
                throw $e;
            }
        }

        $this->fail('Rate limiting did not trigger');
    }
}
```

## Troubleshooting

### Common Issues

#### Gateway Not Starting
**Symptoms:** Gateway fails to start or crashes immediately

**Solutions:**
1. Check port availability: `netstat -tlnp | grep :8080`
2. Verify configuration syntax
3. Check file permissions for SSL certificates
4. Review error logs for specific error messages

#### Backend Connection Failures
**Symptoms:** 502 Bad Gateway errors

**Solutions:**
1. Verify backend service availability
2. Check network connectivity between gateway and backends
3. Validate backend URLs and ports
4. Review backend health check configurations

#### High Latency
**Symptoms:** Slow response times through gateway

**Solutions:**
1. Enable connection pooling
2. Implement response caching
3. Optimize middleware chain
4. Use appropriate load balancing strategy

### Performance Tuning

#### Connection Pooling
```php
<?php
class ConnectionPoolMiddleware implements MiddlewareInterface {
    private $pools = [];
    private $maxConnections = 100;

    public function process(Request $request, Response $response, callable $next): Response {
        $backend = $this->getBackendForRequest($request);

        if (!isset($this->pools[$backend])) {
            $this->pools[$backend] = new ConnectionPool($backend, $this->maxConnections);
        }

        $connection = $this->pools[$backend]->getConnection();
        $request->setContext('connection', $connection);

        try {
            $response = $next($request, $response);
            $this->pools[$backend]->returnConnection($connection);
            return $response;
        } catch (Exception $e) {
            $this->pools[$backend]->invalidateConnection($connection);
            throw $e;
        }
    }

    private function getBackendForRequest(Request $request): string {
        // Determine backend based on routing logic
        return 'http://backend-service:8080';
    }
}
```

#### Monitoring and Metrics
```php
<?php
class GatewayMetricsCollector {
    private $metrics;

    public function __construct(Metrics $metrics) {
        $this->metrics = $metrics;
    }

    public function collectRequestMetrics(Request $request, Response $response, float $duration): void {
        // Request count by method
        $this->metrics->increment("gateway_requests_method_{$request->getMethod()}_total");

        // Response status codes
        $status = $response->getStatusCode();
        $this->metrics->increment("gateway_responses_status_{$status}_total");

        // Request duration
        $this->metrics->histogram('gateway_request_duration_seconds', $duration);

        // Request size
        $requestSize = strlen($request->getBody());
        $this->metrics->histogram('gateway_request_size_bytes', $requestSize);

        // Response size
        $responseSize = strlen($response->getBody());
        $this->metrics->histogram('gateway_response_size_bytes', $responseSize);
    }

    public function collectBackendMetrics(string $backend, bool $success, float $duration): void {
        $backendName = $this->sanitizeBackendName($backend);

        if ($success) {
            $this->metrics->increment("gateway_backend_{$backendName}_success_total");
        } else {
            $this->metrics->increment("gateway_backend_{$backendName}_failure_total");
        }

        $this->metrics->histogram("gateway_backend_{$backendName}_duration_seconds", $duration);
    }

    private function sanitizeBackendName(string $backend): string {
        return preg_replace('/[^a-zA-Z0-9_]/', '_', $backend);
    }
}

// Usage in middleware
class MetricsMiddleware implements MiddlewareInterface {
    private $metricsCollector;

    public function __construct(GatewayMetricsCollector $collector) {
        $this->metricsCollector = $collector;
    }

    public function process(Request $request, Response $response, callable $next): Response {
        $start = microtime(true);

        $response = $next($request, $response);

        $duration = microtime(true) - $start;
        $this->metricsCollector->collectRequestMetrics($request, $response, $duration);

        // Collect backend metrics if available
        $backend = $request->getContext('backend');
        if ($backend) {
            $backendSuccess = $response->getStatusCode() < 500;
            $this->metricsCollector->collectBackendMetrics($backend, $backendSuccess, $duration);
        }

        return $response;
    }
}
```

## Best Practices

### Gateway Architecture
1. **Separation of Concerns**: Keep routing, load balancing, and middleware separate
2. **Stateless Design**: Avoid storing state in the gateway when possible
3. **Horizontal Scaling**: Design for multiple gateway instances
4. **Security First**: Implement authentication and authorization at the gateway level

### Performance Optimization
1. **Connection Reuse**: Use persistent connections to backends
2. **Response Caching**: Cache frequently accessed responses
3. **Request Batching**: Batch similar requests when possible
4. **Async Processing**: Use non-blocking I/O for high concurrency

### Security Considerations
1. **Input Validation**: Validate all incoming requests
2. **Rate Limiting**: Protect against abuse and DoS attacks
3. **Authentication**: Implement proper auth mechanisms
4. **Encryption**: Use HTTPS/TLS for all communications

### Monitoring and Observability
1. **Request Tracing**: Implement distributed tracing
2. **Health Checks**: Monitor backend service health
3. **Metrics Collection**: Track performance and error metrics
4. **Log Aggregation**: Centralize logs for analysis

This comprehensive documentation covers all aspects of the KislayPHP Gateway extension, from basic reverse proxy functionality to advanced microservices gateway patterns and production deployment strategies.