# KislayPHP Gateway

KislayPHP Gateway is a minimal reverse proxy extension for routing HTTP traffic to upstream microservices.

## Key Features

- Route table for method and path matching.
- HTTP proxying to upstream hosts.
- Simple configuration for local or dev gateways.

## Use Cases

- Local API gateway for multiple services.
- Simple reverse proxy during development.
- Lightweight routing layer for prototypes.

## SEO Keywords

PHP API gateway, reverse proxy, HTTP routing, upstream routing, C++ PHP extension, microservices

## Repository

- https://github.com/KislayPHP/gateway

## Related Modules

- https://github.com/KislayPHP/core
- https://github.com/KislayPHP/eventbus
- https://github.com/KislayPHP/discovery
- https://github.com/KislayPHP/config
- https://github.com/KislayPHP/metrics
- https://github.com/KislayPHP/queue

## Build

```sh
phpize
./configure --enable-kislayphp_gateway
make
```

## Run Locally

```sh
cd /path/to/gateway
php -d extension=modules/kislayphp_gateway.so example.php
```

## Example

```php
<?php
extension_loaded('kislayphp_gateway') or die('kislayphp_gateway not loaded');

$gateway = new KislayPHP\Gateway\Gateway();
$gateway->addRoute('GET', '/users', 'http://127.0.0.1:9001');
$gateway->addRoute('POST', '/orders', 'http://127.0.0.1:9002');
$gateway->listen('0.0.0.0', 8081);
print_r($gateway->routes());

// Keep the process alive in CLI usage.
sleep(60);
?>
```
