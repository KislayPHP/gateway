--TEST--
Kislay Gateway registerService publishes native service targets
--EXTENSIONS--
kislayphp_gateway
--FILE--
<?php
putenv('KISLAY_GATEWAY_THREADS=1');

$gateway = new Kislay\Gateway\Gateway();
var_dump($gateway->addServiceRoute('GET', '/api/users', 'user-service'));
var_dump($gateway->registerService('user-service', [
    'http://127.0.0.1:9001',
    'http://127.0.0.1:9002',
]));

$routes = $gateway->routes();
var_dump($routes[0]['method']);
var_dump($routes[0]['path']);
var_dump($routes[0]['service']);
?>
--EXPECT--
bool(true)
bool(true)
string(3) "GET"
string(10) "/api/users"
string(12) "user-service"
