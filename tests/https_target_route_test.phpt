--TEST--
Kislay Gateway accepts HTTPS upstream targets for remote services
--EXTENSIONS--
kislayphp_gateway
--FILE--
<?php
putenv('KISLAY_GATEWAY_THREADS=1');

$gateway = new Kislay\Gateway\Gateway();
var_dump($gateway->addRoute('GET', '/api/*', 'https://remote.example.com/v1'));

$routes = $gateway->routes();
var_dump($routes[0]['method']);
var_dump($routes[0]['path']);
var_dump($routes[0]['target']);
?>
--EXPECT--
bool(true)
string(3) "GET"
string(6) "/api/*"
string(29) "https://remote.example.com/v1"
