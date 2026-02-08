<?php
// Run from this folder with:
// php -d extension=modules/kislayphp_gateway.so example.php

extension_loaded('kislayphp_gateway') or die('kislayphp_gateway not loaded');

$gateway = new KislayPHP\Gateway\Gateway();
$gateway->addRoute('GET', '/users', 'http://127.0.0.1:9001');
$gateway->addRoute('POST', '/orders', 'http://127.0.0.1:9002');
$gateway->listen('0.0.0.0', 8081);
print_r($gateway->routes());

sleep(60);
