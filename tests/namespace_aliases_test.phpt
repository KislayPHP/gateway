--TEST--
Kislay Gateway namespace aliases are available
--EXTENSIONS--
kislayphp_gateway
--FILE--
<?php
putenv('KISLAY_GATEWAY_THREADS=1');

var_dump(class_exists('Kislay\\Gateway\\Gateway'));
var_dump(class_exists('KislayPHP\\Gateway\\Gateway'));

$gateway = new Kislay\Gateway\Gateway();
var_dump($gateway instanceof KislayPHP\Gateway\Gateway);
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
