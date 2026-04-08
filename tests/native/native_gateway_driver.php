<?php

$upstreamPort = (int) (getenv('KISLAY_NATIVE_TEST_UPSTREAM_PORT') ?: 19091);
$gatewayPort = (int) (getenv('KISLAY_NATIVE_TEST_GATEWAY_PORT') ?: 19090);
$mode = getenv('KISLAY_NATIVE_TEST_MODE') ?: 'direct';
$threads = getenv('KISLAY_NATIVE_TEST_THREADS');

$gateway = new Kislay\Gateway\Gateway();
if ($threads !== false && $threads !== '') {
    $gateway->setThreads((int) $threads);
}

$base = "http://127.0.0.1:" . $upstreamPort;
$gateway->addRoute('GET', '/direct', $base);
$gateway->addRoute('GET', '/slow', $base);

if ($mode === 'service') {
    $gateway->addServiceRoute('GET', '/service', 'native-service');
    $gateway->registerService('native-service', [$base]);
}

$gateway->listen('127.0.0.1', $gatewayPort);
while (true) {
    sleep(1);
}
