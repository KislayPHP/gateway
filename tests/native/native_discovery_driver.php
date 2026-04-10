<?php

$upstreamPort = (int) (getenv('KISLAY_NATIVE_TEST_UPSTREAM_PORT') ?: 19291);
$gatewayPort = (int) (getenv('KISLAY_NATIVE_TEST_GATEWAY_PORT') ?: 19290);
$threads = getenv('KISLAY_NATIVE_TEST_THREADS');
$discoveryPath = getenv('KISLAY_NATIVE_TEST_DISCOVERY_PATH') ?: '/tmp/kislay_native_discovery.txt';
$pollMs = (int) (getenv('KISLAY_NATIVE_TEST_DISCOVERY_POLL_MS') ?: 100);

$gateway = new Kislay\Gateway\Gateway();
if ($threads !== false && $threads !== '') {
    $gateway->setThreads((int) $threads);
}

$gateway->addServiceRoute('GET', '/service', 'native-service');
$gateway->registerService('native-service', ["http://127.0.0.1:" . $upstreamPort]);
$gateway->setDiscoveryBackend([
    'backend' => 'file',
    'path' => $discoveryPath,
    'poll_ms' => $pollMs,
]);

$gateway->listen('127.0.0.1', $gatewayPort);
while (true) {
    sleep(1);
}
