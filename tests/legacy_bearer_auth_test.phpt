--TEST--
Kislay Gateway legacy bearer-token auth accepts the correct token and rejects wrong tokens, including same-length and shorter/longer near-misses
--EXTENSIONS--
kislayphp_gateway
--SKIPIF--
<?php if (!extension_loaded('curl')) die('skip curl required'); ?>
--FILE--
<?php
putenv('KISLAY_GATEWAY_THREADS=1');
putenv('KISLAY_GATEWAY_AUTH_TOKEN=s3cret-token-value');

function free_port(): int {
    $sock = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
    $name = stream_socket_get_name($sock, false);
    fclose($sock);
    return (int)substr($name, strrpos($name, ':') + 1);
}

function wait_port(string $host, int $port, float $timeout): bool {
    $deadline = microtime(true) + $timeout;
    while (microtime(true) < $deadline) {
        $conn = @fsockopen($host, $port, $errno, $errstr, 0.2);
        if ($conn !== false) { fclose($conn); return true; }
        usleep(50000);
    }
    return false;
}

$upstreamPort = free_port();
$upstream = proc_open(
    [PHP_BINARY, __DIR__ . '/servers/whoami_upstream.php', (string)$upstreamPort],
    [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
    $pipes
);
if (!wait_port('127.0.0.1', $upstreamPort, 5.0)) {
    echo "FAIL upstream did not start\n";
    exit(1);
}

// requireAuth() with an empty JWT secret routes to the legacy bearer-token
// path (gateway->jwt_secret.empty()), which reads the actual token from
// KISLAY_GATEWAY_AUTH_TOKEN.
$gw = new Kislay\Gateway\Gateway();
$gw->requireAuth('');
$gw->addRoute('GET', '/api/whoami', "http://127.0.0.1:$upstreamPort/");
$gwPort = free_port();
$gw->listen('127.0.0.1', $gwPort);
usleep(500000);

function fetch_with_bearer(string $base, ?string $token): int {
    $ch = curl_init("$base/api/whoami");
    $headers = $token === null ? [] : ["Authorization: Bearer $token"];
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_TIMEOUT => 5,
    ]);
    curl_exec($ch);
    return (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
}

$base = "http://127.0.0.1:$gwPort";

echo "correct token: " . fetch_with_bearer($base, 's3cret-token-value') . "\n";
echo "wrong token, same length: " . fetch_with_bearer($base, 'x3cret-token-value') . "\n";
echo "wrong token, shorter: " . fetch_with_bearer($base, 's3cret-token') . "\n";
echo "wrong token, longer: " . fetch_with_bearer($base, 's3cret-token-value-extra') . "\n";
echo "no token: " . fetch_with_bearer($base, null) . "\n";

proc_terminate($upstream, 9);
proc_close($upstream);
?>
--EXPECT--
correct token: 200
wrong token, same length: 401
wrong token, shorter: 401
wrong token, longer: 401
no token: 401
