--TEST--
Kislay Gateway JWT sub/roles extraction is not confused by decoy substrings elsewhere in the payload
--EXTENSIONS--
kislayphp_gateway
--SKIPIF--
<?php if (!extension_loaded('openssl')) die('skip openssl required'); ?>
--FILE--
<?php
putenv('KISLAY_GATEWAY_THREADS=1');

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

function b64url(string $bin): string {
    return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
}

function make_jwt(string $payloadJson, string $secret): string {
    $header = b64url('{"alg":"HS256","typ":"JWT"}');
    $payload = b64url($payloadJson);
    $signingInput = "$header.$payload";
    $sig = b64url(hash_hmac('sha256', $signingInput, $secret, true));
    return "$signingInput.$sig";
}

$secret = 'test-secret-key-for-jwt-claims';

// Raw-socket upstream (deliberately not php -S: its HTTP/1.1 keep-alive
// behavior doesn't play nicely with the gateway's upstream connection pool
// in a short-lived test). Echoes back the auth headers the gateway forwarded
// as JSON, then closes.
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

$gw = new Kislay\Gateway\Gateway();
$gw->requireAuth($secret);
$gw->addRoute('GET', '/api/whoami', "http://127.0.0.1:$upstreamPort/");
$gwPort = free_port();
$gw->listen('127.0.0.1', $gwPort);
usleep(500000); // let civetweb finish binding

function fetch_with_jwt(string $base, string $jwt): array {
    $ch = curl_init("$base/api/whoami");
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ["Authorization: Bearer $jwt"],
        CURLOPT_TIMEOUT => 5,
    ]);
    $body = curl_exec($ch);
    return json_decode($body ?: '{}', true) ?: [];
}

$base = "http://127.0.0.1:$gwPort";
$exp = time() + 3600;

// Decoy: payload has NO real top-level "sub" claim, but a string value that
// happens to contain the literal text "sub", immediately followed (in the
// raw JSON bytes) by a field whose value must NOT leak into sub_out. A
// naive string search that just does find("\"sub\"") then "the next colon
// after that" finds the "description" value's embedded "sub" text and then
// misreads "other"'s value as if it were the sub claim.
$decoyPayload = json_encode(['exp' => $exp, 'description' => 'sub', 'other' => 'SHOULD-NOT-LEAK']);
$decoyResult = fetch_with_jwt($base, make_jwt($decoyPayload, $secret));

// Real claim, for a positive-path sanity check.
$realPayload = json_encode(['exp' => $exp, 'sub' => 'alice', 'roles' => ['admin', 'ops']]);
$realResult = fetch_with_jwt($base, make_jwt($realPayload, $secret));

proc_terminate($upstream, 9);
proc_close($upstream);

var_dump($decoyResult['user'] ?? null);
var_dump($realResult['user'] ?? null);
var_dump($realResult['roles'] ?? null);
?>
--EXPECT--
NULL
string(5) "alice"
string(9) "admin,ops"
