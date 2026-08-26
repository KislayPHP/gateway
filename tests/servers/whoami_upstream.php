<?php
$port = (int)$argv[1];
$server = stream_socket_server("tcp://127.0.0.1:$port", $errno, $errstr);
if (!$server) { fwrite(STDERR, "bind failed: $errstr\n"); exit(1); }
while (true) {
    $conn = @stream_socket_accept($server, -1);
    if ($conn === false) continue;
    stream_set_timeout($conn, 5);
    $headers = '';
    while (!feof($conn)) {
        $line = fgets($conn);
        if ($line === false) break;
        $headers .= $line;
        if (rtrim($line) === '') break;
    }
    $user = 'null';
    $roles = 'null';
    if (preg_match('/^X-Authenticated-User:\s*(.+)\r?$/mi', $headers, $m)) {
        $user = json_encode(trim($m[1]));
    }
    if (preg_match('/^X-Auth-Roles:\s*(.+)\r?$/mi', $headers, $m)) {
        $roles = json_encode(trim($m[1]));
    }
    $body = '{"user":' . $user . ',"roles":' . $roles . '}';
    $resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " . strlen($body) . "\r\nConnection: close\r\n\r\n" . $body;
    fwrite($conn, $resp);
    fclose($conn);
}
