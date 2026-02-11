<?php
function require_extension($name) {
    if (!extension_loaded($name)) {
        fwrite(STDERR, "Missing extension: {$name}\n");
        exit(1);
    }
}

require_extension('kislayphp_gateway');

if (!function_exists('pcntl_fork') || !function_exists('posix_kill')) {
    fwrite(STDERR, "pcntl/posix not available; run manually in two terminals.\n");
    exit(0);
}

$upstream_dir = sys_get_temp_dir() . '/kislay_gateway_test_' . uniqid();
if (!mkdir($upstream_dir, 0700, true)) {
    fwrite(STDERR, "Failed to create temp dir.\n");
    exit(1);
}
file_put_contents($upstream_dir . '/index.php', "<?php echo 'OK';\n");

$upstream_port = 19001;
$gateway_port = 19002;

$descriptor = [
    0 => ['pipe', 'r'],
    1 => ['pipe', 'w'],
    2 => ['pipe', 'w'],
];
$cmd = sprintf('php -S 127.0.0.1:%d -t %s', $upstream_port, escapeshellarg($upstream_dir));
$process = proc_open($cmd, $descriptor, $pipes);
if (!is_resource($process)) {
    fwrite(STDERR, "Failed to start upstream server.\n");
    exit(1);
}

putenv('KISLAY_GATEWAY_MAX_BODY=5');

$pid = pcntl_fork();
if ($pid === -1) {
    fwrite(STDERR, "Failed to fork.\n");
    proc_terminate($process);
    proc_close($process);
    exit(1);
}

if ($pid === 0) {
    $gateway = new KislayPHP\Gateway\Gateway();
    $gateway->addRoute('POST', '/echo', 'http://127.0.0.1:19001');
    $gateway->listen('127.0.0.1', $gateway_port);
    exit(0);
}

usleep(300000);

$fp = fsockopen('127.0.0.1', $gateway_port, $errno, $errstr, 2.0);
if (!$fp) {
    fwrite(STDERR, "Failed to connect: {$errstr}\n");
    posix_kill($pid, SIGTERM);
    pcntl_waitpid($pid, $status);
    proc_terminate($process);
    proc_close($process);
    exit(1);
}

$body = str_repeat('A', 10);
$request = "POST /echo HTTP/1.1\r\nHost: 127.0.0.1:{$gateway_port}\r\nContent-Length: 10\r\nConnection: close\r\n\r\n{$body}";
fwrite($fp, $request);
$response = stream_get_contents($fp);
fclose($fp);

$ok = false;
if ($response !== false && $response !== '') {
    $first_line = strtok($response, "\r\n");
    if ($first_line !== false && strpos($first_line, '413') !== false) {
        $ok = true;
    }
}

posix_kill($pid, SIGTERM);
pcntl_waitpid($pid, $status);
proc_terminate($process);
proc_close($process);
@unlink($upstream_dir . '/index.php');
@rmdir($upstream_dir);

if (!$ok) {
    fwrite(STDERR, "Unexpected response:\n{$response}\n");
    exit(1);
}

fwrite(STDOUT, "OK\n");
