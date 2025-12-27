<?php

declare(strict_types=1);

// Minimal JSON-RPC proxy used by the blackcat-testing harness.
//
// Purpose:
// - provide a localhost HTTP endpoint (allowed by blackcat-config strict RPC rules)
// - forward requests to a real HTTPS endpoint
// - optionally flip results after a time threshold to simulate Byzantine RPC behavior
//
// This is NOT intended to be used in production.

$upstream = getenv('BLACKCAT_TESTING_RPC_PROXY_UPSTREAM') ?: '';
$startedAt = (int) (getenv('BLACKCAT_TESTING_RPC_PROXY_STARTED_AT') ?: '0');
$sabotageAfter = (int) (getenv('BLACKCAT_TESTING_RPC_PROXY_SABOTAGE_AFTER_SEC') ?: '0');

if ($upstream === '' || strpos($upstream, "\0") !== false) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "rpc proxy misconfigured (missing upstream)\n";
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(405);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Method Not Allowed\n";
    exit;
}

$body = file_get_contents('php://input');
if (!is_string($body) || $body === '') {
    http_response_code(400);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Bad Request\n";
    exit;
}

try {
    /** @var mixed $req */
    $req = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
} catch (\JsonException) {
    http_response_code(400);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Bad JSON\n";
    exit;
}

$method = is_array($req) && isset($req['method']) && is_string($req['method']) ? $req['method'] : null;

$ctx = stream_context_create([
    'http' => [
        'method' => 'POST',
        'header' => "Content-Type: application/json\r\nAccept: application/json\r\n",
        'content' => $body,
        'timeout' => 5,
    ],
]);

$respRaw = @file_get_contents($upstream, false, $ctx);
if (!is_string($respRaw) || $respRaw === '') {
    http_response_code(502);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Upstream error\n";
    exit;
}

$now = time();
$sabotage = $sabotageAfter > 0 && $startedAt > 0 && ($now - $startedAt) >= $sabotageAfter;

if ($sabotage && $method !== null && $method !== 'eth_chainId') {
    try {
        /** @var mixed $resp */
        $resp = json_decode($respRaw, true, 512, JSON_THROW_ON_ERROR);
        if (is_array($resp) && isset($resp['result']) && is_string($resp['result']) && str_starts_with($resp['result'], '0x') && strlen($resp['result']) > 3) {
            $r = strtolower($resp['result']);
            $last = substr($r, -1);
            $flip = $last === '0' ? '1' : '0';
            $resp['result'] = substr($r, 0, -1) . $flip;
            $respRaw = json_encode($resp, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        }
    } catch (\Throwable) {
        // If parsing fails, leave response as-is.
    }
}

header('Content-Type: application/json; charset=utf-8');
echo $respRaw;

