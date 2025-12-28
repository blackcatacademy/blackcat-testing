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

$upstream = trim((string) $upstream);
if ($upstream === '' || str_contains($upstream, "\0")) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "rpc proxy misconfigured (missing upstream)\n";
    exit;
}

$u = parse_url($upstream);
if (!is_array($u) || !isset($u['scheme']) || !is_string($u['scheme'])) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "rpc proxy misconfigured (invalid upstream url)\n";
    exit;
}

$scheme = strtolower($u['scheme']);
if ($scheme !== 'https') {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "rpc proxy misconfigured (upstream must be https)\n";
    exit;
}

if (isset($u['user']) || isset($u['pass'])) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "rpc proxy misconfigured (credentials in url are not allowed)\n";
    exit;
}

$host = isset($u['host']) && is_string($u['host']) ? $u['host'] : '';
if ($host === '' || str_contains($host, "\0")) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "rpc proxy misconfigured (missing upstream host)\n";
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(405);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Method Not Allowed\n";
    exit;
}

$in = fopen('php://input', 'rb');
if (!is_resource($in)) {
    http_response_code(400);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Bad Request\n";
    exit;
}

$maxReqBytes = 64 * 1024;
$body = stream_get_contents($in, $maxReqBytes + 1);
if (!is_string($body) || $body === '') {
    http_response_code(400);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Bad Request\n";
    exit;
}
if (strlen($body) > $maxReqBytes) {
    http_response_code(413);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Request Too Large\n";
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
if ($method === null || !in_array($method, ['eth_chainId', 'eth_call', 'eth_getCode'], true)) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Forbidden\n";
    exit;
}

$ctx = stream_context_create([
    'http' => [
        'method' => 'POST',
        'header' => "Content-Type: application/json\r\nAccept: application/json\r\n",
        'content' => $body,
        'timeout' => 5,
        'follow_location' => 0,
        'max_redirects' => 0,
    ],
    'ssl' => [
        'verify_peer' => true,
        'verify_peer_name' => true,
        'allow_self_signed' => false,
        'peer_name' => $host,
        'SNI_enabled' => true,
    ],
]);

$fp = @fopen($upstream, 'rb', false, $ctx);
if (!is_resource($fp)) {
    http_response_code(502);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Upstream error\n";
    exit;
}

$maxRespBytes = 1024 * 1024;
$respRaw = '';
while (!feof($fp) && strlen($respRaw) <= $maxRespBytes) {
    $chunk = fread($fp, 8192);
    if ($chunk === false) {
        break;
    }
    $respRaw .= $chunk;
}
fclose($fp);

if ($respRaw === '') {
    http_response_code(502);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Upstream error\n";
    exit;
}
if (strlen($respRaw) > $maxRespBytes) {
    http_response_code(502);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Upstream response too large\n";
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
