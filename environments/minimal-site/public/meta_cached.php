<?php

declare(strict_types=1);

// Minimal, fast metadata endpoint for the demo UI.
// Avoids booting TrustKernel (and hitting the chain) inside the HTTP request.

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method !== 'GET' && $method !== 'HEAD') {
    http_response_code(405);
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    echo "Method Not Allowed\n";
    exit;
}

$cfgPath = '/etc/blackcat/config.runtime.json';
$cfg = null;

if (is_file($cfgPath) && !is_link($cfgPath) && is_readable($cfgPath)) {
    $raw = @file_get_contents($cfgPath);
    if (is_string($raw) && trim($raw) !== '') {
        /** @var mixed $decoded */
        $decoded = json_decode($raw, true);
        if (is_array($decoded)) {
            $cfg = $decoded;
        }
    }
}

$getNested = static function (?array $root, array $path): mixed {
    $cur = $root;
    foreach ($path as $k) {
        if (!is_array($cur) || !array_key_exists($k, $cur)) {
            return null;
        }
        $cur = $cur[$k];
    }
    return $cur;
};

$chainId = $getNested($cfg, ['trust', 'web3', 'chain_id']);
$endpoints = $getNested($cfg, ['trust', 'web3', 'rpc_endpoints']);
$quorum = $getNested($cfg, ['trust', 'web3', 'rpc_quorum']);
$controller = $getNested($cfg, ['trust', 'web3', 'contracts', 'instance_controller']);

$demoStatePath = '/etc/blackcat/demo/demo.state.json';
$demoState = null;
if (is_file($demoStatePath) && !is_link($demoStatePath) && is_readable($demoStatePath)) {
    $raw = @file_get_contents($demoStatePath);
    if (is_string($raw) && trim($raw) !== '') {
        /** @var mixed $decoded */
        $decoded = json_decode($raw, true);
        if (is_array($decoded)) {
            $demoState = $decoded;
        }
    }
}

$insecureUrlRaw = getenv('BLACKCAT_TESTING_INSECURE_URL');
$insecureUrl = is_string($insecureUrlRaw) && trim($insecureUrlRaw) !== '' ? trim($insecureUrlRaw) : 'http://localhost:8089/';

$operatorUrlRaw = getenv('BLACKCAT_TESTING_OPERATOR_URL');
$operatorUrl = is_string($operatorUrlRaw) && trim($operatorUrlRaw) !== '' ? trim($operatorUrlRaw) : 'http://localhost:8091';

$operatorTokenPath = '/var/lib/blackcat/operator/operator.token';
$operatorToken = null;
if (is_file($operatorTokenPath) && !is_link($operatorTokenPath) && is_readable($operatorTokenPath)) {
    $raw = @file_get_contents($operatorTokenPath);
    if (is_string($raw) && trim($raw) !== '') {
        $operatorToken = trim($raw);
    }
}

$demo = [
    'tamper_after_sec' => null,
    'tamper_kind' => null,
    'tamper_marker_exists' => null,
    'tamper_marker_mtime_unix' => null,
    'tamper_armed_at_unix' => null,
    'rpc_sabotage_after_sec' => null,
    'rpc_sabotage_marker_exists' => null,
    'rpc_sabotage_marker_mtime_unix' => null,
    'rpc_proxy_sabotage_after_sec' => null,
    'rpc_proxy_sabotage_marker_exists' => null,
    'rpc_proxy_sabotage_marker_mtime_unix' => null,
];

$demoStateMtime = null;
if (is_file($demoStatePath) && !is_link($demoStatePath)) {
    clearstatcache(true, $demoStatePath);
    $mt = @filemtime($demoStatePath);
    if (is_int($mt) && $mt > 0) {
        $demoStateMtime = $mt;
        $demo['tamper_armed_at_unix'] = $mt;
    }
}

$markerPath = '/etc/blackcat/.blackcat_testing_tamper_done';
if (is_array($demoState)) {
    $tamper = $demoState['tamper'] ?? null;
    if (is_array($tamper)) {
        $p = $tamper['marker_path'] ?? null;
        if (
            is_string($p)
            && $p !== ''
            && !str_contains($p, "\0")
            && str_starts_with($p, '/etc/blackcat/')
        ) {
            $markerPath = $p;
        }
    }
}

if ($markerPath !== '' && !str_contains($markerPath, "\0")) {
    $markerExists = is_file($markerPath) && !is_link($markerPath);
    $demo['tamper_marker_exists'] = $markerExists;
    if ($markerExists) {
        clearstatcache(true, $markerPath);
        $mt = @filemtime($markerPath);
        if (is_int($mt) && $mt > 0) {
            $demo['tamper_marker_mtime_unix'] = $mt;
        }
    }
}

$rpcMarkerPath = '/etc/blackcat/.blackcat_testing_rpc_sabotage_done';
if ($rpcMarkerPath !== '' && !str_contains($rpcMarkerPath, "\0")) {
    $rpcMarkerExists = is_file($rpcMarkerPath) && !is_link($rpcMarkerPath);
    $demo['rpc_sabotage_marker_exists'] = $rpcMarkerExists;
    if ($rpcMarkerExists) {
        clearstatcache(true, $rpcMarkerPath);
        $mt = @filemtime($rpcMarkerPath);
        if (is_int($mt) && $mt > 0) {
            $demo['rpc_sabotage_marker_mtime_unix'] = $mt;
        }
    }
}

$rpcProxyMarkerPath = '/etc/blackcat/.blackcat_testing_rpc_proxy_sabotage_done';
if ($rpcProxyMarkerPath !== '' && !str_contains($rpcProxyMarkerPath, "\0")) {
    $rpcProxyMarkerExists = is_file($rpcProxyMarkerPath) && !is_link($rpcProxyMarkerPath);
    $demo['rpc_proxy_sabotage_marker_exists'] = $rpcProxyMarkerExists;
    if ($rpcProxyMarkerExists) {
        clearstatcache(true, $rpcProxyMarkerPath);
        $mt = @filemtime($rpcProxyMarkerPath);
        if (is_int($mt) && $mt > 0) {
            $demo['rpc_proxy_sabotage_marker_mtime_unix'] = $mt;
        }
    }
}

if (is_array($demoState)) {
    $tamper = $demoState['tamper'] ?? null;
    if (is_array($tamper)) {
        $after = $tamper['after_sec'] ?? null;
        if (is_int($after)) {
            $demo['tamper_after_sec'] = $after;
        } elseif (is_string($after) && ctype_digit(trim($after))) {
            $demo['tamper_after_sec'] = (int) trim($after);
        }

        $kind = $tamper['kind'] ?? null;
        if (is_string($kind) && trim($kind) !== '') {
            $demo['tamper_kind'] = trim($kind);
        }
    }

    $rpcSab = $demoState['rpc_sabotage_after_sec'] ?? null;
    if (is_int($rpcSab)) {
        $demo['rpc_sabotage_after_sec'] = $rpcSab;
    } elseif (is_string($rpcSab) && ctype_digit(trim($rpcSab))) {
        $demo['rpc_sabotage_after_sec'] = (int) trim($rpcSab);
    }

    $rpcProxySab = $demoState['rpc_proxy_sabotage_after_sec'] ?? null;
    if (is_int($rpcProxySab)) {
        $demo['rpc_proxy_sabotage_after_sec'] = $rpcProxySab;
    } elseif (is_string($rpcProxySab) && ctype_digit(trim($rpcProxySab))) {
        $demo['rpc_proxy_sabotage_after_sec'] = (int) trim($rpcProxySab);
    }
}

$meta = [
    'ok' => true,
    'chain_id' => is_int($chainId) ? $chainId : (is_string($chainId) && ctype_digit(trim($chainId)) ? (int) trim($chainId) : null),
    'rpc_endpoints_count' => is_array($endpoints) ? count($endpoints) : null,
    'rpc_quorum' => is_int($quorum) ? $quorum : (is_string($quorum) && ctype_digit(trim($quorum)) ? (int) trim($quorum) : null),
    'instance_controller' => is_string($controller) && trim($controller) !== '' ? trim($controller) : null,
    'explorer_base_url' => null,
    'insecure_demo_url' => $insecureUrl,
    'operator_url' => $operatorUrl,
    'operator_token' => $operatorToken,
    'demo' => $demo,
];

if ($meta['chain_id'] === 4207) {
    $meta['explorer_base_url'] = 'https://edgenscan.io';
}

http_response_code(200);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
echo json_encode($meta, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) . "\n";
