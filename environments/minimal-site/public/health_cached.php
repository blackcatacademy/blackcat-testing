<?php

declare(strict_types=1);

// Minimal, fast monitoring endpoint backed by trust-runner cache.
// Avoids running a full TrustKernel check inside the HTTP request (PHP built-in server is single-threaded).

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method !== 'GET' && $method !== 'HEAD') {
    http_response_code(405);
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    echo "Method Not Allowed\n";
    exit;
}

$cachePath = '/var/lib/blackcat/trust.status.json';
if (!is_file($cachePath) || is_link($cachePath) || !is_readable($cachePath)) {
    http_response_code(503);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode([
        'ok' => false,
        'cached' => true,
        'error' => 'trust_status_cache_unavailable',
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) . "\n";
    exit;
}

$raw = @file_get_contents($cachePath);
if (!is_string($raw) || trim($raw) === '') {
    http_response_code(503);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode([
        'ok' => false,
        'cached' => true,
        'error' => 'trust_status_cache_empty',
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) . "\n";
    exit;
}

/** @var mixed $decoded */
$decoded = json_decode($raw, true);
if (!is_array($decoded)) {
    http_response_code(503);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode([
        'ok' => false,
        'cached' => true,
        'error' => 'trust_status_cache_invalid_json',
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) . "\n";
    exit;
}

$debug = $_GET['debug'] ?? null;
$wantDebug = is_string($debug) && ($debug === '1' || strtolower($debug) === 'true');

$trust = null;
$trustRoot = $decoded['trust'] ?? null;
if (is_array($trustRoot)) {
    if ($wantDebug) {
        $trust = $trustRoot['debug'] ?? null;
    } else {
        $trust = $trustRoot['monitor'] ?? null;
    }
}

if (!is_array($trust)) {
    http_response_code(503);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode([
        'ok' => false,
        'cached' => true,
        'error' => 'trust_status_cache_missing_trust',
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) . "\n";
    exit;
}

http_response_code(200);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
echo json_encode([
    'ok' => true,
    'cached' => true,
    'generated_at' => is_string($decoded['generated_at'] ?? null) ? $decoded['generated_at'] : null,
    'generated_unix' => is_int($decoded['generated_unix'] ?? null) ? $decoded['generated_unix'] : null,
    'trust' => $trust,
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) . "\n";

