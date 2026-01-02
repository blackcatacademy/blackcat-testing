<?php

declare(strict_types=1);

// Minimal, fast tx-outbox summary for demo UI.
// Avoids booting TrustKernel (and hitting the chain) inside the HTTP request.

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method !== 'GET' && $method !== 'HEAD') {
    http_response_code(405);
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    echo "Method Not Allowed\n";
    exit;
}

$dir = '/var/lib/blackcat/tx-outbox';
if (!is_dir($dir) || is_link($dir) || !is_readable($dir)) {
    http_response_code(200);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode([
        'ok' => false,
        'error' => 'tx_outbox_unavailable',
        'items' => [],
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) . "\n";
    exit;
}

$safeJsonRead = static function (string $path, int $maxBytes = 65536): ?array {
    if (trim($path) === '' || str_contains($path, "\0")) {
        return null;
    }
    if (!is_file($path) || is_link($path) || !is_readable($path)) {
        return null;
    }

    $raw = @file_get_contents($path, false, null, 0, $maxBytes);
    if (!is_string($raw) || trim($raw) === '') {
        return null;
    }

    /** @var mixed $decoded */
    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : null;
};

/**
 * @param list<'tx'|'sig'> $prefixes
 * @return list<string>
 */
$listJsonFiles = static function (string $stateDir, array $prefixes): array {
    if (trim($stateDir) === '' || str_contains($stateDir, "\0")) {
        return [];
    }
    if (!is_dir($stateDir) || is_link($stateDir) || !is_readable($stateDir)) {
        return [];
    }

    $all = [];
    foreach ($prefixes as $p) {
        if ($p !== 'tx' && $p !== 'sig') {
            continue;
        }
        $files = glob(rtrim($stateDir, '/\\') . '/' . $p . '.*.json') ?: [];
        foreach ($files as $f) {
            if (is_string($f)) {
                $all[] = $f;
            }
        }
    }

    rsort($all);
    return $all;
};

$states = [
    'pending' => $dir,
    'processing' => rtrim($dir, '/\\') . '/processing',
    'signed' => rtrim($dir, '/\\') . '/signed',
    'sent' => rtrim($dir, '/\\') . '/sent',
    'failed' => rtrim($dir, '/\\') . '/failed',
];

$counts = [];
$latest = [
    'pending' => [],
    'sent' => [],
    'failed' => [],
];

foreach ($states as $state => $stateDir) {
    $prefixes = ['tx'];
    if ($state === 'pending' || $state === 'processing' || $state === 'failed') {
        $prefixes = ['tx', 'sig'];
    } elseif ($state === 'signed') {
        $prefixes = ['sig'];
    }

    $files = $listJsonFiles($stateDir, $prefixes);
    $counts[$state] = count($files);

    if ($state !== 'pending') {
        continue;
    }

    foreach ($files as $file) {
        $base = basename($file);
        if ($base === '' || str_contains($base, "\0")) {
            continue;
        }

        $decoded = $safeJsonRead($file);
        if ($decoded === null) {
            continue;
        }

        $latest['pending'][] = [
            'file' => $base,
            'type' => $decoded['type'] ?? null,
            'kind' => $decoded['kind'] ?? null,
            'created_at' => $decoded['created_at'] ?? null,
            'to' => $decoded['to'] ?? null,
            'method' => $decoded['method'] ?? null,
            'args' => $decoded['args'] ?? null,
            'meta' => $decoded['meta'] ?? null,
        ];

        if (count($latest['pending']) >= 10) {
            break;
        }
    }
}

http_response_code(200);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
echo json_encode([
    'ok' => true,
    'counts' => $counts,
    'latest' => $latest,
    'note' => 'Tx outbox holds tx intents + signature requests. Broadcasting requires a signer+relayer (or direct mode).',
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) . "\n";

