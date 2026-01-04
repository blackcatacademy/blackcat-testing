<?php

declare(strict_types=1);

// Minimal, fast soak metadata endpoint for the demo UI.
// Avoids booting TrustKernel (and hitting the chain) inside the HTTP request.

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method !== 'GET' && $method !== 'HEAD') {
    http_response_code(405);
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    echo "Method Not Allowed\n";
    exit;
}

$sendJson = static function (int $status, array $payload): void {
    if (!headers_sent()) {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
    }
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) . "\n";
};

$logsDir = '/var/lib/blackcat/harness/logs';

if (!is_dir($logsDir) || is_link($logsDir) || !is_readable($logsDir)) {
    $sendJson(200, [
        'ok' => false,
        'error' => 'logs_dir_unavailable',
        'hint' => 'Mount the harness logs volume into the app container (presentation mode) or run the attacker harness.',
    ]);
    return;
}

$bestMetaPath = null;
$bestMtime = null;
$bestRunId = null;

$files = glob($logsDir . DIRECTORY_SEPARATOR . 'meta.*.json', GLOB_NOSORT);
if ($files !== false) {
    foreach ($files as $candidatePath) {
        if (!is_string($candidatePath) || $candidatePath === '' || !is_file($candidatePath) || is_link($candidatePath) || !is_readable($candidatePath)) {
            continue;
        }
        $base = basename($candidatePath);
        if (!preg_match('/^meta\\.(?<id>[A-Za-z0-9_.-]{6,80})\\.json$/', $base, $m)) {
            continue;
        }
        $mtime = @filemtime($candidatePath);
        if (!is_int($mtime)) {
            continue;
        }
        if ($bestMtime === null || $mtime >= $bestMtime) {
            $bestMtime = $mtime;
            $bestMetaPath = $candidatePath;
            $bestRunId = $m['id'];
        }
    }
}

if (!is_string($bestRunId)) {
    $sendJson(200, [
        'ok' => false,
        'error' => 'no_runs_found',
        'hint' => 'No attacker/soak runs found yet. Start the attacker harness to generate meta.*.json + summary.*.json in /var/lib/blackcat/harness/logs.',
    ]);
    return;
}

$readJson = static function (string $path, int $maxBytes = 262144): ?array {
    $path = trim($path);
    if ($path === '' || str_contains($path, "\0")) {
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
    if (!is_array($decoded)) {
        return null;
    }

    return $decoded;
};

$meta = is_string($bestMetaPath) ? $readJson($bestMetaPath) : null;
$summary = $readJson($logsDir . DIRECTORY_SEPARATOR . 'summary.' . $bestRunId . '.json');

$sendJson(200, [
    'ok' => true,
    'latest_run_id' => $bestRunId,
    'meta' => $meta,
    'summary' => $summary,
    'report_url' => '/demo/soak/report?run_id=' . urlencode($bestRunId),
]);

