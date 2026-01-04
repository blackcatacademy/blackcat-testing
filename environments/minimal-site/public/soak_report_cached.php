<?php

declare(strict_types=1);

// Minimal, fast soak report endpoint for the demo UI.
// Avoids booting TrustKernel (and hitting the chain) inside the HTTP request.

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method !== 'GET' && $method !== 'HEAD') {
    http_response_code(405);
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    echo "Method Not Allowed\n";
    exit;
}

$sendText = static function (int $status, string $body): void {
    if (!headers_sent()) {
        http_response_code($status);
        header('Content-Type: text/plain; charset=utf-8');
        header('Cache-Control: no-store');
    }
    echo $body;
    if (!str_ends_with($body, "\n")) {
        echo "\n";
    }
};

$logsDir = '/var/lib/blackcat/harness/logs';
if (!is_dir($logsDir) || is_link($logsDir) || !is_readable($logsDir)) {
    $sendText(404, 'soak logs not available');
    exit;
}

require __DIR__ . '/../../vendor/autoload.php';

$runId = $_GET['run_id'] ?? null;
$runId = is_string($runId) ? trim($runId) : null;
$runId = $runId === '' ? null : $runId;

try {
    $md = \BlackCat\Testing\Soak\SoakReportGenerator::generateMarkdown(
        $runId,
        $logsDir,
        null,
        '/etc/blackcat/config.runtime.json',
    );

    if (!headers_sent()) {
        http_response_code(200);
        header('Content-Type: text/markdown; charset=utf-8');
        header('Cache-Control: no-store');
    }
    echo $md;
    if (!str_ends_with($md, "\n")) {
        echo "\n";
    }
    exit;
} catch (\Throwable $e) {
    $sendText(500, 'report_failed: ' . $e->getMessage());
    exit;
}

