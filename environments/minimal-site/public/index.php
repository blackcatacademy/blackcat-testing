<?php

declare(strict_types=1);

use BlackCat\Config\Runtime\Config;
use BlackCat\Core\Database;
use BlackCat\Core\Kernel\HttpKernel;
use BlackCat\Core\Kernel\HttpKernelContext;
use BlackCat\Core\Kernel\HttpKernelOptions;
use BlackCat\Core\TrustKernel\TrustKernelException;

require __DIR__ . '/../../vendor/autoload.php';

$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
$path = parse_url((string) $requestUri, PHP_URL_PATH);
if (!is_string($path) || $path === '') {
    $path = '/';
}

// Allow a small monitoring endpoint even when strict mode is denying reads.
// This endpoint must remain read-only and must not expose secrets.
$opts = new HttpKernelOptions();
if ($path === '/health') {
    $opts->checkTrustOnRequest = false;
}

$sendJson = static function (int $status, array $payload): void {
    if (!headers_sent()) {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
    }
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) . "\n";
};

$sendText = static function (int $status, string $body): void {
    if (!headers_sent()) {
        http_response_code($status);
        header('Content-Type: text/plain; charset=utf-8');
    }
    echo $body;
    if (!str_ends_with($body, "\n")) {
        echo "\n";
    }
};

$ensureDb = static function (): Database {
    if (!Database::isInitialized()) {
        $dsn = Config::requireString('db.dsn');
        $user = Config::get('db.user');
        $pass = Config::get('db.pass');

        Database::init(
            [
                'dsn' => $dsn,
                'user' => is_string($user) ? $user : null,
                'pass' => is_string($pass) ? $pass : null,
                'options' => [],
                'init_commands' => [
                    "SET time_zone = '+00:00'",
                ],
                'appName' => 'blackcat-testing',
            ],
            null,
        );
    }

    return Database::getInstance();
};

$initSchema = static function (Database $db): void {
    $db->exec(
        'CREATE TABLE IF NOT EXISTS bc_test_events (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            msg VARCHAR(255) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
    );
};

HttpKernel::run(
    static function (HttpKernelContext $kernelCtx) use ($path, $sendJson, $sendText, $ensureDb, $initSchema): void {
    if ($path === '/health') {
        // Intentionally exclude local filesystem details (computed_root) from the public output.
        $status = $kernelCtx->kernel->check()->toArray();
        unset($status['computed_root']);

        $sendJson(200, [
            'ok' => true,
            'trust' => $status,
        ]);
        return;
    }

    if ($path === '/db/write') {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            $sendText(405, 'Method Not Allowed');
            return;
        }

        try {
            $db = $ensureDb();
            $initSchema($db);
            $db->exec('INSERT INTO bc_test_events (msg) VALUES (?)', ['hello']);
            $sendText(200, 'write ok');
            return;
        } catch (TrustKernelException $e) {
            $sendText(403, 'denied');
            return;
        } catch (\Throwable $e) {
            $sendText(500, 'error');
            return;
        }
    }

    if ($path === '/db/read') {
        try {
            $db = $ensureDb();
            $row = $db->fetch('SELECT COUNT(*) AS c FROM bc_test_events');
            $count = is_array($row) ? (int) ($row['c'] ?? 0) : 0;
            $sendJson(200, ['count' => $count]);
            return;
        } catch (TrustKernelException $e) {
            $sendText(403, 'denied');
            return;
        } catch (\Throwable) {
            $sendText(500, 'error');
            return;
        }
    }

    if ($path === '/bypass/pdo') {
        try {
            $db = $ensureDb();
            $pdo = $db->getPdo(); // must be denied by TrustKernel guard
            $sendText(500, 'unexpected: raw pdo allowed: ' . get_class($pdo));
            return;
        } catch (TrustKernelException) {
            $sendText(403, 'denied');
            return;
        } catch (\Throwable) {
            $sendText(500, 'error');
            return;
        }
    }

    $sendText(404, 'Not Found');
},
    $_SERVER,
    $opts,
);
