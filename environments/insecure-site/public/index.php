<?php

declare(strict_types=1);

$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
$path = parse_url((string) $requestUri, PHP_URL_PATH);
if (!is_string($path) || $path === '') {
    $path = '/';
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

$db = static function (): PDO {
    $dsn = (string) getenv('DB_DSN');
    $user = (string) getenv('DB_USER');
    $pass = (string) getenv('DB_PASS');

    if ($dsn === '' || $user === '' || $pass === '') {
        throw new RuntimeException('missing db env (DB_DSN/DB_USER/DB_PASS)');
    }

    return new PDO($dsn, $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
};

$ensureSchema = static function (PDO $pdo): void {
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS bc_test_events (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            msg VARCHAR(255) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
    );
};

$insecureKeyPath = static function (): string {
    $p = getenv('INSECURE_KEYS_FILE');
    if (is_string($p)) {
        $p = trim($p);
        if ($p !== '' && !str_contains($p, "\0")) {
            return $p;
        }
    }

    return __DIR__ . '/../keys/crypto_key_v1.key';
};

if ($path === '/health') {
    try {
        $pdo = $db();
        $pdo->query('SELECT 1');
        $sendJson(200, ['ok' => true, 'db_ok' => true]);
        return;
    } catch (Throwable $e) {
        $sendJson(500, ['ok' => false, 'db_ok' => false, 'error' => $e->getMessage()]);
        return;
    }
}

if ($path === '/leak/db') {
    $sendJson(200, [
        'ok' => true,
        'db' => [
            'dsn' => getenv('DB_DSN') ?: null,
            'user' => getenv('DB_USER') ?: null,
            'pass' => getenv('DB_PASS') ?: null,
        ],
        'note' => 'This endpoint is intentionally insecure (demo only).',
    ]);
    return;
}

if ($path === '/leak/key') {
    $keyFile = $insecureKeyPath();

    $raw = @file_get_contents($keyFile);
    if (!is_string($raw) || $raw === '') {
        $sendJson(404, ['ok' => false, 'error' => 'key file not readable', 'path' => $keyFile]);
        return;
    }

    $sendJson(200, [
        'ok' => true,
        'key_path' => $keyFile,
        'key_b64' => base64_encode($raw),
        'key_len' => strlen($raw),
        'note' => 'This is what BlackCat secrets-agent is designed to prevent.',
    ]);
    return;
}

if ($path === '/db/read') {
    try {
        $pdo = $db();
        $ensureSchema($pdo);
        $stmt = $pdo->query('SELECT id,msg,created_at FROM bc_test_events ORDER BY id DESC LIMIT 5');
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $sendJson(200, ['ok' => true, 'rows' => $rows]);
        return;
    } catch (Throwable $e) {
        $sendJson(500, ['ok' => false, 'error' => $e->getMessage()]);
        return;
    }
}

if ($path === '/db/write') {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        $sendText(405, 'Method Not Allowed');
        return;
    }

    try {
        $pdo = $db();
        $ensureSchema($pdo);
        $msg = 'insecure-write ' . gmdate('c');
        $stmt = $pdo->prepare('INSERT INTO bc_test_events (msg) VALUES (?)');
        $stmt->execute([$msg]);
        $sendJson(200, ['ok' => true, 'inserted' => $msg]);
        return;
    } catch (Throwable $e) {
        $sendJson(500, ['ok' => false, 'error' => $e->getMessage()]);
        return;
    }
}

if ($path !== '/' && $path !== '/demo') {
    $sendText(404, 'Not Found');
    return;
}

if (!headers_sent()) {
    http_response_code(200);
    header('Content-Type: text/html; charset=utf-8');
}

echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
echo '<title>Unprotected Demo (No BlackCat)</title>';
echo '<style>
  :root{color-scheme:dark;--bg:#160a0a;--card:#2a1010;--muted:#ffb3b3;--b:#3a1717;--mono:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace}
  body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:#fff}
  header{border-bottom:1px solid var(--b);background:linear-gradient(180deg,#2a1010,#160a0a)}
  .wrap{max-width:1100px;margin:0 auto;padding:18px}
  .grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px}
  .card{grid-column:span 12;background:var(--card);border:1px solid var(--b);border-radius:14px;padding:14px}
  .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
  button{background:#3a1717;border:1px solid var(--b);color:#fff;padding:10px 12px;border-radius:10px;cursor:pointer}
  button:hover{border-color:#ff6b6b}
  pre{margin:12px 0 0;background:#100606;border:1px solid var(--b);border-radius:10px;padding:10px;overflow:auto;font-family:var(--mono);font-size:12px;line-height:1.45}
  a{color:#ffd7d7;text-decoration:none}
  a:hover{text-decoration:underline}
  .muted{color:var(--muted);font-size:12px}
</style></head><body>';

echo '<header><div class="wrap"><h1>Unprotected Demo</h1><p class="muted">This is intentionally insecure: no TrustKernel, no guards, secrets readable by the web runtime.</p></div></header>';
echo '<div class="wrap"><div class="grid">';

echo '<div class="card"><div class="row">';
echo '<a href="http://localhost:8088/" target="_blank" rel="noopener">Open protected demo →</a>';
echo '</div><p class="muted">Compare with the BlackCat-protected target on port <span style="font-family:var(--mono)">8088</span>.</p></div>';

echo '<div class="card"><div class="row">';
echo '<button id="btnHealth">Health</button>';
echo '<button id="btnRead">DB read</button>';
echo '<button id="btnWrite">DB write</button>';
echo '<button id="btnLeakDb">Leak DB creds</button>';
echo '<button id="btnLeakKey">Leak key file</button>';
echo '<button id="btnClear">Clear</button>';
echo '</div><pre id="out">Ready.</pre></div>';

echo '</div></div>';

echo '<script>
  const out = document.getElementById("out");
  const log = (msg) => { out.textContent = (new Date().toISOString()) + " " + msg + "\\n" + out.textContent; };
  async function call(path, method="GET") {
    const res = await fetch(path, {method});
    const text = await res.text();
    log(method + " " + path + " -> " + res.status + " " + text.trim());
  }
  document.getElementById("btnHealth").addEventListener("click", () => call("/health"));
  document.getElementById("btnRead").addEventListener("click", () => call("/db/read"));
  document.getElementById("btnWrite").addEventListener("click", () => call("/db/write","POST"));
  document.getElementById("btnLeakDb").addEventListener("click", () => call("/leak/db"));
  document.getElementById("btnLeakKey").addEventListener("click", () => call("/leak/key"));
  document.getElementById("btnClear").addEventListener("click", () => { out.textContent = "Ready.\\n"; });
</script>';

echo '</body></html>';

