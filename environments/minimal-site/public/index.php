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
if ($path === '/health' || $path === '/' || $path === '/demo') {
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
    if ($path === '/' || $path === '/demo') {
        if (!headers_sent()) {
            http_response_code(200);
            header('Content-Type: text/html; charset=utf-8');
        }

        echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
        echo '<title>BlackCat Kernel Demo</title>';
        echo '<style>
          :root{color-scheme:dark;--bg:#0b1020;--card:#121a33;--muted:#95a3c3;--ok:#37d67a;--bad:#ff5c5c;--warn:#ffb84d;--b:#1f2a4f;--mono:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace}
          body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;background:var(--bg);color:#e8eeff}
          header{padding:24px 20px;border-bottom:1px solid var(--b);background:linear-gradient(180deg,rgba(255,255,255,.04),transparent)}
          h1{margin:0 0 6px;font-size:18px;letter-spacing:.2px}
          p{margin:0;color:var(--muted);font-size:13px}
          .wrap{max-width:980px;margin:0 auto;padding:18px 20px}
          .grid{display:grid;grid-template-columns:1fr;gap:12px}
          @media (min-width:900px){.grid{grid-template-columns:1.2fr .8fr}}
          .card{background:var(--card);border:1px solid var(--b);border-radius:12px;padding:14px}
          .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
          .pill{border:1px solid var(--b);border-radius:999px;padding:6px 10px;font-size:12px;color:var(--muted)}
          .pill strong{color:#e8eeff}
          .pill.ok{border-color:rgba(55,214,122,.3)}
          .pill.bad{border-color:rgba(255,92,92,.35)}
          .pill.warn{border-color:rgba(255,184,77,.35)}
          button{appearance:none;border:1px solid var(--b);background:#0f1730;color:#e8eeff;border-radius:10px;padding:10px 12px;font-size:13px;cursor:pointer}
          button:hover{border-color:#2a3a6f}
          button:disabled{opacity:.6;cursor:not-allowed}
          pre{margin:10px 0 0;background:#0a1126;border:1px solid var(--b);border-radius:10px;padding:10px;overflow:auto;font-family:var(--mono);font-size:12px;line-height:1.45}
          .muted{color:var(--muted);font-size:12px}
          .k{font-family:var(--mono);font-size:12px;color:#cfe0ff}
          .statusDot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px;background:var(--warn)}
          .dotOk{background:var(--ok)} .dotBad{background:var(--bad)} .dotWarn{background:var(--warn)}
        </style></head><body>';

        echo '<header><div class="wrap"><h1>BlackCat Kernel Demo</h1><p>Live status from <span class="k">/health</span> + guarded DB probes.</p></div></header>';
        echo '<div class="wrap"><div class="grid">';

        echo '<div class="card"><div class="row" style="justify-content:space-between">';
        echo '<div class="row"><span id="dot" class="statusDot dotWarn"></span><span class="pill"><strong id="titleState">Loading…</strong></span><span class="pill">enforcement: <strong id="enf">?</strong></span><span class="pill">rpc: <strong id="rpc">?</strong></span></div>';
        echo '<div class="row"><span class="pill">read: <strong id="read">?</strong></span><span class="pill">write: <strong id="write">?</strong></span><span class="pill">paused: <strong id="paused">?</strong></span></div>';
        echo '</div>';
        echo '<pre id="healthRaw">{"loading":true}</pre>';
        echo '<p class="muted">This page is intentionally allowed even when strict mode denies reads, so you can observe failures. It does not expose local filesystem details.</p>';
        echo '</div>';

        echo '<div class="card"><div class="row"><button id="btnRead">DB read</button><button id="btnWrite">DB write</button><button id="btnBypass">Probe PDO bypass</button></div>';
        echo '<pre id="actionsLog">Ready.</pre>';
        echo '<p class="muted">Expected behaviour in strict mode: writes are denied when <span class="k">write_allowed=false</span>, reads are denied when <span class="k">read_allowed=false</span>, and the PDO bypass probe must always be denied.</p>';
        echo '</div>';

        echo '</div></div>';

        echo '<script>
          const $ = (id) => document.getElementById(id);
          const log = (msg) => { const el = $("actionsLog"); el.textContent = (new Date().toISOString()) + " " + msg + "\\n" + el.textContent; };
          const setBool = (id, v) => { $(id).textContent = v === true ? "true" : v === false ? "false" : "?"; };
          const setDot = (mode) => { const d = $("dot"); d.className = "statusDot " + (mode === "ok" ? "dotOk" : mode === "bad" ? "dotBad" : "dotWarn"); };
          async function refresh() {
            try {
              const res = await fetch("/health", {cache:"no-store"});
              const json = await res.json();
              const trust = json && json.trust ? json.trust : null;
              $("healthRaw").textContent = JSON.stringify(json, null, 2);
              if (!trust) { $("titleState").textContent = "No trust payload"; setDot("warn"); return; }
              $("enf").textContent = trust.enforcement ?? "?";
              setBool("rpc", trust.rpc_ok_now);
              setBool("read", trust.read_allowed);
              setBool("write", trust.write_allowed);
              setBool("paused", trust.paused);
              const ok = trust.trusted_now === true;
              $("titleState").textContent = ok ? "Trusted" : "Not trusted";
              setDot(ok ? "ok" : "bad");
            } catch (e) {
              $("titleState").textContent = "Health fetch failed";
              setDot("bad");
            }
          }

          async function call(path, method="GET") {
            const res = await fetch(path, {method});
            const text = await res.text();
            log(method + " " + path + " -> " + res.status + " " + text.trim());
          }

          $("btnRead").addEventListener("click", () => call("/db/read", "GET"));
          $("btnWrite").addEventListener("click", () => call("/db/write", "POST"));
          $("btnBypass").addEventListener("click", () => call("/bypass/pdo", "GET"));

          refresh();
          setInterval(refresh, 1000);
        </script>';

        echo '</body></html>';
        return;
    }

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
