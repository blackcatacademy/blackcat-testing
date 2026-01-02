<?php

declare(strict_types=1);

/**
 * WARNING: This is a deliberately insecure demo site.
 * It exists only to showcase how easy it is to exfiltrate secrets / abuse a system WITHOUT BlackCat protections.
 * Do not reuse this code in real projects.
 */

$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
$path = parse_url((string) $requestUri, PHP_URL_PATH);
if (!is_string($path) || $path === '') {
    $path = '/';
}
if (PHP_SAPI === 'cli-server') {
    $p = $path;
    if ($p !== '/' && str_starts_with($p, '/') && !str_contains($p, '..') && !str_contains($p, "\0")) {
        $candidate = __DIR__ . $p;
        if (is_file($candidate)) {
            return false;
        }
    }
}

$cors = static function (): void {
    if (!headers_sent()) {
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type');
        header('Access-Control-Max-Age: 86400');
    }
};

$cors();

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
    if (!headers_sent()) {
        http_response_code(204);
    }
    exit;
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

$ensureDemoSchema = static function (PDO $pdo): void {
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS bc_demo_users (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            email VARCHAR(255) NOT NULL,
            password VARCHAR(255) NOT NULL,
            notes TEXT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
    );

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS bc_demo_vault (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            label VARCHAR(255) NOT NULL,
            nonce_b64 VARCHAR(64) NOT NULL,
            ciphertext_b64 MEDIUMTEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
    );

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS bc_demo_spamlist (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            email VARCHAR(255) NOT NULL,
            source VARCHAR(64) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
    );

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS bc_demo_loot (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            kind VARCHAR(64) NOT NULL,
            payload MEDIUMTEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
    );
};

$seedDemoDataIfEmpty = static function (PDO $pdo, string $keyFile): void {
    $pdo->beginTransaction();
    try {
        $usersCount = (int) ($pdo->query('SELECT COUNT(*) AS c FROM bc_demo_users')->fetchColumn() ?: 0);
        if ($usersCount === 0) {
            $stmt = $pdo->prepare('INSERT INTO bc_demo_users (email, password, notes) VALUES (?,?,?)');
            $stmt->execute(['admin@example.test', 'Password123!', 'Plaintext credentials in DB (bad).']);
            $stmt->execute(['client@example.test', 'winter2026', 'Customer account with weak password (bad).']);
            $stmt->execute(['billing@example.test', 'letmein', 'This should never be stored like this.']);
        }

        $vaultCount = (int) ($pdo->query('SELECT COUNT(*) AS c FROM bc_demo_vault')->fetchColumn() ?: 0);
        if ($vaultCount === 0) {
            $rawKey = @file_get_contents($keyFile);
            if (!is_string($rawKey) || strlen($rawKey) < SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
                throw new RuntimeException('missing/invalid key file for vault seed');
            }
            $key = substr($rawKey, 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

            $secrets = [
                ['label' => 'payment_card', 'plaintext' => 'CARD=4242 4242 4242 4242 | EXP=12/29 | CVV=123 (demo)'],
                ['label' => 'api_key', 'plaintext' => 'API_KEY=sk_demo_1234567890 (demo)'],
                ['label' => 'private_note', 'plaintext' => '“If the web runtime can read keys, encryption becomes theater.”'],
            ];

            $stmt = $pdo->prepare('INSERT INTO bc_demo_vault (label, nonce_b64, ciphertext_b64) VALUES (?,?,?)');
            foreach ($secrets as $s) {
                $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
                $cipher = sodium_crypto_secretbox($s['plaintext'], $nonce, $key);
                $stmt->execute([
                    $s['label'],
                    base64_encode($nonce),
                    base64_encode($cipher),
                ]);
            }
        }

        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        throw $e;
    }
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

$readJsonBody = static function (): array {
    $raw = file_get_contents('php://input');
    if (!is_string($raw) || trim($raw) === '') {
        return [];
    }
    /** @var mixed $decoded */
    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
};

$setCookieIfMissing = static function (): void {
    if (!isset($_COOKIE['demo_session'])) {
        $v = 'sess_' . bin2hex(random_bytes(10));
        // Intentionally insecure: NOT HttpOnly, to demonstrate how XSS/executed JS can steal cookies.
        // Also no SameSite/secure flags here.
        setcookie('demo_session', $v, [
            'expires' => time() + 3600,
            'path' => '/',
        ]);
        $_COOKIE['demo_session'] = $v;
    }
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

if ($path === '/attack/seed') {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        $sendText(405, 'Method Not Allowed');
        return;
    }

    try {
        $pdo = $db();
        $ensureSchema($pdo);
        $ensureDemoSchema($pdo);
        $seedDemoDataIfEmpty($pdo, $insecureKeyPath());
        $sendJson(200, [
            'ok' => true,
            'note' => 'Seeded demo tables (users, vault, spamlist, loot).',
        ]);
        return;
    } catch (Throwable $e) {
        $sendJson(500, ['ok' => false, 'error' => $e->getMessage()]);
        return;
    }
}

if ($path === '/attack/dbdump') {
    try {
        $pdo = $db();
        $ensureSchema($pdo);
        $ensureDemoSchema($pdo);

        $events = $pdo->query('SELECT id,msg,created_at FROM bc_test_events ORDER BY id DESC LIMIT 5')->fetchAll(PDO::FETCH_ASSOC);
        $users = $pdo->query('SELECT id,email,password,notes,created_at FROM bc_demo_users ORDER BY id ASC')->fetchAll(PDO::FETCH_ASSOC);
        $vault = $pdo->query('SELECT id,label,nonce_b64,ciphertext_b64,created_at FROM bc_demo_vault ORDER BY id ASC')->fetchAll(PDO::FETCH_ASSOC);

        $sendJson(200, [
            'ok' => true,
            'dump' => [
                'bc_test_events' => $events,
                'bc_demo_users' => $users,
                'bc_demo_vault' => $vault,
            ],
            'note' => 'In a typical unprotected app, dumping DB tables is "just code".',
        ]);
        return;
    } catch (Throwable $e) {
        $sendJson(500, ['ok' => false, 'error' => $e->getMessage()]);
        return;
    }
}

if ($path === '/attack/vault/decrypt-all') {
    try {
        $pdo = $db();
        $ensureDemoSchema($pdo);

        $keyFile = $insecureKeyPath();
        $rawKey = @file_get_contents($keyFile);
        if (!is_string($rawKey) || strlen($rawKey) < SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new RuntimeException('key file missing/invalid');
        }
        $key = substr($rawKey, 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

        $rows = $pdo->query('SELECT id,label,nonce_b64,ciphertext_b64 FROM bc_demo_vault ORDER BY id ASC')->fetchAll(PDO::FETCH_ASSOC);
        $out = [];
        foreach ($rows as $r) {
            $nonce = base64_decode((string) ($r['nonce_b64'] ?? ''), true);
            $cipher = base64_decode((string) ($r['ciphertext_b64'] ?? ''), true);
            if (!is_string($nonce) || !is_string($cipher)) {
                $out[] = ['id' => $r['id'] ?? null, 'label' => $r['label'] ?? null, 'ok' => false, 'error' => 'bad base64'];
                continue;
            }
            $plain = sodium_crypto_secretbox_open($cipher, $nonce, $key);
            if (!is_string($plain)) {
                $out[] = ['id' => $r['id'] ?? null, 'label' => $r['label'] ?? null, 'ok' => false, 'error' => 'decrypt failed'];
                continue;
            }
            $out[] = ['id' => $r['id'] ?? null, 'label' => $r['label'] ?? null, 'ok' => true, 'plaintext' => $plain];
        }

        $sendJson(200, [
            'ok' => true,
            'key_path' => $keyFile,
            'decrypted' => $out,
            'note' => 'This simulates the attacker either stealing the key OR forcing the app to decrypt for them.',
        ]);
        return;
    } catch (Throwable $e) {
        $sendJson(500, ['ok' => false, 'error' => $e->getMessage()]);
        return;
    }
}

if ($path === '/attack/collect') {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        $sendText(405, 'Method Not Allowed');
        return;
    }

    try {
        $pdo = $db();
        $ensureDemoSchema($pdo);

        $body = $readJsonBody();
        $kind = $body['kind'] ?? 'unknown';
        if (!is_string($kind) || trim($kind) === '') {
            $kind = 'unknown';
        }
        $payload = json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($payload)) {
            $payload = '{"error":"json_encode_failed"}';
        }

        $stmt = $pdo->prepare('INSERT INTO bc_demo_loot (kind, payload) VALUES (?,?)');
        $stmt->execute([$kind, $payload]);

        $sendJson(200, ['ok' => true, 'stored' => true]);
        return;
    } catch (Throwable $e) {
        $sendJson(500, ['ok' => false, 'error' => $e->getMessage()]);
        return;
    }
}

if ($path === '/attack/spam') {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        $sendText(405, 'Method Not Allowed');
        return;
    }

    try {
        $pdo = $db();
        $ensureDemoSchema($pdo);

        $body = $readJsonBody();
        $email = $body['email'] ?? '';
        if (!is_string($email)) {
            $email = '';
        }
        $email = trim($email);
        if ($email === '' || strlen($email) > 255) {
            $sendJson(400, ['ok' => false, 'error' => 'invalid email']);
            return;
        }

        $src = $body['source'] ?? 'unprotected_form';
        if (!is_string($src) || trim($src) === '') {
            $src = 'unprotected_form';
        }
        $src = substr($src, 0, 64);

        $stmt = $pdo->prepare('INSERT INTO bc_demo_spamlist (email, source) VALUES (?,?)');
        $stmt->execute([$email, $src]);

        $sendJson(200, [
            'ok' => true,
            'email' => $email,
            'note' => 'Simulation only (no real email is sent). This is what weak app boundaries enable.',
        ]);
        return;
    } catch (Throwable $e) {
        $sendJson(500, ['ok' => false, 'error' => $e->getMessage()]);
        return;
    }
}

if ($path === '/attack/loot') {
    try {
        $pdo = $db();
        $ensureDemoSchema($pdo);
        $loot = $pdo->query('SELECT id,kind,payload,created_at FROM bc_demo_loot ORDER BY id DESC LIMIT 20')->fetchAll(PDO::FETCH_ASSOC);
        $spam = $pdo->query('SELECT id,email,source,created_at FROM bc_demo_spamlist ORDER BY id DESC LIMIT 20')->fetchAll(PDO::FETCH_ASSOC);
        $sendJson(200, [
            'ok' => true,
            'loot' => $loot,
            'spamlist' => $spam,
        ]);
        return;
    } catch (Throwable $e) {
        $sendJson(500, ['ok' => false, 'error' => $e->getMessage()]);
        return;
    }
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

if ($path === '/bypass/pdo') {
    try {
        $pdo = $db(); // intentionally raw PDO (demo only)
        $pdo->query('SELECT 1');
        $sendJson(200, [
            'ok' => true,
            'pdo' => true,
            'note' => 'This is intentionally insecure: nothing prevents raw PDO access in the web runtime.',
        ]);
        return;
    } catch (Throwable $e) {
        $sendJson(500, ['ok' => false, 'pdo' => false, 'error' => $e->getMessage()]);
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

if ($path === '/start') {
    $setCookieIfMissing();

    if (!headers_sent()) {
        http_response_code(200);
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store');
    }

    $spamGifs = [
        '/assets/spam/television-ads.gif',
        '/assets/spam/mcdonalds-commercial.gif',
        '/assets/spam/taco-bell-commercial.gif',
        '/assets/spam/pringles-chips.gif',
        '/assets/spam/duracell-batteries-duracell.gif',
        '/assets/spam/15second-unskippable-youtube-ad-youtube.gif',
        '/assets/spam/zuckerberg-smile.gif',
    ];

    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
    echo '<title>Unprotected Attack Demo</title>';
    echo '<style>
      :root{color-scheme:dark;--bg:#120507;--card:#230b0f;--muted:#ffb3b3;--b:#3a1717;--hot:#ff5c5c;--ok:#37d67a;--mono:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace}
      body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:radial-gradient(1000px 600px at 20% -10%, rgba(255,92,92,.25), transparent 60%), var(--bg);color:#fff}
      header{border-bottom:1px solid var(--b);background:linear-gradient(180deg,#2a1010,#120507)}
      .wrap{max-width:1200px;margin:0 auto;padding:18px}
      .grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px}
      .card{grid-column:span 12;background:rgba(35,11,15,.9);border:1px solid var(--b);border-radius:16px;padding:14px;box-shadow:0 10px 30px rgba(0,0,0,.25)}
      .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
      .logo{width:64px;height:64px;object-fit:contain;filter:drop-shadow(0 10px 20px rgba(0,0,0,.35))}
      h1{margin:0;font-size:18px;letter-spacing:.2px}
      h2{margin:0;font-size:14px}
      a{color:#ffd7d7;text-decoration:none}
      a:hover{text-decoration:underline}
      .muted{color:var(--muted);font-size:12px}
      .pill{display:inline-flex;gap:8px;align-items:center;padding:6px 10px;border-radius:999px;background:#100606;border:1px solid var(--b);font-size:12px}
      .warn{border-color:#ff5c5c;color:#ffd7d7}
      .ok{border-color:rgba(55,214,122,.5)}
      .btn{background:#3a1717;border:1px solid var(--b);color:#fff;padding:10px 12px;border-radius:10px;cursor:pointer}
      .btn:hover{border-color:#ff6b6b}
      pre{margin:12px 0 0;background:#0f0507;border:1px solid var(--b);border-radius:12px;padding:12px;overflow:auto;font-family:var(--mono);font-size:12px;line-height:1.45;max-height:360px}
      ol{margin:10px 0 0 20px;color:#ffd7d7}
      li{margin:6px 0}
      .steps{display:grid;grid-template-columns:repeat(12,1fr);gap:10px}
      .step{grid-column:span 12;background:#0f0507;border:1px dashed var(--b);border-radius:14px;padding:10px}
      .step.active{border-color:#ff6b6b;box-shadow:0 0 0 2px rgba(255,92,92,.15) inset}
      .step.done{border-style:solid;border-color:rgba(55,214,122,.45)}
      .two{display:grid;grid-template-columns:repeat(12,1fr);gap:14px}
      .col{grid-column:span 12}
      @media(min-width:900px){.col{grid-column:span 6}}
      .gifwall{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
      @media(min-width:900px){.gifwall{grid-template-columns:repeat(3,1fr)}}
      .gifwall img{width:100%;border-radius:12px;border:1px solid var(--b);background:#0f0507}
      input{background:#0f0507;border:1px solid var(--b);border-radius:10px;padding:10px 12px;color:#fff;min-width:260px}
    </style></head><body>';

    echo '<header><div class="wrap"><div class="row" style="justify-content:space-between">';
    echo '<div class="row"><img class="logo" src="/assets/unprotected.png" alt="Unprotected"><div>';
    echo '<h1>Unprotected Attack Demo</h1>';
    echo '<div class="muted">A dramatic simulation of what attackers can do when your app has no security kernel.</div>';
    echo '</div></div>';
    echo '<div class="row">';
    echo '<span class="pill warn">NO TrustKernel</span>';
    echo '<span class="pill warn">Secrets readable</span>';
    echo '<span class="pill warn">Raw PDO allowed</span>';
    echo '<a class="pill ok" href="http://localhost:8088/" target="_blank" rel="noopener">Open protected demo →</a>';
    echo '</div></div></div></header>';

    echo '<div class="wrap"><div class="grid">';
    echo '<div class="card"><div class="row" style="justify-content:space-between"><div>';
    echo '<h2>Attack timeline (auto)</h2><div class="muted">Everything below is a demo inside docker. No real emails are sent.</div></div>';
    echo '<div class="row"><button class="btn" id="btnRun">Run demo</button><button class="btn" id="btnLoot">Show loot</button><a class="pill" href="/">Back</a></div></div>';
    echo '<div class="two" style="margin-top:10px">';
    echo '<div class="col"><div class="muted">Attacker console</div><pre id="console">Ready. Click “Run demo”.</pre></div>';
    echo '<div class="col"><div class="muted">Victim surface (unprotected)</div>';
    echo '<div class="row" style="margin-top:10px"><span class="pill">demo_session cookie: <strong style="font-family:var(--mono)">' . htmlspecialchars((string) ($_COOKIE['demo_session'] ?? ''), ENT_QUOTES) . '</strong></span></div>';
    echo '<div class="row" style="margin-top:10px"><input id="email" placeholder="victim@example.com" value="victim@example.com"><button class="btn" id="btnSubmit">Submit contact form</button></div>';
    echo '<div class="muted" style="margin-top:8px">This form is “the mistake”: user input becomes attacker data.</div>';
    echo '<div id="spamWall" style="margin-top:12px;display:none"><div class="muted">SPAM WALL (simulation)</div><div class="gifwall">';
    foreach ($spamGifs as $gif) {
        echo '<img src="' . htmlspecialchars($gif, ENT_QUOTES) . '" alt="spam">';
    }
    echo '</div></div>';
    echo '</div></div>';
    echo '<div class="steps" style="margin-top:14px" id="steps"></div>';
    echo '</div></div></div>';

    echo '<script>
      const consoleEl = document.getElementById("console");
      const stepsEl = document.getElementById("steps");
      const spamWall = document.getElementById("spamWall");
      const log = (msg) => { consoleEl.textContent = (new Date().toISOString()) + " " + msg + "\\n" + consoleEl.textContent; };

      async function call(path, method="GET", body=null) {
        const opt = { method, headers: {} };
        if (body !== null) {
          opt.headers["Content-Type"] = "application/json";
          opt.body = JSON.stringify(body);
        }
        const res = await fetch(path, opt);
        const text = await res.text();
        let parsed = null;
        try { parsed = JSON.parse(text); } catch {}
        return { ok: res.ok, status: res.status, text, json: parsed };
      }

      function addStep(title, why, blackcat) {
        const el = document.createElement("div");
        el.className = "step";
        el.innerHTML = `
          <div class="row" style="justify-content:space-between">
            <div><strong>${title}</strong></div>
            <div class="muted">unprotected</div>
          </div>
          <div class="muted" style="margin-top:6px">${why}</div>
          <div class="muted" style="margin-top:6px"><strong>With BlackCat:</strong> ${blackcat}</div>
          <pre class="out" style="display:none"></pre>
        `;
        stepsEl.appendChild(el);
        return el;
      }

      const steps = [];
      steps.push({
        el: addStep(
          "1) Recon: health check",
          "I probe /health to see if the target is alive.",
          "TrustKernel can fail-closed and expose only safe health signals."
        ),
        run: async () => call("/health")
      });
      steps.push({
        el: addStep(
          "2) Instant DB credential leak",
          "If DB creds are in env/files readable by web runtime, exfil is trivial.",
          "DB creds can be moved behind a secrets-agent boundary; the web runtime never sees them."
        ),
        run: async () => call("/leak/db")
      });
      steps.push({
        el: addStep(
          "3) Dump unencrypted data",
          "Raw PDO is allowed; I can read tables directly.",
          "SQL firewall + secrets boundary + strict kernel bootstrap blocks raw PDO access."
        ),
        run: async () => call("/db/read")
      });
      steps.push({
        el: addStep(
          "4) Seed + dump a vault (encrypted at rest)",
          "Even if data is encrypted in DB, I can still steal the key if it is reachable.",
          "Keyless crypto agent: keys never leave the boundary; only encrypt/decrypt operations are allowed."
        ),
        run: async () => {
          await call("/attack/seed","POST");
          return call("/attack/dbdump");
        }
      });
      steps.push({
        el: addStep(
          "5) Steal the encryption key file",
          "One world-readable key file = game over for all encrypted fields.",
          "Key files must not be readable by the web runtime; only the agent can access them."
        ),
        run: async () => call("/leak/key")
      });
      steps.push({
        el: addStep(
          "6) Decrypt everything",
          "Now I can decrypt vault secrets (offline or by forcing the app to decrypt).",
          "TrustKernel enforces on-chain integrity + policies before sensitive operations."
        ),
        run: async () => call("/attack/vault/decrypt-all")
      });
      steps.push({
        el: addStep(
          "7) Cookie exfil (simulated)",
          "If attacker code runs in the browser (XSS), non-HttpOnly cookies are stealable.",
          "HttpKernel hardening: secure cookies + host allowlist + strict bootstrap reduces common injection surfaces."
        ),
        run: async () => {
          const data = { kind: "cookie", cookie: document.cookie };
          return call("/attack/collect","POST", data);
        }
      });
      steps.push({
        el: addStep(
          "8) Harvest an email + start spam (simulation)",
          "A simple form can become an exfil + abuse channel.",
          "With BlackCat, incident intents can be queued on anomaly/rate-limit; external watchers can react."
        ),
        run: async () => {
          const email = (document.getElementById("email").value || "victim@example.com").trim();
          const res = await call("/attack/spam","POST", { kind: "spam", email, source: "demo_auto" });
          spamWall.style.display = "block";
          return res;
        }
      });

      async function runAll() {
        consoleEl.textContent = "Starting attack demo...\\n";
        for (let i=0;i<steps.length;i++) {
          const s = steps[i];
          steps.forEach(x => x.el.classList.remove("active"));
          s.el.classList.add("active");
          log(`Step ${i+1}/${steps.length}: ${s.el.querySelector("strong").textContent}`);
          let res;
          try {
            res = await s.run();
          } catch (e) {
            res = { ok:false, status:0, text:String(e), json:null };
          }
          const pre = s.el.querySelector("pre.out");
          pre.style.display = "block";
          pre.textContent = (res.json ? JSON.stringify(res.json, null, 2) : res.text).trim();
          s.el.classList.remove("active");
          s.el.classList.add(res.ok ? "done" : "");
          await new Promise(r => setTimeout(r, 700));
        }
        log("Demo finished. Open the protected site to compare fail-closed behavior.");
      }

      document.getElementById("btnRun").addEventListener("click", runAll);
      document.getElementById("btnLoot").addEventListener("click", async () => {
        const r = await call("/attack/loot");
        log("Loot: " + (r.json ? JSON.stringify(r.json).slice(0,400) + "..." : r.text));
      });
      document.getElementById("btnSubmit").addEventListener("click", async () => {
        const email = (document.getElementById("email").value || "").trim();
        if (!email) { alert("Enter an email"); return; }
        await call("/attack/spam","POST", { kind: "spam", email, source: "contact_form" });
        spamWall.style.display = "block";
        log("Victim submitted contact form. Email harvested (simulation).");
      });

      // Auto-run when opened (so presenters can just share a link).
      runAll();
    </script>';

    echo '</body></html>';
    return;
}

if ($path !== '/' && $path !== '/demo') {
    $sendText(404, 'Not Found');
    return;
}

$setCookieIfMissing();

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
  .logo{width:54px;height:54px;object-fit:contain;filter:drop-shadow(0 10px 20px rgba(0,0,0,.35))}
  button{background:#3a1717;border:1px solid var(--b);color:#fff;padding:10px 12px;border-radius:10px;cursor:pointer}
  button:hover{border-color:#ff6b6b}
  pre{margin:12px 0 0;background:#100606;border:1px solid var(--b);border-radius:10px;padding:10px;overflow:auto;font-family:var(--mono);font-size:12px;line-height:1.45}
  a{color:#ffd7d7;text-decoration:none}
  a:hover{text-decoration:underline}
  .muted{color:var(--muted);font-size:12px}
</style></head><body>';

echo '<header><div class="wrap"><div class="row" style="justify-content:space-between">';
echo '<div class="row"><img class="logo" src="/assets/unprotected.png" alt="Unprotected"><div>';
echo '<h1>Unprotected Demo</h1><p class="muted">Intentionally insecure: no TrustKernel, no guards, secrets readable by the web runtime.</p>';
echo '</div></div>';
echo '<div class="row"><a href="/start" class="muted" style="font-weight:600">Start attack demo →</a></div>';
echo '</div></div></header>';
echo '<div class="wrap"><div class="grid">';

echo '<div class="card"><div class="row">';
echo '<a href="http://localhost:8088/" target="_blank" rel="noopener">Open protected demo →</a>';
echo '</div><p class="muted">Compare with the BlackCat-protected target on port <span style="font-family:var(--mono)">8088</span>.</p></div>';

echo '<div class="card"><div class="row">';
echo '<span class="muted">demo_session cookie (not HttpOnly):</span>';
echo '<span style="font-family:var(--mono)">' . htmlspecialchars((string) ($_COOKIE['demo_session'] ?? ''), ENT_QUOTES) . '</span>';
echo '</div><p class="muted">This is intentionally unsafe to demonstrate cookie theft when attacker JS runs (XSS).</p></div>';

echo '<div class="card"><div class="row">';
echo '<button id="btnHealth">Health</button>';
echo '<button id="btnRead">DB read</button>';
echo '<button id="btnWrite">DB write</button>';
echo '<button id="btnLeakDb">Leak DB creds</button>';
echo '<button id="btnLeakKey">Leak key file</button>';
echo '<button id="btnSeed">Seed vault</button>';
echo '<button id="btnDump">DB dump</button>';
echo '<button id="btnDecrypt">Decrypt vault</button>';
echo '<button id="btnClear">Clear</button>';
echo '</div><pre id="out">Ready.</pre></div>';

echo '</div></div>';

echo '<script>
  const out = document.getElementById("out");
  const log = (msg) => { out.textContent = (new Date().toISOString()) + " " + msg + "\\n" + out.textContent; };
  async function call(path, method="GET", body=null) {
    const opt = {method, headers:{}};
    if (body !== null) { opt.headers["Content-Type"]="application/json"; opt.body = JSON.stringify(body); }
    const res = await fetch(path, opt);
    const text = await res.text();
    log(method + " " + path + " -> " + res.status + " " + text.trim());
  }
  document.getElementById("btnHealth").addEventListener("click", () => call("/health"));
  document.getElementById("btnRead").addEventListener("click", () => call("/db/read"));
  document.getElementById("btnWrite").addEventListener("click", () => call("/db/write","POST"));
  document.getElementById("btnLeakDb").addEventListener("click", () => call("/leak/db"));
  document.getElementById("btnLeakKey").addEventListener("click", () => call("/leak/key"));
  document.getElementById("btnSeed").addEventListener("click", () => call("/attack/seed","POST"));
  document.getElementById("btnDump").addEventListener("click", () => call("/attack/dbdump"));
  document.getElementById("btnDecrypt").addEventListener("click", () => call("/attack/vault/decrypt-all"));
  document.getElementById("btnClear").addEventListener("click", () => { out.textContent = "Ready.\\n"; });
</script>';

echo '</body></html>';
