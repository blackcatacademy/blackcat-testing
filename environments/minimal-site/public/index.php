<?php

declare(strict_types=1);

use BlackCat\Config\Runtime\Config;
use BlackCat\Core\Database;
use BlackCat\Core\Database\DbBootstrap;
use BlackCat\Core\Kernel\HttpKernel;
use BlackCat\Core\Kernel\HttpKernelContext;
use BlackCat\Core\Kernel\HttpKernelOptions;
use BlackCat\Core\Security\Crypto;
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
if ($path === '/health' || $path === '/health/debug' || $path === '/' || $path === '/demo') {
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
        DbBootstrap::initFromSecretsAgentIfNeeded(null, 'blackcat-testing');
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

        $meta = [
            'chain_id' => null,
            'rpc_endpoints_count' => null,
            'rpc_quorum' => null,
            'instance_controller' => null,
            'explorer_base_url' => null,
            'demo' => [
                'tamper_after_sec' => getenv('BLACKCAT_TESTING_TAMPER_AFTER_SEC') ?: null,
                'tamper_kind' => getenv('BLACKCAT_TESTING_TAMPER_KIND') ?: null,
                'rpc_sabotage_after_sec' => getenv('BLACKCAT_TESTING_RPC_SABOTAGE_AFTER_SEC') ?: null,
                'rpc_proxy_sabotage_after_sec' => getenv('BLACKCAT_TESTING_RPC_PROXY_SABOTAGE_AFTER_SEC') ?: null,
            ],
        ];

        try {
            $chainId = Config::get('trust.web3.chain_id');
            if (is_int($chainId)) {
                $meta['chain_id'] = $chainId;
            } elseif (is_string($chainId) && ctype_digit(trim($chainId))) {
                $meta['chain_id'] = (int) trim($chainId);
            }

            $endpoints = Config::get('trust.web3.rpc_endpoints');
            if (is_array($endpoints)) {
                $meta['rpc_endpoints_count'] = count($endpoints);
            }

            $quorum = Config::get('trust.web3.rpc_quorum');
            if (is_int($quorum)) {
                $meta['rpc_quorum'] = $quorum;
            } elseif (is_string($quorum) && ctype_digit(trim($quorum))) {
                $meta['rpc_quorum'] = (int) trim($quorum);
            }

            $controller = Config::get('trust.web3.contracts.instance_controller');
            if (is_string($controller) && $controller !== '') {
                $meta['instance_controller'] = $controller;
            }

            if ($meta['chain_id'] === 4207) {
                $meta['explorer_base_url'] = 'https://edgenscan.io';
            }
        } catch (\Throwable) {
            // best-effort only
        }

        $metaJson = json_encode($meta, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($metaJson)) {
            $metaJson = '{}';
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
          a{color:#cfe0ff;text-decoration:none}
          a:hover{text-decoration:underline}
          details{margin-top:10px}
          summary{cursor:pointer;color:var(--muted);font-size:12px}
        </style></head><body>';

        echo '<header><div class="wrap"><h1>BlackCat Kernel Demo</h1><p>Live status from <span class="k">/health</span> + guarded DB probes.</p></div></header>';
        echo '<div class="wrap"><div class="grid">';

        echo '<div class="card"><div class="row" style="justify-content:space-between">';
        echo '<div class="row"><span id="dot" class="statusDot dotWarn"></span><span class="pill"><strong id="titleState">Loading…</strong></span><span class="pill">enforcement: <strong id="enf">?</strong></span><span class="pill">rpc: <strong id="rpc">?</strong></span><span class="pill">mode: <strong id="mode">?</strong></span></div>';
        echo '<div class="row"><span class="pill">read: <strong id="read">?</strong></span><span class="pill">write: <strong id="write">?</strong></span><span class="pill">paused: <strong id="paused">?</strong></span><span class="pill">last_ok_age: <strong id="lastOkAge">?</strong></span></div>';
        echo '</div>';
        echo '<div class="row" style="margin-top:10px"><span class="pill">chain_id: <strong id="chainId">?</strong></span><span class="pill">rpc_endpoints: <strong id="rpcEndpointsCount">?</strong></span><span class="pill">rpc_quorum: <strong id="rpcQuorum">?</strong></span><span class="pill">controller: <a class="k" id="controllerLink" href="#" target="_blank" rel="noopener">?</a></span></div>';

        echo '<div class="row" style="margin-top:10px"><span class="pill">active_root: <span class="k" id="activeRoot">?</span></span><span class="pill">policy_hash: <span class="k" id="activePolicy">?</span></span></div>';
        echo '<pre id="errorsBox" style="display:none"></pre>';

        echo '<details><summary>Raw /health JSON</summary><pre id="healthRaw">{"loading":true}</pre></details>';
        echo '<p class="muted">This page is intentionally allowed even when strict mode denies reads, so you can observe failures. It does not expose local filesystem details.</p>';
        echo '</div>';

        echo '<div class="card"><div class="row"><button id="btnRead">DB read</button><button id="btnWrite">DB write</button><button id="btnBypass">Probe PDO bypass</button><button id="btnTraffic">Start traffic</button><button id="btnClear">Clear log</button></div>';
        echo '<pre id="actionsLog">Ready.</pre>';
        echo '<p class="muted">Expected in strict mode: writes denied when <span class="k">write_allowed=false</span>, reads denied when <span class="k">read_allowed=false</span>, and the PDO bypass probe is always denied.</p>';
        echo '</div>';

        echo '<div class="card"><div class="row"><button id="btnCrypto">Crypto roundtrip</button><button id="btnKeyBypass">Probe key file read</button><button id="btnAgentBypass">Probe secrets-agent</button></div>';
        echo '<p class="muted">Secrets-agent mode: key files must not be readable by the web runtime, but crypto operations can still work through the agent (and the agent also enforces TrustKernel).</p>';
        echo '</div>';

        echo '</div></div>';

        echo '<script>window.__BLACKCAT_META__=' . $metaJson . ';</script>';

        echo '<script>
          const $ = (id) => document.getElementById(id);
          const log = (msg) => { const el = $("actionsLog"); el.textContent = (new Date().toISOString()) + " " + msg + "\\n" + el.textContent; };
          const setBool = (id, v) => { $(id).textContent = v === true ? "true" : v === false ? "false" : "?"; };
          const setDot = (mode) => { const d = $("dot"); d.className = "statusDot " + (mode === "ok" ? "dotOk" : mode === "bad" ? "dotBad" : "dotWarn"); };
          const shortHex = (h) => typeof h === "string" && h.startsWith("0x") && h.length > 18 ? (h.slice(0, 10) + "…" + h.slice(-8)) : (h ?? "?");

          const meta = window.__BLACKCAT_META__ || {};
          $("chainId").textContent = meta.chain_id ?? "?";
          $("rpcEndpointsCount").textContent = meta.rpc_endpoints_count ?? "?";
          $("rpcQuorum").textContent = meta.rpc_quorum ?? "?";
          const controller = meta.instance_controller;
          if (typeof controller === "string" && controller) {
            const base = typeof meta.explorer_base_url === "string" && meta.explorer_base_url ? meta.explorer_base_url : "";
            const url = base ? (base.replace(/\\/$/, "") + "/address/" + controller) : "#";
            $("controllerLink").href = url;
            $("controllerLink").textContent = shortHex(controller);
          } else {
            $("controllerLink").href = "#";
            $("controllerLink").textContent = "?";
          }

	          let lastTrusted = null;
	          let lastDebugTrust = null;
	          let debugTick = 0;
	          let trafficTimer = null;
	          let trafficInFlight = false;
	          let trafficTick = 0;

	          async function refreshDebug() {
	            try {
	              const res = await fetch("/health/debug", {cache:"no-store"});
	              const json = await res.json();
	              const trust = json && json.trust ? json.trust : null;
	              if (!trust) return;
	              lastDebugTrust = trust;
	            } catch (e) {
	              // best-effort only
	            }
	          }

	          async function refresh() {
	            try {
	              const res = await fetch("/health", {cache:"no-store"});
	              const json = await res.json();
	              const trust = json && json.trust ? json.trust : null;
	              $("healthRaw").textContent = JSON.stringify(json, null, 2);
	              if (!trust) { $("titleState").textContent = "No trust payload"; setDot("warn"); return; }
	              $("enf").textContent = trust.enforcement ?? "?";
	              $("mode").textContent = trust.mode ?? "?";
	              setBool("rpc", trust.rpc_ok_now);
	              setBool("read", trust.read_allowed);
	              setBool("write", trust.write_allowed);
	              setBool("paused", trust.paused);
	              const checkedAt = typeof trust.checked_at === "number" ? trust.checked_at : null;
	              const lastOkAt = typeof trust.last_ok_at === "number" ? trust.last_ok_at : null;
	              if (checkedAt && lastOkAt) {
	                $("lastOkAge").textContent = Math.max(0, checkedAt - lastOkAt) + "s";
	              } else {
	                $("lastOkAge").textContent = "?";
	              }

	              debugTick++;
	              if (lastDebugTrust === null || trust.trusted_now !== true || debugTick % 5 === 0) {
	                await refreshDebug();
	              }

	              const snap = (lastDebugTrust && lastDebugTrust.snapshot) ? lastDebugTrust.snapshot : null;
	              $("activeRoot").textContent = snap && snap.active_root ? shortHex(snap.active_root) : "?";
	              $("activePolicy").textContent = snap && snap.active_policy_hash ? shortHex(snap.active_policy_hash) : "?";

	              const codes = Array.isArray(trust.error_codes) ? trust.error_codes : [];
	              const errs = (lastDebugTrust && Array.isArray(lastDebugTrust.errors)) ? lastDebugTrust.errors : [];
	              const errEl = $("errorsBox");
	              if (codes.length || errs.length) {
	                errEl.style.display = "block";
	                errEl.textContent = "error_codes:\\n- " + (codes.length ? codes.join(\"\\n- \") : \"(none)\") + \"\\n\\nerrors:\\n- \" + (errs.length ? errs.join(\"\\n- \") : \"(none)\");
	              } else {
	                errEl.style.display = "none";
	                errEl.textContent = "";
	              }

              const ok = trust.trusted_now === true;
              $("titleState").textContent = ok ? "Trusted" : "Not trusted";
              setDot(ok ? "ok" : "bad");
              if (lastTrusted !== null && lastTrusted !== ok) {
                log("[STATE] trusted_now changed: " + (lastTrusted ? "true" : "false") + " -> " + (ok ? "true" : "false"));
              }
              lastTrusted = ok;
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
          $("btnCrypto").addEventListener("click", () => call("/crypto/roundtrip", "POST"));
          $("btnKeyBypass").addEventListener("click", () => call("/bypass/keys", "GET"));
          $("btnAgentBypass").addEventListener("click", () => call("/bypass/agent", "GET"));
          $("btnClear").addEventListener("click", () => { $("actionsLog").textContent = "Ready.\\n"; });

          $("btnTraffic").addEventListener("click", () => {
            if (trafficTimer) {
              clearInterval(trafficTimer);
              trafficTimer = null;
              log("[TRAFFIC] stopped");
              $("btnTraffic").textContent = "Start traffic";
              return;
            }
            log("[TRAFFIC] started (1 rps, mixed)");
            $("btnTraffic").textContent = "Stop traffic";
            trafficTimer = setInterval(async () => {
              if (trafficInFlight) return;
              trafficInFlight = true;
              try {
                trafficTick++;
                if (trafficTick % 10 === 0) {
                  await call("/bypass/pdo", "GET");
                } else if (trafficTick % 15 === 0) {
                  await call("/crypto/roundtrip", "POST");
                } else if (trafficTick % 3 === 0) {
                  await call("/db/write", "POST");
                } else {
                  await call("/db/read", "GET");
                }
              } finally {
                trafficInFlight = false;
              }
            }, 1000);
          });

          refresh();
          setInterval(refresh, 1000);
        </script>';

        echo '</body></html>';
        return;
    }

    if ($path === '/health') {
        $status = $kernelCtx->kernel->check()->toMonitorArray();

        $sendJson(200, [
            'ok' => true,
            'trust' => $status,
        ]);
        return;
    }

    if ($path === '/health/debug') {
        // Debug payload for local development / demo UI.
        // Not intended for public monitoring endpoints.
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

    if ($path === '/bypass/keys') {
        try {
            $keysDir = Config::get('crypto.keys_dir');
            if (!is_string($keysDir) || trim($keysDir) === '') {
                $sendText(404, 'crypto.keys_dir not configured');
                return;
            }

            $path = rtrim($keysDir, '/\\') . '/crypto_key_v1.key';
            $raw = @file_get_contents($path);
            if (is_string($raw) && strlen($raw) > 0) {
                $sendText(500, 'unexpected: key file readable (' . strlen($raw) . ' bytes)');
                return;
            }

            $sendText(403, 'denied');
            return;
        } catch (\Throwable) {
            $sendText(500, 'error');
            return;
        }
    }

    if ($path === '/bypass/agent') {
        try {
            $socketPath = Config::get('crypto.agent.socket_path');
            if (!is_string($socketPath) || trim($socketPath) === '') {
                $sendText(404, 'crypto.agent.socket_path not configured');
                return;
            }

            $shouldBeDenied = !$kernelCtx->status->readAllowed;

            $socketPath = trim($socketPath);
            if ($socketPath === '' || str_contains($socketPath, "\0")) {
                $sendText(500, 'invalid socket path');
                return;
            }

            $errno = 0;
            $errstr = '';
            $fp = @stream_socket_client('unix://' . $socketPath, $errno, $errstr, 1, STREAM_CLIENT_CONNECT);
            if (!is_resource($fp)) {
                $sendText(500, 'connect_failed');
                return;
            }

            stream_set_timeout($fp, 1);
            $payload = json_encode(['op' => 'get_all_keys', 'basename' => 'crypto_key'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if (!is_string($payload)) {
                fclose($fp);
                $sendText(500, 'encode_failed');
                return;
            }

            $ok = @fwrite($fp, $payload . "\n");
            if ($ok === false) {
                fclose($fp);
                $sendText(500, 'write_failed');
                return;
            }

            $raw = stream_get_contents($fp, 256 * 1024);
            fclose($fp);

            if (!is_string($raw) || trim($raw) === '') {
                $sendText($shouldBeDenied ? 403 : 500, $shouldBeDenied ? 'denied' : 'unexpected empty response');
                return;
            }

            $raw = trim($raw);
            $decoded = json_decode($raw, true);
            if (!is_array($decoded)) {
                $sendText(500, 'bad_response');
                return;
            }

            $okFlag = $decoded['ok'] ?? null;
            if ($okFlag === true) {
                $keys = $decoded['keys'] ?? null;
                $count = is_array($keys) ? count($keys) : 0;
                if ($count > 0) {
                    if ($shouldBeDenied) {
                        $sendText(500, 'unexpected: secrets-agent returned key material while read_allowed=false');
                        return;
                    }

                    $sendText(200, 'ok (keys_count=' . $count . ')');
                    return;
                }

                $sendText($shouldBeDenied ? 403 : 500, $shouldBeDenied ? 'denied' : 'unexpected: agent returned no keys');
                return;
            }

            $sendText($shouldBeDenied ? 403 : 500, $shouldBeDenied ? 'denied' : 'unexpected: agent denied while read_allowed=true');
            return;
        } catch (\Throwable) {
            $sendText(500, 'error');
            return;
        }
    }

    if ($path === '/crypto/roundtrip') {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            $sendText(405, 'Method Not Allowed');
            return;
        }

        try {
            $keysDir = Config::get('crypto.keys_dir');
            if (!is_string($keysDir) || trim($keysDir) === '') {
                $sendText(404, 'crypto.keys_dir not configured');
                return;
            }

            Crypto::initFromKeyManager($keysDir);

            $cipher = Crypto::encrypt('hello', 'compact_base64');
            $plain = Crypto::decrypt($cipher);

            Crypto::clearKey();

            if ($plain !== 'hello') {
                $sendText(500, 'roundtrip mismatch');
                return;
            }

            $sendJson(200, [
                'ok' => true,
                'cipher_len' => strlen($cipher),
            ]);
            return;
        } catch (TrustKernelException) {
            $sendText(403, 'denied');
            return;
        } catch (\Throwable) {
            try {
                Crypto::clearKey();
            } catch (\Throwable) {
            }
            $sendText(500, 'error');
            return;
        }
    }

    $sendText(404, 'Not Found');
},
    $_SERVER,
    $opts,
);
