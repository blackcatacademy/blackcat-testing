<?php

declare(strict_types=1);

use BlackCat\Config\Runtime\Config;
use BlackCat\Config\Security\KernelAttestations;
use BlackCat\Core\Database;
use BlackCat\Core\Database\DbBootstrap;
use BlackCat\Core\Kernel\HttpKernel;
use BlackCat\Core\Kernel\HttpKernelContext;
use BlackCat\Core\Kernel\HttpKernelOptions;
use BlackCat\Core\Security\Crypto;
use BlackCat\Core\TrustKernel\TrustKernelException;
use BlackCat\Core\TrustKernel\BlackCatConfigRepositoryAdapter;
use BlackCat\Core\TrustKernel\InstanceControllerReader;
use BlackCat\Core\TrustKernel\Sha256Merkle;
use BlackCat\Core\TrustKernel\TrustKernelConfig;
use BlackCat\Core\TrustKernel\Web3RpcQuorumClient;

require __DIR__ . '/../../vendor/autoload.php';

$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
$path = parse_url((string) $requestUri, PHP_URL_PATH);
if (!is_string($path) || $path === '') {
    $path = '/';
}

// Allow a small monitoring endpoint even when strict mode is denying reads.
// This endpoint must remain read-only and must not expose secrets.
$opts = new HttpKernelOptions();
if (
    $path === '/health'
    || $path === '/health/debug'
    || $path === '/'
    || $path === '/demo'
    || $path === '/demo/wallets'
    || $path === '/demo/tx-outbox'
) {
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
            'insecure_demo_url' => getenv('BLACKCAT_TESTING_INSECURE_URL') ?: 'http://localhost:8089/',
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

        echo '<header><div class="wrap"><h1>BlackCat Kernel Demo</h1><p>Live status from <span class="k">/health</span> + guarded DB probes.</p><p class="muted" style="margin-top:8px"><a id="insecureLinkTop" href="#" target="_blank" rel="noopener">Open unprotected demo →</a></p></div></header>';
        echo '<div class="wrap"><div class="grid">';

        echo '<div class="card"><div class="row" style="justify-content:space-between">';
        echo '<div class="row"><span id="dot" class="statusDot dotWarn"></span><span class="pill"><strong id="titleState">Loading…</strong></span><span class="pill">enforcement: <strong id="enf">?</strong></span><span class="pill">rpc: <strong id="rpc">?</strong></span><span class="pill">mode: <strong id="mode">?</strong></span></div>';
        echo '<div class="row"><span class="pill">read: <strong id="read">?</strong></span><span class="pill">write: <strong id="write">?</strong></span><span class="pill">paused: <strong id="paused">?</strong></span><span class="pill">last_ok_age: <strong id="lastOkAge">?</strong></span></div>';
        echo '</div>';
        echo '<div class="row" style="margin-top:10px"><span class="pill">chain_id: <strong id="chainId">?</strong></span><span class="pill">rpc_endpoints: <strong id="rpcEndpointsCount">?</strong></span><span class="pill">rpc_quorum: <strong id="rpcQuorum">?</strong></span><span class="pill">controller: <a class="k" id="controllerLink" href="#" target="_blank" rel="noopener">?</a></span></div>';

        echo '<div class="row" style="margin-top:10px"><span class="pill">active_root: <span class="k" id="activeRoot">?</span></span><span class="pill">policy_hash: <span class="k" id="activePolicy">?</span></span></div>';
        echo '<pre id="errorsBox" style="display:none"></pre>';

        echo '<details><summary>Raw /health JSON</summary><pre id="healthRaw">{"loading":true}</pre></details>';
        echo '<details><summary>Presentation script (secure vs unprotected)</summary><pre>';
        echo '1) Open the unprotected demo and click: leak key + leak DB creds' . "\n";
        echo '2) Back here: run the protected probes (key/db/agent) and see they are denied' . "\n";
        echo '3) While trusted: DB write works, crypto works' . "\n";
        echo '4) Wait for the scheduled tamper and watch the kernel fail-closed (writes blocked)' . "\n";
        echo '5) Optional: use the on-chain panel + Foundry runbooks to demo upgrade flows' . "\n";
        echo '</pre></details>';
        echo '<p class="muted">This page is intentionally allowed even when strict mode denies reads, so you can observe failures. It does not expose local filesystem details.</p>';
        echo '</div>';

        echo '<div class="card"><div class="row" style="justify-content:space-between">';
        echo '<div class="row"><span class="pill"><strong>Demo wallets</strong></span><span class="pill">token: <strong id="tokenSymbol">?</strong></span><span class="pill">wallets: <strong id="walletCount">?</strong></span></div>';
        echo '<div class="row"><button id="btnRefreshWallets">Refresh</button></div>';
        echo '</div>';
        echo '<pre id="walletsBox">{"loading":true}</pre>';
        echo '<p class="muted">Optional: mount <span class="k">/etc/blackcat/demo.wallets.public.json</span> (addresses only). Balances are read via JSON-RPC quorum (<span class="k">eth_getBalance</span>).</p>';
        echo '</div>';

        echo '<div class="card"><div class="row" style="justify-content:space-between">';
        echo '<div class="row"><span class="pill"><strong>Tx outbox</strong></span><span class="pill">anonymized on-chain signals</span></div>';
        echo '<div class="row"><button id="btnRefreshOutbox">Refresh</button></div>';
        echo '</div>';
        echo '<pre id="outboxBox">{"loading":true}</pre>';
        echo '<p class="muted">The trust-runner writes anonymized <span class="k">tx intents</span> here (incident reports by default; check-ins optional). A separate relayer can broadcast them to the chain (optional).</p>';
        echo '</div>';

        echo '<div class="card"><div class="row" style="justify-content:space-between">';
        echo '<div class="row"><span class="pill"><strong>On-chain upgrade info</strong></span><span class="pill">read-gated in strict mode</span></div>';
        echo '<div class="row"><button id="btnRefreshUpgrade">Refresh</button></div>';
        echo '</div>';
        echo '<pre id="upgradeBox">{"loading":true}</pre>';
        echo '<p class="muted">This block is intentionally unavailable when strict mode denies reads. Use it to copy values for Foundry scripts (publish release / set attestation / propose+activate upgrade).</p>';
        echo '</div>';

        echo '<div class="card"><div class="row"><button id="btnRead">DB read</button><button id="btnWrite">DB write</button><button id="btnBypass">Probe PDO bypass</button><button id="btnTraffic">Start traffic</button><button id="btnClear">Clear log</button></div>';
        echo '<pre id="actionsLog">Ready.</pre>';
        echo '<p class="muted">Expected in strict mode: writes denied when <span class="k">write_allowed=false</span>, reads denied when <span class="k">read_allowed=false</span>, and the PDO bypass probe is always denied.</p>';
        echo '</div>';

        echo '<div class="card"><div class="row"><button id="btnCrypto">Crypto roundtrip</button><button id="btnKeyBypass">Probe key file read</button><button id="btnDbCredsBypass">Probe DB creds file read</button><button id="btnAgentBypass">Probe secrets-agent</button></div>';
        echo '<p class="muted">Secrets-agent mode: key files and DB credential files must not be readable by the web runtime, but crypto/DB can still work through the agent (and the agent also enforces TrustKernel).</p>';
        echo '</div>';

        echo '<div class="card">';
        echo '<div class="row" style="justify-content:space-between">';
        echo '<div class="row"><span class="pill"><strong>Guided comparison</strong></span><span class="pill">secure vs unprotected</span></div>';
        echo '<div class="row"><button id="btnOpenInsecureHome">Open unprotected</button><button id="btnOpenInsecureLeakKey">Unprotected: leak key</button><button id="btnOpenInsecureLeakDb">Unprotected: leak DB creds</button><button id="btnOpenInsecureRead">Unprotected: DB read</button></div>';
        echo '</div>';
        echo '<p class="muted" style="margin-top:10px">';
        echo 'Suggested demo flow: (1) open the unprotected site and click leak endpoints, (2) run the protected probes above (key/db/agent), (3) wait for a tamper event and observe the kernel fail-closed.';
        echo '</p>';
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
          const insecureUrl = (typeof meta.insecure_demo_url === "string" && meta.insecure_demo_url) ? meta.insecure_demo_url : "http://localhost:8089/";
          $("insecureLinkTop").href = insecureUrl;
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
	              let walletsInFlight = false;
	              let lastWalletsAt = 0;
                let outboxInFlight = false;
                let lastOutboxAt = 0;
                let upgradeInFlight = false;
                let lastUpgradeAt = 0;

            function formatEdgenFromWeiHex(hexWei) {
              if (typeof hexWei !== "string" || !hexWei.startsWith("0x")) return "?";
              let wei;
              try { wei = BigInt(hexWei); } catch { return "?"; }
              const base = 10n ** 18n;
              const whole = wei / base;
              const frac = wei % base;
              const fracStr = frac.toString().padStart(18, "0").slice(0, 4);
              return `${whole.toString()}.${fracStr}`;
            }

            async function refreshWallets(force = false) {
              const now = Date.now();
              if (!force && walletsInFlight) return;
              if (!force && (now - lastWalletsAt) < 5000) return;
              walletsInFlight = true;
              lastWalletsAt = now;

              try {
                const res = await fetch("/demo/wallets", {cache:"no-store"});
                const json = await res.json();

                const token = json && typeof json.token_symbol === "string" ? json.token_symbol : "EDGEN";
                $("tokenSymbol").textContent = token;

                const wallets = json && Array.isArray(json.wallets) ? json.wallets : [];
                $("walletCount").textContent = wallets.length.toString();

                const rpcOk = json && json.rpc_ok === true;
                const lines = [];
                lines.push(rpcOk ? "[RPC] quorum ok" : "[RPC] not available (or quorum not met)");
                for (const w of wallets) {
                  const addr = w && typeof w.address === "string" ? w.address : "?";
                  const label = w && typeof w.label === "string" ? w.label : "wallet";
                  const bal = w && typeof w.balance_wei === "string" ? w.balance_wei : null;
                  const fmt = bal ? formatEdgenFromWeiHex(bal) : "?";
                  lines.push(`${label}: ${shortHex(addr)} balance=${fmt} ${token}`);
                }
                $("walletsBox").textContent = lines.join("\n");
              } catch (e) {
                $("walletsBox").textContent = "[wallets] fetch failed";
                $("walletCount").textContent = "?";
                $("tokenSymbol").textContent = "EDGEN";
              } finally {
                walletsInFlight = false;
              }
            }

            async function refreshOutbox(force = false) {
              const now = Date.now();
              if (!force && outboxInFlight) return;
              if (!force && (now - lastOutboxAt) < 2000) return;
              outboxInFlight = true;
              lastOutboxAt = now;

              try {
                const res = await fetch("/demo/tx-outbox", {cache:"no-store"});
                const text = await res.text();
                const raw = text.trim() !== "" ? text : "{}";
                try {
                  const json = JSON.parse(raw);
                  if (json && json.ok === true && json.counts) {
                    const c = json.counts;
                    const pending = typeof c.pending === "number" ? c.pending : 0;
                    const processing = typeof c.processing === "number" ? c.processing : 0;
                    const sent = typeof c.sent === "number" ? c.sent : 0;
                    const failed = typeof c.failed === "number" ? c.failed : 0;
                    const summary = {
                      counts: { pending, processing, sent, failed },
                      latest: json.latest ?? null
                    };
                    $("outboxBox").textContent = JSON.stringify(summary, null, 2);
                  } else {
                    $("outboxBox").textContent = raw;
                  }
                } catch (e) {
                  $("outboxBox").textContent = raw;
                }
              } catch (e) {
                $("outboxBox").textContent = "[outbox] fetch failed";
              } finally {
                outboxInFlight = false;
              }
            }

            async function refreshUpgrade(force = false) {
              const now = Date.now();
              if (!force && upgradeInFlight) return;
              if (!force && (now - lastUpgradeAt) < 5000) return;
              upgradeInFlight = true;
              lastUpgradeAt = now;

              try {
                const res = await fetch("/demo/upgrade-info", {cache:"no-store"});
                const text = await res.text();
                $("upgradeBox").textContent = text.trim() !== "" ? text : "{}";
              } catch (e) {
                $("upgradeBox").textContent = "[upgrade] fetch failed (expected when strict mode denies reads)";
              } finally {
                upgradeInFlight = false;
              }
            }

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
	                errEl.textContent = "error_codes:\\n- " + (codes.length ? codes.join("\\n- ") : "(none)") + "\\n\\nerrors:\\n- " + (errs.length ? errs.join("\\n- ") : "(none)");
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
            $("btnDbCredsBypass").addEventListener("click", () => call("/bypass/db-creds", "GET"));
            $("btnAgentBypass").addEventListener("click", () => call("/bypass/agent", "GET"));
            $("btnRefreshWallets").addEventListener("click", () => refreshWallets(true));
            $("btnRefreshOutbox").addEventListener("click", () => refreshOutbox(true));
            $("btnRefreshUpgrade").addEventListener("click", () => refreshUpgrade(true));
	          $("btnClear").addEventListener("click", () => { $("actionsLog").textContent = "Ready.\\n"; });

          const insecureBase = insecureUrl.replace(/\\/+$/, "");
          const openInsecure = (path) => {
            const p = typeof path === "string" ? path : "/";
            const url = insecureBase + (p.startsWith("/") ? p : ("/" + p));
            window.open(url, "_blank", "noopener");
          };

          $("btnOpenInsecureHome").addEventListener("click", () => openInsecure("/"));
          $("btnOpenInsecureLeakKey").addEventListener("click", () => openInsecure("/leak/key"));
          $("btnOpenInsecureLeakDb").addEventListener("click", () => openInsecure("/leak/db"));
          $("btnOpenInsecureRead").addEventListener("click", () => openInsecure("/db/read"));

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
            refreshWallets(true);
            refreshOutbox(true);
            refreshUpgrade(true);
	          setInterval(refresh, 1000);
            setInterval(() => refreshWallets(false), 5000);
            setInterval(() => refreshOutbox(false), 2000);
            setInterval(() => refreshUpgrade(false), 10000);
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

    if ($path === '/demo/wallets') {
        $file = '/etc/blackcat/demo.wallets.public.json';

        /** @var list<array{label:string,address:string}> $wallets */
        $wallets = [];

        try {
            if (is_file($file) && !is_link($file) && is_readable($file)) {
                $raw = @file_get_contents($file);
                if (is_string($raw) && trim($raw) !== '') {
                    /** @var mixed $decoded */
                    $decoded = json_decode($raw, true);
                    if (is_array($decoded)) {
                        $items = isset($decoded['wallets']) && is_array($decoded['wallets']) ? $decoded['wallets'] : $decoded;
                        if (is_array($items)) {
                            foreach ($items as $i => $w) {
                                $addr = null;
                                $label = null;
                                if (is_string($w)) {
                                    $addr = $w;
                                } elseif (is_array($w)) {
                                    $addr = $w['address'] ?? null;
                                    $label = $w['label'] ?? null;
                                }
                                if (!is_string($addr)) {
                                    continue;
                                }
                                $addr = trim($addr);
                                if (!preg_match('/^0x[a-fA-F0-9]{40}$/', $addr)) {
                                    continue;
                                }
                                $addr = '0x' . strtolower(substr($addr, 2));
                                if ($addr === '0x0000000000000000000000000000000000000000') {
                                    continue;
                                }
                                $labelStr = is_string($label) && trim($label) !== '' ? trim($label) : ('wallet-' . ((int) $i + 1));
                                $wallets[] = ['label' => $labelStr, 'address' => $addr];
                                if (count($wallets) >= 10) {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        } catch (\Throwable) {
            // best-effort only
        }

        $chainId = null;
        $endpoints = null;
        $quorum = null;
        $timeoutSec = 5;

        try {
            $v = Config::get('trust.web3.chain_id');
            if (is_int($v)) {
                $chainId = $v;
            } elseif (is_string($v) && ctype_digit(trim($v))) {
                $chainId = (int) trim($v);
            }

            $e = Config::get('trust.web3.rpc_endpoints');
            if (is_array($e)) {
                $out = [];
                foreach ($e as $ep) {
                    if (!is_string($ep)) {
                        continue;
                    }
                    $ep = trim($ep);
                    if ($ep === '' || str_contains($ep, "\0")) {
                        continue;
                    }
                    $out[] = $ep;
                }
                $endpoints = $out !== [] ? $out : null;
            }

            $q = Config::get('trust.web3.rpc_quorum');
            if (is_int($q)) {
                $quorum = $q;
            } elseif (is_string($q) && ctype_digit(trim($q))) {
                $quorum = (int) trim($q);
            }

            $t = Config::get('trust.web3.timeout_sec');
            if (is_int($t) && $t >= 1 && $t <= 60) {
                $timeoutSec = $t;
            } elseif (is_string($t) && ctype_digit(trim($t))) {
                $timeoutSec = max(1, min(60, (int) trim($t)));
            }
        } catch (\Throwable) {
            // best-effort only
        }

        $outWallets = [];
        $rpcOk = false;
        $rpcError = null;

        if ($chainId !== null && $endpoints !== null && $quorum !== null && $wallets !== []) {
            try {
                $rpc = new Web3RpcQuorumClient($endpoints, $chainId, $quorum, null, $timeoutSec);
                foreach ($wallets as $w) {
                    $addr = $w['address'];
                    $bal = $rpc->ethGetBalanceQuorum($addr);
                    $outWallets[] = [
                        'label' => $w['label'],
                        'address' => $addr,
                        'balance_wei' => $bal,
                    ];
                }
                $rpcOk = true;
            } catch (\Throwable) {
                $rpcOk = false;
                $rpcError = 'rpc_error';
            }
        } else {
            $outWallets = $wallets;
        }

        $sendJson(200, [
            'ok' => true,
            'token_symbol' => 'EDGEN',
            'chain_id' => $chainId,
            'rpc_ok' => $rpcOk,
            'wallets' => $outWallets,
            'error' => $rpcError,
        ]);
        return;
    }

    if ($path === '/demo/tx-outbox') {
        $dir = null;

        try {
            $raw = Config::get('trust.web3.tx_outbox_dir');
            if (is_string($raw) && trim($raw) !== '') {
                $dir = Config::repo()->resolvePath(trim($raw));
            }
        } catch (\Throwable) {
            $dir = null;
        }

        if (!is_string($dir) || trim($dir) === '' || str_contains($dir, "\0")) {
            $sendJson(200, ['ok' => false, 'error' => 'tx_outbox_not_configured', 'items' => []]);
            return;
        }

        $dir = trim($dir);
        if (!is_dir($dir) || is_link($dir) || !is_readable($dir)) {
            $sendJson(200, ['ok' => false, 'error' => 'tx_outbox_unavailable', 'items' => []]);
            return;
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
            if (!is_array($decoded)) {
                return null;
            }

            return $decoded;
        };

        $safeTextRead = static function (string $path, int $maxBytes = 2048): ?string {
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

            return trim($raw);
        };

        $listTxJsonFiles = static function (string $stateDir): array {
            if (trim($stateDir) === '' || str_contains($stateDir, "\0")) {
                return [];
            }
            if (!is_dir($stateDir) || is_link($stateDir) || !is_readable($stateDir)) {
                return [];
            }

            $files = glob(rtrim($stateDir, '/\\') . '/tx.*.json') ?: [];
            rsort($files);
            return array_values(array_filter($files, 'is_string'));
        };

        $states = [
            'pending' => $dir,
            'processing' => rtrim($dir, '/\\') . '/processing',
            'sent' => rtrim($dir, '/\\') . '/sent',
            'failed' => rtrim($dir, '/\\') . '/failed',
        ];

        $explorerBaseUrl = null;
        try {
            $cid = Config::get('trust.web3.chain_id');
            if (is_int($cid)) {
                if ($cid === 4207) {
                    $explorerBaseUrl = 'https://edgenscan.io';
                }
            } elseif (is_string($cid) && ctype_digit(trim($cid))) {
                if ((int) trim($cid) === 4207) {
                    $explorerBaseUrl = 'https://edgenscan.io';
                }
            }
        } catch (\Throwable) {
            $explorerBaseUrl = null;
        }

        $counts = [];
        $latest = [
            'pending' => [],
            'sent' => [],
            'failed' => [],
        ];

        foreach ($states as $state => $stateDir) {
            $files = $listTxJsonFiles($stateDir);
            $counts[$state] = count($files);

            if ($state === 'pending') {
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
                continue;
            }

            if ($state === 'sent') {
                foreach ($files as $file) {
                    $base = basename($file);
                    if ($base === '' || str_contains($base, "\0")) {
                        continue;
                    }

                    $stem = preg_replace('/\\.json$/', '', $base);
                    if (!is_string($stem) || $stem === '') {
                        continue;
                    }

                    $decoded = $safeJsonRead($file);
                    $receiptPath = rtrim($stateDir, '/\\') . '/' . $stem . '.receipt.json';
                    $receipt = $safeJsonRead($receiptPath, 128 * 1024);

                    $txHash = null;
                    $status = null;
                    if (is_array($receipt)) {
                        if (isset($receipt['transactionHash']) && is_string($receipt['transactionHash'])) {
                            $txHash = $receipt['transactionHash'];
                            $status = $receipt['status'] ?? null;
                        } elseif (isset($receipt['tx_hash']) && is_string($receipt['tx_hash'])) {
                            $txHash = $receipt['tx_hash'];
                            $status = $receipt['receipt'] ?? null;
                        }
                    }

                    $explorerUrl = null;
                    if (is_string($txHash) && preg_match('/^0x[0-9a-fA-F]{64}$/', $txHash) === 1) {
                        if (is_string($explorerBaseUrl) && trim($explorerBaseUrl) !== '') {
                            $explorerUrl = rtrim($explorerBaseUrl, '/') . '/tx/' . $txHash;
                        }
                    }

                    $latest['sent'][] = [
                        'file' => $base,
                        'tx_hash' => $txHash,
                        'explorer' => $explorerUrl,
                        'receipt_status' => $status,
                        'intent' => is_array($decoded) ? [
                            'created_at' => $decoded['created_at'] ?? null,
                            'method' => $decoded['method'] ?? null,
                            'meta' => $decoded['meta'] ?? null,
                        ] : null,
                    ];

                    if (count($latest['sent']) >= 10) {
                        break;
                    }
                }
                continue;
            }

            if ($state === 'failed') {
                foreach ($files as $file) {
                    $base = basename($file);
                    if ($base === '' || str_contains($base, "\0")) {
                        continue;
                    }

                    $stem = preg_replace('/\\.json$/', '', $base);
                    if (!is_string($stem) || $stem === '') {
                        continue;
                    }

                    $decoded = $safeJsonRead($file);
                    $errorPath = rtrim($stateDir, '/\\') . '/' . $stem . '.error.txt';
                    $error = $safeTextRead($errorPath, 4096);

                    $latest['failed'][] = [
                        'file' => $base,
                        'error' => $error,
                        'intent' => is_array($decoded) ? [
                            'created_at' => $decoded['created_at'] ?? null,
                            'method' => $decoded['method'] ?? null,
                            'meta' => $decoded['meta'] ?? null,
                        ] : null,
                    ];

                    if (count($latest['failed']) >= 10) {
                        break;
                    }
                }
                continue;
            }
        }

        $sendJson(200, [
            'ok' => true,
            'counts' => $counts,
            'latest' => $latest,
            'note' => 'These are tx intents only; broadcasting requires an external relayer (EOA/Safe/KernelAuthority).',
        ]);
        return;
    }

    if ($path === '/demo/upgrade-info') {
        try {
            $repo = Config::repo();
            $tk = TrustKernelConfig::fromRuntimeConfig(new BlackCatConfigRepositoryAdapter($repo));
            if ($tk === null) {
                $sendJson(500, ['ok' => false, 'error' => 'trust.web3 not configured']);
                return;
            }

            $manifestPath = $tk->integrityManifestPath;
            $integrityRoot = null;
            $integrityUriHash = null;
            $filesCount = null;

            if (is_file($manifestPath) && !is_link($manifestPath) && is_readable($manifestPath)) {
                $raw = @file_get_contents($manifestPath);
                if (is_string($raw) && trim($raw) !== '') {
                    /** @var mixed $decoded */
                    $decoded = json_decode($raw, true);
                    if (is_array($decoded)) {
                        $files = $decoded['files'] ?? null;
                        if (is_array($files) && $files !== []) {
                            $integrityRoot = Sha256Merkle::root($files);
                            $filesCount = count($files);
                        }
                        $uri = $decoded['uri'] ?? null;
                        if (is_string($uri) && trim($uri) !== '') {
                            $integrityUriHash = \BlackCat\Core\TrustKernel\UriHasher::sha256Bytes32($uri);
                        }
                    }
                }
            }

            $rpc = new Web3RpcQuorumClient($tk->rpcEndpoints, $tk->chainId, $tk->rpcQuorum, null, $tk->rpcTimeoutSec);
            $ic = new InstanceControllerReader($rpc);

            $controller = $tk->instanceController;
            $componentId = $ic->expectedComponentId($controller);

            $attV1Key = $tk->runtimeConfigAttestationKey;
            $attV2Key = $tk->runtimeConfigAttestationKeyV2;
            $attV1 = [
                'key' => $attV1Key,
                'value' => $ic->attestation($controller, $attV1Key),
                'locked' => $ic->attestationLocked($controller, $attV1Key),
                'updated_at' => $ic->attestationUpdatedAt($controller, $attV1Key),
            ];
            $attV2 = [
                'key' => $attV2Key,
                'value' => $ic->attestation($controller, $attV2Key),
                'locked' => $ic->attestationLocked($controller, $attV2Key),
                'updated_at' => $ic->attestationUpdatedAt($controller, $attV2Key),
            ];

            $composerLockKey = KernelAttestations::composerLockAttestationKeyV1();
            $composerLockLocal = null;
            $composerLockPath = rtrim($tk->integrityRootDir, "/\\") . DIRECTORY_SEPARATOR . 'composer.lock';
            if (is_file($composerLockPath) && !is_link($composerLockPath) && is_readable($composerLockPath)) {
                $raw = @file_get_contents($composerLockPath);
                if (is_string($raw) && trim($raw) !== '') {
                    /** @var mixed $decoded */
                    $decoded = json_decode($raw, true);
                    if (is_array($decoded)) {
                        /** @var array<string,mixed> $decoded */
                        $composerLockLocal = KernelAttestations::composerLockAttestationValueV1($decoded);
                    }
                }
            }

            $composerLockOnChain = [
                'key' => $composerLockKey,
                'value' => $ic->attestation($controller, $composerLockKey),
                'locked' => $ic->attestationLocked($controller, $composerLockKey),
                'updated_at' => $ic->attestationUpdatedAt($controller, $composerLockKey),
            ];

            $phpFingerprintKey = KernelAttestations::phpFingerprintAttestationKeyV2();
            $phpFingerprintPayload = KernelAttestations::phpFingerprintPayloadV2();
            $phpFingerprintLocal = KernelAttestations::phpFingerprintAttestationValueV2($phpFingerprintPayload);

            $phpFingerprintOnChain = [
                'key' => $phpFingerprintKey,
                'value' => $ic->attestation($controller, $phpFingerprintKey),
                'locked' => $ic->attestationLocked($controller, $phpFingerprintKey),
                'updated_at' => $ic->attestationUpdatedAt($controller, $phpFingerprintKey),
            ];

            $imageDigestKey = KernelAttestations::imageDigestAttestationKeyV1();
            $imageDigestLocal = null;
            $imageDigestPath = '/etc/blackcat/image.digest';
            if (is_file($imageDigestPath) && !is_link($imageDigestPath) && is_readable($imageDigestPath)) {
                $raw = @file_get_contents($imageDigestPath);
                if (is_string($raw) && trim($raw) !== '') {
                    try {
                        $imageDigestLocal = KernelAttestations::imageDigestAttestationValueV1($raw);
                    } catch (\Throwable) {
                        $imageDigestLocal = null;
                    }
                }
            }

            $imageDigestOnChain = [
                'key' => $imageDigestKey,
                'value' => $ic->attestation($controller, $imageDigestKey),
                'locked' => $ic->attestationLocked($controller, $imageDigestKey),
                'updated_at' => $ic->attestationUpdatedAt($controller, $imageDigestKey),
            ];

            $payload = [
                'ok' => true,
                'controller' => $controller,
                'component_id' => $componentId,
                'local' => [
                    'integrity_root' => $integrityRoot,
                    'integrity_uri_hash' => $integrityUriHash,
                    'files_count' => $filesCount,
                    'policy_hash_v3_strict' => $tk->policyHashV3Strict,
                    'policy_hash_v3_warn' => $tk->policyHashV3Warn,
                    'policy_hash_v3_strict_v2' => $tk->policyHashV3StrictV2,
                    'policy_hash_v3_warn_v2' => $tk->policyHashV3WarnV2,
                    'policy_hash_v4_strict' => $tk->policyHashV4Strict,
                    'policy_hash_v4_warn' => $tk->policyHashV4Warn,
                    'policy_hash_v4_strict_v2' => $tk->policyHashV4StrictV2,
                    'policy_hash_v4_warn_v2' => $tk->policyHashV4WarnV2,
                    'policy_hash_v5_strict' => $tk->policyHashV5Strict,
                    'policy_hash_v5_warn' => $tk->policyHashV5Warn,
                    'policy_hash_v5_strict_v2' => $tk->policyHashV5StrictV2,
                    'policy_hash_v5_warn_v2' => $tk->policyHashV5WarnV2,
                    'runtime_config_value' => $tk->runtimeConfigCanonicalSha256,
                    'attestation_key_v1' => $attV1Key,
                    'attestation_key_v2' => $attV2Key,
                    'http_allowed_hosts' => Config::get('http.allowed_hosts'),
                    'http_allowed_hosts_value' => $tk->httpAllowedHostsCanonicalSha256,
                    'http_allowed_hosts_attestation_key' => $tk->httpAllowedHostsAttestationKeyV1,
                    'composer_lock_path' => $composerLockPath,
                    'composer_lock_value' => $composerLockLocal,
                    'composer_lock_attestation_key' => $composerLockKey,
                    'php_fingerprint_value' => $phpFingerprintLocal,
                    'php_fingerprint_attestation_key' => $phpFingerprintKey,
                    'php_fingerprint_meta' => [
                        'php_version' => $phpFingerprintPayload['php_version'] ?? null,
                        'extensions_count' => is_array($phpFingerprintPayload['extensions'] ?? null) ? count($phpFingerprintPayload['extensions']) : null,
                    ],
                    'image_digest_path' => $imageDigestPath,
                    'image_digest_config_path' => $tk->imageDigestFilePath,
                    'image_digest_value' => $imageDigestLocal,
                    'image_digest_attestation_key' => $imageDigestKey,
                ],
                'on_chain' => [
                    'attestation_v1' => $attV1,
                    'attestation_v2' => $attV2,
                    'attestation_http_allowed_hosts_v1' => [
                        'key' => $tk->httpAllowedHostsAttestationKeyV1,
                        'value' => $ic->attestation($controller, $tk->httpAllowedHostsAttestationKeyV1),
                        'locked' => $ic->attestationLocked($controller, $tk->httpAllowedHostsAttestationKeyV1),
                        'updated_at' => $ic->attestationUpdatedAt($controller, $tk->httpAllowedHostsAttestationKeyV1),
                    ],
                    'attestation_composer_lock_v1' => $composerLockOnChain,
                    'attestation_php_fingerprint_v1' => $phpFingerprintOnChain,
                    'attestation_image_digest_v1' => $imageDigestOnChain,
                ],
                'notes' => [
                    'To run a live upgrade demo, use blackcat-kernel-contracts Foundry scripts (publish release, set+lock attestation if needed, then propose+activate upgrade).',
                    'Use policy_hash_v3_strict_v2 if the v1 attestation key is already locked and the runtime config changed.',
                    'Policy v5 additionally binds http.allowed_hosts via an on-chain attestation (defense-in-depth against host allowlist tamper).',
                    'Optional additional attestations (composer.lock / PHP fingerprint / image digest) provide deeper tamper resistance, but increase upgrade discipline (you must update+lock them on upgrades).',
                ],
            ];

            $sendJson(200, $payload);
            return;
        } catch (\Throwable $e) {
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

    if ($path === '/bypass/db-creds') {
        try {
            $file = Config::get('db.credentials_file');
            if (!is_string($file) || trim($file) === '') {
                $sendText(404, 'db.credentials_file not configured');
                return;
            }

            $file = trim($file);
            if ($file === '' || str_contains($file, "\0")) {
                $sendText(500, 'invalid db.credentials_file path');
                return;
            }

            $raw = @file_get_contents($file);
            if (is_string($raw) && strlen($raw) > 0) {
                $sendText(500, 'unexpected: db credentials file readable (' . strlen($raw) . ' bytes)');
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
            $modeRaw = Config::get('crypto.agent.mode');
            $mode = is_string($modeRaw) ? strtolower(trim($modeRaw)) : 'keyless';
            if ($mode !== 'keys' && $mode !== 'keyless') {
                $mode = 'keyless';
            }

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
                    if ($mode === 'keyless') {
                        $sendText(500, 'unexpected: secrets-agent exported keys in keyless mode');
                        return;
                    }
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

            $err = $decoded['error'] ?? null;
            if (is_string($err) && $err === 'key_export_disabled') {
                $sendText(403, 'denied (key export disabled by design)');
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
