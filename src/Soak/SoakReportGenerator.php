<?php

declare(strict_types=1);

namespace BlackCat\Testing\Soak;

final class SoakReportGenerator
{
    /**
     * Generates an English Markdown report for a completed minimal-prod run.
     *
     * The report is built from:
     * - attacker logs: meta + events JSONL (and summary JSON if present),
     * - runtime config (optional),
     * - tx-outbox (optional, for intent/broadcast stats).
     */
    public static function generateToFile(
        ?string $runId,
        string $logsDir,
        string $outDir,
        ?string $outboxDir = null,
        ?string $runtimeConfigPath = null,
    ): string {
        $logsDir = self::normalizeDir($logsDir, 'logs_dir');
        $outDir = self::normalizeDir($outDir, 'out_dir', createIfMissing: true);

        $runId = self::resolveRunId($runId, $logsDir);

        $meta = self::readJsonFileIfExists($logsDir . DIRECTORY_SEPARATOR . 'meta.' . $runId . '.json');
        $summary = self::readJsonFileIfExists($logsDir . DIRECTORY_SEPARATOR . 'summary.' . $runId . '.json');

        $eventsPath = $logsDir . DIRECTORY_SEPARATOR . 'events.' . $runId . '.jsonl';
        if (!is_file($eventsPath) || is_link($eventsPath) || !is_readable($eventsPath)) {
            throw new \RuntimeException('events file is missing/unreadable: ' . $eventsPath);
        }

        $runtimeCfg = null;
        if (is_string($runtimeConfigPath) && trim($runtimeConfigPath) !== '') {
            $runtimeCfg = self::readJsonFileIfExists(trim($runtimeConfigPath));
        }

        if ($outboxDir === null && is_array($runtimeCfg)) {
            $derived = self::getNestedString($runtimeCfg, ['trust', 'web3', 'tx_outbox_dir']);
            if (is_string($derived) && trim($derived) !== '') {
                $outboxDir = trim($derived);
            }
        }

        $events = self::scanEvents($eventsPath);
        $outbox = null;
        if (is_string($outboxDir) && trim($outboxDir) !== '') {
            try {
                $outbox = self::scanOutbox(trim($outboxDir));
            } catch (\Throwable $e) {
                $outbox = [
                    'dir' => trim($outboxDir),
                    'error' => $e->getMessage(),
                ];
            }
        }

        $md = self::renderMarkdown($runId, $meta, $summary, $events, $runtimeCfg, $outbox);

        $outPath = $outDir . DIRECTORY_SEPARATOR . 'SOAK_REPORT_' . $runId . '.md';
        $bytes = @file_put_contents($outPath, $md);
        if (!is_int($bytes) || $bytes < 1) {
            throw new \RuntimeException('unable to write report: ' . $outPath);
        }

        return $outPath;
    }

    private static function normalizeDir(string $path, string $label, bool $createIfMissing = false): string
    {
        $path = trim($path);
        if ($path === '' || str_contains($path, "\0")) {
            throw new \RuntimeException($label . ' is invalid.');
        }

        if ($createIfMissing && !is_dir($path)) {
            @mkdir($path, 0770, true);
        }

        if (!is_dir($path) || is_link($path) || !is_readable($path)) {
            throw new \RuntimeException($label . ' is not a readable directory: ' . $path);
        }

        return rtrim($path, DIRECTORY_SEPARATOR);
    }

    private static function resolveRunId(?string $runId, string $logsDir): string
    {
        $runId = is_string($runId) ? trim($runId) : '';
        if ($runId === '') {
            $latest = self::latestRunIdFromMeta($logsDir);
            if ($latest === null) {
                throw new \RuntimeException('unable to detect run_id (no meta.*.json in logs dir).');
            }
            $runId = $latest;
        }

        if (!preg_match('/^[A-Za-z0-9_.-]{6,80}$/', $runId)) {
            throw new \RuntimeException('run_id format is invalid: ' . $runId);
        }

        return $runId;
    }

    private static function latestRunIdFromMeta(string $logsDir): ?string
    {
        $pattern = $logsDir . DIRECTORY_SEPARATOR . 'meta.*.json';
        $files = glob($pattern, GLOB_NOSORT);
        if ($files === false || $files === []) {
            return null;
        }

        $bestPath = null;
        $bestMtime = null;

        foreach ($files as $file) {
            if (!is_string($file) || $file === '' || !is_file($file) || is_link($file)) {
                continue;
            }
            $base = basename($file);
            if (!preg_match('/^meta\\.(?<id>[A-Za-z0-9_.-]{6,80})\\.json$/', $base, $m)) {
                continue;
            }
            $mtime = @filemtime($file);
            if (!is_int($mtime)) {
                continue;
            }
            if ($bestMtime === null || $mtime >= $bestMtime) {
                $bestMtime = $mtime;
                $bestPath = $file;
            }
        }

        if (!is_string($bestPath)) {
            return null;
        }

        $base = basename($bestPath);
        if (!preg_match('/^meta\\.(?<id>[A-Za-z0-9_.-]{6,80})\\.json$/', $base, $m)) {
            return null;
        }

        return $m['id'];
    }

    /**
     * @return array<string,mixed>|null
     */
    private static function readJsonFileIfExists(string $path): ?array
    {
        $path = trim($path);
        if ($path === '' || str_contains($path, "\0")) {
            return null;
        }
        if (!is_file($path) || is_link($path) || !is_readable($path)) {
            return null;
        }

        $raw = @file_get_contents($path);
        if (!is_string($raw) || $raw === '' || str_contains($raw, "\0")) {
            return null;
        }

        try {
            /** @var mixed $decoded */
            $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return null;
        }

        if (!is_array($decoded)) {
            return null;
        }

        /** @var array<string,mixed> $decoded */
        return $decoded;
    }

    /**
     * @return array{
     *   ticks:int,
     *   first_ts:?string,
     *   last_ts:?string,
     *   first_t_sec:?int,
     *   last_t_sec:?int,
     *   enforcement:?string,
     *   trust_true:int,
     *   trust_false:int,
     *   trust_flips:int,
     *   rpc_ok_true:int,
     *   rpc_ok_false:int,
     *   rpc_flips:int,
     *   max_consecutive_rpc_outage:int,
     *   read_allowed_true:int,
     *   read_allowed_false:int,
     *   write_allowed_true:int,
     *   write_allowed_false:int,
     *   http_codes:array<string,array<int,int>>,
     *   error_codes:array<string,int>
     * }
     */
    private static function scanEvents(string $eventsPath): array
    {
        $fp = @fopen($eventsPath, 'rb');
        if ($fp === false) {
            throw new \RuntimeException('unable to open events file: ' . $eventsPath);
        }

        $ticks = 0;
        $firstTs = null;
        $lastTs = null;
        $firstTSec = null;
        $lastTSec = null;
        $enforcement = null;

        $trustTrue = 0;
        $trustFalse = 0;
        $trustFlips = 0;
        $rpcOkTrue = 0;
        $rpcOkFalse = 0;
        $rpcFlips = 0;
        $readAllowedTrue = 0;
        $readAllowedFalse = 0;
        $writeAllowedTrue = 0;
        $writeAllowedFalse = 0;

        $maxConsecutiveRpcOutage = 0;
        $rpcOutageRun = 0;

        /** @var array<string,array<int,int>> $httpCodes */
        $httpCodes = [];
        /** @var array<string,int> $errorCodes */
        $errorCodes = [];

        $prevTrusted = null;
        $prevRpcOk = null;

        try {
            while (($line = fgets($fp)) !== false) {
                $line = trim($line);
                if ($line === '') {
                    continue;
                }

                try {
                    /** @var mixed $decoded */
                    $decoded = json_decode($line, true, 128, JSON_THROW_ON_ERROR);
                } catch (\Throwable) {
                    continue;
                }

                if (!is_array($decoded)) {
                    continue;
                }
                /** @var array<string,mixed> $event */
                $event = $decoded;

                $ticks++;

                $ts = $event['ts'] ?? null;
                if (is_string($ts) && $ts !== '' && !str_contains($ts, "\0")) {
                    if ($firstTs === null) {
                        $firstTs = $ts;
                    }
                    $lastTs = $ts;
                }

                $tSec = $event['t_sec'] ?? null;
                if (is_int($tSec) || (is_string($tSec) && ctype_digit($tSec))) {
                    $tSec = (int) $tSec;
                    if ($firstTSec === null) {
                        $firstTSec = $tSec;
                    }
                    $lastTSec = $tSec;
                }

                $http = $event['http'] ?? null;
                if (is_array($http)) {
                    /** @var array<string,mixed> $http */
                    foreach ($http as $name => $codeRaw) {
                        if (!is_string($name) || $name === '' || str_contains($name, "\0")) {
                            continue;
                        }
                        if (!is_int($codeRaw) && !(is_string($codeRaw) && ctype_digit($codeRaw))) {
                            continue;
                        }
                        $code = (int) $codeRaw;
                        if (!isset($httpCodes[$name])) {
                            $httpCodes[$name] = [];
                        }
                        $httpCodes[$name][$code] = ($httpCodes[$name][$code] ?? 0) + 1;
                    }
                }

                $health = $event['health'] ?? null;
                if (!is_array($health)) {
                    continue;
                }
                /** @var array<string,mixed> $health */

                if ($enforcement === null) {
                    $enf = $health['enforcement'] ?? null;
                    if (is_string($enf) && $enf !== '' && !str_contains($enf, "\0")) {
                        $enforcement = $enf;
                    }
                }

                $trustedNow = $health['trusted_now'] ?? null;
                if (is_bool($trustedNow)) {
                    if ($trustedNow) {
                        $trustTrue++;
                    } else {
                        $trustFalse++;
                    }

                    if (is_bool($prevTrusted) && $prevTrusted !== $trustedNow) {
                        $trustFlips++;
                    }
                    $prevTrusted = $trustedNow;
                }

                $rpcOkNow = $health['rpc_ok_now'] ?? null;
                if (is_bool($rpcOkNow)) {
                    if ($rpcOkNow) {
                        $rpcOkTrue++;
                        $rpcOutageRun = 0;
                    } else {
                        $rpcOkFalse++;
                        $rpcOutageRun++;
                        if ($rpcOutageRun > $maxConsecutiveRpcOutage) {
                            $maxConsecutiveRpcOutage = $rpcOutageRun;
                        }
                    }

                    if (is_bool($prevRpcOk) && $prevRpcOk !== $rpcOkNow) {
                        $rpcFlips++;
                    }
                    $prevRpcOk = $rpcOkNow;
                }

                $readAllowed = $health['read_allowed'] ?? null;
                if (is_bool($readAllowed)) {
                    $readAllowed ? $readAllowedTrue++ : $readAllowedFalse++;
                }

                $writeAllowed = $health['write_allowed'] ?? null;
                if (is_bool($writeAllowed)) {
                    $writeAllowed ? $writeAllowedTrue++ : $writeAllowedFalse++;
                }

                $codes = $health['error_codes'] ?? null;
                if (is_array($codes)) {
                    foreach ($codes as $code) {
                        if (!is_string($code) || $code === '' || str_contains($code, "\0")) {
                            continue;
                        }
                        $errorCodes[$code] = ($errorCodes[$code] ?? 0) + 1;
                    }
                }
            }
        } finally {
            fclose($fp);
        }

        foreach ($httpCodes as $k => $map) {
            ksort($map);
            $httpCodes[$k] = $map;
        }
        ksort($httpCodes);
        ksort($errorCodes);

        return [
            'ticks' => $ticks,
            'first_ts' => $firstTs,
            'last_ts' => $lastTs,
            'first_t_sec' => $firstTSec,
            'last_t_sec' => $lastTSec,
            'enforcement' => $enforcement,
            'trust_true' => $trustTrue,
            'trust_false' => $trustFalse,
            'trust_flips' => $trustFlips,
            'rpc_ok_true' => $rpcOkTrue,
            'rpc_ok_false' => $rpcOkFalse,
            'rpc_flips' => $rpcFlips,
            'max_consecutive_rpc_outage' => $maxConsecutiveRpcOutage,
            'read_allowed_true' => $readAllowedTrue,
            'read_allowed_false' => $readAllowedFalse,
            'write_allowed_true' => $writeAllowedTrue,
            'write_allowed_false' => $writeAllowedFalse,
            'http_codes' => $httpCodes,
            'error_codes' => $errorCodes,
        ];
    }

    /**
     * @return array{
     *   dir:string,
     *   sig:array{pending:int,processing:int,signed:int,failed:int,total:int,by_kind:array<string,int>},
     *   tx:array{pending:int,processing:int,sent:int,failed:int,total:int,by_method:array<string,int>},
     *   receipts:array{total:int,dry_run:int,pending:int,success:int,revert:int,unknown:int}
     * }
     */
    private static function scanOutbox(string $outboxDir): array
    {
        $outboxDir = self::normalizeDir($outboxDir, 'tx_outbox_dir');

        $dirs = [
            'root' => $outboxDir,
            'processing' => $outboxDir . DIRECTORY_SEPARATOR . 'processing',
            'signed' => $outboxDir . DIRECTORY_SEPARATOR . 'signed',
            'sent' => $outboxDir . DIRECTORY_SEPARATOR . 'sent',
            'failed' => $outboxDir . DIRECTORY_SEPARATOR . 'failed',
        ];

        /** @var array<string,int> $sigByKind */
        $sigByKind = [];
        $sigPending = 0;
        $sigProcessing = 0;
        $sigSigned = 0;
        $sigFailed = 0;

        foreach (['root' => 'pending', 'processing' => 'processing', 'signed' => 'signed', 'failed' => 'failed'] as $key => $bucket) {
            $dir = $dirs[$key];
            if (!is_dir($dir) || is_link($dir) || !is_readable($dir)) {
                continue;
            }
            $files = self::globSorted($dir . DIRECTORY_SEPARATOR . 'sig.*.json');
            foreach ($files as $f) {
                $bucket === 'pending' && $sigPending++;
                $bucket === 'processing' && $sigProcessing++;
                $bucket === 'signed' && $sigSigned++;
                $bucket === 'failed' && $sigFailed++;

                $payload = self::readJsonFileIfExists($f);
                $kind = is_array($payload) ? ($payload['kind'] ?? null) : null;
                if (!is_string($kind) || trim($kind) === '' || str_contains($kind, "\0")) {
                    $kind = 'unknown';
                }
                $kind = trim($kind);
                $sigByKind[$kind] = ($sigByKind[$kind] ?? 0) + 1;
            }
        }

        /** @var array<string,int> $txByMethod */
        $txByMethod = [];
        $txPending = 0;
        $txProcessing = 0;
        $txSent = 0;
        $txFailed = 0;

        foreach (['root' => 'pending', 'processing' => 'processing', 'sent' => 'sent', 'failed' => 'failed'] as $key => $bucket) {
            $dir = $dirs[$key];
            if (!is_dir($dir) || is_link($dir) || !is_readable($dir)) {
                continue;
            }
            $files = self::globSorted($dir . DIRECTORY_SEPARATOR . 'tx.*.json');
            foreach ($files as $f) {
                $bucket === 'pending' && $txPending++;
                $bucket === 'processing' && $txProcessing++;
                $bucket === 'sent' && $txSent++;
                $bucket === 'failed' && $txFailed++;

                $payload = self::readJsonFileIfExists($f);
                $method = is_array($payload) ? ($payload['method'] ?? null) : null;
                if (!is_string($method) || trim($method) === '' || str_contains($method, "\0")) {
                    $method = 'unknown';
                }
                $method = trim($method);
                $txByMethod[$method] = ($txByMethod[$method] ?? 0) + 1;
            }
        }

        $receiptTotal = 0;
        $receiptDryRun = 0;
        $receiptPending = 0;
        $receiptSuccess = 0;
        $receiptRevert = 0;
        $receiptUnknown = 0;

        if (is_dir($dirs['sent']) && !is_link($dirs['sent']) && is_readable($dirs['sent'])) {
            $receiptFiles = self::globSorted($dirs['sent'] . DIRECTORY_SEPARATOR . '*.receipt.json');
            foreach ($receiptFiles as $rf) {
                $receiptTotal++;
                $payload = self::readJsonFileIfExists($rf);
                if (!is_array($payload)) {
                    $receiptUnknown++;
                    continue;
                }

                $dry = $payload['dry_run'] ?? null;
                if (is_bool($dry) && $dry) {
                    $receiptDryRun++;
                    continue;
                }

                $receipt = $payload['receipt'] ?? null;
                if (is_string($receipt) && strtolower(trim($receipt)) === 'pending') {
                    $receiptPending++;
                    continue;
                }

                $status = $payload['status'] ?? null;
                if (is_string($status)) {
                    $s = strtolower(trim($status));
                    if ($s === '0x1' || $s === '1') {
                        $receiptSuccess++;
                        continue;
                    }
                    if ($s === '0x0' || $s === '0') {
                        $receiptRevert++;
                        continue;
                    }
                }
                if (is_int($status)) {
                    $status === 1 ? $receiptSuccess++ : $receiptRevert++;
                    continue;
                }

                $receiptUnknown++;
            }
        }

        ksort($sigByKind);
        ksort($txByMethod);

        return [
            'dir' => $outboxDir,
            'sig' => [
                'pending' => $sigPending,
                'processing' => $sigProcessing,
                'signed' => $sigSigned,
                'failed' => $sigFailed,
                'total' => $sigPending + $sigProcessing + $sigSigned + $sigFailed,
                'by_kind' => $sigByKind,
            ],
            'tx' => [
                'pending' => $txPending,
                'processing' => $txProcessing,
                'sent' => $txSent,
                'failed' => $txFailed,
                'total' => $txPending + $txProcessing + $txSent + $txFailed,
                'by_method' => $txByMethod,
            ],
            'receipts' => [
                'total' => $receiptTotal,
                'dry_run' => $receiptDryRun,
                'pending' => $receiptPending,
                'success' => $receiptSuccess,
                'revert' => $receiptRevert,
                'unknown' => $receiptUnknown,
            ],
        ];
    }

    /**
     * @return list<string>
     */
    private static function globSorted(string $pattern): array
    {
        $files = glob($pattern, GLOB_NOSORT);
        if ($files === false || $files === []) {
            return [];
        }
        $out = [];
        foreach ($files as $f) {
            if (!is_string($f) || $f === '' || !is_file($f) || is_link($f) || !is_readable($f)) {
                continue;
            }
            $out[] = $f;
        }
        sort($out, SORT_STRING);
        return $out;
    }

    /**
     * @param array<string,mixed> $cfg
     * @param list<string> $path
     */
    private static function getNestedString(array $cfg, array $path): ?string
    {
        /** @var mixed $cur */
        $cur = $cfg;
        foreach ($path as $key) {
            if (!is_array($cur) || !array_key_exists($key, $cur)) {
                return null;
            }
            $cur = $cur[$key];
        }
        return is_string($cur) ? $cur : null;
    }

    /**
     * @param array<string,mixed>|null $meta
     * @param array<string,mixed>|null $summary
     * @param array<string,mixed>|null $runtimeCfg
     * @param array<string,mixed>|null $outbox
     * @param array{
     *   ticks:int,
     *   first_ts:?string,
     *   last_ts:?string,
     *   first_t_sec:?int,
     *   last_t_sec:?int,
     *   enforcement:?string,
     *   trust_true:int,
     *   trust_false:int,
     *   trust_flips:int,
     *   rpc_ok_true:int,
     *   rpc_ok_false:int,
     *   rpc_flips:int,
     *   max_consecutive_rpc_outage:int,
     *   read_allowed_true:int,
     *   read_allowed_false:int,
     *   write_allowed_true:int,
     *   write_allowed_false:int,
     *   http_codes:array<string,array<int,int>>,
     *   error_codes:array<string,int>
     * } $events
     */
    private static function renderMarkdown(
        string $runId,
        ?array $meta,
        ?array $summary,
        array $events,
        ?array $runtimeCfg,
        ?array $outbox,
    ): string {
        $generatedAt = gmdate('c');

        $lines = [];
        $lines[] = '# BlackCat Soak Report';
        $lines[] = '';
        $lines[] = '- Run ID: `' . $runId . '`';
        $lines[] = '- Generated at: `' . $generatedAt . '`';

        $target = is_array($meta) ? ($meta['target'] ?? null) : null;
        if (is_string($target) && trim($target) !== '' && !str_contains($target, "\0")) {
            $lines[] = '- Target: `' . trim($target) . '`';
        }

        $lines[] = '';
        $lines[] = '## Summary';
        $lines[] = '';

        $ticks = $events['ticks'];
        $lines[] = '- Ticks: `' . $ticks . '`';

        $firstTs = $events['first_ts'];
        $lastTs = $events['last_ts'];
        if (is_string($firstTs) && is_string($lastTs)) {
            $lines[] = '- Window: `' . $firstTs . '` → `' . $lastTs . '`';
        }

        $enforcement = $events['enforcement'];
        if (is_string($enforcement) && $enforcement !== '') {
            $lines[] = '- Enforcement: `' . $enforcement . '`';
        }

        $trustTrue = $events['trust_true'];
        $rpcOkTrue = $events['rpc_ok_true'];
        $readTrue = $events['read_allowed_true'];
        $writeTrue = $events['write_allowed_true'];

        if ($ticks > 0) {
            $lines[] = '- Trusted ratio: `' . self::pct($trustTrue, $ticks) . '` (flips: `' . $events['trust_flips'] . '`)';
            $lines[] = '- RPC quorum OK ratio: `' . self::pct($rpcOkTrue, $ticks) . '` (flips: `' . $events['rpc_flips'] . '`, max outage ticks: `' . $events['max_consecutive_rpc_outage'] . '`)';
            $lines[] = '- Read allowed ratio: `' . self::pct($readTrue, $ticks) . '`';
            $lines[] = '- Write allowed ratio: `' . self::pct($writeTrue, $ticks) . '`';
        }

        if (is_array($runtimeCfg)) {
            $chainId = self::getNestedInt($runtimeCfg, ['trust', 'web3', 'chain_id']);
            $controller = self::getNestedString($runtimeCfg, ['trust', 'web3', 'contracts', 'instance_controller']);
            $quorum = self::getNestedInt($runtimeCfg, ['trust', 'web3', 'rpc_quorum']);
            $maxStale = self::getNestedInt($runtimeCfg, ['trust', 'web3', 'max_stale_sec']);
            $rpcEndpointsCount = self::getNestedListCount($runtimeCfg, ['trust', 'web3', 'rpc_endpoints']);

            $lines[] = '';
            $lines[] = '## Runtime config (snapshot)';
            $lines[] = '';
            if (is_int($chainId)) {
                $lines[] = '- chain_id: `' . $chainId . '`';
            }
            if (is_string($controller) && preg_match('/^0x[a-fA-F0-9]{40}$/', trim($controller))) {
                $lines[] = '- instance_controller: `' . trim($controller) . '`';
            }
            if (is_int($rpcEndpointsCount)) {
                $lines[] = '- rpc_endpoints: `' . $rpcEndpointsCount . '`';
            }
            if (is_int($quorum)) {
                $lines[] = '- rpc_quorum: `' . $quorum . '`';
            }
            if (is_int($maxStale)) {
                $lines[] = '- max_stale_sec: `' . $maxStale . '`';
            }
        }

        $lines[] = '';
        $lines[] = '## HTTP results (from attacker logs)';
        $lines[] = '';

        $httpCodes = $events['http_codes'];
        if ($httpCodes === []) {
            $lines[] = '- No HTTP code data found in events.';
        } else {
            $lines[] = '| Endpoint | Codes |';
            $lines[] = '|---|---|';
            foreach ($httpCodes as $name => $codes) {
                $parts = [];
                foreach ($codes as $code => $count) {
                    $parts[] = $code . '×' . $count;
                }
                $lines[] = '| `' . $name . '` | ' . implode(', ', $parts) . ' |';
            }
        }

        $lines[] = '';
        $lines[] = '## Trust errors (from /health.error_codes)';
        $lines[] = '';

        $errs = $events['error_codes'];
        if ($errs === []) {
            $lines[] = '- None.';
        } else {
            $lines[] = '| Error code | Count |';
            $lines[] = '|---|---:|';
            foreach ($errs as $code => $count) {
                $lines[] = '| `' . $code . '` | ' . $count . ' |';
            }
        }

        if (is_array($outbox)) {
            $lines[] = '';
            $lines[] = '## Tx-outbox (intent/broadcast stats)';
            $lines[] = '';
            $lines[] = '- tx_outbox_dir: `' . ($outbox['dir'] ?? '') . '`';
            $outboxErr = $outbox['error'] ?? null;
            if (is_string($outboxErr) && trim($outboxErr) !== '' && !str_contains($outboxErr, "\0")) {
                $lines[] = '- WARN: unable to scan tx-outbox: `' . trim($outboxErr) . '`';
            }

            $sig = $outbox['sig'] ?? null;
            if (is_array($sig)) {
                $lines[] = '';
                $lines[] = '### Signature requests (`sig.*.json`)';
                $lines[] = '';
                $lines[] = '- total: `' . ($sig['total'] ?? 0) . '` (pending: `' . ($sig['pending'] ?? 0) . '`, signed: `' . ($sig['signed'] ?? 0) . '`, failed: `' . ($sig['failed'] ?? 0) . '`, processing: `' . ($sig['processing'] ?? 0) . '`)';
                $byKind = $sig['by_kind'] ?? null;
                if (is_array($byKind) && $byKind !== []) {
                    $lines[] = '';
                    $lines[] = '| kind | count |';
                    $lines[] = '|---|---:|';
                    foreach ($byKind as $kind => $count) {
                        if (!is_string($kind) || !is_int($count)) {
                            continue;
                        }
                        $lines[] = '| `' . $kind . '` | ' . $count . ' |';
                    }
                }
            }

            $tx = $outbox['tx'] ?? null;
            if (is_array($tx)) {
                $lines[] = '';
                $lines[] = '### Tx intents (`tx.*.json`)';
                $lines[] = '';
                $lines[] = '- total: `' . ($tx['total'] ?? 0) . '` (pending: `' . ($tx['pending'] ?? 0) . '`, sent: `' . ($tx['sent'] ?? 0) . '`, failed: `' . ($tx['failed'] ?? 0) . '`, processing: `' . ($tx['processing'] ?? 0) . '`)';
                $byMethod = $tx['by_method'] ?? null;
                if (is_array($byMethod) && $byMethod !== []) {
                    $lines[] = '';
                    $lines[] = '| method | count |';
                    $lines[] = '|---|---:|';
                    foreach ($byMethod as $method => $count) {
                        if (!is_string($method) || !is_int($count)) {
                            continue;
                        }
                        $lines[] = '| `' . $method . '` | ' . $count . ' |';
                    }
                }
            }

            $receipts = $outbox['receipts'] ?? null;
            if (is_array($receipts)) {
                $lines[] = '';
                $lines[] = '### Broadcast receipts (`sent/*.receipt.json`)';
                $lines[] = '';
                $lines[] = '- total: `' . ($receipts['total'] ?? 0) . '` (success: `' . ($receipts['success'] ?? 0) . '`, revert: `' . ($receipts['revert'] ?? 0) . '`, pending: `' . ($receipts['pending'] ?? 0) . '`, dry_run: `' . ($receipts['dry_run'] ?? 0) . '`, unknown: `' . ($receipts['unknown'] ?? 0) . '`)';
            }
        }

        $lines[] = '';
        $lines[] = '## Notes';
        $lines[] = '';
        $lines[] = '- This report is generated from **local harness logs** and tx-outbox artifacts; it contains no secrets/key material.';
        $lines[] = '- Use this as an investor/audit summary; for raw data see `events.<run_id>.jsonl` + `summary.<run_id>.json`.';

        return implode("\n", $lines) . "\n";
    }

    private static function pct(int $num, int $den): string
    {
        if ($den <= 0) {
            return 'n/a';
        }

        $p = ($num / $den) * 100;
        return number_format($p, 2) . '%';
    }

    /**
     * @param array<string,mixed> $cfg
     * @param list<string> $path
     */
    private static function getNestedInt(array $cfg, array $path): ?int
    {
        /** @var mixed $cur */
        $cur = $cfg;
        foreach ($path as $key) {
            if (!is_array($cur) || !array_key_exists($key, $cur)) {
                return null;
            }
            $cur = $cur[$key];
        }

        if (is_int($cur)) {
            return $cur;
        }
        if (is_string($cur) && ctype_digit($cur)) {
            return (int) $cur;
        }
        return null;
    }

    /**
     * @param array<string,mixed> $cfg
     * @param list<string> $path
     */
    private static function getNestedListCount(array $cfg, array $path): ?int
    {
        /** @var mixed $cur */
        $cur = $cfg;
        foreach ($path as $key) {
            if (!is_array($cur) || !array_key_exists($key, $cur)) {
                return null;
            }
            $cur = $cur[$key];
        }

        return is_array($cur) ? count($cur) : null;
    }
}
