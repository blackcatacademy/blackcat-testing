<?php

declare(strict_types=1);

require '/srv/blackcat/vendor/autoload.php';

use BlackCat\Config\Runtime\Config;
use BlackCat\Core\Security\FilesystemThreatScanner;
use BlackCat\Core\TrustKernel\Bytes32;
use BlackCat\Core\TrustKernel\CanonicalJson;
use BlackCat\Core\TrustKernel\AuditChain;
use BlackCat\Core\TrustKernel\TrustKernelBootstrap;
use BlackCat\Core\TrustKernel\TxOutbox;

$intervalSecRaw = getenv('BLACKCAT_TRUST_RUNNER_INTERVAL_SEC');
$intervalSec = is_string($intervalSecRaw) && ctype_digit($intervalSecRaw) ? (int) $intervalSecRaw : 5;
if ($intervalSec < 1) {
    $intervalSec = 1;
}
if ($intervalSec > 300) {
    $intervalSec = 300;
}

$logEverySecRaw = getenv('BLACKCAT_TRUST_RUNNER_LOG_EVERY_SEC');
$logEverySec = is_string($logEverySecRaw) && ctype_digit($logEverySecRaw) ? (int) $logEverySecRaw : 30;
if ($logEverySec < 0) {
    $logEverySec = 0;
}

$sabotageAfterRaw = getenv('BLACKCAT_TESTING_RPC_SABOTAGE_AFTER_SEC');
$sabotageAfterSec = is_string($sabotageAfterRaw) && ctype_digit($sabotageAfterRaw) ? (int) $sabotageAfterRaw : 0;
if ($sabotageAfterSec < 0) {
    $sabotageAfterSec = 0;
}

$exitAfterRaw = getenv('BLACKCAT_TESTING_RUNNER_EXIT_AFTER_SEC');
$exitAfterSec = is_string($exitAfterRaw) && ctype_digit($exitAfterRaw) ? (int) $exitAfterRaw : 0;
if ($exitAfterSec < 0) {
    $exitAfterSec = 0;
}
if ($exitAfterSec > 86400) {
    $exitAfterSec = 86400;
}

$startedAt = time();
$lastLogAt = 0;
$sabotaged = false;

$checkInIntervalRaw = getenv('BLACKCAT_TRUST_RUNNER_CHECKIN_INTERVAL_SEC');
$checkInIntervalSec = is_string($checkInIntervalRaw) && ctype_digit($checkInIntervalRaw) ? (int) $checkInIntervalRaw : 0;
if ($checkInIntervalSec < 0) {
    $checkInIntervalSec = 0;
}
if ($checkInIntervalSec > 86400) {
    $checkInIntervalSec = 86400;
}

$emitIncidents = getenv('BLACKCAT_TRUST_RUNNER_EMIT_INCIDENTS');
$emitIncidents = $emitIncidents === false ? true : ($emitIncidents !== '0');

$auditAnchorIntervalRaw = getenv('BLACKCAT_TRUST_RUNNER_AUDIT_ANCHOR_INTERVAL_SEC');
$auditAnchorIntervalSec = is_string($auditAnchorIntervalRaw) && ctype_digit($auditAnchorIntervalRaw) ? (int) $auditAnchorIntervalRaw : 0;
if ($auditAnchorIntervalSec < 0) {
    $auditAnchorIntervalSec = 0;
}
if ($auditAnchorIntervalSec > 86400) {
    $auditAnchorIntervalSec = 86400;
}

$fsScanIntervalRaw = getenv('BLACKCAT_TRUST_RUNNER_FS_SCAN_INTERVAL_SEC');
$fsScanIntervalSec = is_string($fsScanIntervalRaw) && ctype_digit($fsScanIntervalRaw) ? (int) $fsScanIntervalRaw : 60;
if ($fsScanIntervalSec < 0) {
    $fsScanIntervalSec = 0;
}
if ($fsScanIntervalSec > 3600) {
    $fsScanIntervalSec = 3600;
}

$fsScanDirsRaw = getenv('BLACKCAT_TRUST_RUNNER_FS_SCAN_DIRS');
$fsScanDirsRaw = $fsScanDirsRaw === false ? '/var/lib/blackcat,/etc/blackcat' : $fsScanDirsRaw;
$fsScanDirs = [];
foreach (array_map('trim', explode(',', (string) $fsScanDirsRaw)) as $dir) {
    if ($dir === '' || str_contains($dir, "\0")) {
        continue;
    }
    $fsScanDirs[] = $dir;
}
$fsScanDirs = array_values(array_unique($fsScanDirs));
if ($fsScanDirs === []) {
    $fsScanIntervalSec = 0;
}

$sigTtlRaw = getenv('BLACKCAT_TRUST_RUNNER_SIG_TTL_SEC');
$sigTtlSec = is_string($sigTtlRaw) && ctype_digit($sigTtlRaw) ? (int) $sigTtlRaw : 300;
if ($sigTtlSec < 30) {
    $sigTtlSec = 30;
}
if ($sigTtlSec > 3600) {
    $sigTtlSec = 3600;
}

$txModeRaw = getenv('BLACKCAT_TRUST_RUNNER_TX_MODE');
$txMode = is_string($txModeRaw) ? strtolower(trim($txModeRaw)) : 'authorized';
if (!in_array($txMode, ['authorized', 'direct'], true)) {
    $txMode = 'authorized';
}

$lastCheckInEnqueuedAt = 0;
$lastIncidentHash = null;
$lastIncidentEnqueuedAt = 0;
$lastAuditAnchorEnqueuedAt = 0;
$lastAuditHeadHash = null;
$lastFsScanAt = 0;
$lastFsIncidentHash = null;
$lastFsIncidentEnqueuedAt = 0;

fwrite(STDERR, sprintf(
    "[trust-runner] interval=%ds log_every=%ds sabotage_after=%ds exit_after=%ds checkin_interval=%ds audit_anchor_interval=%ds fs_scan_interval=%ds\n",
    $intervalSec,
    $logEverySec,
    $sabotageAfterSec,
    $exitAfterSec,
    $checkInIntervalSec,
    $auditAnchorIntervalSec,
    $fsScanIntervalSec,
));
fwrite(STDERR, "[trust-runner] tx_mode={$txMode} sig_ttl_sec={$sigTtlSec}\n");

while (true) {
    $now = time();

    if ($exitAfterSec > 0 && ($now - $startedAt) >= $exitAfterSec) {
        fwrite(STDERR, "[trust-runner] exiting after {$exitAfterSec}s (test-only)\n");
        exit(0);
    }

    if (!$sabotaged && $sabotageAfterSec > 0 && ($now - $startedAt) >= $sabotageAfterSec) {
        $sabotaged = true;
        fwrite(STDERR, "[trust-runner] simulating RPC outage by poisoning /etc/hosts\n");
        if (is_writable('/etc/hosts')) {
            @file_put_contents('/etc/hosts', "\n127.0.0.1 rpc.layeredge.io\n", FILE_APPEND);
        } else {
            fwrite(STDERR, "[trust-runner] WARN: /etc/hosts is not writable; cannot sabotage RPC\n");
        }
    }

    try {
        $kernel = TrustKernelBootstrap::bootFromBlackCatConfigOrFail();
        $status = $kernel->check();

        $outbox = TxOutbox::fromRuntimeConfigBestEffort();
        if ($outbox !== null) {
            // ===== Filesystem threat scan (recommended for writable dirs) =====
            if ($fsScanIntervalSec > 0 && ($lastFsScanAt === 0 || ($now - $lastFsScanAt) >= $fsScanIntervalSec)) {
                $lastFsScanAt = $now;
                try {
                    $report = FilesystemThreatScanner::scan($fsScanDirs, [
                        'max_depth' => 12,
                        'max_dirs' => 2500,
                        'max_files' => 5000,
                        'max_findings' => 50,
                        'max_file_bytes' => 16384,
                        'ignore_paths' => ['/etc/blackcat/keys'],
                        'ignore_dir_names' => ['keys'],
                    ]);

                    $summary = is_array($report['summary'] ?? null) ? $report['summary'] : null;
                    $byCode = is_array($summary['by_code'] ?? null) ? $summary['by_code'] : [];
                    $scanErrors = is_int($summary['errors'] ?? null) ? (int) $summary['errors'] : 0;

                    if ($byCode !== []) {
                        ksort($byCode, SORT_STRING);

                        $controller = Config::get('trust.web3.contracts.instance_controller');
                        $controller = is_string($controller) ? trim($controller) : '';

                        if (is_string($controller) && preg_match('/^0x[a-fA-F0-9]{40}$/', $controller)) {
                            $incidentHash = CanonicalJson::sha256Bytes32([
                                'schema_version' => 1,
                                'type' => 'blackcat.filesystem.scan.incident',
                                'controller' => $controller,
                                'codes' => $byCode,
                                'errors' => $scanErrors,
                            ]);

                            if (!is_string($lastFsIncidentHash) || !hash_equals($lastFsIncidentHash, $incidentHash) || ($now - $lastFsIncidentEnqueuedAt) >= 300) {
                                $payload = [
                                    'schema_version' => 1,
                                    'created_at' => gmdate('c'),
                                    'to' => $controller,
                                    'meta' => [
                                        'source' => 'trust-runner',
                                        'kind' => 'filesystem_scan',
                                        'codes' => $byCode,
                                        'errors' => $scanErrors,
                                    ],
                                ];

                                if ($txMode === 'direct') {
                                    $payload['type'] = 'blackcat.tx_request';
                                    $payload['method'] = 'reportIncident(bytes32)';
                                    $payload['args'] = [$incidentHash];

                                    $written = $outbox->enqueue($payload);
                                    fwrite(STDERR, "[trust-runner] outbox: queued filesystem scan incident tx: {$written}\n");
                                } else {
                                    $payload['type'] = 'blackcat.sig_request';
                                    $payload['kind'] = 'report_incident';
                                    $payload['incident_hash'] = $incidentHash;
                                    $payload['ttl_sec'] = $sigTtlSec;

                                    $written = $outbox->enqueueWithPrefix('sig', $payload);
                                    fwrite(STDERR, "[trust-runner] outbox: queued filesystem scan incident signature request: {$written}\n");
                                }
                                $lastFsIncidentHash = $incidentHash;
                                $lastFsIncidentEnqueuedAt = $now;
                            }
                        }
                    }
                } catch (\Throwable $e) {
                    fwrite(STDERR, "[trust-runner] WARN: filesystem scan failed: " . $e->getMessage() . "\n");
                }
            }

            // ===== Audit-chain anchoring (recommended) =====
            if ($auditAnchorIntervalSec > 0 && ($now - $lastAuditAnchorEnqueuedAt) >= $auditAnchorIntervalSec) {
                try {
                    $audit = AuditChain::fromRuntimeConfigBestEffort();
                    $head = $audit?->head();
                    $headHash = is_array($head) ? ($head['head_hash'] ?? null) : null;
                    $seq = is_array($head) ? ($head['seq'] ?? null) : null;

                    if (is_string($headHash) && is_int($seq) && $seq > 0) {
                        $headHash = Bytes32::normalizeHex($headHash);
                        if (!is_string($lastAuditHeadHash) || !hash_equals($lastAuditHeadHash, $headHash)) {
                            $controller = Config::get('trust.web3.contracts.instance_controller');
                            $controller = is_string($controller) ? trim($controller) : '';

                            if (is_string($controller) && preg_match('/^0x[a-fA-F0-9]{40}$/', $controller)) {
                                $preimage = [
                                    'schema_version' => 1,
                                    'type' => 'blackcat.audit_chain.anchor',
                                    'controller' => $controller,
                                    'audit_seq' => $seq,
                                    'audit_head_hash' => $headHash,
                                ];

                                $anchorHash = CanonicalJson::sha256Bytes32($preimage);
                                $payload = [
                                    'schema_version' => 1,
                                    'created_at' => gmdate('c'),
                                    'to' => $controller,
                                    'meta' => [
                                        'source' => 'trust-runner',
                                        'kind' => 'audit_anchor',
                                        'audit' => [
                                            'seq' => $seq,
                                            'head_hash' => $headHash,
                                        ],
                                        'preimage' => $preimage,
                                    ],
                                ];

                                if ($txMode === 'direct') {
                                    $payload['type'] = 'blackcat.tx_request';
                                    $payload['method'] = 'reportIncident(bytes32)';
                                    $payload['args'] = [$anchorHash];

                                    $written = $outbox->enqueue($payload);
                                    fwrite(STDERR, "[trust-runner] outbox: queued audit anchor tx: {$written}\n");
                                } else {
                                    $payload['type'] = 'blackcat.sig_request';
                                    $payload['kind'] = 'report_incident';
                                    $payload['incident_hash'] = $anchorHash;
                                    $payload['ttl_sec'] = $sigTtlSec;

                                    $written = $outbox->enqueueWithPrefix('sig', $payload);
                                    fwrite(STDERR, "[trust-runner] outbox: queued audit anchor signature request: {$written}\n");
                                }
                                $lastAuditAnchorEnqueuedAt = $now;
                                $lastAuditHeadHash = $headHash;
                            }
                        }
                    }
                } catch (\Throwable $e) {
                    fwrite(STDERR, "[trust-runner] WARN: audit chain anchor failed: " . $e->getMessage() . "\n");
                }
            }

            // ===== On-chain "check-in" (optional) =====
            if (
                $checkInIntervalSec > 0
                && $status->trustedNow
                && $status->rpcOkNow
                && ($now - $lastCheckInEnqueuedAt) >= $checkInIntervalSec
            ) {
                $controller = Config::get('trust.web3.contracts.instance_controller');
                $controller = is_string($controller) ? trim($controller) : '';

                $observedRoot = is_string($status->computedRoot ?? null) ? (string) $status->computedRoot : null;
                $observedPolicy = $status->snapshot?->activePolicyHash;

                $observedUriHash = null;
                try {
                    $manifestPath = Config::get('trust.integrity.manifest');
                    if (is_string($manifestPath) && trim($manifestPath) !== '') {
                        $repo = Config::repo();
                        $resolved = $repo->resolvePath($manifestPath);
                        if (is_file($resolved) && !is_link($resolved) && is_readable($resolved)) {
                            $raw = @file_get_contents($resolved);
                            if (is_string($raw) && trim($raw) !== '') {
                                /** @var mixed $decoded */
                                $decoded = json_decode($raw, true);
                                if (is_array($decoded)) {
                                    $uri = $decoded['uri'] ?? null;
                                    if (is_string($uri) && trim($uri) !== '') {
                                        $observedUriHash = '0x' . hash('sha256', trim($uri));
                                    }
                                }
                            }
                        }
                    }
                } catch (\Throwable) {
                    $observedUriHash = null;
                }

                $zero = '0x' . str_repeat('00', 32);
                $observedUriHash ??= $zero;

                if (
                    is_string($controller) && preg_match('/^0x[a-fA-F0-9]{40}$/', $controller)
                    && is_string($observedRoot) && str_starts_with($observedRoot, '0x') && strlen($observedRoot) === 66
                    && is_string($observedPolicy) && str_starts_with($observedPolicy, '0x') && strlen($observedPolicy) === 66
                ) {
                    try {
                        $payload = [
                            'schema_version' => 1,
                            'created_at' => gmdate('c'),
                            'to' => $controller,
                            'meta' => [
                                'source' => 'trust-runner',
                                'trusted_now' => $status->trustedNow,
                                'read_allowed' => $status->readAllowed,
                                'write_allowed' => $status->writeAllowed,
                            ],
                        ];

                        $rootNorm = Bytes32::normalizeHex($observedRoot);
                        $uriNorm = Bytes32::normalizeHex($observedUriHash);
                        $policyNorm = Bytes32::normalizeHex($observedPolicy);

                        if ($txMode === 'direct') {
                            $payload['type'] = 'blackcat.tx_request';
                            $payload['method'] = 'checkIn(bytes32,bytes32,bytes32)';
                            $payload['args'] = [$rootNorm, $uriNorm, $policyNorm];

                            $written = $outbox->enqueue($payload);
                            fwrite(STDERR, "[trust-runner] outbox: queued checkIn tx: {$written}\n");
                        } else {
                            $payload['type'] = 'blackcat.sig_request';
                            $payload['kind'] = 'check_in';
                            $payload['observed_root'] = $rootNorm;
                            $payload['observed_uri_hash'] = $uriNorm;
                            $payload['observed_policy_hash'] = $policyNorm;
                            $payload['ttl_sec'] = $sigTtlSec;

                            $written = $outbox->enqueueWithPrefix('sig', $payload);
                            fwrite(STDERR, "[trust-runner] outbox: queued checkIn signature request: {$written}\n");
                        }
                        $lastCheckInEnqueuedAt = $now;
                    } catch (\Throwable $e) {
                        fwrite(STDERR, "[trust-runner] WARN: outbox checkIn enqueue failed: " . $e->getMessage() . "\n");
                    }
                }
            }

            // ===== On-chain incident report (recommended) =====
            if ($emitIncidents) {
                $isBad = !$status->trustedNow || !$status->readAllowed || !$status->writeAllowed || $status->paused || !$status->rpcOkNow;
                if ($isBad && ($now - $lastIncidentEnqueuedAt) >= 5) {
                    try {
                        $controller = Config::get('trust.web3.contracts.instance_controller');
                        $controller = is_string($controller) ? trim($controller) : '';

                        if (is_string($controller) && preg_match('/^0x[a-fA-F0-9]{40}$/', $controller)) {
                            $incidentHash = CanonicalJson::sha256Bytes32([
                                'schema_version' => 1,
                                'type' => 'blackcat.trust_kernel.incident',
                                'controller' => $controller,
                                'checked_at' => $status->checkedAt,
                                'error_codes' => $status->errorCodes,
                                'paused' => $status->paused,
                                'rpc_ok_now' => $status->rpcOkNow,
                                'read_allowed' => $status->readAllowed,
                                'write_allowed' => $status->writeAllowed,
                            ]);

                            if (!is_string($lastIncidentHash) || !hash_equals($lastIncidentHash, $incidentHash)) {
                                $payload = [
                                    'schema_version' => 1,
                                    'created_at' => gmdate('c'),
                                    'to' => $controller,
                                    'meta' => [
                                        'source' => 'trust-runner',
                                        'error_codes' => $status->errorCodes,
                                    ],
                                ];

                                if ($txMode === 'direct') {
                                    $payload['type'] = 'blackcat.tx_request';
                                    $payload['method'] = 'reportIncident(bytes32)';
                                    $payload['args'] = [$incidentHash];

                                    $written = $outbox->enqueue($payload);
                                    fwrite(STDERR, "[trust-runner] outbox: queued reportIncident tx: {$written}\n");
                                } else {
                                    $payload['type'] = 'blackcat.sig_request';
                                    $payload['kind'] = 'report_incident';
                                    $payload['incident_hash'] = $incidentHash;
                                    $payload['ttl_sec'] = $sigTtlSec;

                                    $written = $outbox->enqueueWithPrefix('sig', $payload);
                                    fwrite(STDERR, "[trust-runner] outbox: queued reportIncident signature request: {$written}\n");
                                }
                                $lastIncidentHash = $incidentHash;
                                $lastIncidentEnqueuedAt = $now;
                            }
                        }
                    } catch (\Throwable $e) {
                        fwrite(STDERR, "[trust-runner] WARN: outbox reportIncident enqueue failed: " . $e->getMessage() . "\n");
                    }
                }
            }
        }

        if ($logEverySec > 0 && ($lastLogAt === 0 || ($now - $lastLogAt) >= $logEverySec)) {
            $lastLogAt = $now;
            fwrite(STDERR, sprintf(
                "[trust-runner] t=%ds trusted_now=%s rpc_ok_now=%s read_allowed=%s write_allowed=%s last_ok_at=%s errors=%d\n",
                $now - $startedAt,
                $status->trustedNow ? 'true' : 'false',
                $status->rpcOkNow ? 'true' : 'false',
                $status->readAllowed ? 'true' : 'false',
                $status->writeAllowed ? 'true' : 'false',
                $status->lastOkAt !== null ? (string) $status->lastOkAt : 'null',
                count($status->errors),
            ));
        }
    } catch (Throwable $e) {
        fwrite(STDERR, "[trust-runner] ERROR: " . $e->getMessage() . "\n");
    }

    sleep($intervalSec);
}
