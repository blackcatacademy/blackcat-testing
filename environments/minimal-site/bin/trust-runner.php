<?php

declare(strict_types=1);

require '/srv/blackcat/vendor/autoload.php';

use BlackCat\Config\Runtime\Config;
use BlackCat\Core\TrustKernel\Bytes32;
use BlackCat\Core\TrustKernel\CanonicalJson;
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

$lastCheckInEnqueuedAt = 0;
$lastIncidentHash = null;
$lastIncidentEnqueuedAt = 0;

fwrite(STDERR, sprintf(
    "[trust-runner] interval=%ds log_every=%ds sabotage_after=%ds checkin_interval=%ds\n",
    $intervalSec,
    $logEverySec,
    $sabotageAfterSec,
    $checkInIntervalSec,
));

while (true) {
    $now = time();

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
                            'type' => 'blackcat.tx_request',
                            'created_at' => gmdate('c'),
                            'to' => $controller,
                            'method' => 'checkIn(bytes32,bytes32,bytes32)',
                            'args' => [
                                Bytes32::normalizeHex($observedRoot),
                                Bytes32::normalizeHex($observedUriHash),
                                Bytes32::normalizeHex($observedPolicy),
                            ],
                            'meta' => [
                                'source' => 'trust-runner',
                                'trusted_now' => $status->trustedNow,
                                'read_allowed' => $status->readAllowed,
                                'write_allowed' => $status->writeAllowed,
                            ],
                        ];
                        $written = $outbox->enqueue($payload);
                        $lastCheckInEnqueuedAt = $now;
                        fwrite(STDERR, "[trust-runner] outbox: queued checkIn tx: {$written}\n");
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
                                    'type' => 'blackcat.tx_request',
                                    'created_at' => gmdate('c'),
                                    'to' => $controller,
                                    'method' => 'reportIncident(bytes32)',
                                    'args' => [$incidentHash],
                                    'meta' => [
                                        'source' => 'trust-runner',
                                        'error_codes' => $status->errorCodes,
                                    ],
                                ];

                                $written = $outbox->enqueue($payload);
                                $lastIncidentHash = $incidentHash;
                                $lastIncidentEnqueuedAt = $now;
                                fwrite(STDERR, "[trust-runner] outbox: queued reportIncident tx: {$written}\n");
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
