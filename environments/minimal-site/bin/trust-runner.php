<?php

declare(strict_types=1);

require '/srv/blackcat/vendor/autoload.php';

use BlackCat\Core\TrustKernel\TrustKernelBootstrap;

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

fwrite(STDERR, sprintf(
    "[trust-runner] interval=%ds log_every=%ds sabotage_after=%ds\n",
    $intervalSec,
    $logEverySec,
    $sabotageAfterSec,
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

