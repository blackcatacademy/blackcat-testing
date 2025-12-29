<?php

declare(strict_types=1);

require '/srv/blackcat/vendor/autoload.php';

use BlackCat\Testing\Soak\SoakReportGenerator;

/**
 * Generate a Markdown report for a completed docker harness run.
 *
 * Defaults (docker/minimal-prod):
 * - logs: /var/log/blackcat-testing (mounted from blackcat-testing/var/harness/minimal-prod/logs)
 * - out:  /var/report (mounted from blackcat-testing/var/harness/minimal-prod/reports)
 * - config: /etc/blackcat/config.runtime.json (runtime config volume)
 */

function usage(): void
{
    $msg = <<<TXT
Usage: php /srv/blackcat/site/bin/soak-report.php [--run-id=...] [--logs-dir=...] [--out-dir=...] [--outbox-dir=...] [--config=...]

If --run-id is omitted, the latest meta.*.json run_id from logs-dir is used.

Environment variables (optional):
  BLACKCAT_SOAK_RUN_ID
  BLACKCAT_SOAK_LOG_DIR
  BLACKCAT_SOAK_REPORT_OUT_DIR
  BLACKCAT_CONFIG_PATH
TXT;
    fwrite(STDERR, $msg . "\n");
}

$args = $argv;
array_shift($args);

$opts = [];
foreach ($args as $a) {
    if ($a === '--help' || $a === '-h') {
        usage();
        exit(0);
    }
    if (!str_starts_with($a, '--') || !str_contains($a, '=')) {
        fwrite(STDERR, "Invalid arg: {$a}\n");
        usage();
        exit(2);
    }
    [$k, $v] = explode('=', substr($a, 2), 2);
    $k = strtolower(trim($k));
    $opts[$k] = $v;
}

$runId = $opts['run-id'] ?? getenv('BLACKCAT_SOAK_RUN_ID') ?: null;
$logsDir = $opts['logs-dir'] ?? getenv('BLACKCAT_SOAK_LOG_DIR') ?: '/var/log/blackcat-testing';
$outDir = $opts['out-dir'] ?? getenv('BLACKCAT_SOAK_REPORT_OUT_DIR') ?: '/var/report';
$outboxDir = $opts['outbox-dir'] ?? null;
$configPath = $opts['config'] ?? getenv('BLACKCAT_CONFIG_PATH') ?: '/etc/blackcat/config.runtime.json';

try {
    $outPath = SoakReportGenerator::generateToFile(
        is_string($runId) ? $runId : null,
        (string) $logsDir,
        (string) $outDir,
        is_string($outboxDir) ? $outboxDir : null,
        is_string($configPath) ? $configPath : null,
    );
    fwrite(STDOUT, $outPath . "\n");
    exit(0);
} catch (\Throwable $e) {
    fwrite(STDERR, "[soak-report] ERROR: " . $e->getMessage() . "\n");
    exit(1);
}

