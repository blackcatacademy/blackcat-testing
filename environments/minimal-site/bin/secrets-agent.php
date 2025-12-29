<?php

declare(strict_types=1);

// BlackCat secrets agent (demo/prototype).
//
// Purpose:
// - Run as a privileged user (root) with access to a root-owned keys directory.
// - Serve key material to the web runtime over a UNIX socket (group-readable).
//
// This is intentionally minimal and single-purpose. It is NOT a general secret manager.

require '/srv/blackcat/vendor/autoload.php';

use BlackCat\Config\Runtime\Config;
use BlackCat\Config\Runtime\ConfigBootstrap;
use BlackCat\Core\Kernel\KernelBootstrap;
use BlackCat\Core\TrustKernel\TrustKernel;
use BlackCat\Core\TrustKernel\TrustKernelException;
use BlackCat\Core\TrustKernel\AuditChain;
use BlackCat\Core\Security\KeyManager;
use BlackCat\Core\Security\SecretsAgentPolicy;
use BlackCat\Core\Security\FileVault;

function out(string $msg): void
{
    fwrite(STDERR, $msg . "\n");
}

/**
 * @return array<string,int>
 */
function keyBasenameAllowlist(): array
{
    if (class_exists(SecretsAgentPolicy::class) && is_callable([SecretsAgentPolicy::class, 'keyBasenameAllowlist'])) {
        /** @var mixed $m */
        $m = SecretsAgentPolicy::keyBasenameAllowlist();
        if (is_array($m)) {
            /** @var array<string,int> $m */
            return $m;
        }
    }

    return [
        // Fallback (should match blackcat-core)
        'crypto_key' => KeyManager::keyByteLen(),
        'filevault_key' => KeyManager::keyByteLen(),
        'cache_crypto' => KeyManager::keyByteLen(),
        'password_pepper' => 32,
        'app_salt' => 32,
        'session_key' => 32,
        'ip_hash_key' => 32,
        'csrf_key' => 32,
        'jwt_key' => 32,
        'email_key' => KeyManager::keyByteLen(),
        'email_hash_key' => KeyManager::keyByteLen(),
        'email_verification_key' => KeyManager::keyByteLen(),
        'unsubscribe_key' => KeyManager::keyByteLen(),
        'profile_crypto' => KeyManager::keyByteLen(),
    ];
}

function safeString(mixed $v): ?string
{
    if (!is_string($v)) {
        return null;
    }
    $v = trim($v);
    if ($v === '' || str_contains($v, "\0")) {
        return null;
    }
    return $v;
}

function assertSecureDir(string $path, string $label): void
{
    clearstatcache(true, $path);

    if (!is_dir($path) || is_link($path)) {
        throw new \RuntimeException($label . '_dir_unavailable');
    }

    $st = @stat($path);
    if (!is_array($st)) {
        throw new \RuntimeException($label . '_dir_stat_failed');
    }

    $mode = (int) ($st['mode'] ?? 0);
    $perms = $mode & 0o777;

    $type = $mode & 0o170000;
    if ($type !== 0o040000) {
        throw new \RuntimeException($label . '_dir_not_a_dir');
    }

    $uid = (int) ($st['uid'] ?? -1);
    if ($uid !== 0) {
        throw new \RuntimeException($label . '_dir_owner_not_root');
    }

    if (($perms & 0o022) !== 0) {
        throw new \RuntimeException($label . '_dir_writable');
    }
}

function assertSecureFile(string $path, string $label, ?int $expectedLen = null): void
{
    clearstatcache(true, $path);

    if (!is_file($path) || is_link($path)) {
        throw new \RuntimeException($label . '_file_unavailable');
    }

    $st = @stat($path);
    if (!is_array($st)) {
        throw new \RuntimeException($label . '_file_stat_failed');
    }

    $mode = (int) ($st['mode'] ?? 0);
    $perms = $mode & 0o777;

    $type = $mode & 0o170000;
    if ($type !== 0o100000) {
        throw new \RuntimeException($label . '_file_not_regular');
    }

    $uid = (int) ($st['uid'] ?? -1);
    if ($uid !== 0) {
        throw new \RuntimeException($label . '_file_owner_not_root');
    }

    if (($perms & 0o077) !== 0) {
        throw new \RuntimeException($label . '_file_perms_too_open');
    }

    if ($expectedLen !== null) {
        $size = (int) ($st['size'] ?? -1);
        if ($size !== $expectedLen) {
            throw new \RuntimeException($label . '_file_bad_len');
        }
    }
}

function resolveConfigIfPossible(): void
{
    if (Config::isInitialized()) {
        return;
    }

    try {
        $scan = ConfigBootstrap::scanFirstAvailableJsonFile();
        $selected = is_array($scan) ? ($scan['selected'] ?? null) : null;
        if (is_string($selected) && trim($selected) !== '') {
            Config::initFromJsonFileIfNeeded($selected);
        }
    } catch (\Throwable $e) {
        out('[secrets-agent] WARN: config bootstrap failed: ' . $e->getMessage());
    }
}

resolveConfigIfPossible();

$socketPath = null;
$keysDir = null;
$dbCredsPath = null;
$auditDir = null;
$kernel = null;
$peerCredRequired = true;
/** @var list<int> */
$allowedPeerUids = [];
$agentMode = 'keyless';
$limiterEnabled = true;
$limiterDefaultRpm = 6000;
/** @var array<string,int> */
$limiterOpRpm = [];
/** @var AuditChain|null */
$auditChain = null;
$filevaultMaxBytes = 256 * 1024 * 1024; // 256 MiB
$filevaultTimeoutSec = 120;

/**
 * @param resource $conn
 */
function readExactToFile(mixed $conn, string $destPath, int $bytes, int $chunkSize = 1048576): int
{
    $fh = fopen($destPath, 'wb');
    if ($fh === false) {
        throw new \RuntimeException('tmp_file_open_failed');
    }
    chmod($destPath, 0600);

    $readTotal = 0;
    try {
        while ($readTotal < $bytes) {
            $want = min($chunkSize, $bytes - $readTotal);
            $buf = fread($conn, $want);
            if ($buf === false || $buf === '') {
                break;
            }
            $w = fwrite($fh, $buf);
            if ($w === false || $w !== strlen($buf)) {
                throw new \RuntimeException('tmp_file_write_failed');
            }
            $readTotal += $w;
        }
        fflush($fh);
        return $readTotal;
    } finally {
        fclose($fh);
    }
}

/**
 * @param resource $conn
 */
function streamFileToConn(mixed $conn, string $srcPath, int $chunkSize = 1048576): int
{
    $fh = fopen($srcPath, 'rb');
    if ($fh === false) {
        throw new \RuntimeException('tmp_file_open_failed');
    }

    $sent = 0;
    try {
        while (!feof($fh)) {
            $buf = fread($fh, $chunkSize);
            if ($buf === false || $buf === '') {
                break;
            }
            $off = 0;
            $len = strlen($buf);
            while ($off < $len) {
                $w = fwrite($conn, substr($buf, $off));
                if ($w === false || $w === 0) {
                    throw new \RuntimeException('conn_write_failed');
                }
                $off += $w;
                $sent += $w;
            }
        }
        return $sent;
    } finally {
        fclose($fh);
    }
}

/**
 * @return array{uid:?int,gid:?int,pid:?int,peer:?string}
 */
function peerInfo(mixed $conn): array
{
    $peer = null;
    $name = @stream_socket_get_name($conn, true);
    if (is_string($name)) {
        $name = trim($name);
        if ($name !== '' && !str_contains($name, "\0")) {
            $peer = $name;
        }
    }

    $uid = null;
    $gid = null;
    $pid = null;

    if (
        function_exists('socket_import_stream')
        && function_exists('socket_get_option')
        && defined('SOL_SOCKET')
        && defined('SO_PEERCRED')
    ) {
        /** @var \Socket|false $sock */
        $sock = @socket_import_stream($conn);
        if ($sock !== false) {
            /** @var mixed $cred */
            $cred = @socket_get_option($sock, SOL_SOCKET, SO_PEERCRED);
            if (is_array($cred)) {
                $uid = isset($cred['uid']) && is_int($cred['uid']) ? $cred['uid'] : null;
                $gid = isset($cred['gid']) && is_int($cred['gid']) ? $cred['gid'] : null;
                $pid = isset($cred['pid']) && is_int($cred['pid']) ? $cred['pid'] : null;
            }
        }
    }

    return [
        'uid' => $uid,
        'gid' => $gid,
        'pid' => $pid,
        'peer' => $peer,
    ];
}

function peerKey(array $info): string
{
    $parts = [];
    if (isset($info['uid']) && is_int($info['uid'])) {
        $parts[] = 'uid=' . $info['uid'];
    }
    if (isset($info['gid']) && is_int($info['gid'])) {
        $parts[] = 'gid=' . $info['gid'];
    }
    if (isset($info['pid']) && is_int($info['pid'])) {
        $parts[] = 'pid=' . $info['pid'];
    }
    $peer = $info['peer'] ?? null;
    if (is_string($peer) && $peer !== '') {
        $parts[] = 'peer=' . $peer;
    }

    return $parts !== [] ? implode(' ', $parts) : 'peer=unknown';
}

/**
 * @param AuditChain|null $chain
 * @param array<string,mixed> $actor
 * @param array<string,mixed> $meta
 */
function auditAppend(?AuditChain $chain, string $type, array $actor, array $meta): void
{
    if ($chain === null) {
        return;
    }

    try {
        $chain->append($type, $meta, $actor);
    } catch (\Throwable $e) {
        out('[secrets-agent] WARN: audit append failed: ' . $e->getMessage());
    }
}

try {
    if (Config::isInitialized()) {
        $repo = Config::repo();

        $socketRaw = safeString($repo->get('crypto.agent.socket_path'));
        if ($socketRaw !== null) {
            $socketPath = $repo->resolvePath($socketRaw);
        }

        $keysDirRaw = safeString($repo->get('crypto.keys_dir'));
        if ($keysDirRaw !== null) {
            $keysDir = $repo->resolvePath($keysDirRaw);
        }

        $dbCredsRaw = safeString($repo->get('db.credentials_file'));
        if ($dbCredsRaw !== null) {
            $dbCredsPath = $repo->resolvePath($dbCredsRaw);
        }

        $peerReqRaw = $repo->get('crypto.agent.require_peercred');
        if (is_bool($peerReqRaw)) {
            $peerCredRequired = $peerReqRaw;
        } elseif (is_int($peerReqRaw)) {
            $peerCredRequired = $peerReqRaw !== 0;
        } elseif (is_string($peerReqRaw)) {
            $peerCredRequired = trim($peerReqRaw) !== '' && trim($peerReqRaw) !== '0';
        }

        $uidsRaw = $repo->get('crypto.agent.allowed_peer_uids');
        if (is_array($uidsRaw)) {
            $uids = [];
            foreach ($uidsRaw as $v) {
                if (is_int($v) && $v >= 0) {
                    $uids[] = $v;
                    continue;
                }
                if (is_string($v) && ctype_digit(trim($v))) {
                    $uids[] = (int) trim($v);
                    continue;
                }
            }
            $allowedPeerUids = array_values(array_unique($uids));
        }

        $modeRaw = $repo->get('crypto.agent.mode');
        if (is_string($modeRaw) && trim($modeRaw) !== '') {
            $agentMode = strtolower(trim($modeRaw));
        }

        $limEnabledRaw = $repo->get('crypto.agent.limiter.enabled');
        if (is_bool($limEnabledRaw)) {
            $limiterEnabled = $limEnabledRaw;
        } elseif (is_int($limEnabledRaw)) {
            $limiterEnabled = $limEnabledRaw !== 0;
        } elseif (is_string($limEnabledRaw)) {
            $limiterEnabled = trim($limEnabledRaw) !== '' && trim($limEnabledRaw) !== '0';
        }

        $limDefaultRaw = $repo->get('crypto.agent.limiter.default_rpm');
        if (is_int($limDefaultRaw) && $limDefaultRaw > 0) {
            $limiterDefaultRpm = $limDefaultRaw;
        } elseif (is_string($limDefaultRaw) && ctype_digit(trim($limDefaultRaw))) {
            $limiterDefaultRpm = max(1, (int) trim($limDefaultRaw));
        }

        $limOpsRaw = $repo->get('crypto.agent.limiter.op_rpm');
        if (is_array($limOpsRaw)) {
            $out = [];
            foreach ($limOpsRaw as $k => $v) {
                if (!is_string($k) || $k === '' || str_contains($k, "\0")) {
                    continue;
                }
                $rpm = null;
                if (is_int($v)) {
                    $rpm = $v;
                } elseif (is_string($v) && ctype_digit(trim($v))) {
                    $rpm = (int) trim($v);
                }
                if ($rpm === null || $rpm < 0) {
                    continue;
                }
                $out[strtolower(trim($k))] = $rpm;
            }
            $limiterOpRpm = $out;
        }

        $fvMaxRaw = $repo->get('crypto.agent.filevault.max_bytes');
        if (is_int($fvMaxRaw) && $fvMaxRaw > 0) {
            $filevaultMaxBytes = $fvMaxRaw;
        } elseif (is_string($fvMaxRaw) && ctype_digit(trim($fvMaxRaw))) {
            $filevaultMaxBytes = max(1, (int) trim($fvMaxRaw));
        }

        $fvTimeoutRaw = $repo->get('crypto.agent.filevault.timeout_sec');
        if (is_int($fvTimeoutRaw) && $fvTimeoutRaw > 0) {
            $filevaultTimeoutSec = $fvTimeoutRaw;
        } elseif (is_string($fvTimeoutRaw) && ctype_digit(trim($fvTimeoutRaw))) {
            $filevaultTimeoutSec = max(5, (int) trim($fvTimeoutRaw));
        }

        $auditRaw = safeString($repo->get('trust.audit.dir'));
        if ($auditRaw !== null) {
            $auditDir = $repo->resolvePath($auditRaw);
        }
    }
} catch (\Throwable $e) {
    out('[secrets-agent] WARN: runtime config read failed: ' . $e->getMessage());
}

$socketPath ??= '/etc/blackcat/secrets-agent.sock';
$keysDir ??= '/etc/blackcat/keys';
$dbCredsPath ??= '/etc/blackcat/db.credentials.json';
$auditDir ??= '/var/lib/blackcat/audit-chain';

// Default peer allowlist (best-effort): allow only www-data uid when available.
if ($allowedPeerUids === []) {
    if (function_exists('posix_getpwnam')) {
        /** @var array<string,mixed>|false $pw */
        $pw = @posix_getpwnam('www-data');
        if (is_array($pw) && isset($pw['uid']) && is_int($pw['uid']) && $pw['uid'] >= 0) {
            $allowedPeerUids = [(int) $pw['uid']];
        }
    }
    if ($allowedPeerUids === []) {
        $allowedPeerUids = [33];
    }
}

$socketPath = trim($socketPath);
$keysDir = trim($keysDir);
$auditDir = trim($auditDir);

if ($socketPath === '' || str_contains($socketPath, "\0")) {
    throw new \RuntimeException('Invalid socket path.');
}
if ($keysDir === '' || str_contains($keysDir, "\0")) {
    throw new \RuntimeException('Invalid keys directory path.');
}
if ($dbCredsPath === '' || str_contains($dbCredsPath, "\0")) {
    throw new \RuntimeException('Invalid db credentials file path.');
}
if ($auditDir === '' || str_contains($auditDir, "\0")) {
    throw new \RuntimeException('Invalid audit dir path.');
}

assertSecureDir(dirname($socketPath), 'socket_parent');

try {
    $kernel = KernelBootstrap::bootOrFail();
} catch (\Throwable $e) {
    out('[secrets-agent] ERROR: TrustKernel bootstrap failed: ' . $e->getMessage());
    exit(2);
}

if (file_exists($socketPath) || is_link($socketPath)) {
    if (is_link($socketPath)) {
        throw new \RuntimeException('Refusing to use symlink socket path: ' . $socketPath);
    }
    @unlink($socketPath);
}

$server = @stream_socket_server('unix://' . $socketPath, $errno, $errstr);
if (!is_resource($server)) {
    throw new \RuntimeException('Unable to bind unix socket: ' . $socketPath . ' (' . $errstr . ')');
}

@chmod($socketPath, 0660);
@chgrp($socketPath, 'www-data');

out('[secrets-agent] listening on ' . $socketPath);
out('[secrets-agent] keys_dir=' . $keysDir);
out('[secrets-agent] peercred_required=' . ($peerCredRequired ? 'true' : 'false') . ' allowed_peer_uids=' . implode(',', $allowedPeerUids));
out('[secrets-agent] mode=' . $agentMode . ' limiter=' . ($limiterEnabled ? 'on' : 'off') . ' default_rpm=' . $limiterDefaultRpm);

// Hard cap to avoid abuse.
$maxLine = 64 * 1024;
$maxKeyBytes = 4096;
$maxDataBytes = 32 * 1024;

if (is_link($keysDir)) {
    throw new \RuntimeException('Refusing to use symlink keys_dir: ' . $keysDir);
}

if (is_link($dbCredsPath)) {
    throw new \RuntimeException('Refusing to use symlink db credentials file: ' . $dbCredsPath);
}

assertSecureDir($keysDir, 'keys_dir');
assertSecureDir(dirname($dbCredsPath), 'db_credentials_parent');

if (!is_file($dbCredsPath)) {
    out('[secrets-agent] WARN: db credentials file not found: ' . $dbCredsPath);
}

if (is_link($auditDir)) {
    throw new \RuntimeException('Refusing to use symlink audit dir: ' . $auditDir);
}
if (!is_dir($auditDir)) {
    // Best-effort create; running as root in secrets-agent mode.
    @mkdir($auditDir, 0750, true);
    @chmod($auditDir, 0750);
    if (DIRECTORY_SEPARATOR !== '\\') {
        $gid = @filegroup(dirname($auditDir));
        if (is_int($gid) && $gid >= 0) {
            @chgrp($auditDir, $gid);
        }
    }
}
try {
    assertSecureDir(dirname($auditDir), 'audit_parent');
    assertSecureDir($auditDir, 'audit_dir');
    $auditChain = new AuditChain($auditDir);
    out('[secrets-agent] audit_chain=' . $auditDir);
} catch (\Throwable $e) {
    $auditChain = null;
    out('[secrets-agent] WARN: audit chain disabled: ' . $e->getMessage());
}

/**
 * Simple in-process audit counters (no secrets).
 *
 * @var array<string,int>
 */
$audit = [];

/**
 * Best-effort in-process token buckets for rate limiting.
 *
 * @var array<string,array{tokens:float,updated_at:float}>
 */
$buckets = [];

/**
 * @return bool true when allowed
 */
$limiterAllow = static function (?int $uid, string $op) use (&$buckets, $limiterEnabled, $limiterDefaultRpm, $limiterOpRpm): bool {
    if (!$limiterEnabled) {
        return true;
    }

    $op = strtolower(trim($op));
    if ($op === '' || str_contains($op, "\0")) {
        return false;
    }

    $rpm = $limiterOpRpm[$op] ?? $limiterDefaultRpm;
    if (!is_int($rpm) || $rpm <= 0) {
        return false;
    }

    $bucketKey = (is_int($uid) ? ('uid=' . $uid) : 'uid=unknown') . '|op=' . $op;
    $now = microtime(true);
    $ratePerSec = $rpm / 60.0;
    $burst = (float) $rpm;

    $b = $buckets[$bucketKey] ?? ['tokens' => $burst, 'updated_at' => $now];
    $elapsed = $now - $b['updated_at'];
    if ($elapsed > 0) {
        $b['tokens'] = min($burst, $b['tokens'] + ($elapsed * $ratePerSec));
        $b['updated_at'] = $now;
    }

    if ($b['tokens'] < 1.0) {
        $buckets[$bucketKey] = $b;
        return false;
    }

    $b['tokens'] -= 1.0;
    $buckets[$bucketKey] = $b;
    return true;
};

while (true) {
    $conn = @stream_socket_accept($server, -1);
    if (!is_resource($conn)) {
        continue;
    }

    $peerInfo = peerInfo($conn);
    $peer = peerKey($peerInfo);
    $actor = [
        'uid' => $peerInfo['uid'] ?? null,
        'gid' => $peerInfo['gid'] ?? null,
        'pid' => $peerInfo['pid'] ?? null,
        'peer' => $peer,
    ];

    if ($peerCredRequired) {
        $uid = $peerInfo['uid'] ?? null;
        if (!is_int($uid)) {
            auditAppend($auditChain, 'secrets_agent.reject.peercred_unavailable', $actor, []);
            fwrite($conn, json_encode(['ok' => false, 'error' => 'peercred_unavailable']) . "\n");
            fclose($conn);
            continue;
        }
        if ($allowedPeerUids !== [] && !in_array($uid, $allowedPeerUids, true)) {
            auditAppend($auditChain, 'secrets_agent.reject.peercred_uid_not_allowed', $actor, []);
            fwrite($conn, json_encode(['ok' => false, 'error' => 'peercred_uid_not_allowed']) . "\n");
            fclose($conn);
            continue;
        }
    }

    stream_set_timeout($conn, 2);

    $line = stream_get_line($conn, $maxLine, "\n");
    if (!is_string($line) || trim($line) === '') {
        auditAppend($auditChain, 'secrets_agent.reject.empty_request', $actor, []);
        fwrite($conn, json_encode(['ok' => false, 'error' => 'empty_request']) . "\n");
        fclose($conn);
        continue;
    }

    try {
        /** @var mixed $req */
        $req = json_decode($line, true, 64, JSON_THROW_ON_ERROR);
    } catch (\JsonException) {
        auditAppend($auditChain, 'secrets_agent.reject.bad_json', $actor, []);
        fwrite($conn, json_encode(['ok' => false, 'error' => 'bad_json']) . "\n");
        fclose($conn);
        continue;
    }

    if (!is_array($req)) {
        auditAppend($auditChain, 'secrets_agent.reject.bad_request', $actor, []);
        fwrite($conn, json_encode(['ok' => false, 'error' => 'bad_request']) . "\n");
        fclose($conn);
        continue;
    }

    $op = $req['op'] ?? null;
    if (
        $op !== 'get_all_keys'
        && $op !== 'get_db_credentials'
        && $op !== 'crypto_encrypt'
        && $op !== 'crypto_decrypt'
        && $op !== 'hmac_latest'
        && $op !== 'hmac_candidates'
        && $op !== 'filevault_encrypt_stream'
        && $op !== 'filevault_decrypt_stream'
    ) {
        auditAppend($auditChain, 'secrets_agent.reject.unsupported_op', $actor, []);
        fwrite($conn, json_encode(['ok' => false, 'error' => 'unsupported_op']) . "\n");
        fclose($conn);
        continue;
    }

    try {
        $uid = $peerInfo['uid'] ?? null;
        $uid = is_int($uid) ? $uid : null;

        if (!$limiterAllow($uid, (string) $op)) {
            auditAppend($auditChain, 'secrets_agent.reject.rate_limited', $actor, ['op' => (string) $op]);
            fwrite($conn, json_encode(['ok' => false, 'error' => 'rate_limited']) . "\n");
            fclose($conn);
            continue;
        }

        if ($op === 'filevault_encrypt_stream' || $op === 'filevault_decrypt_stream') {
            stream_set_timeout($conn, $filevaultTimeoutSec);
        }

        if ($op === 'get_all_keys') {
            if ($agentMode !== 'keys') {
                auditAppend($auditChain, 'secrets_agent.reject.key_export_disabled', $actor, [
                    'basename' => is_string($req['basename'] ?? null) ? (string) $req['basename'] : null,
                ]);
                fwrite($conn, json_encode(['ok' => false, 'error' => 'key_export_disabled']) . "\n");
                fclose($conn);
                continue;
            }

            $basename = $req['basename'] ?? null;
            if (!is_string($basename)) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'bad_basename']) . "\n");
                fclose($conn);
                continue;
            }
            $basename = trim($basename);
            if ($basename === '' || str_contains($basename, "\0") || !preg_match('/^[a-z0-9_]{1,64}$/', $basename)) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'bad_basename']) . "\n");
                fclose($conn);
                continue;
            }

            $allow = keyBasenameAllowlist();
            if (!array_key_exists($basename, $allow)) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'basename_not_allowed']) . "\n");
                fclose($conn);
                continue;
            }
            $expectedLen = (int) $allow[$basename];
            if ($expectedLen < 1 || $expectedLen > $maxKeyBytes) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'basename_policy_invalid']) . "\n");
                fclose($conn);
                continue;
            }

            if ($kernel instanceof TrustKernel) {
                $kernel->assertReadAllowed('secrets-agent:get_all_keys');
            }

            $versions = KeyManager::listKeyVersions($keysDir, $basename);
            $outKeys = [];
            foreach ($versions as $ver => $path) {
                if (!is_string($ver) || !is_string($path)) {
                    continue;
                }
                assertSecureFile($path, 'key_file', $expectedLen);
                $raw = @file_get_contents($path);
                if (!is_string($raw) || $raw === '') {
                    continue;
                }
                $outKeys[] = [
                    'version' => $ver,
                    'b64' => base64_encode($raw),
                ];
            }

            $auditKey = 'keys:' . $basename;
            $peerAuditKey = $peer . '|' . $auditKey;
            $audit[$peerAuditKey] = ($audit[$peerAuditKey] ?? 0) + 1;
            out('[secrets-agent] audit ' . $peer . ' op=get_all_keys basename=' . $basename . ' versions=' . count($outKeys) . ' total=' . $audit[$peerAuditKey]);
            auditAppend($auditChain, 'secrets_agent.get_all_keys', $actor, [
                'basename' => $basename,
                'versions' => count($outKeys),
            ]);

            fwrite($conn, json_encode(['ok' => true, 'keys' => $outKeys], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
            fclose($conn);
            continue;
        }

        if ($op === 'filevault_encrypt_stream') {
            $basename = $req['basename'] ?? null;
            $plainSize = $req['plain_size'] ?? null;
            $context = $req['context'] ?? null;

            if (is_string($plainSize) && ctype_digit(trim($plainSize))) {
                $plainSize = (int) trim($plainSize);
            }
            if (!is_string($basename) || !is_int($plainSize) || $plainSize < 0) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'bad_request']) . "\n");
                fclose($conn);
                continue;
            }

            if ($plainSize > $filevaultMaxBytes) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'payload_too_large']) . "\n");
                fclose($conn);
                continue;
            }

            $basename = trim($basename);
            if ($basename === '' || str_contains($basename, "\0") || !preg_match('/^[a-z0-9_]{1,64}$/', $basename)) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'bad_basename']) . "\n");
                fclose($conn);
                continue;
            }

            $allow = keyBasenameAllowlist();
            if (!array_key_exists($basename, $allow)) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'basename_not_allowed']) . "\n");
                fclose($conn);
                continue;
            }

            if ($kernel instanceof TrustKernel) {
                $kernel->assertReadAllowed('secrets-agent:filevault_encrypt_stream');
            }

            $tmpDir = sys_get_temp_dir();
            $tmpPlain = tempnam($tmpDir, 'blackcat-fv-plain-');
            $tmpEnc = tempnam($tmpDir, 'blackcat-fv-enc-');
            if (!is_string($tmpPlain) || !is_string($tmpEnc)) {
                throw new \RuntimeException('tempnam_failed');
            }
            @unlink($tmpEnc);
            $tmpEnc .= '.bin';

            try {
                $read = readExactToFile($conn, $tmpPlain, $plainSize);
                if ($read !== $plainSize) {
                    throw new \RuntimeException('payload_truncated');
                }

                FileVault::setKeysDir($keysDir);
                $okPath = FileVault::uploadAndEncrypt($tmpPlain, $tmpEnc);
                if (!is_string($okPath) || $okPath === '' || !is_file($okPath)) {
                    throw new \RuntimeException('encrypt_failed');
                }

                $cipherSize = filesize($okPath);
                if (!is_int($cipherSize) || $cipherSize < 0) {
                    throw new \RuntimeException('cipher_stat_failed');
                }

                $metaPath = $okPath . '.meta';
                $metaRaw = is_file($metaPath) ? file_get_contents($metaPath) : false;
                $meta = null;
                if (is_string($metaRaw) && trim($metaRaw) !== '') {
                    $decoded = json_decode($metaRaw, true);
                    if (is_array($decoded)) {
                        $meta = $decoded;
                    }
                }
                if (!is_array($meta)) {
                    $meta = [
                        'plain_size' => $plainSize,
                        'mode' => 'unknown',
                        'version' => 2,
                        'key_version' => null,
                        'context' => is_string($context) ? trim($context) : null,
                    ];
                } else {
                    if (is_string($context) && trim($context) !== '' && !str_contains($context, "\0")) {
                        $meta['context'] = trim($context);
                    }
                }

                $auditKey = 'filevault_encrypt:' . $basename;
                $peerAuditKey = $peer . '|' . $auditKey;
                $audit[$peerAuditKey] = ($audit[$peerAuditKey] ?? 0) + 1;
                out('[secrets-agent] audit ' . $peer . ' op=filevault_encrypt_stream basename=' . $basename . ' total=' . $audit[$peerAuditKey]);
                auditAppend($auditChain, 'secrets_agent.filevault_encrypt_stream', $actor, [
                    'basename' => $basename,
                    'plain_size' => $plainSize,
                    'cipher_size' => $cipherSize,
                    'mode' => is_string($meta['mode'] ?? null) ? (string) $meta['mode'] : null,
                    'key_version' => is_string($meta['key_version'] ?? null) ? (string) $meta['key_version'] : null,
                ]);

                fwrite(
                    $conn,
                    json_encode(
                        [
                            'ok' => true,
                            'cipher_size' => $cipherSize,
                            'meta' => $meta,
                        ],
                        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
                    ) . "\n"
                );
                try {
                    streamFileToConn($conn, $okPath);
                } catch (\Throwable) {
                    // If streaming fails mid-response, do not send JSON (protocol already switched to binary).
                }
                fclose($conn);
                continue;
            } finally {
                @unlink($tmpPlain);
                @unlink($tmpEnc);
                @unlink($tmpEnc . '.meta');
            }
        }

        if ($op === 'filevault_decrypt_stream') {
            $basename = $req['basename'] ?? null;
            $cipherSize = $req['cipher_size'] ?? null;

            if (is_string($cipherSize) && ctype_digit(trim($cipherSize))) {
                $cipherSize = (int) trim($cipherSize);
            }
            if (!is_string($basename) || !is_int($cipherSize) || $cipherSize < 0) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'bad_request']) . "\n");
                fclose($conn);
                continue;
            }

            if ($cipherSize > $filevaultMaxBytes) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'payload_too_large']) . "\n");
                fclose($conn);
                continue;
            }

            $basename = trim($basename);
            if ($basename === '' || str_contains($basename, "\0") || !preg_match('/^[a-z0-9_]{1,64}$/', $basename)) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'bad_basename']) . "\n");
                fclose($conn);
                continue;
            }

            $allow = keyBasenameAllowlist();
            if (!array_key_exists($basename, $allow)) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'basename_not_allowed']) . "\n");
                fclose($conn);
                continue;
            }

            if ($kernel instanceof TrustKernel) {
                $kernel->assertReadAllowed('secrets-agent:filevault_decrypt_stream');
            }

            $tmpDir = sys_get_temp_dir();
            $tmpEnc = tempnam($tmpDir, 'blackcat-fv-enc-');
            $tmpPlain = tempnam($tmpDir, 'blackcat-fv-plain-');
            if (!is_string($tmpEnc) || !is_string($tmpPlain)) {
                throw new \RuntimeException('tempnam_failed');
            }
            @unlink($tmpPlain);
            $tmpPlain .= '.bin';

            try {
                $read = readExactToFile($conn, $tmpEnc, $cipherSize);
                if ($read !== $cipherSize) {
                    throw new \RuntimeException('payload_truncated');
                }

                FileVault::setKeysDir($keysDir);
                $ok = FileVault::decryptToFile($tmpEnc, $tmpPlain);
                if (!$ok) {
                    fwrite($conn, json_encode(['ok' => false, 'error' => 'decrypt_failed']) . "\n");
                    fclose($conn);
                    continue;
                }

                $plainSize = filesize($tmpPlain);
                if (!is_int($plainSize) || $plainSize < 0) {
                    throw new \RuntimeException('plain_stat_failed');
                }

                $keyVersion = null;
                // Best-effort: derive key id/version from encrypted header (v2 contains key_id).
                $fh = fopen($tmpEnc, 'rb');
                if (is_resource($fh)) {
                    $v = fread($fh, 1);
                    if (is_string($v) && strlen($v) === 1 && ord($v) === 2) {
                        $b = fread($fh, 1);
                        if (is_string($b) && strlen($b) === 1) {
                            $klen = ord($b);
                            if ($klen > 0 && $klen <= 64) {
                                $kid = fread($fh, $klen);
                                if (is_string($kid) && preg_match('/^v[0-9]+$/', $kid)) {
                                    $keyVersion = $kid;
                                }
                            }
                        }
                    }
                    fclose($fh);
                }

                $auditKey = 'filevault_decrypt:' . $basename;
                $peerAuditKey = $peer . '|' . $auditKey;
                $audit[$peerAuditKey] = ($audit[$peerAuditKey] ?? 0) + 1;
                out('[secrets-agent] audit ' . $peer . ' op=filevault_decrypt_stream basename=' . $basename . ' total=' . $audit[$peerAuditKey]);
                auditAppend($auditChain, 'secrets_agent.filevault_decrypt_stream', $actor, [
                    'basename' => $basename,
                    'cipher_size' => $cipherSize,
                    'plain_size' => $plainSize,
                    'key_version' => $keyVersion,
                ]);

                fwrite(
                    $conn,
                    json_encode(
                        [
                            'ok' => true,
                            'plain_size' => $plainSize,
                            'key_version' => $keyVersion,
                        ],
                        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
                    ) . "\n"
                );
                try {
                    streamFileToConn($conn, $tmpPlain);
                } catch (\Throwable) {
                    // If streaming fails mid-response, do not send JSON (protocol already switched to binary).
                }
                fclose($conn);
                continue;
            } finally {
                @unlink($tmpEnc);
                @unlink($tmpPlain);
            }
        }

        if ($op === 'crypto_encrypt') {
            $basename = $req['basename'] ?? null;
            $plaintextB64 = $req['plaintext_b64'] ?? null;

            if (!is_string($basename) || !is_string($plaintextB64)) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'bad_request']) . "\n");
                fclose($conn);
                continue;
            }

            $basename = trim($basename);
            if ($basename === '' || str_contains($basename, "\0") || !preg_match('/^[a-z0-9_]{1,64}$/', $basename)) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'bad_basename']) . "\n");
                fclose($conn);
                continue;
            }

            $allow = keyBasenameAllowlist();
            if (!array_key_exists($basename, $allow)) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'basename_not_allowed']) . "\n");
                fclose($conn);
                continue;
            }
            $expectedLen = (int) $allow[$basename];
            if ($expectedLen < 1 || $expectedLen > $maxKeyBytes) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'basename_policy_invalid']) . "\n");
                fclose($conn);
                continue;
            }

            $plain = base64_decode($plaintextB64, true);
            if (!is_string($plain)) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'bad_plaintext_b64']) . "\n");
                fclose($conn);
                continue;
            }
            if (strlen($plain) > $maxDataBytes) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'payload_too_large']) . "\n");
                fclose($conn);
                continue;
            }

            if ($kernel instanceof TrustKernel) {
                $kernel->assertReadAllowed('secrets-agent:crypto_encrypt');
            }

            $versions = KeyManager::listKeyVersions($keysDir, $basename);
            $latestVer = array_key_last($versions);
            $latestPath = is_string($latestVer) ? ($versions[$latestVer] ?? null) : null;
            if (!is_string($latestVer) || !is_string($latestPath)) {
                throw new \RuntimeException('key_not_found');
            }

            assertSecureFile($latestPath, 'key_file', $expectedLen);
            $key = @file_get_contents($latestPath);
            if (!is_string($key) || strlen($key) !== $expectedLen) {
                throw new \RuntimeException('key_read_failed');
            }

            $nonceLen = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
            $nonce = random_bytes($nonceLen);
            $ad = 'app:crypto:v1';
            $cipher = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plain, $ad, $nonce, $key);

            // Best-effort wipe key copy.
            try {
                KeyManager::memzero($key);
            } catch (\Throwable) {
            }

            $out = base64_encode($nonce . $cipher);

            $auditKey = 'crypto_encrypt:' . $basename;
            $peerAuditKey = $peer . '|' . $auditKey;
            $audit[$peerAuditKey] = ($audit[$peerAuditKey] ?? 0) + 1;
            out('[secrets-agent] audit ' . $peer . ' op=crypto_encrypt basename=' . $basename . ' total=' . $audit[$peerAuditKey]);
            auditAppend($auditChain, 'secrets_agent.crypto_encrypt', $actor, [
                'basename' => $basename,
                'plaintext_len' => strlen($plain),
                'ciphertext_len' => strlen($out),
                'key_version' => $latestVer,
            ]);

            fwrite(
                $conn,
                json_encode(
                    [
                        'ok' => true,
                        'ciphertext' => $out,
                        'key_version' => $latestVer,
                    ],
                    JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
                ) . "\n"
            );
            fclose($conn);
            continue;
        }

        if ($op === 'crypto_decrypt') {
            $basename = $req['basename'] ?? null;
            $ciphertext = $req['ciphertext'] ?? null;

            if (!is_string($basename) || !is_string($ciphertext)) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'bad_request']) . "\n");
                fclose($conn);
                continue;
            }

            $basename = trim($basename);
            if ($basename === '' || str_contains($basename, "\0") || !preg_match('/^[a-z0-9_]{1,64}$/', $basename)) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'bad_basename']) . "\n");
                fclose($conn);
                continue;
            }

            $allow = keyBasenameAllowlist();
            if (!array_key_exists($basename, $allow)) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'basename_not_allowed']) . "\n");
                fclose($conn);
                continue;
            }
            $expectedLen = (int) $allow[$basename];
            if ($expectedLen < 1 || $expectedLen > $maxKeyBytes) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'basename_policy_invalid']) . "\n");
                fclose($conn);
                continue;
            }

            $decoded = base64_decode($ciphertext, true);
            if (!is_string($decoded)) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'bad_ciphertext']) . "\n");
                fclose($conn);
                continue;
            }
            if (strlen($decoded) > $maxDataBytes + 1024) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'payload_too_large']) . "\n");
                fclose($conn);
                continue;
            }

            $nonceLen = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
            if (strlen($decoded) < $nonceLen + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'bad_ciphertext']) . "\n");
                fclose($conn);
                continue;
            }

            $nonce = substr($decoded, 0, $nonceLen);
            $cipher = substr($decoded, $nonceLen);
            $ad = 'app:crypto:v1';

            if ($kernel instanceof TrustKernel) {
                $kernel->assertReadAllowed('secrets-agent:crypto_decrypt');
            }

            $versions = KeyManager::listKeyVersions($keysDir, $basename);
            $plain = null;
            $usedVer = null;
            $vers = array_keys($versions);
            for ($i = count($vers) - 1; $i >= 0; $i--) {
                $ver = $vers[$i];
                $path = $versions[$ver] ?? null;
                if (!is_string($ver) || !is_string($path)) {
                    continue;
                }

                assertSecureFile($path, 'key_file', $expectedLen);
                $key = @file_get_contents($path);
                if (!is_string($key) || strlen($key) !== $expectedLen) {
                    continue;
                }

                $res = @sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($cipher, $ad, $nonce, $key);
                try {
                    KeyManager::memzero($key);
                } catch (\Throwable) {
                }

                if ($res !== false) {
                    $plain = $res;
                    $usedVer = $ver;
                    break;
                }
            }

            $auditKey = 'crypto_decrypt:' . $basename;
            $peerAuditKey = $peer . '|' . $auditKey;
            $audit[$peerAuditKey] = ($audit[$peerAuditKey] ?? 0) + 1;
            out('[secrets-agent] audit ' . $peer . ' op=crypto_decrypt basename=' . $basename . ' ok=' . ($plain !== null ? 'true' : 'false') . ' total=' . $audit[$peerAuditKey]);
            auditAppend($auditChain, 'secrets_agent.crypto_decrypt', $actor, [
                'basename' => $basename,
                'ciphertext_len' => strlen($ciphertext),
                'ok' => $plain !== null,
                'key_version' => $usedVer,
            ]);

            if ($plain === null) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'decrypt_failed']) . "\n");
                fclose($conn);
                continue;
            }

            fwrite(
                $conn,
                json_encode(
                    [
                        'ok' => true,
                        'plaintext_b64' => base64_encode($plain),
                        'key_version' => $usedVer,
                    ],
                    JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
                ) . "\n"
            );
            fclose($conn);
            continue;
        }

        if ($op === 'hmac_latest' || $op === 'hmac_candidates') {
            $basename = $req['basename'] ?? null;
            $dataB64 = $req['data_b64'] ?? null;

            if (!is_string($basename) || !is_string($dataB64)) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'bad_request']) . "\n");
                fclose($conn);
                continue;
            }

            $basename = trim($basename);
            if ($basename === '' || str_contains($basename, "\0") || !preg_match('/^[a-z0-9_]{1,64}$/', $basename)) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'bad_basename']) . "\n");
                fclose($conn);
                continue;
            }

            $allow = keyBasenameAllowlist();
            if (!array_key_exists($basename, $allow)) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'basename_not_allowed']) . "\n");
                fclose($conn);
                continue;
            }
            $expectedLen = (int) $allow[$basename];
            if ($expectedLen < 1 || $expectedLen > $maxKeyBytes) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'basename_policy_invalid']) . "\n");
                fclose($conn);
                continue;
            }

            $data = base64_decode($dataB64, true);
            if (!is_string($data)) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'bad_data_b64']) . "\n");
                fclose($conn);
                continue;
            }
            if (strlen($data) > $maxDataBytes) {
                fwrite($conn, json_encode(['ok' => false, 'error' => 'payload_too_large']) . "\n");
                fclose($conn);
                continue;
            }

            if ($kernel instanceof TrustKernel) {
                $kernel->assertReadAllowed('secrets-agent:hmac');
            }

            $versions = KeyManager::listKeyVersions($keysDir, $basename);
            $vers = array_keys($versions);

            if ($op === 'hmac_latest') {
                $latestVer = array_key_last($versions);
                $latestPath = is_string($latestVer) ? ($versions[$latestVer] ?? null) : null;
                if (!is_string($latestVer) || !is_string($latestPath)) {
                    throw new \RuntimeException('key_not_found');
                }

                assertSecureFile($latestPath, 'key_file', $expectedLen);
                $key = @file_get_contents($latestPath);
                if (!is_string($key) || strlen($key) !== $expectedLen) {
                    throw new \RuntimeException('key_read_failed');
                }

                $hash = hash_hmac('sha256', $data, $key, true);
                try {
                    KeyManager::memzero($key);
                } catch (\Throwable) {
                }

                $auditKey = 'hmac_latest:' . $basename;
                $peerAuditKey = $peer . '|' . $auditKey;
                $audit[$peerAuditKey] = ($audit[$peerAuditKey] ?? 0) + 1;
                out('[secrets-agent] audit ' . $peer . ' op=hmac_latest basename=' . $basename . ' total=' . $audit[$peerAuditKey]);
                auditAppend($auditChain, 'secrets_agent.hmac_latest', $actor, [
                    'basename' => $basename,
                    'data_len' => strlen($data),
                    'key_version' => $latestVer,
                ]);

                fwrite(
                    $conn,
                    json_encode(
                        [
                            'ok' => true,
                            'hash_b64' => base64_encode($hash),
                            'key_version' => $latestVer,
                        ],
                        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
                    ) . "\n"
                );
                fclose($conn);
                continue;
            }

            $maxCandidates = $req['max_candidates'] ?? 20;
            if (is_string($maxCandidates) && ctype_digit(trim($maxCandidates))) {
                $maxCandidates = (int) trim($maxCandidates);
            }
            if (!is_int($maxCandidates)) {
                $maxCandidates = 20;
            }
            $maxCandidates = max(1, min(50, $maxCandidates));

            $outHashes = [];
            $count = 0;
            for ($i = count($vers) - 1; $i >= 0; $i--) {
                if ($count >= $maxCandidates) {
                    break;
                }

                $ver = $vers[$i];
                $path = $versions[$ver] ?? null;
                if (!is_string($ver) || !is_string($path)) {
                    continue;
                }

                assertSecureFile($path, 'key_file', $expectedLen);
                $key = @file_get_contents($path);
                if (!is_string($key) || strlen($key) !== $expectedLen) {
                    continue;
                }

                $hash = hash_hmac('sha256', $data, $key, true);
                try {
                    KeyManager::memzero($key);
                } catch (\Throwable) {
                }

                $outHashes[] = [
                    'key_version' => $ver,
                    'hash_b64' => base64_encode($hash),
                ];
                $count++;
            }

            $auditKey = 'hmac_candidates:' . $basename;
            $peerAuditKey = $peer . '|' . $auditKey;
            $audit[$peerAuditKey] = ($audit[$peerAuditKey] ?? 0) + 1;
            out('[secrets-agent] audit ' . $peer . ' op=hmac_candidates basename=' . $basename . ' count=' . count($outHashes) . ' total=' . $audit[$peerAuditKey]);
            auditAppend($auditChain, 'secrets_agent.hmac_candidates', $actor, [
                'basename' => $basename,
                'data_len' => strlen($data),
                'count' => count($outHashes),
            ]);

            fwrite(
                $conn,
                json_encode(
                    [
                        'ok' => true,
                        'hashes' => $outHashes,
                    ],
                    JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
                ) . "\n"
            );
            fclose($conn);
            continue;
        }

        $role = $req['role'] ?? null;
        if (!is_string($role)) {
            fwrite($conn, json_encode(['ok' => false, 'error' => 'bad_role']) . "\n");
            fclose($conn);
            continue;
        }
        $role = strtolower(trim($role));
        if (!in_array($role, ['read', 'write'], true)) {
            fwrite($conn, json_encode(['ok' => false, 'error' => 'bad_role']) . "\n");
            fclose($conn);
            continue;
        }

        if ($kernel instanceof TrustKernel) {
            if ($role === 'write') {
                $kernel->assertWriteAllowed('secrets-agent:get_db_credentials');
            } else {
                $kernel->assertReadAllowed('secrets-agent:get_db_credentials');
            }
        }

        assertSecureFile($dbCredsPath, 'db_credentials');

        $raw = @file_get_contents($dbCredsPath);
        if (!is_string($raw) || trim($raw) === '') {
            throw new \RuntimeException('db_credentials_file_empty');
        }

        /** @var mixed $decoded */
        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            throw new \RuntimeException('db_credentials_file_bad_json');
        }

        $section = $decoded[$role] ?? null;
        if (!is_array($section)) {
            throw new \RuntimeException('db_credentials_missing_section');
        }

        $dsn = safeString($section['dsn'] ?? null);
        $user = safeString($section['user'] ?? null);
        $pass = safeString($section['pass'] ?? null);
        if ($dsn === null || $user === null || $pass === null) {
            throw new \RuntimeException('db_credentials_invalid');
        }

        $auditKey = 'db:' . $role;
        $peerAuditKey = $peer . '|' . $auditKey;
        $audit[$peerAuditKey] = ($audit[$peerAuditKey] ?? 0) + 1;
        out('[secrets-agent] audit ' . $peer . ' op=get_db_credentials role=' . $role . ' total=' . $audit[$peerAuditKey]);
        auditAppend($auditChain, 'secrets_agent.get_db_credentials', $actor, [
            'role' => $role,
        ]);

        fwrite(
            $conn,
            json_encode(
                [
                    'ok' => true,
                    'dsn' => $dsn,
                    'user' => $user,
                    'pass' => $pass,
                ],
                JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
            ) . "\n"
        );
        fclose($conn);
        continue;

    } catch (TrustKernelException) {
        auditAppend($auditChain, 'secrets_agent.reject.denied', $actor, ['op' => (string) $op]);
        fwrite($conn, json_encode(['ok' => false, 'error' => 'denied']) . "\n");
    } catch (\Throwable $e) {
        auditAppend($auditChain, 'secrets_agent.error', $actor, ['op' => (string) $op, 'error' => $e->getMessage()]);
        fwrite($conn, json_encode(['ok' => false, 'error' => 'agent_error:' . $e->getMessage()]) . "\n");
    } finally {
        fclose($conn);
    }
}
