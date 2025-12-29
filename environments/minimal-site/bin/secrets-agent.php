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
use BlackCat\Core\Security\KeyManager;
use BlackCat\Core\Security\SecretsAgentPolicy;

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
$kernel = null;
$peerCredRequired = true;
/** @var list<int> */
$allowedPeerUids = [];
$agentMode = 'keyless';
$limiterEnabled = true;
$limiterDefaultRpm = 6000;
/** @var array<string,int> */
$limiterOpRpm = [];

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
    }
} catch (\Throwable $e) {
    out('[secrets-agent] WARN: runtime config read failed: ' . $e->getMessage());
}

$socketPath ??= '/etc/blackcat/secrets-agent.sock';
$keysDir ??= '/etc/blackcat/keys';
$dbCredsPath ??= '/etc/blackcat/db.credentials.json';

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

if ($socketPath === '' || str_contains($socketPath, "\0")) {
    throw new \RuntimeException('Invalid socket path.');
}
if ($keysDir === '' || str_contains($keysDir, "\0")) {
    throw new \RuntimeException('Invalid keys directory path.');
}
if ($dbCredsPath === '' || str_contains($dbCredsPath, "\0")) {
    throw new \RuntimeException('Invalid db credentials file path.');
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

    if ($peerCredRequired) {
        $uid = $peerInfo['uid'] ?? null;
        if (!is_int($uid)) {
            fwrite($conn, json_encode(['ok' => false, 'error' => 'peercred_unavailable']) . "\n");
            fclose($conn);
            continue;
        }
        if ($allowedPeerUids !== [] && !in_array($uid, $allowedPeerUids, true)) {
            fwrite($conn, json_encode(['ok' => false, 'error' => 'peercred_uid_not_allowed']) . "\n");
            fclose($conn);
            continue;
        }
    }

    stream_set_timeout($conn, 2);

    $line = stream_get_line($conn, $maxLine, "\n");
    if (!is_string($line) || trim($line) === '') {
        fwrite($conn, json_encode(['ok' => false, 'error' => 'empty_request']) . "\n");
        fclose($conn);
        continue;
    }

    try {
        /** @var mixed $req */
        $req = json_decode($line, true, 64, JSON_THROW_ON_ERROR);
    } catch (\JsonException) {
        fwrite($conn, json_encode(['ok' => false, 'error' => 'bad_json']) . "\n");
        fclose($conn);
        continue;
    }

    if (!is_array($req)) {
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
    ) {
        fwrite($conn, json_encode(['ok' => false, 'error' => 'unsupported_op']) . "\n");
        fclose($conn);
        continue;
    }

    try {
        $uid = $peerInfo['uid'] ?? null;
        $uid = is_int($uid) ? $uid : null;

        if (!$limiterAllow($uid, (string) $op)) {
            fwrite($conn, json_encode(['ok' => false, 'error' => 'rate_limited']) . "\n");
            fclose($conn);
            continue;
        }

        if ($op === 'get_all_keys') {
            if ($agentMode !== 'keys') {
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

            fwrite($conn, json_encode(['ok' => true, 'keys' => $outKeys], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
            fclose($conn);
            continue;
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
        fwrite($conn, json_encode(['ok' => false, 'error' => 'denied']) . "\n");
    } catch (\Throwable $e) {
        fwrite($conn, json_encode(['ok' => false, 'error' => 'agent_error:' . $e->getMessage()]) . "\n");
    } finally {
        fclose($conn);
    }
}
