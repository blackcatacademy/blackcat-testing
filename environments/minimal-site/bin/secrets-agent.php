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

static function out(string $msg): void
{
    fwrite(STDERR, $msg . "\n");
}

static function safeString(mixed $v): ?string
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

static function resolveConfigIfPossible(): void
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
$kernel = null;

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
    }
} catch (\Throwable $e) {
    out('[secrets-agent] WARN: runtime config read failed: ' . $e->getMessage());
}

$socketPath ??= '/etc/blackcat/secrets-agent.sock';
$keysDir ??= '/etc/blackcat/keys';

$socketPath = trim($socketPath);
$keysDir = trim($keysDir);

if ($socketPath === '' || str_contains($socketPath, "\0")) {
    throw new \RuntimeException('Invalid socket path.');
}
if ($keysDir === '' || str_contains($keysDir, "\0")) {
    throw new \RuntimeException('Invalid keys directory path.');
}

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

// Hard cap to avoid abuse.
$maxLine = 8 * 1024;
$maxKeyBytes = 4096;

if (is_link($keysDir)) {
    throw new \RuntimeException('Refusing to use symlink keys_dir: ' . $keysDir);
}

while (true) {
    $conn = @stream_socket_accept($server, -1);
    if (!is_resource($conn)) {
        continue;
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
    if ($op !== 'get_all_keys') {
        fwrite($conn, json_encode(['ok' => false, 'error' => 'unsupported_op']) . "\n");
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

    try {
        if ($kernel instanceof TrustKernel) {
            $kernel->assertReadAllowed('secrets-agent:get_all_keys');
        }

        $versions = KeyManager::listKeyVersions($keysDir, $basename);
        $outKeys = [];
        foreach ($versions as $ver => $path) {
            if (!is_string($ver) || !is_string($path)) {
                continue;
            }
            if (is_link($path)) {
                throw new \RuntimeException('symlink_key_file');
            }
            $raw = @file_get_contents($path);
            if (!is_string($raw) || $raw === '') {
                continue;
            }
            if (strlen($raw) > $maxKeyBytes) {
                throw new \RuntimeException('key_too_large');
            }
            $outKeys[] = [
                'version' => $ver,
                'b64' => base64_encode($raw),
            ];
        }

        fwrite($conn, json_encode(['ok' => true, 'keys' => $outKeys], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
    } catch (TrustKernelException) {
        fwrite($conn, json_encode(['ok' => false, 'error' => 'denied']) . "\n");
    } catch (\Throwable $e) {
        fwrite($conn, json_encode(['ok' => false, 'error' => 'agent_error:' . $e->getMessage()]) . "\n");
    } finally {
        fclose($conn);
    }
}
