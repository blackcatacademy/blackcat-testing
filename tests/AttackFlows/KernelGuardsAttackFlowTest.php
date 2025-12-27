<?php

declare(strict_types=1);

namespace BlackCat\Testing\Tests\AttackFlows;

use BlackCat\Core\Database;
use BlackCat\Core\DatabaseException;
use BlackCat\Core\Security\KeyManager;
use BlackCat\Core\Security\KeyManagerException;
use BlackCat\Core\TrustKernel\TrustKernel;
use BlackCat\Core\TrustKernel\TrustKernelConfig;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

final class KernelGuardsAttackFlowTest extends TestCase
{
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function test_install_guards_locks_kernel_guards_and_prevents_runtime_disabling(): void
    {
        $tmp = rtrim(sys_get_temp_dir(), '/\\') . '/bctest-guards-' . bin2hex(random_bytes(6));
        mkdir($tmp, 0700, true);
        $rootDir = $tmp . '/root';
        mkdir($rootDir, 0700, true);
        file_put_contents($rootDir . '/a.txt', "A\n");

        $cfg = new TrustKernelConfig(
            chainId: 4207,
            rpcEndpoints: ['https://stub.local'],
            rpcQuorum: 1,
            maxStaleSec: 60,
            mode: 'full',
            instanceController: '0x7777777777777777777777777777777777777777',
            releaseRegistry: null,
            integrityRootDir: $rootDir,
            integrityManifestPath: $tmp . '/manifest.json',
            rpcTimeoutSec: 5,
            runtimeConfigCanonicalSha256: null,
            runtimeConfigSourcePath: null,
        );

        $kernel = new TrustKernel($cfg);
        $kernel->installGuards();

        self::assertTrue(KeyManager::hasAccessGuard());
        self::assertTrue(KeyManager::isAccessGuardLocked());
        self::assertTrue(Database::hasWriteGuard());
        self::assertTrue(Database::isWriteGuardLocked());
        self::assertTrue(Database::hasPdoAccessGuard());
        self::assertTrue(Database::isPdoAccessGuardLocked());

        $this->expectException(DatabaseException::class);
        Database::setWriteGuard(null);
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function test_locked_guards_reject_attempts_to_disable_pdo_and_secrets_guards(): void
    {
        $tmp = rtrim(sys_get_temp_dir(), '/\\') . '/bctest-guards2-' . bin2hex(random_bytes(6));
        mkdir($tmp, 0700, true);
        $rootDir = $tmp . '/root';
        mkdir($rootDir, 0700, true);
        file_put_contents($rootDir . '/a.txt', "A\n");

        $cfg = new TrustKernelConfig(
            chainId: 4207,
            rpcEndpoints: ['https://stub.local'],
            rpcQuorum: 1,
            maxStaleSec: 60,
            mode: 'full',
            instanceController: '0x8888888888888888888888888888888888888888',
            releaseRegistry: null,
            integrityRootDir: $rootDir,
            integrityManifestPath: $tmp . '/manifest.json',
            rpcTimeoutSec: 5,
            runtimeConfigCanonicalSha256: null,
            runtimeConfigSourcePath: null,
        );

        $kernel = new TrustKernel($cfg);
        $kernel->installGuards();

        try {
            Database::setPdoAccessGuard(null);
            $this->fail('Expected DatabaseException.');
        } catch (DatabaseException) {
            self::assertTrue(true);
        }

        // KeyManager is also locked by installGuards().
        try {
            KeyManager::setAccessGuard(null);
            $this->fail('Expected KeyManagerException.');
        } catch (KeyManagerException) {
            self::assertTrue(true);
        }
    }
}
