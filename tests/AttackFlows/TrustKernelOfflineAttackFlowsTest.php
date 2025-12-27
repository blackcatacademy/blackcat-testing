<?php

declare(strict_types=1);

namespace BlackCat\Testing\Tests\AttackFlows;

use BlackCat\Config\Runtime\ConfigRepository;
use BlackCat\Core\TrustKernel\BlackCatConfigRepositoryAdapter;
use BlackCat\Core\TrustKernel\Bytes32;
use BlackCat\Core\TrustKernel\IntegrityManifestBuilder;
use BlackCat\Core\TrustKernel\TrustKernel;
use BlackCat\Core\TrustKernel\TrustKernelConfig;
use BlackCat\Core\TrustKernel\TrustKernelException;
use BlackCat\Testing\Tests\Support\StubWeb3Transport;
use PHPUnit\Framework\TestCase;

final class TrustKernelOfflineAttackFlowsTest extends TestCase
{
    public function test_strict_v3_happy_path_runtime_config_attested_and_locked(): void
    {
        $base = self::mkTempDir('bctest-v3-ok-');
        $rootDir = $base . '/root';
        $manifestPath = $base . '/integrity.manifest.json';
        $configPath = $base . '/config.runtime.json';
        $instanceController = '0x1111111111111111111111111111111111111111';

        mkdir($rootDir, 0700, true);
        file_put_contents($rootDir . '/index.php', "<?php\nreturn 'ok';\n");
        mkdir($rootDir . '/src', 0700, true);
        file_put_contents($rootDir . '/src/app.php', "<?php\nreturn 123;\n");

        $uri = 'ipfs://example';
        $manifestBuild = IntegrityManifestBuilder::build($rootDir, $uri);
        self::writeJsonFile($manifestPath, $manifestBuild['manifest'], 0600);

        $runtimeConfig = self::runtimeConfig(
            chainId: 4207,
            rpcEndpoints: ['https://stub.local'],
            rpcQuorum: 1,
            mode: 'full',
            maxStaleSec: 60,
            timeoutSec: 5,
            instanceController: $instanceController,
            integrityRootDir: $rootDir,
            integrityManifestPath: $manifestPath,
        );
        self::writeJsonFile($configPath, $runtimeConfig, 0600);

        $repo = ConfigRepository::fromJsonFile($configPath);
        $cfg = TrustKernelConfig::fromRuntimeConfig(new BlackCatConfigRepositoryAdapter($repo));
        self::assertNotNull($cfg);
        self::assertNotNull($cfg->runtimeConfigCanonicalSha256);

        $snapshotHex = self::encodeSnapshotHex(
            paused: false,
            activeRoot: $manifestBuild['root'],
            activeUriHash: $manifestBuild['uri_hash'] ?? ('0x' . str_repeat('00', 32)),
            activePolicyHash: $cfg->policyHashV3Strict,
        );

        $transport = new StubWeb3Transport(
            chainId: 4207,
            snapshotResultHex: $snapshotHex,
            attestations: [
                Bytes32::normalizeHex($cfg->runtimeConfigAttestationKey) => Bytes32::normalizeHex($cfg->runtimeConfigCanonicalSha256),
            ],
            attestationLocked: [
                Bytes32::normalizeHex($cfg->runtimeConfigAttestationKey) => true,
            ],
        );

        $kernel = new TrustKernel($cfg, null, $transport);
        $status = $kernel->check();

        self::assertTrue($status->trustedNow);
        self::assertTrue($status->readAllowed);
        self::assertTrue($status->writeAllowed);
        self::assertSame([], $status->errorCodes);
    }

    public function test_integrity_hash_mismatch_is_detected(): void
    {
        $base = self::mkTempDir('bctest-integrity-mismatch-');
        $rootDir = $base . '/root';
        $manifestPath = $base . '/integrity.manifest.json';
        $configPath = $base . '/config.runtime.json';
        $instanceController = '0x2222222222222222222222222222222222222222';

        mkdir($rootDir, 0700, true);
        file_put_contents($rootDir . '/a.txt', "A\n");
        file_put_contents($rootDir . '/b.txt', "B\n");

        $manifestBuild = IntegrityManifestBuilder::build($rootDir, null);
        self::writeJsonFile($manifestPath, $manifestBuild['manifest'], 0600);

        $runtimeConfig = self::runtimeConfig(
            chainId: 4207,
            rpcEndpoints: ['https://stub.local'],
            rpcQuorum: 1,
            mode: 'full',
            maxStaleSec: 60,
            timeoutSec: 5,
            instanceController: $instanceController,
            integrityRootDir: $rootDir,
            integrityManifestPath: $manifestPath,
        );
        self::writeJsonFile($configPath, $runtimeConfig, 0600);

        $repo = ConfigRepository::fromJsonFile($configPath);
        $cfg = TrustKernelConfig::fromRuntimeConfig(new BlackCatConfigRepositoryAdapter($repo));
        self::assertNotNull($cfg);

        // Tamper after manifest build.
        sleep(1);
        file_put_contents($rootDir . '/a.txt', "X\n");

        $snapshotHex = self::encodeSnapshotHex(
            paused: false,
            activeRoot: $manifestBuild['root'],
            activeUriHash: $manifestBuild['uri_hash'] ?? ('0x' . str_repeat('00', 32)),
            activePolicyHash: $cfg->policyHashV2Strict,
        );

        $kernel = new TrustKernel($cfg, null, new StubWeb3Transport(4207, $snapshotHex));
        $status = $kernel->check();

        self::assertFalse($status->trustedNow);
        self::assertContains('integrity_hash_mismatch', $status->errorCodes);
        self::assertFalse($status->writeAllowed);
    }

    public function test_integrity_unexpected_file_is_detected_in_full_mode(): void
    {
        $base = self::mkTempDir('bctest-integrity-unexpected-');
        $rootDir = $base . '/root';
        $manifestPath = $base . '/integrity.manifest.json';
        $configPath = $base . '/config.runtime.json';
        $instanceController = '0x3333333333333333333333333333333333333333';

        mkdir($rootDir, 0700, true);
        file_put_contents($rootDir . '/a.txt', "A\n");

        $manifestBuild = IntegrityManifestBuilder::build($rootDir, null);
        self::writeJsonFile($manifestPath, $manifestBuild['manifest'], 0600);

        // Add an unexpected file after manifest build.
        sleep(1);
        file_put_contents($rootDir . '/unexpected.txt', "boom\n");

        $runtimeConfig = self::runtimeConfig(
            chainId: 4207,
            rpcEndpoints: ['https://stub.local'],
            rpcQuorum: 1,
            mode: 'full',
            maxStaleSec: 60,
            timeoutSec: 5,
            instanceController: $instanceController,
            integrityRootDir: $rootDir,
            integrityManifestPath: $manifestPath,
        );
        self::writeJsonFile($configPath, $runtimeConfig, 0600);

        $repo = ConfigRepository::fromJsonFile($configPath);
        $cfg = TrustKernelConfig::fromRuntimeConfig(new BlackCatConfigRepositoryAdapter($repo));
        self::assertNotNull($cfg);

        $snapshotHex = self::encodeSnapshotHex(
            paused: false,
            activeRoot: $manifestBuild['root'],
            activeUriHash: $manifestBuild['uri_hash'] ?? ('0x' . str_repeat('00', 32)),
            activePolicyHash: $cfg->policyHashV2Strict,
        );

        $kernel = new TrustKernel($cfg, null, new StubWeb3Transport(4207, $snapshotHex));
        $status = $kernel->check();

        self::assertFalse($status->trustedNow);
        self::assertContains('integrity_unexpected_file', $status->errorCodes);
    }

    public function test_policy_v3_runtime_config_tamper_is_detected_via_attestation_mismatch(): void
    {
        $base = self::mkTempDir('bctest-v3-tamper-');
        $rootDir = $base . '/root';
        $manifestPath = $base . '/integrity.manifest.json';
        $configPath = $base . '/config.runtime.json';
        $instanceController = '0x4444444444444444444444444444444444444444';

        mkdir($rootDir, 0700, true);
        file_put_contents($rootDir . '/app.php', "<?php\nreturn 'x';\n");
        $manifestBuild = IntegrityManifestBuilder::build($rootDir, null);
        self::writeJsonFile($manifestPath, $manifestBuild['manifest'], 0600);

        $runtimeConfigV1 = self::runtimeConfig(
            chainId: 4207,
            rpcEndpoints: ['https://stub.local'],
            rpcQuorum: 1,
            mode: 'full',
            maxStaleSec: 60,
            timeoutSec: 5,
            instanceController: $instanceController,
            integrityRootDir: $rootDir,
            integrityManifestPath: $manifestPath,
        );
        self::writeJsonFile($configPath, $runtimeConfigV1, 0600);

        $repoV1 = ConfigRepository::fromJsonFile($configPath);
        $cfgV1 = TrustKernelConfig::fromRuntimeConfig(new BlackCatConfigRepositoryAdapter($repoV1));
        self::assertNotNull($cfgV1);
        self::assertNotNull($cfgV1->runtimeConfigCanonicalSha256);

        $snapshotHex = self::encodeSnapshotHex(
            paused: false,
            activeRoot: $manifestBuild['root'],
            activeUriHash: $manifestBuild['uri_hash'] ?? ('0x' . str_repeat('00', 32)),
            activePolicyHash: $cfgV1->policyHashV3Strict,
        );

        $attestationKey = Bytes32::normalizeHex($cfgV1->runtimeConfigAttestationKey);
        $onChainValue = Bytes32::normalizeHex($cfgV1->runtimeConfigCanonicalSha256);

        // Now tamper runtime config locally (adds a key).
        sleep(1);
        $runtimeConfigV2 = $runtimeConfigV1;
        $runtimeConfigV2['debug'] = true;
        self::writeJsonFile($configPath, $runtimeConfigV2, 0600);

        $repoV2 = ConfigRepository::fromJsonFile($configPath);
        $cfgV2 = TrustKernelConfig::fromRuntimeConfig(new BlackCatConfigRepositoryAdapter($repoV2));
        self::assertNotNull($cfgV2);
        self::assertNotNull($cfgV2->runtimeConfigCanonicalSha256);

        $kernel = new TrustKernel(
            $cfgV2,
            null,
            new StubWeb3Transport(
                chainId: 4207,
                snapshotResultHex: $snapshotHex,
                attestations: [$attestationKey => $onChainValue],
                attestationLocked: [$attestationKey => true],
            ),
        );

        $status = $kernel->check();
        self::assertFalse($status->trustedNow);
        self::assertContains('runtime_config_commitment_mismatch', $status->errorCodes);
    }

    public function test_stale_reads_are_allowed_on_rpc_outage_but_writes_are_denied(): void
    {
        $base = self::mkTempDir('bctest-stale-reads-');
        $rootDir = $base . '/root';
        $manifestPath = $base . '/integrity.manifest.json';
        $configPath = $base . '/config.runtime.json';
        $instanceController = '0x5555555555555555555555555555555555555555';

        mkdir($rootDir, 0700, true);
        file_put_contents($rootDir . '/a.txt', "A\n");

        $manifestBuild = IntegrityManifestBuilder::build($rootDir, null);
        self::writeJsonFile($manifestPath, $manifestBuild['manifest'], 0600);

        $runtimeConfig = self::runtimeConfig(
            chainId: 4207,
            rpcEndpoints: ['https://stub.local'],
            rpcQuorum: 1,
            mode: 'full',
            maxStaleSec: 5,
            timeoutSec: 5,
            instanceController: $instanceController,
            integrityRootDir: $rootDir,
            integrityManifestPath: $manifestPath,
        );
        self::writeJsonFile($configPath, $runtimeConfig, 0600);

        $repo = ConfigRepository::fromJsonFile($configPath);
        $cfg = TrustKernelConfig::fromRuntimeConfig(new BlackCatConfigRepositoryAdapter($repo));
        self::assertNotNull($cfg);

        $snapshotHex = self::encodeSnapshotHex(
            paused: false,
            activeRoot: $manifestBuild['root'],
            activeUriHash: $manifestBuild['uri_hash'] ?? ('0x' . str_repeat('00', 32)),
            activePolicyHash: $cfg->policyHashV2Strict,
        );

        $transport = new StubWeb3Transport(
            chainId: 4207,
            snapshotResultHex: $snapshotHex,
            ethCallFailAfter: 2,
        );
        $kernel = new TrustKernel($cfg, null, $transport);

        $ok = $kernel->check();
        self::assertTrue($ok->trustedNow);

        sleep(1);

        $stale = $kernel->check();
        self::assertFalse($stale->rpcOkNow);
        self::assertFalse($stale->trustedNow);
        self::assertTrue($stale->readAllowed);
        self::assertFalse($stale->writeAllowed);
        self::assertContains('rpc_error', $stale->errorCodes);
    }

    public function test_rpc_outage_plus_local_tamper_denies_stale_reads(): void
    {
        $base = self::mkTempDir('bctest-stale-tamper-');
        $rootDir = $base . '/root';
        $manifestPath = $base . '/integrity.manifest.json';
        $configPath = $base . '/config.runtime.json';
        $instanceController = '0x6666666666666666666666666666666666666666';

        mkdir($rootDir, 0700, true);
        file_put_contents($rootDir . '/a.txt', "A\n");

        $manifestBuild = IntegrityManifestBuilder::build($rootDir, null);
        self::writeJsonFile($manifestPath, $manifestBuild['manifest'], 0600);

        $runtimeConfig = self::runtimeConfig(
            chainId: 4207,
            rpcEndpoints: ['https://stub.local'],
            rpcQuorum: 1,
            mode: 'full',
            maxStaleSec: 5,
            timeoutSec: 5,
            instanceController: $instanceController,
            integrityRootDir: $rootDir,
            integrityManifestPath: $manifestPath,
        );
        self::writeJsonFile($configPath, $runtimeConfig, 0600);

        $repo = ConfigRepository::fromJsonFile($configPath);
        $cfg = TrustKernelConfig::fromRuntimeConfig(new BlackCatConfigRepositoryAdapter($repo));
        self::assertNotNull($cfg);

        $snapshotHex = self::encodeSnapshotHex(
            paused: false,
            activeRoot: $manifestBuild['root'],
            activeUriHash: $manifestBuild['uri_hash'] ?? ('0x' . str_repeat('00', 32)),
            activePolicyHash: $cfg->policyHashV2Strict,
        );

        $transport = new StubWeb3Transport(
            chainId: 4207,
            snapshotResultHex: $snapshotHex,
            ethCallFailAfter: 2,
        );
        $kernel = new TrustKernel($cfg, null, $transport);

        $ok = $kernel->check();
        self::assertTrue($ok->trustedNow);

        sleep(1);
        file_put_contents($rootDir . '/a.txt', "HACKED\n");

        sleep(1);
        $stale = $kernel->check();
        self::assertFalse($stale->readAllowed);
        self::assertFalse($stale->writeAllowed);
        self::assertContains('rpc_error', $stale->errorCodes);
        self::assertContains('stale_integrity_recheck_failed', $stale->errorCodes);
    }

    public function test_paused_controller_is_emergency_stop_even_in_warn_policy(): void
    {
        $base = self::mkTempDir('bctest-paused-');
        $rootDir = $base . '/root';
        $manifestPath = $base . '/integrity.manifest.json';
        $configPath = $base . '/config.runtime.json';
        $instanceController = '0x9999999999999999999999999999999999999999';

        mkdir($rootDir, 0700, true);
        file_put_contents($rootDir . '/a.txt', "A\n");

        $manifestBuild = IntegrityManifestBuilder::build($rootDir, null);
        self::writeJsonFile($manifestPath, $manifestBuild['manifest'], 0600);

        $runtimeConfig = self::runtimeConfig(
            chainId: 4207,
            rpcEndpoints: ['https://stub.local'],
            rpcQuorum: 1,
            mode: 'full',
            maxStaleSec: 60,
            timeoutSec: 5,
            instanceController: $instanceController,
            integrityRootDir: $rootDir,
            integrityManifestPath: $manifestPath,
        );
        self::writeJsonFile($configPath, $runtimeConfig, 0600);

        $repo = ConfigRepository::fromJsonFile($configPath);
        $cfg = TrustKernelConfig::fromRuntimeConfig(new BlackCatConfigRepositoryAdapter($repo));
        self::assertNotNull($cfg);

        $snapshotHex = self::encodeSnapshotHex(
            paused: true,
            activeRoot: $manifestBuild['root'],
            activeUriHash: $manifestBuild['uri_hash'] ?? ('0x' . str_repeat('00', 32)),
            activePolicyHash: $cfg->policyHashV2Warn,
        );

        $kernel = new TrustKernel($cfg, null, new StubWeb3Transport(4207, $snapshotHex));

        $this->expectException(TrustKernelException::class);
        $kernel->assertReadAllowed('test.read');
    }

    /**
     * @param list<string> $rpcEndpoints
     * @return array<string,mixed>
     */
    private static function runtimeConfig(
        int $chainId,
        array $rpcEndpoints,
        int $rpcQuorum,
        string $mode,
        int $maxStaleSec,
        int $timeoutSec,
        string $instanceController,
        string $integrityRootDir,
        string $integrityManifestPath,
    ): array
    {
        return [
            'trust' => [
                'integrity' => [
                    'root_dir' => $integrityRootDir,
                    'manifest' => $integrityManifestPath,
                ],
                'web3' => [
                    'chain_id' => $chainId,
                    'rpc_endpoints' => $rpcEndpoints,
                    'rpc_quorum' => $rpcQuorum,
                    'mode' => $mode,
                    'max_stale_sec' => $maxStaleSec,
                    'timeout_sec' => $timeoutSec,
                    'contracts' => [
                        'instance_controller' => $instanceController,
                    ],
                ],
            ],
        ];
    }

    private static function mkTempDir(string $prefix): string
    {
        $base = rtrim(sys_get_temp_dir(), '/\\');
        $dir = $base . '/' . $prefix . bin2hex(random_bytes(6));
        mkdir($dir, 0700, true);
        return $dir;
    }

    /**
     * @param array<string,mixed> $data
     */
    private static function writeJsonFile(string $path, array $data, int $mode): void
    {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }

        $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        if (!is_string($json)) {
            throw new \RuntimeException('Unable to encode JSON.');
        }

        file_put_contents($path, $json . "\n");
        @chmod($path, $mode);
    }

    private static function encodeSnapshotHex(
        bool $paused,
        string $activeRoot,
        string $activeUriHash,
        string $activePolicyHash,
        int $pendingCreatedAt = 0,
        int $pendingTtlSec = 0,
        int $genesisAt = 0,
        int $lastUpgradeAt = 0,
    ): string
    {
        $zero = '0x' . str_repeat('00', 32);

        $words = [
            self::wordUint8(1),                    // version
            self::wordBool($paused),               // paused
            self::wordBytes32($activeRoot),        // activeRoot
            self::wordBytes32($activeUriHash),     // activeUriHash
            self::wordBytes32($activePolicyHash),  // activePolicyHash
            self::wordBytes32($zero),              // pendingRoot
            self::wordBytes32($zero),              // pendingUriHash
            self::wordBytes32($zero),              // pendingPolicyHash
            self::wordUint64($pendingCreatedAt),
            self::wordUint64($pendingTtlSec),
            self::wordUint64($genesisAt),
            self::wordUint64($lastUpgradeAt),
        ];

        return '0x' . implode('', $words);
    }

    private static function wordBytes32(string $bytes32): string
    {
        return substr(Bytes32::normalizeHex($bytes32), 2);
    }

    private static function wordUint8(int $value): string
    {
        if ($value < 0 || $value > 255) {
            throw new \InvalidArgumentException('uint8 out of range.');
        }
        return str_repeat('0', 62) . str_pad(dechex($value), 2, '0', STR_PAD_LEFT);
    }

    private static function wordBool(bool $value): string
    {
        return str_repeat('0', 63) . ($value ? '1' : '0');
    }

    private static function wordUint64(int $value): string
    {
        if ($value < 0 || $value > 0xffffffffffffffff) {
            throw new \InvalidArgumentException('uint64 out of range.');
        }
        $hex = str_pad(dechex($value), 16, '0', STR_PAD_LEFT);
        return str_repeat('0', 48) . $hex;
    }
}
