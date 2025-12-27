<?php

declare(strict_types=1);

namespace BlackCat\Testing\Tests\Live;

use BlackCat\Config\Runtime\ConfigRepository;
use BlackCat\Core\TrustKernel\BlackCatConfigRepositoryAdapter;
use BlackCat\Core\TrustKernel\TrustKernel;
use BlackCat\Core\TrustKernel\TrustKernelConfig;
use PHPUnit\Framework\TestCase;

final class TrustKernelLiveSmokeTest extends TestCase
{
    public function test_live_chain_smoke_check_reads_snapshot(): void
    {
        $configPath = getenv('BLACKCAT_TESTING_LIVE_CONFIG');
        if (!is_string($configPath) || trim($configPath) === '') {
            $this->markTestSkipped('Set BLACKCAT_TESTING_LIVE_CONFIG to a runtime config JSON file to run live tests.');
        }

        $repo = ConfigRepository::fromJsonFile($configPath);
        $cfg = TrustKernelConfig::fromRuntimeConfig(new BlackCatConfigRepositoryAdapter($repo));
        if ($cfg === null) {
            $this->markTestSkipped('Runtime config does not configure trust.web3.');
        }

        $kernel = new TrustKernel($cfg);
        $status = $kernel->check();

        self::assertTrue($status->rpcOkNow, 'RPC must be reachable for the live smoke test.');
        self::assertNotNull($status->snapshot);
        self::assertSame(1, $status->snapshot->version);

        $assertTrusted = getenv('BLACKCAT_TESTING_LIVE_ASSERT_TRUSTED');
        if ($assertTrusted === '1') {
            self::assertTrue($status->trustedNow);
            self::assertTrue($status->readAllowed);
            self::assertTrue($status->writeAllowed);
        }
    }
}

