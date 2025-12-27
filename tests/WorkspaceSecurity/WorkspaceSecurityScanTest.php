<?php

declare(strict_types=1);

namespace BlackCat\Testing\Tests\WorkspaceSecurity;

use BlackCat\Config\Security\AttackSurfaceScanner;
use PHPUnit\Framework\TestCase;

final class WorkspaceSecurityScanTest extends TestCase
{
    public function testWorkspaceDoesNotUseObviousHighRiskPhpPrimitives(): void
    {
        $academyRoot = self::academyRoot();

        $scanRoots = [
            'blackcat-core' => $academyRoot . '/blackcat-core/src',
            'blackcat-config' => $academyRoot . '/blackcat-config/src',
            'blackcat-crypto' => $academyRoot . '/blackcat-crypto/src',
            'blackcat-database' => $academyRoot . '/blackcat-database/src',
            'blackcat-database-crypto' => $academyRoot . '/blackcat-database-crypto/src',
        ];

        $errors = [];
        $warns = [];

        foreach ($scanRoots as $label => $dir) {
            if (!is_dir($dir)) {
                continue;
            }

            $result = AttackSurfaceScanner::scan($dir, [
                'max_files' => 50000,
            ]);

            foreach ($result['findings'] as $finding) {
                $entry = sprintf('%s:%d [%s] %s', $finding['file'], $finding['line'], $finding['rule'], $finding['message']);
                if ($finding['severity'] === 'error') {
                    $errors[] = $entry;
                } else {
                    $warns[] = $entry;
                }
            }
        }

        if ($errors !== []) {
            self::fail("Attack surface scanner found forbidden patterns:\n" . implode("\n", $errors));
        }

        // Warnings are reported but not failed by default (runbooks may choose to treat them as failures).
        self::assertTrue(true, implode("\n", $warns));
    }

    public function testWorkspaceDoesNotBypassKernelWithRawPdoOutsideCore(): void
    {
        $academyRoot = self::academyRoot();

        $scanned = [
            $academyRoot . '/blackcat-config/src',
            $academyRoot . '/blackcat-crypto/src',
            $academyRoot . '/blackcat-database/src',
            $academyRoot . '/blackcat-database-crypto/src',
        ];

        $violations = [];

        foreach ($scanned as $dir) {
            if (!is_dir($dir)) {
                continue;
            }

            foreach (self::phpFiles($dir) as $file) {
                $code = @file_get_contents($file);
                if (!is_string($code)) {
                    continue;
                }

                foreach (self::scanPhpForRawPdo($code, $file) as $v) {
                    $violations[] = $v;
                }
            }
        }

        if ($violations !== []) {
            self::fail("Raw PDO usage detected outside blackcat-core (bypass surface):\n" . implode("\n", $violations));
        }

        self::assertCount(0, $violations);
    }

    public function testWorkspaceDoesNotReadKeyFilesDirectlyInCodeOutsideCore(): void
    {
        $academyRoot = self::academyRoot();

        $scanned = [
            $academyRoot . '/blackcat-config/src',
            $academyRoot . '/blackcat-crypto/src',
            $academyRoot . '/blackcat-database/src',
            $academyRoot . '/blackcat-database-crypto/src',
        ];

        $violations = [];

        foreach ($scanned as $dir) {
            if (!is_dir($dir)) {
                continue;
            }

            foreach (self::phpFiles($dir) as $file) {
                $code = @file_get_contents($file);
                if (!is_string($code)) {
                    continue;
                }

                foreach (self::scanPhpForDirectKeyFileReads($code, $file) as $v) {
                    $violations[] = $v;
                }
            }
        }

        if ($violations !== []) {
            self::fail("Direct reads of *.key files detected outside blackcat-core (must go through KeyManager):\n" . implode("\n", $violations));
        }

        self::assertCount(0, $violations);
    }

    private static function academyRoot(): string
    {
        return dirname(__DIR__, 3);
    }

    /**
     * @return list<string>
     */
    private static function phpFiles(string $rootDir): array
    {
        $out = [];

        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($rootDir, \FilesystemIterator::SKIP_DOTS)
        );

        /** @var \SplFileInfo $file */
        foreach ($it as $file) {
            if ($file->isDir()) {
                continue;
            }

            $path = $file->getPathname();
            $rel = str_replace('\\', '/', substr($path, strlen($rootDir)));
            $rel = ltrim($rel, '/');

            if (str_starts_with($rel, 'vendor/') || str_starts_with($rel, 'tests/')) {
                continue;
            }

            if (strtolower($file->getExtension()) !== 'php') {
                continue;
            }

            $out[] = $path;
        }

        sort($out, SORT_STRING);
        return $out;
    }

    /**
     * @return list<string>
     */
    private static function scanPhpForRawPdo(string $code, string $file): array
    {
        $tokens = token_get_all($code);
        $count = count($tokens);
        $out = [];

        for ($i = 0; $i < $count; $i++) {
            $tok = $tokens[$i];
            if (!is_array($tok) || $tok[0] !== T_NEW) {
                continue;
            }

            $j = self::nextNonTriviaTokenIndex($tokens, $i + 1);
            if ($j === null) {
                continue;
            }

            $nameTok = $tokens[$j];
            if (!is_array($nameTok)) {
                continue;
            }

            $name = $nameTok[1];
            if ($name === '') {
                continue;
            }

            $normalized = ltrim($name, '\\');
            if (strcasecmp($normalized, 'PDO') === 0) {
                $line = (int) $tok[2];
                $out[] = sprintf('%s:%d new PDO(...)', $file, $line);
            }
        }

        return $out;
    }

    /**
     * @return list<string>
     */
    private static function scanPhpForDirectKeyFileReads(string $code, string $file): array
    {
        $tokens = token_get_all($code);
        $count = count($tokens);
        $out = [];

        for ($i = 0; $i < $count; $i++) {
            $tok = $tokens[$i];
            if (!is_array($tok) || $tok[0] !== T_STRING) {
                continue;
            }

            $fn = strtolower((string) $tok[1]);
            if (!in_array($fn, ['file_get_contents', 'fopen'], true)) {
                continue;
            }

            $call = self::isFunctionCall($tokens, $i);
            if (!$call) {
                continue;
            }

            $argTokIndex = self::nextNonTriviaTokenIndex($tokens, $i + 1);
            if ($argTokIndex === null || $tokens[$argTokIndex] !== '(') {
                continue;
            }

            $firstArgIndex = self::nextNonTriviaTokenIndex($tokens, $argTokIndex + 1);
            if ($firstArgIndex === null) {
                continue;
            }

            $firstArgTok = $tokens[$firstArgIndex];
            if (!is_array($firstArgTok) || $firstArgTok[0] !== T_CONSTANT_ENCAPSED_STRING) {
                continue;
            }

            $raw = (string) $firstArgTok[1];
            $lit = self::unquotePhpStringLiteral($raw);
            if ($lit === null) {
                continue;
            }

            if (str_contains($lit, '.key')) {
                $line = (int) $tok[2];
                $out[] = sprintf('%s:%d %s(%s)', $file, $line, $fn, $raw);
            }
        }

        return $out;
    }

    /**
     * @param array<int,mixed> $tokens
     */
    private static function isFunctionCall(array $tokens, int $i): bool
    {
        $prev = self::prevNonTriviaToken($tokens, $i - 1);
        if (is_array($prev)) {
            if (in_array($prev[0], [T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_NEW], true)) {
                return false;
            }
        } elseif (is_string($prev)) {
            if ($prev === '->' || $prev === '::') {
                return false;
            }
        }

        return true;
    }

    /**
     * @param array<int,mixed> $tokens
     */
    private static function prevNonTriviaToken(array $tokens, int $i): mixed
    {
        for ($j = $i; $j >= 0; $j--) {
            $tok = $tokens[$j];
            if (is_array($tok)) {
                if (in_array($tok[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                    continue;
                }
                return $tok;
            }
            if (is_string($tok) && trim($tok) === '') {
                continue;
            }
            return $tok;
        }

        return null;
    }

    /**
     * @param array<int,mixed> $tokens
     */
    private static function nextNonTriviaTokenIndex(array $tokens, int $i): ?int
    {
        $count = count($tokens);
        for ($j = $i; $j < $count; $j++) {
            $tok = $tokens[$j];
            if (is_array($tok)) {
                if (in_array($tok[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                    continue;
                }
                return $j;
            }
            if (is_string($tok) && trim($tok) === '') {
                continue;
            }
            return $j;
        }

        return null;
    }

    private static function unquotePhpStringLiteral(string $raw): ?string
    {
        $raw = trim($raw);
        if ($raw === '') {
            return null;
        }
        $q = $raw[0];
        if (($q !== '"' && $q !== "'") || !str_ends_with($raw, $q)) {
            return null;
        }

        $inner = substr($raw, 1, -1);
        if (!is_string($inner)) {
            return null;
        }

        // Best-effort: treat it as a literal; we don't fully unescape here.
        return $inner;
    }
}
