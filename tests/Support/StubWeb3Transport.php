<?php

declare(strict_types=1);

namespace BlackCat\Testing\Tests\Support;

use BlackCat\Core\TrustKernel\Web3TransportInterface;

/**
 * Minimal JSON-RPC transport stub for TrustKernel tests.
 *
 * It responds to:
 * - eth_chainId
 * - eth_getCode
 * - eth_call (snapshot/releaseRegistry/attestations/attestationLocked/attestationUpdatedAt)
 */
final class StubWeb3Transport implements Web3TransportInterface
{
    private const SELECTOR_SNAPSHOT = '0x9711715a';
    private const SELECTOR_RELEASE_REGISTRY = '0x19ee073e';
    private const SELECTOR_ATTESTATIONS = '0x940992a3';
    private const SELECTOR_ATTESTATION_UPDATED_AT = '0xb54917aa';
    private const SELECTOR_ATTESTATION_LOCKED = '0xa93a4e86';

    private int $ethCallCount = 0;

    /**
     * @param array<string,string> $attestations key(bytes32) => value(bytes32)
     * @param array<string,bool> $attestationLocked key(bytes32) => locked
     * @param array<string,int> $attestationUpdatedAt key(bytes32) => uint64 timestamp
     */
    public function __construct(
        private readonly int $chainId,
        private readonly string $snapshotResultHex,
        private readonly string $ethGetCodeHex = '0x60006000',
        private readonly string $releaseRegistryAddress = '0x0000000000000000000000000000000000000000',
        private readonly array $attestations = [],
        private readonly array $attestationLocked = [],
        private readonly array $attestationUpdatedAt = [],
        private readonly ?int $ethCallFailAfter = null,
    ) {
        if ($this->chainId <= 0) {
            throw new \InvalidArgumentException('chainId must be > 0');
        }
        self::assertHex($this->snapshotResultHex, 'snapshotResultHex');
        if (substr(trim($this->snapshotResultHex), 2) === '') {
            throw new \InvalidArgumentException('snapshotResultHex must not be empty.');
        }

        self::assertHex($this->ethGetCodeHex, 'ethGetCodeHex');
        self::assertEvmAddress($this->releaseRegistryAddress, 'releaseRegistryAddress');

        if ($this->ethCallFailAfter !== null && $this->ethCallFailAfter < 0) {
            throw new \InvalidArgumentException('ethCallFailAfter must be >= 0 or null.');
        }
    }

    public function postJson(string $url, string $jsonBody, int $timeoutSec): string
    {
        $decoded = json_decode($jsonBody, true);
        if (!is_array($decoded)) {
            throw new \RuntimeException('StubWeb3Transport: invalid JSON-RPC request (not an object).');
        }

        $method = $decoded['method'] ?? null;
        if (!is_string($method) || $method === '') {
            throw new \RuntimeException('StubWeb3Transport: missing JSON-RPC method.');
        }

        $id = $decoded['id'] ?? 1;
        $params = $decoded['params'] ?? [];
        if (!is_array($params)) {
            $params = [];
        }

        return match ($method) {
            'eth_chainId' => $this->ok($id, '0x' . dechex($this->chainId)),
            'eth_getCode' => $this->ok($id, strtolower($this->ethGetCodeHex)),
            'eth_call' => $this->handleEthCall($id, $params),
            default => $this->err($id, 'Unsupported JSON-RPC method in stub: ' . $method),
        };
    }

    /**
     * @param array<int,mixed> $params
     */
    private function handleEthCall(mixed $id, array $params): string
    {
        $this->ethCallCount++;
        if ($this->ethCallFailAfter !== null && $this->ethCallCount > $this->ethCallFailAfter) {
            return $this->err($id, 'eth_call simulated failure (stub).');
        }

        $call = $params[0] ?? null;
        if (!is_array($call)) {
            return $this->err($id, 'eth_call params[0] must be an object.');
        }

        $data = $call['data'] ?? null;
        if (!is_string($data) || $data === '' || !str_starts_with($data, '0x')) {
            return $this->err($id, 'eth_call data must be 0x-hex string.');
        }

        $data = strtolower($data);
        if (strlen($data) < 10) {
            return $this->err($id, 'eth_call data too short.');
        }

        $selector = substr($data, 0, 10);

        if ($selector === self::SELECTOR_SNAPSHOT) {
            return $this->ok($id, strtolower($this->snapshotResultHex));
        }

        if ($selector === self::SELECTOR_RELEASE_REGISTRY) {
            return $this->ok($id, self::encodeAddressWord($this->releaseRegistryAddress));
        }

        if ($selector === self::SELECTOR_ATTESTATIONS) {
            $key = self::decodeBytes32Arg($data);
            $val = $this->attestations[$key] ?? ('0x' . str_repeat('00', 32));
            return $this->ok($id, self::encodeBytes32Word($val));
        }

        if ($selector === self::SELECTOR_ATTESTATION_UPDATED_AT) {
            $key = self::decodeBytes32Arg($data);
            $at = $this->attestationUpdatedAt[$key] ?? 0;
            return $this->ok($id, self::encodeUint64Word($at));
        }

        if ($selector === self::SELECTOR_ATTESTATION_LOCKED) {
            $key = self::decodeBytes32Arg($data);
            $locked = (bool) ($this->attestationLocked[$key] ?? false);
            return $this->ok($id, self::encodeBoolWord($locked));
        }

        return $this->err($id, 'Unsupported eth_call selector in stub: ' . $selector);
    }

    private function ok(mixed $id, mixed $result): string
    {
        $payload = [
            'jsonrpc' => '2.0',
            'id' => $id,
            'result' => $result,
        ];

        $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if (!is_string($json)) {
            throw new \RuntimeException('StubWeb3Transport: unable to encode response.');
        }

        return $json;
    }

    private function err(mixed $id, string $message): string
    {
        $payload = [
            'jsonrpc' => '2.0',
            'id' => $id,
            'error' => [
                'code' => -32000,
                'message' => $message,
            ],
        ];

        $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if (!is_string($json)) {
            throw new \RuntimeException('StubWeb3Transport: unable to encode error response.');
        }

        return $json;
    }

    private static function decodeBytes32Arg(string $dataHex): string
    {
        // calldata: 0x + 4-byte selector + 32-byte arg
        if (strlen($dataHex) < 10 + 64) {
            throw new \RuntimeException('eth_call bytes32 arg missing.');
        }

        $arg = substr($dataHex, 10, 64);
        if (!is_string($arg) || strlen($arg) !== 64 || !ctype_xdigit($arg)) {
            throw new \RuntimeException('eth_call bytes32 arg invalid.');
        }

        return '0x' . strtolower($arg);
    }

    private static function encodeBytes32Word(string $bytes32): string
    {
        $bytes32 = strtolower(trim($bytes32));
        if (!preg_match('/^0x[a-f0-9]{64}$/', $bytes32)) {
            throw new \InvalidArgumentException('Invalid bytes32.');
        }
        return $bytes32;
    }

    private static function encodeAddressWord(string $address): string
    {
        self::assertEvmAddress($address, 'address');
        return '0x' . str_repeat('0', 24 * 2) . strtolower(substr($address, 2));
    }

    private static function encodeBoolWord(bool $value): string
    {
        return '0x' . str_repeat('0', 63) . ($value ? '1' : '0');
    }

    private static function encodeUint64Word(int $value): string
    {
        if ($value < 0 || $value > 0xffffffffffffffff) {
            throw new \InvalidArgumentException('uint64 out of range.');
        }

        $hex = dechex($value);
        $hex = str_pad($hex, 16, '0', STR_PAD_LEFT);
        return '0x' . str_repeat('0', 64 - 16) . strtolower($hex);
    }

    private static function assertEvmAddress(string $address, string $label): void
    {
        $address = trim($address);
        if (!preg_match('/^0x[a-fA-F0-9]{40}$/', $address)) {
            throw new \InvalidArgumentException("Invalid {$label} address.");
        }
    }

    private static function assertHex(string $hex, string $label): void
    {
        $hex = trim($hex);
        if ($hex === '' || !str_starts_with($hex, '0x')) {
            throw new \InvalidArgumentException('Invalid ' . $label . ' hex.');
        }

        $payload = substr($hex, 2);
        if ($payload !== '' && !ctype_xdigit($payload)) {
            throw new \InvalidArgumentException('Invalid ' . $label . ' hex.');
        }
    }
}
