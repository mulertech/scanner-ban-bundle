<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan\Tests\Double;

use MulerTech\ScannerBan\Detection\DnsResolverInterface;

final class FakeDnsResolver implements DnsResolverInterface
{
    public int $reverseCalls = 0;

    /**
     * @param array<string, string>       $reverse
     * @param array<string, list<string>> $forward
     */
    public function __construct(
        private readonly array $reverse = [],
        private readonly array $forward = [],
    ) {
    }

    public function reverse(string $ip): ?string
    {
        ++$this->reverseCalls;

        return $this->reverse[$ip] ?? null;
    }

    public function forward(string $hostname): array
    {
        return $this->forward[$hostname] ?? [];
    }
}
