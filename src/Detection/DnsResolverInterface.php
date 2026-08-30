<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan\Detection;

interface DnsResolverInterface
{
    public function reverse(string $ip): ?string;

    /**
     * @return list<string>
     */
    public function forward(string $hostname): array;
}
