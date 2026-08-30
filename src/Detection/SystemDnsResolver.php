<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan\Detection;

final class SystemDnsResolver implements DnsResolverInterface
{
    public function reverse(string $ip): ?string
    {
        $hostname = @gethostbyaddr($ip);

        if (false === $hostname || $hostname === $ip) {
            return null;
        }

        return $hostname;
    }

    public function forward(string $hostname): array
    {
        $addresses = @gethostbynamel($hostname);
        $ipv4 = false === $addresses ? [] : $addresses;

        $records = @dns_get_record($hostname, \DNS_AAAA);
        $ipv6 = [];

        if (false !== $records) {
            foreach ($records as $record) {
                if (isset($record['ipv6']) && \is_string($record['ipv6'])) {
                    $ipv6[] = $record['ipv6'];
                }
            }
        }

        return array_merge($ipv4, $ipv6);
    }
}
