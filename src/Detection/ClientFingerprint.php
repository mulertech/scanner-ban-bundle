<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan\Detection;

use Symfony\Component\HttpFoundation\Request;

/**
 * Identifies a client by its User-Agent bound to its network neighbourhood.
 *
 * The User-Agent alone would be collective: millions of visitors share the exact string of a given
 * browser release, and banning it would lock every one of them out on the strength of five requests.
 * Pairing it with the subnet keeps the reach of a ban to the range the traffic actually came from,
 * which is what a rotating set of addresses behind one scan has in common.
 */
final readonly class ClientFingerprint
{
    private const int IPV4_KEPT_GROUPS = 3;
    private const int IPV6_KEPT_GROUPS = 4;

    public function of(Request $request): string
    {
        $userAgent = (string) $request->headers->get('User-Agent', '');

        return md5($userAgent.'|'.self::subnet((string) $request->getClientIp()));
    }

    public static function subnet(string $ip): string
    {
        if (str_contains($ip, ':')) {
            return implode(':', \array_slice(explode(':', $ip), 0, self::IPV6_KEPT_GROUPS));
        }

        return implode('.', \array_slice(explode('.', $ip), 0, self::IPV4_KEPT_GROUPS));
    }
}
