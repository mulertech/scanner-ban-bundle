<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan\Tests\Detection;

use MulerTech\ScannerBan\Detection\SystemDnsResolver;
use PHPUnit\Framework\TestCase;

final class SystemDnsResolverTest extends TestCase
{
    public function testAnAddressWithoutAReverseRecordResolvesToNothing(): void
    {
        // Reserved for documentation, so it carries no PTR record anywhere.
        self::assertNull(new SystemDnsResolver()->reverse('203.0.113.42'));
    }

    public function testAHostnameThatDoesNotExistResolvesToNothing(): void
    {
        self::assertSame([], new SystemDnsResolver()->forward('nonexistent.invalid'));
    }

    public function testLocalhostResolvesForward(): void
    {
        self::assertContains('127.0.0.1', new SystemDnsResolver()->forward('localhost'));
    }

    /**
     * The loopback carries a PTR record on the platforms that define one, and none on the others.
     * Both outcomes are correct, so the assertion holds the contract rather than the value: a name,
     * or nothing, but never the address handed back as if it were a name.
     */
    public function testLoopbackReverseEitherNamesAHostOrNothing(): void
    {
        $hostname = new SystemDnsResolver()->reverse('127.0.0.1');

        self::assertTrue(null === $hostname || '127.0.0.1' !== $hostname);
    }
}
