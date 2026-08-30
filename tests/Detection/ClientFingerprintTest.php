<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan\Tests\Detection;

use MulerTech\ScannerBan\Detection\ClientFingerprint;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

final class ClientFingerprintTest extends TestCase
{
    private const string BROWSER_UA = 'Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/141.0 Safari/537.36';

    public function testSameUserAgentInAnotherSubnetIsAnotherClient(): void
    {
        $fingerprint = new ClientFingerprint();

        self::assertNotSame(
            $fingerprint->of($this->request('203.0.113.4', self::BROWSER_UA)),
            $fingerprint->of($this->request('198.51.100.4', self::BROWSER_UA)),
        );
    }

    public function testSameUserAgentInTheSameSubnetIsOneClient(): void
    {
        $fingerprint = new ClientFingerprint();

        self::assertSame(
            $fingerprint->of($this->request('203.0.113.4', self::BROWSER_UA)),
            $fingerprint->of($this->request('203.0.113.250', self::BROWSER_UA)),
        );
    }

    public function testAnotherUserAgentInTheSameSubnetIsAnotherClient(): void
    {
        $fingerprint = new ClientFingerprint();

        self::assertNotSame(
            $fingerprint->of($this->request('203.0.113.4', self::BROWSER_UA)),
            $fingerprint->of($this->request('203.0.113.4', 'Mozilla/5.0 Firefox/140.0')),
        );
    }

    public function testIpv4SubnetKeepsThreeGroups(): void
    {
        self::assertSame('203.0.113', ClientFingerprint::subnet('203.0.113.42'));
    }

    public function testIpv6SubnetKeepsFourGroups(): void
    {
        self::assertSame('2001:db8:1234:5678', ClientFingerprint::subnet('2001:db8:1234:5678:9abc:def0:1234:5678'));
    }

    private function request(string $ip, string $userAgent): Request
    {
        $request = Request::create('/', 'GET', server: ['REMOTE_ADDR' => $ip]);
        $request->headers->set('User-Agent', $userAgent);

        return $request;
    }
}
