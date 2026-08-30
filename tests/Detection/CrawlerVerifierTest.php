<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan\Tests\Detection;

use MulerTech\ScannerBan\Detection\CrawlerVerifier;
use MulerTech\ScannerBan\Detection\DnsResolverInterface;
use MulerTech\ScannerBan\Tests\Double\FakeDnsResolver;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

final class CrawlerVerifierTest extends TestCase
{
    private const string GOOGLEBOT_UA = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
    private const string GOOGLE_IP = '66.249.66.1';

    public function testVerifiedCrawlerPassesTheDoubleLookup(): void
    {
        $resolver = new FakeDnsResolver(
            ['66.249.66.1' => 'crawl-66-249-66-1.googlebot.com'],
            ['crawl-66-249-66-1.googlebot.com' => ['66.249.66.1']],
        );

        self::assertTrue($this->verifier($resolver)->isVerified(self::GOOGLE_IP, self::GOOGLEBOT_UA));
    }

    public function testImpostorFailsTheReverseLookup(): void
    {
        $resolver = new FakeDnsResolver(
            ['203.0.113.9' => 'host.example.net'],
            ['host.example.net' => ['203.0.113.9']],
        );

        self::assertFalse($this->verifier($resolver)->isVerified('203.0.113.9', self::GOOGLEBOT_UA));
    }

    public function testHostnameThatDoesNotResolveBackIsRefused(): void
    {
        $resolver = new FakeDnsResolver(
            ['203.0.113.9' => 'fake.googlebot.com'],
            ['fake.googlebot.com' => ['66.249.66.1']],
        );

        self::assertFalse($this->verifier($resolver)->isVerified('203.0.113.9', self::GOOGLEBOT_UA));
    }

    public function testAddressWithoutReverseRecordIsRefused(): void
    {
        self::assertFalse($this->verifier(new FakeDnsResolver())->isVerified('203.0.113.9', self::GOOGLEBOT_UA));
    }

    public function testClientClaimingNothingIsNeverLookedUp(): void
    {
        $resolver = $this->createMock(DnsResolverInterface::class);
        $resolver->expects(self::never())->method('reverse');

        self::assertFalse($this->verifier($resolver)->isVerified(self::GOOGLE_IP, 'Mozilla/5.0 Chrome/141.0'));
    }

    public function testVerdictIsCachedPerAddress(): void
    {
        $resolver = new FakeDnsResolver(
            ['66.249.66.1' => 'crawl-66-249-66-1.googlebot.com'],
            ['crawl-66-249-66-1.googlebot.com' => ['66.249.66.1']],
        );
        $verifier = $this->verifier($resolver);

        self::assertTrue($verifier->isVerified(self::GOOGLE_IP, self::GOOGLEBOT_UA));
        self::assertTrue($verifier->isVerified(self::GOOGLE_IP, self::GOOGLEBOT_UA));
        self::assertSame(1, $resolver->reverseCalls);
    }

    public function testRefusalIsCachedToo(): void
    {
        $resolver = new FakeDnsResolver(['203.0.113.9' => 'host.example.net']);
        $verifier = $this->verifier($resolver);

        self::assertFalse($verifier->isVerified('203.0.113.9', self::GOOGLEBOT_UA));
        self::assertFalse($verifier->isVerified('203.0.113.9', self::GOOGLEBOT_UA));
        self::assertSame(1, $resolver->reverseCalls);
    }

    public function testResolverFailureIsLoggedAndRefuses(): void
    {
        $resolver = $this->createStub(DnsResolverInterface::class);
        $resolver->method('reverse')->willThrowException(new \RuntimeException('dns down'));

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with('Crawler verification failed, the claim is refused.', self::anything());

        $verifier = new CrawlerVerifier(
            $resolver,
            new ArrayAdapter(),
            $logger,
            ['googlebot' => ['googlebot.com']],
            86400,
        );

        self::assertFalse($verifier->isVerified(self::GOOGLE_IP, self::GOOGLEBOT_UA));
    }

    public function testClaimedCrawlerNamesTheToken(): void
    {
        $verifier = $this->verifier(new FakeDnsResolver());

        self::assertSame('googlebot', $verifier->claimedCrawler(self::GOOGLEBOT_UA));
        self::assertNull($verifier->claimedCrawler('Mozilla/5.0 Chrome/141.0'));
    }

    private function verifier(DnsResolverInterface $resolver): CrawlerVerifier
    {
        return new CrawlerVerifier(
            $resolver,
            new ArrayAdapter(),
            new NullLogger(),
            ['googlebot' => ['googlebot.com', 'google.com']],
            86400,
        );
    }
}
