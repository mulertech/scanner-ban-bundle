<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan\Tests\Ban;

use MulerTech\ScannerBan\Ban\BanRegistry;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;
use MulerTech\ScannerBan\Tests\Double\PartiallyBrokenCache;
use Psr\Log\NullLogger;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

final class BanRegistryTest extends TestCase
{
    private const string IP = '203.0.113.20';
    private const string FINGERPRINT = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4';
    private const string UA = 'Mozilla/5.0 normal-browser';

    public function testScoreBelowThresholdDoesNotBan(): void
    {
        $cache = new ArrayAdapter();
        $registry = $this->registry($cache);

        self::assertFalse($registry->record(self::IP, self::FINGERPRINT, self::UA, '/missing', 1));
        self::assertFalse($registry->isBanned(md5(self::IP), self::FINGERPRINT));
    }

    public function testScoresAccumulateUntilTheThreshold(): void
    {
        $cache = new ArrayAdapter();
        $registry = $this->registry($cache);

        for ($i = 0; $i < 9; ++$i) {
            self::assertFalse($registry->record(self::IP, self::FINGERPRINT, self::UA, '/missing', 1));
        }

        self::assertTrue($registry->record(self::IP, self::FINGERPRINT, self::UA, '/missing', 1));
        self::assertTrue($registry->isBanned(md5(self::IP)));
    }

    public function testProbeWeightBansOnTheFirstRequest(): void
    {
        $registry = $this->registry(new ArrayAdapter());

        self::assertTrue($registry->record(self::IP, self::FINGERPRINT, self::UA, '/.env', 10));
        self::assertTrue($registry->isBanned(md5(self::IP)));
        self::assertTrue($registry->isBanned(self::FINGERPRINT));
    }

    public function testBanClearsTheRunningScore(): void
    {
        $cache = new ArrayAdapter();
        $this->registry($cache)->record(self::IP, self::FINGERPRINT, self::UA, '/.env', 10);

        self::assertFalse($cache->getItem(BanRegistry::SCORE_PREFIX.md5(self::IP))->isHit());
    }

    public function testBanFeedsTheDigest(): void
    {
        $registry = $this->registry(new ArrayAdapter());
        $registry->record(self::IP, self::FINGERPRINT, self::UA, '/.env', 10);

        $digest = $registry->digest();

        self::assertNotNull($digest);
        self::assertSame(2, $digest['bans']);
        self::assertSame(2, $digest['ips'][self::IP]);
        self::assertSame(2, $digest['paths']['/.env']);
        self::assertSame(2, $digest['user_agents'][self::UA]);
    }

    public function testDigestIsEmptyBeforeAnyBan(): void
    {
        self::assertNull($this->registry(new ArrayAdapter())->digest());
    }

    public function testDigestIsForgotten(): void
    {
        $registry = $this->registry(new ArrayAdapter());
        $registry->record(self::IP, self::FINGERPRINT, self::UA, '/.env', 10);
        $registry->forgetDigest();

        self::assertNull($registry->digest());
    }

    public function testDigestStopsGrowingPastItsLimit(): void
    {
        $cache = new ArrayAdapter();
        $registry = new BanRegistry($cache, new NullLogger(), 10, 300, 86400, 172800, 1);

        $registry->record('203.0.113.1', self::FINGERPRINT, self::UA, '/.env', 10);
        $registry->record('203.0.113.2', 'ffffffffffffffffffffffffffffffff', self::UA, '/.env', 10);

        $digest = $registry->digest();

        self::assertNotNull($digest);
        self::assertCount(1, $digest['ips']);
        self::assertArrayNotHasKey('203.0.113.2', $digest['ips']);
    }

    public function testEmptyValuesStayOutOfTheDigest(): void
    {
        $registry = $this->registry(new ArrayAdapter());
        $registry->record(self::IP, self::FINGERPRINT, '', '/.env', 10);

        $digest = $registry->digest();

        self::assertNotNull($digest);
        self::assertSame([], $digest['user_agents']);
    }

    public function testForgetLiftsTheBanAndTheScore(): void
    {
        $cache = new ArrayAdapter();
        $registry = $this->registry($cache);
        $registry->record(self::IP, self::FINGERPRINT, self::UA, '/.env', 10);

        $registry->forget(md5(self::IP));

        self::assertFalse($registry->isBanned(md5(self::IP)));
    }

    public function testCacheFailureOnLookupIsLoggedAndServesTheRequest(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with('Scanner ban lookup failed, the request is served.', self::anything());

        self::assertFalse($this->registry($this->brokenCache(), $logger)->isBanned('whatever'));
    }

    public function testCacheFailureOnScoringIsLoggedAndCountsNothing(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::atLeastOnce())
            ->method('warning')
            ->with('Scanner score update failed, the client is not counted.', self::anything());

        $registry = $this->registry($this->brokenCache(), $logger);

        self::assertFalse($registry->record(self::IP, self::FINGERPRINT, self::UA, '/.env', 10));
    }

    public function testCacheFailureOnDigestReadIsLogged(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with('Scanner digest read failed.', self::anything());

        self::assertNull($this->registry($this->brokenCache(), $logger)->digest());
    }

    public function testCacheFailureOnDigestRemovalIsLogged(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with('Scanner digest removal failed.', self::anything());

        $this->registry($this->brokenCache(), $logger)->forgetDigest();
    }

    public function testCacheFailureOnForgetIsLogged(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with('Scanner ban removal failed.', self::anything());

        $this->registry($this->brokenCache(), $logger)->forget('whatever');
    }

    public function testCacheFailureOnBanWriteIsLoggedAndKeepsServing(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::atLeastOnce())
            ->method('warning')
            ->with('Scanner ban write failed, the client stays served.', self::anything());

        $cache = new PartiallyBrokenCache([BanRegistry::BAN_PREFIX]);

        self::assertTrue($this->registry($cache, $logger)->record(self::IP, self::FINGERPRINT, self::UA, '/.env', 10));
    }

    public function testCacheFailureOnDigestWriteIsLogged(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::atLeastOnce())
            ->method('warning')
            ->with('Scanner digest update failed.', self::anything());

        $cache = new PartiallyBrokenCache([BanRegistry::DIGEST_KEY]);

        $this->registry($cache, $logger)->record(self::IP, self::FINGERPRINT, self::UA, '/.env', 10);
    }

    private function brokenCache(): CacheItemPoolInterface
    {
        $cache = $this->createStub(CacheItemPoolInterface::class);
        $cache->method('getItem')->willThrowException(new \RuntimeException('cache down'));
        $cache->method('deleteItem')->willThrowException(new \RuntimeException('cache down'));

        return $cache;
    }

    private function registry(CacheItemPoolInterface $cache, ?LoggerInterface $logger = null): BanRegistry
    {
        return new BanRegistry($cache, $logger ?? new NullLogger(), 10, 300, 86400, 172800, 500);
    }
}
