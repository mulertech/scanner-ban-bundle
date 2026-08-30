<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan\Tests\Command;

use MulerTech\ScannerBan\Ban\BanRegistry;
use MulerTech\ScannerBan\Command\ScannerBanDigestCommand;
use MulerTech\ScannerBan\Tests\Double\RecordingNotifier;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

final class ScannerBanDigestCommandTest extends TestCase
{
    private const string UA = 'Mozilla/5.0 normal-browser';

    public function testItReportsAnEmptyDigest(): void
    {
        $notifier = new RecordingNotifier();
        $tester = new CommandTester(new ScannerBanDigestCommand($this->registry(new ArrayAdapter()), $notifier));

        self::assertSame(Command::SUCCESS, $tester->execute([]));
        self::assertStringContainsString('No scanner banned', $tester->getDisplay());
        self::assertSame([], $notifier->messages);
    }

    public function testItSendsTheDigestAndClearsIt(): void
    {
        $cache = new ArrayAdapter();
        $registry = $this->registry($cache);
        $registry->record('203.0.113.1', str_repeat('a', 32), self::UA, '/.env', 10);

        $notifier = new RecordingNotifier();
        $tester = new CommandTester(new ScannerBanDigestCommand($registry, $notifier));

        self::assertSame(Command::SUCCESS, $tester->execute([]));
        self::assertCount(1, $notifier->messages);
        self::assertStringContainsString('Bans: 2', $notifier->messages[0]);
        self::assertStringContainsString('203.0.113.1', $notifier->messages[0]);
        self::assertStringContainsString('/.env', $notifier->messages[0]);
        self::assertStringContainsString(self::UA, $notifier->messages[0]);
        self::assertNull($registry->digest());
    }

    public function testItShortensAnOverlongUserAgent(): void
    {
        $cache = new ArrayAdapter();
        $registry = $this->registry($cache);
        $registry->record('203.0.113.1', str_repeat('a', 32), str_repeat('u', 200), '/.env', 10);

        $notifier = new RecordingNotifier();
        new CommandTester(new ScannerBanDigestCommand($registry, $notifier))->execute([]);

        self::assertStringContainsString(str_repeat('u', 80).'…', $notifier->messages[0]);
        self::assertStringNotContainsString(str_repeat('u', 81).'…', $notifier->messages[0]);
    }

    public function testAnEmptySectionIsLeftOut(): void
    {
        $cache = new ArrayAdapter();
        $registry = $this->registry($cache);
        $registry->record('203.0.113.1', str_repeat('a', 32), '', '/.env', 10);

        $notifier = new RecordingNotifier();
        new CommandTester(new ScannerBanDigestCommand($registry, $notifier))->execute([]);

        self::assertStringNotContainsString('Top User-Agents', $notifier->messages[0]);
        self::assertStringContainsString('Top paths', $notifier->messages[0]);
    }

    private function registry(ArrayAdapter $cache): BanRegistry
    {
        return new BanRegistry($cache, new NullLogger(), 10, 300, 86400, 172800, 500);
    }
}
