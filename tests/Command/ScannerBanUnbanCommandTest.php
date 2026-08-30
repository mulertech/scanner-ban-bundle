<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan\Tests\Command;

use MulerTech\ScannerBan\Ban\BanRegistry;
use MulerTech\ScannerBan\Command\ScannerBanUnbanCommand;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

final class ScannerBanUnbanCommandTest extends TestCase
{
    public function testItLiftsTheBan(): void
    {
        $cache = new ArrayAdapter();
        $registry = new BanRegistry($cache, new NullLogger(), 10, 300, 86400, 172800, 500);
        $registry->record('203.0.113.1', str_repeat('a', 32), 'Mozilla/5.0', '/.env', 10);

        $tester = new CommandTester(new ScannerBanUnbanCommand($registry));

        self::assertSame(Command::SUCCESS, $tester->execute(['ip' => '203.0.113.1']));
        self::assertFalse($registry->isBanned(md5('203.0.113.1')));
        self::assertStringContainsString('served again', $tester->getDisplay());
    }

    public function testItRefusesAnArgumentThatIsNotAnAddress(): void
    {
        $registry = new BanRegistry(new ArrayAdapter(), new NullLogger(), 10, 300, 86400, 172800, 500);
        $tester = new CommandTester(new ScannerBanUnbanCommand($registry));

        self::assertSame(Command::INVALID, $tester->execute(['ip' => 'not-an-address']));
        self::assertStringContainsString('valid IPv4 or IPv6 address', $tester->getDisplay());
    }
}
