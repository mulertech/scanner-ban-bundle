<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan\Tests\Notifier;

use MulerTech\ScannerBan\Notifier\LoggerScannerBanNotifier;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

final class LoggerScannerBanNotifierTest extends TestCase
{
    public function testTheDigestReachesTheLog(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('info')->with('Scanner ban digest');

        new LoggerScannerBanNotifier($logger)->notify('Scanner ban digest');
    }
}
