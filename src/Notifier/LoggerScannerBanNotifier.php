<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan\Notifier;

use Psr\Log\LoggerInterface;

final readonly class LoggerScannerBanNotifier implements ScannerBanNotifierInterface
{
    public function __construct(private LoggerInterface $logger)
    {
    }

    public function notify(string $message): void
    {
        $this->logger->info($message);
    }
}
