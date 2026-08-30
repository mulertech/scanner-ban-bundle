<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan\Tests\Double;

use MulerTech\ScannerBan\Notifier\ScannerBanNotifierInterface;

final class RecordingNotifier implements ScannerBanNotifierInterface
{
    /** @var list<string> */
    public array $messages = [];

    public function notify(string $message): void
    {
        $this->messages[] = $message;
    }
}
