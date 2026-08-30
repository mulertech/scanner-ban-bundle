<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan\Notifier;

/**
 * Carries the daily digest wherever the project can be reached.
 *
 * The bundle ships a logging implementation so the digest is never lost. A project with a messaging
 * channel of its own replaces it by aliasing this interface to its own service.
 */
interface ScannerBanNotifierInterface
{
    public function notify(string $message): void;
}
