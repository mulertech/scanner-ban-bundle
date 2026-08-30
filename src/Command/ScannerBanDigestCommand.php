<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan\Command;

use MulerTech\ScannerBan\Ban\BanRegistry;
use MulerTech\ScannerBan\Notifier\ScannerBanNotifierInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'scanner-ban:digest',
    description: 'Sends the bans accumulated since the last run and clears the digest',
)]
final class ScannerBanDigestCommand extends Command
{
    private const int TOP_LIMIT = 5;
    private const int UA_MAX_LENGTH = 80;

    public function __construct(
        private readonly BanRegistry $registry,
        private readonly ScannerBanNotifierInterface $notifier,
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $digest = $this->registry->digest();

        if (null === $digest) {
            $io->success('No scanner banned since the last digest.');

            return Command::SUCCESS;
        }

        $this->registry->forgetDigest();
        $this->notifier->notify($this->format($digest));

        $io->success(\sprintf('Digest sent: %d bans.', $digest['bans']));

        return Command::SUCCESS;
    }

    /**
     * @param array{bans: int, ips: array<string, int>, user_agents: array<string, int>, paths: array<string, int>} $digest
     */
    private function format(array $digest): string
    {
        $message = \sprintf("Scanner ban digest\n\nBans: %d", $digest['bans']);
        $message .= $this->section('Top addresses', $digest['ips']);
        $message .= $this->section('Top paths', $digest['paths']);

        return $message.$this->section('Top User-Agents', $digest['user_agents'], self::UA_MAX_LENGTH);
    }

    /**
     * @param array<string, int> $counters
     */
    private function section(string $title, array $counters, ?int $maxLength = null): string
    {
        if ([] === $counters) {
            return '';
        }

        arsort($counters);
        $section = \sprintf("\n\n%s:", $title);

        foreach (\array_slice($counters, 0, self::TOP_LIMIT, true) as $value => $count) {
            $label = (string) $value;

            if (null !== $maxLength && mb_strlen($label) > $maxLength) {
                $label = mb_substr($label, 0, $maxLength).'…';
            }

            $section .= \sprintf("\n  %s (%d)", $label, $count);
        }

        return $section;
    }
}
