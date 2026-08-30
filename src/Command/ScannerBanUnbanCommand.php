<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan\Command;

use MulerTech\ScannerBan\Ban\BanRegistry;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'scanner-ban:unban',
    description: 'Lifts the ban and the running score of one address',
)]
final class ScannerBanUnbanCommand extends Command
{
    public function __construct(private readonly BanRegistry $registry)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addArgument('ip', InputArgument::REQUIRED, 'Address to lift the ban from');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $ip = $input->getArgument('ip');

        if (!\is_string($ip) || false === filter_var($ip, \FILTER_VALIDATE_IP)) {
            $io->error('The argument must be a valid IPv4 or IPv6 address.');

            return Command::INVALID;
        }

        $this->registry->forget(md5($ip));

        $io->success(\sprintf('%s is served again.', $ip));

        return Command::SUCCESS;
    }
}
