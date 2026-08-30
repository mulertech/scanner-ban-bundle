<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan\Tests;

use MulerTech\ScannerBan\Ban\BanRegistry;
use MulerTech\ScannerBan\Detection\CrawlerVerifier;
use MulerTech\ScannerBan\Detection\RequestScorer;
use MulerTech\ScannerBan\EventSubscriber\ScannerBanSubscriber;
use MulerTech\ScannerBan\MulerTechScannerBanBundle;
use MulerTech\ScannerBan\Notifier\ScannerBanNotifierInterface;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;

final class MulerTechScannerBanBundleTest extends TestCase
{
    public function testItWiresEveryService(): void
    {
        $container = $this->build();

        self::assertInstanceOf(ScannerBanSubscriber::class, $container->get('mulertech_scanner_ban.subscriber'));
        self::assertInstanceOf(BanRegistry::class, $container->get(BanRegistry::class));
        self::assertInstanceOf(RequestScorer::class, $container->get(RequestScorer::class));
        self::assertInstanceOf(CrawlerVerifier::class, $container->get(CrawlerVerifier::class));
        self::assertInstanceOf(ScannerBanNotifierInterface::class, $container->get(ScannerBanNotifierInterface::class));
    }

    public function testTheSubscriberIsRegisteredOnTheDispatcher(): void
    {
        $definition = $this->build()->getDefinition('mulertech_scanner_ban.subscriber');

        self::assertArrayHasKey('kernel.event_subscriber', $definition->getTags());
    }

    public function testBothCommandsAreRegistered(): void
    {
        $container = $this->build();

        self::assertArrayHasKey('console.command', $container->getDefinition('mulertech_scanner_ban.command.digest')->getTags());
        self::assertArrayHasKey('console.command', $container->getDefinition('mulertech_scanner_ban.command.unban')->getTags());
    }

    public function testDisablingTheBundleRegistersNothing(): void
    {
        $container = $this->build(['enabled' => false]);

        self::assertFalse($container->has('mulertech_scanner_ban.subscriber'));
    }

    public function testConfigurationReachesTheServices(): void
    {
        $container = $this->build(['login_route' => 'app_admin_login', 'max_score' => 3]);

        self::assertSame('app_admin_login', $container->getDefinition('mulertech_scanner_ban.scorer')->getArgument(4));
        self::assertSame(3, $container->getDefinition('mulertech_scanner_ban.registry')->getArgument(2));
    }

    public function testAnEmptyCacheServiceIsRefusedLoudly(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('mulertech_scanner_ban.cache_service');

        $this->build(['cache_service' => '']);
    }

    /**
     * @param array<string, mixed> $config
     */
    private function build(array $config = []): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setDefinition('cache.app', new Definition(ArrayAdapter::class)->setPublic(true));
        $container->setDefinition('logger', new Definition(NullLogger::class)->setPublic(true));

        $bundle = new MulerTechScannerBanBundle();
        $extension = $bundle->getContainerExtension();

        self::assertNotNull($extension);
        $extension->load([$config], $container);

        foreach ($container->getDefinitions() as $definition) {
            $definition->setPublic(true);
        }

        foreach ($container->getAliases() as $alias) {
            $alias->setPublic(true);
        }

        $container->compile();

        return $container;
    }
}
