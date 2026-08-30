<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan;

use MulerTech\ScannerBan\Ban\BanRegistry;
use MulerTech\ScannerBan\Command\ScannerBanDigestCommand;
use MulerTech\ScannerBan\Command\ScannerBanUnbanCommand;
use MulerTech\ScannerBan\Detection\ClientFingerprint;
use MulerTech\ScannerBan\Detection\CrawlerVerifier;
use MulerTech\ScannerBan\Detection\DnsResolverInterface;
use MulerTech\ScannerBan\Detection\RequestScorer;
use MulerTech\ScannerBan\Detection\SystemDnsResolver;
use MulerTech\ScannerBan\EventSubscriber\ScannerBanSubscriber;
use MulerTech\ScannerBan\Notifier\LoggerScannerBanNotifier;
use MulerTech\ScannerBan\Notifier\ScannerBanNotifierInterface;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

final class MulerTechScannerBanBundle extends AbstractBundle
{
    protected string $extensionAlias = 'mulertech_scanner_ban';

    /**
     * Paths no browser and no crawler ever asks for on its own. Each one is a wordlist entry, which
     * is why a single hit is worth the whole threshold: there is no innocent reading of the request.
     */
    private const array PROBE_PATHS = [
        '/.env',
        '/.git',
        '/.svn',
        '/.hg',
        '/.aws',
        '/.ssh',
        '/.docker',
        '/.ds_store',
        '/.htaccess',
        '/web.config',
        '/wp-admin',
        '/wp-content',
        '/wp-includes',
        '/wp-login.php',
        '/xmlrpc.php',
        '/phpmyadmin',
        '/pma',
        '/adminer',
        '/vendor/phpunit',
        '/_profiler',
        '/_ignition',
        '/telescope',
        '/actuator',
        '/server-status',
        '/cgi-bin',
        '/solr',
        '/jenkins',
    ];

    private const array ASSET_PREFIXES = ['/assets', '/bundles', '/build', '/media'];

    private const array ASSET_EXTENSIONS = [
        'avif', 'css', 'eot', 'gif', 'ico', 'jpeg', 'jpg', 'js', 'map', 'mjs',
        'mp3', 'mp4', 'otf', 'png', 'svg', 'ttf', 'webm', 'webp', 'woff', 'woff2',
    ];

    private const array EXEMPT_PATHS = ['/robots.txt', '/sitemap.xml', '/llms.txt'];

    /**
     * Naming a tool is an admission, and refusing it costs nothing. It catches only the sender who
     * did not think to lie, which is why nothing important may rest on this list.
     */
    private const array USER_AGENT_BLOCKLIST = [
        'python-requests',
        'curl/',
        'wget/',
        'go-http-client',
        'nmap',
        'masscan',
        'zgrab',
        'nuclei',
        'sqlmap',
        'nikto',
        'wapiti',
        'openvas',
        'acunetix',
        'gospider',
        'hakrawler',
        'burpsuite',
        'zmeu',
    ];

    /**
     * Only crawlers whose operator documents a reverse lookup can be verified, so only those are
     * listed. Anyone else is measured on what it requests, like every other client.
     */
    private const array VERIFIED_CRAWLERS = [
        'googlebot' => ['googlebot.com', 'google.com'],
        'google-inspectiontool' => ['googlebot.com', 'google.com'],
        'bingbot' => ['search.msn.com'],
        'applebot' => ['applebot.apple.com'],
    ];

    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->rootNode()
            ->children()
                ->booleanNode('enabled')->defaultTrue()->end()
                ->scalarNode('cache_service')->defaultValue('cache.app')->end()
                ->scalarNode('logger_service')->defaultValue('logger')->end()
                ->scalarNode('login_route')
                    ->defaultValue('app_login')
                    ->info('Route name of the firewall check_path')
                ->end()
                ->scalarNode('allowed_ips')
                    ->defaultValue('')
                    ->info('Comma separated addresses or CIDR ranges, never counted and never blocked')
                ->end()
                ->integerNode('max_score')->defaultValue(10)->min(1)->end()
                ->integerNode('probe_weight')->defaultValue(10)->min(1)->end()
                ->integerNode('not_found_weight')->defaultValue(1)->min(0)->end()
                ->integerNode('window')->defaultValue(300)->min(1)->end()
                ->integerNode('ban_duration')->defaultValue(86400)->min(1)->end()
                ->integerNode('digest_ttl')->defaultValue(172800)->min(1)->end()
                ->integerNode('digest_max_entries')->defaultValue(500)->min(1)->end()
                ->integerNode('crawler_cache_ttl')->defaultValue(86400)->min(1)->end()
                ->integerNode('user_agent_min_length')->defaultValue(10)->min(0)->end()
                ->arrayNode('probe_paths')
                    ->scalarPrototype()->end()
                    ->defaultValue(self::PROBE_PATHS)
                ->end()
                ->arrayNode('asset_prefixes')
                    ->scalarPrototype()->end()
                    ->defaultValue(self::ASSET_PREFIXES)
                ->end()
                ->arrayNode('asset_extensions')
                    ->scalarPrototype()->end()
                    ->defaultValue(self::ASSET_EXTENSIONS)
                ->end()
                ->arrayNode('exempt_paths')
                    ->scalarPrototype()->end()
                    ->defaultValue(self::EXEMPT_PATHS)
                ->end()
                ->arrayNode('user_agent_blocklist')
                    ->scalarPrototype()->end()
                    ->defaultValue(self::USER_AGENT_BLOCKLIST)
                ->end()
                ->arrayNode('verified_crawlers')
                    ->useAttributeAsKey('name')
                    ->arrayPrototype()->scalarPrototype()->end()->end()
                    ->defaultValue(self::VERIFIED_CRAWLERS)
                ->end()
            ->end();
    }

    /**
     * @param array<mixed> $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        if (true !== ($config['enabled'] ?? true)) {
            return;
        }

        $cache = service(self::stringValue($config, 'cache_service'));
        $logger = service(self::stringValue($config, 'logger_service'));
        $services = $container->services();

        $services->set('mulertech_scanner_ban.dns_resolver', SystemDnsResolver::class);
        $services->alias(DnsResolverInterface::class, 'mulertech_scanner_ban.dns_resolver');

        $services->set('mulertech_scanner_ban.notifier', LoggerScannerBanNotifier::class)
            ->args([$logger]);
        $services->alias(ScannerBanNotifierInterface::class, 'mulertech_scanner_ban.notifier');

        $services->set('mulertech_scanner_ban.scorer', RequestScorer::class)
            ->args([
                $config['probe_paths'],
                $config['asset_prefixes'],
                $config['asset_extensions'],
                $config['exempt_paths'],
                $config['login_route'],
                $config['probe_weight'],
                $config['not_found_weight'],
            ]);
        $services->alias(RequestScorer::class, 'mulertech_scanner_ban.scorer');

        $services->set('mulertech_scanner_ban.fingerprint', ClientFingerprint::class);
        $services->alias(ClientFingerprint::class, 'mulertech_scanner_ban.fingerprint');

        $services->set('mulertech_scanner_ban.crawler_verifier', CrawlerVerifier::class)
            ->args([
                service('mulertech_scanner_ban.dns_resolver'),
                $cache,
                $logger,
                $config['verified_crawlers'],
                $config['crawler_cache_ttl'],
            ]);
        $services->alias(CrawlerVerifier::class, 'mulertech_scanner_ban.crawler_verifier');

        $services->set('mulertech_scanner_ban.registry', BanRegistry::class)
            ->args([
                $cache,
                $logger,
                $config['max_score'],
                $config['window'],
                $config['ban_duration'],
                $config['digest_ttl'],
                $config['digest_max_entries'],
            ]);
        $services->alias(BanRegistry::class, 'mulertech_scanner_ban.registry');

        $services->set('mulertech_scanner_ban.subscriber', ScannerBanSubscriber::class)
            ->args([
                service('mulertech_scanner_ban.scorer'),
                service('mulertech_scanner_ban.registry'),
                service('mulertech_scanner_ban.crawler_verifier'),
                service('mulertech_scanner_ban.fingerprint'),
                $logger,
                $config['allowed_ips'],
                $config['user_agent_blocklist'],
                $config['user_agent_min_length'],
            ])
            ->tag('kernel.event_subscriber');

        $services->set('mulertech_scanner_ban.command.digest', ScannerBanDigestCommand::class)
            ->args([
                service('mulertech_scanner_ban.registry'),
                service(ScannerBanNotifierInterface::class),
            ])
            ->tag('console.command');

        $services->set('mulertech_scanner_ban.command.unban', ScannerBanUnbanCommand::class)
            ->args([service('mulertech_scanner_ban.registry')])
            ->tag('console.command');
    }

    /**
     * @param array<mixed> $config
     */
    private static function stringValue(array $config, string $key): string
    {
        $value = $config[$key] ?? null;

        if (!\is_string($value) || '' === $value) {
            throw new \InvalidArgumentException(\sprintf('mulertech_scanner_ban.%s must be a non-empty service id.', $key));
        }

        return $value;
    }
}
