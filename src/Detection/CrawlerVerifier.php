<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan\Detection;

use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;

/**
 * Grants an exemption only to a crawler whose address confirms its claim.
 *
 * A User-Agent is written by the client, so it can never earn anything on its own. It selects which
 * domains the address must resolve to, and the double lookup, reverse then forward, is what decides.
 * This is the method Google and Bing document for their own crawlers.
 */
final readonly class CrawlerVerifier
{
    public const string CACHE_PREFIX = 'scanner_ban_crawler_';

    /**
     * @param array<string, list<string>> $crawlers User-Agent token mapped to the domain suffixes its address must carry
     */
    public function __construct(
        private DnsResolverInterface $resolver,
        private CacheItemPoolInterface $cache,
        private LoggerInterface $logger,
        private array $crawlers,
        private int $ttl,
    ) {
    }

    public function claimedCrawler(string $userAgent): ?string
    {
        $lower = strtolower($userAgent);

        foreach (array_keys($this->crawlers) as $token) {
            if (str_contains($lower, $token)) {
                return $token;
            }
        }

        return null;
    }

    public function isVerified(string $ip, string $userAgent): bool
    {
        $token = $this->claimedCrawler($userAgent);

        if (null === $token) {
            return false;
        }

        $cacheKey = self::CACHE_PREFIX.md5($token.'|'.$ip);

        try {
            $item = $this->cache->getItem($cacheKey);

            if ($item->isHit()) {
                return true === $item->get();
            }

            $verified = $this->resolve($ip, $this->crawlers[$token]);
            $item->set($verified);
            $item->expiresAfter($this->ttl);
            $this->cache->save($item);

            return $verified;
        } catch (\Throwable $exception) {
            $this->logger->warning('Crawler verification failed, the claim is refused.', [
                'ip' => $ip,
                'claimed' => $token,
                'exception' => $exception,
            ]);

            return false;
        }
    }

    /**
     * @param list<string> $domains
     */
    private function resolve(string $ip, array $domains): bool
    {
        $hostname = $this->resolver->reverse($ip);

        if (null === $hostname || !$this->endsWithAny($hostname, $domains)) {
            return false;
        }

        return \in_array($ip, $this->resolver->forward($hostname), true);
    }

    /**
     * @param list<string> $domains
     */
    private function endsWithAny(string $hostname, array $domains): bool
    {
        $lower = strtolower(rtrim($hostname, '.'));

        foreach ($domains as $domain) {
            if (str_ends_with($lower, strtolower($domain))) {
                return true;
            }
        }

        return false;
    }
}
