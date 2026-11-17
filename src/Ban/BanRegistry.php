<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan\Ban;

use MulerTech\ScannerBan\Detection\ClientFingerprint;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;

/**
 * Holds the scores, the bans and the digest they feed.
 *
 * @phpstan-type Digest array{bans: int, ips: array<string, int>, user_agents: array<string, int>, paths: array<string, int>}
 */
final readonly class BanRegistry
{
    public const string SCORE_PREFIX = 'scanner_score_';
    public const string BAN_PREFIX = 'scanner_ban_';
    public const string SUBNET_PREFIX = 'scanner_subnet_';
    public const string DIGEST_KEY = 'scanner_digest';

    public function __construct(
        private CacheItemPoolInterface $cache,
        private LoggerInterface $logger,
        private int $maxScore,
        private int $window,
        private int $banDuration,
        private int $digestTtl,
        private int $digestMaxEntries,
    ) {
    }

    public function isBanned(string ...$keys): bool
    {
        try {
            foreach ($keys as $key) {
                if ($this->cache->getItem(self::BAN_PREFIX.$key)->isHit()) {
                    return true;
                }
            }
        } catch (\Throwable $exception) {
            $this->logger->warning('Scanner ban lookup failed, the request is served.', [
                'exception' => $exception,
            ]);
        }

        return false;
    }

    /**
     * @return bool whether this request pushed the client over the threshold
     */
    public function record(string $ip, string $fingerprint, string $userAgent, string $path, int $weight): bool
    {
        $banned = false;

        foreach (['ip' => md5($ip), 'fingerprint' => $fingerprint] as $type => $key) {
            if (!$this->increment($key, $weight)) {
                continue;
            }

            $this->ban($key);

            if ('fingerprint' === $type) {
                $this->indexFingerprint($ip, $fingerprint);
            }

            $this->addToDigest($ip, $userAgent, $path);
            $banned = true;

            $this->logger->info('Scanner banned.', [
                'ip' => $ip,
                'user_agent' => $userAgent,
                'path' => $path,
                'banned_key' => $type,
                'ban_duration' => $this->banDuration,
            ]);
        }

        return $banned;
    }

    /**
     * Lifts everything that refuses this address: its own ban, and the fingerprints banned in its
     * subnet. A fingerprint cannot be rebuilt from the address, since it also carries a User-Agent
     * nobody typing the command knows, which is why bans leave an index behind them.
     *
     * @return bool whether the removal went through, false leaving the address possibly still banned
     */
    public function forget(string $ip): bool
    {
        try {
            $indexKey = $this->subnetKey($ip);

            foreach ([md5($ip), ...$this->indexedFingerprints($indexKey)] as $key) {
                $this->cache->deleteItem(self::BAN_PREFIX.$key);
                $this->cache->deleteItem(self::SCORE_PREFIX.$key);
            }

            $this->cache->deleteItem($indexKey);

            return true;
        } catch (\Throwable $exception) {
            $this->logger->warning('Scanner ban removal failed.', [
                'ip' => $ip,
                'exception' => $exception,
            ]);

            return false;
        }
    }

    /**
     * @return Digest|null
     */
    public function digest(): ?array
    {
        try {
            $item = $this->cache->getItem(self::DIGEST_KEY);

            if (!$item->isHit()) {
                return null;
            }

            /** @var Digest $digest */
            $digest = $item->get();

            return $digest;
        } catch (\Throwable $exception) {
            $this->logger->warning('Scanner digest read failed.', ['exception' => $exception]);

            return null;
        }
    }

    public function forgetDigest(): void
    {
        try {
            $this->cache->deleteItem(self::DIGEST_KEY);
        } catch (\Throwable $exception) {
            $this->logger->warning('Scanner digest removal failed.', ['exception' => $exception]);
        }
    }

    private function increment(string $key, int $weight): bool
    {
        try {
            $item = $this->cache->getItem(self::SCORE_PREFIX.$key);
            $previous = $item->get();
            $score = (\is_int($previous) ? $previous : 0) + $weight;

            $item->set($score);
            $item->expiresAfter($this->window);
            $this->cache->save($item);

            if ($score < $this->maxScore) {
                return false;
            }

            $this->cache->deleteItem(self::SCORE_PREFIX.$key);

            return true;
        } catch (\Throwable $exception) {
            $this->logger->warning('Scanner score update failed, the client is not counted.', [
                'exception' => $exception,
            ]);

            return false;
        }
    }

    private function ban(string $key): void
    {
        try {
            $item = $this->cache->getItem(self::BAN_PREFIX.$key);
            $item->set(true);
            $item->expiresAfter($this->banDuration);
            $this->cache->save($item);
        } catch (\Throwable $exception) {
            $this->logger->warning('Scanner ban write failed, the client stays served.', [
                'exception' => $exception,
            ]);
        }
    }

    private function indexFingerprint(string $ip, string $fingerprint): void
    {
        try {
            $indexKey = $this->subnetKey($ip);
            $item = $this->cache->getItem($indexKey);
            $item->set(array_values(array_unique([...$this->indexedFingerprints($indexKey), $fingerprint])));
            $item->expiresAfter($this->banDuration);
            $this->cache->save($item);
        } catch (\Throwable $exception) {
            $this->logger->warning('Scanner fingerprint index update failed, lifting the ban of this address will leave the fingerprint banned.', [
                'ip' => $ip,
                'exception' => $exception,
            ]);
        }
    }

    /**
     * @return list<string>
     */
    private function indexedFingerprints(string $indexKey): array
    {
        $fingerprints = $this->cache->getItem($indexKey)->get();

        return \is_array($fingerprints) ? array_values(array_filter($fingerprints, \is_string(...))) : [];
    }

    private function subnetKey(string $ip): string
    {
        return self::SUBNET_PREFIX.md5(ClientFingerprint::subnet($ip));
    }

    private function addToDigest(string $ip, string $userAgent, string $path): void
    {
        try {
            $item = $this->cache->getItem(self::DIGEST_KEY);
            /** @var Digest $digest */
            $digest = $item->isHit()
                ? $item->get()
                : ['bans' => 0, 'ips' => [], 'user_agents' => [], 'paths' => []];

            ++$digest['bans'];
            $this->countIn($digest['ips'], $ip);
            $this->countIn($digest['user_agents'], $userAgent);
            $this->countIn($digest['paths'], $path);

            $item->set($digest);
            $item->expiresAfter($this->digestTtl);
            $this->cache->save($item);
        } catch (\Throwable $exception) {
            $this->logger->warning('Scanner digest update failed.', ['exception' => $exception]);
        }
    }

    /**
     * @param array<string, int> $counters
     */
    private function countIn(array &$counters, string $value): void
    {
        if ('' === $value) {
            return;
        }

        if (!isset($counters[$value]) && \count($counters) >= $this->digestMaxEntries) {
            return;
        }

        $counters[$value] = ($counters[$value] ?? 0) + 1;
    }
}
