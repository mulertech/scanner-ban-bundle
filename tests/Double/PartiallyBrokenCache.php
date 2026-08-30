<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan\Tests\Double;

use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * Answers normally except on the keys carrying one of the given prefixes, which throw.
 *
 * A pool that fails on every call never reaches the writes that follow the first read, so failures
 * deeper in a sequence need a pool that breaks down on one key only.
 */
final class PartiallyBrokenCache implements CacheItemPoolInterface
{
    private readonly ArrayAdapter $inner;

    /**
     * @param list<string> $brokenPrefixes
     */
    public function __construct(private readonly array $brokenPrefixes)
    {
        $this->inner = new ArrayAdapter();
    }

    public function getItem(string $key): CacheItemInterface
    {
        $this->guard($key);

        return $this->inner->getItem($key);
    }

    public function getItems(array $keys = []): iterable
    {
        return $this->inner->getItems($keys);
    }

    public function hasItem(string $key): bool
    {
        return $this->inner->hasItem($key);
    }

    public function clear(): bool
    {
        return $this->inner->clear();
    }

    public function deleteItem(string $key): bool
    {
        $this->guard($key);

        return $this->inner->deleteItem($key);
    }

    public function deleteItems(array $keys): bool
    {
        return $this->inner->deleteItems($keys);
    }

    public function save(CacheItemInterface $item): bool
    {
        return $this->inner->save($item);
    }

    public function saveDeferred(CacheItemInterface $item): bool
    {
        return $this->inner->saveDeferred($item);
    }

    public function commit(): bool
    {
        return $this->inner->commit();
    }

    private function guard(string $key): void
    {
        foreach ($this->brokenPrefixes as $prefix) {
            if (str_starts_with($key, $prefix)) {
                throw new \RuntimeException('cache down');
            }
        }
    }
}
