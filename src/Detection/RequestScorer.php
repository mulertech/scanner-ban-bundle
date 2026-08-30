<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan\Detection;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;

/**
 * Weighs a rejected request on what it asked for, never on what its sender claims to be.
 *
 * A path from an attack list is the attack itself: giving it up means giving up the scan. A
 * User-Agent, a referrer or a fetch metadata header are all written by the client and buy nothing.
 */
final readonly class RequestScorer
{
    /**
     * Destinations a browser sets when the page, not the visitor, asks for the resource. The header
     * is forbidden to scripts, so a browser cannot lie about it, but a client that is not a browser
     * writes what it likes: it may only cancel the weight of an ordinary miss, never of a probe.
     */
    private const array SUBRESOURCE_DESTINATIONS = [
        'audio', 'embed', 'font', 'image', 'manifest', 'object',
        'script', 'style', 'track', 'video',
    ];

    /**
     * @param list<string> $probePaths      path prefixes no browser and no crawler ever requests
     * @param list<string> $assetPrefixes   path prefixes serving the resources of a page
     * @param list<string> $assetExtensions file extensions serving the resources of a page
     * @param list<string> $exemptPaths     paths that never count, whatever they answer
     */
    public function __construct(
        private array $probePaths,
        private array $assetPrefixes,
        private array $assetExtensions,
        private array $exemptPaths,
        private string $loginRoute,
        private int $probeWeight,
        private int $notFoundWeight,
    ) {
    }

    public function isExempt(Request $request): bool
    {
        return \in_array(strtolower($request->getPathInfo()), $this->exemptPaths, true);
    }

    /**
     * A login form always sends its username field, so a bad request on that route came from a
     * client posting foreign field names. Keying on the route rather than on the field name is what
     * makes the rule portable: a project is free to rename "_username".
     */
    public function isLoginProbe(Request $request, HttpExceptionInterface $throwable): bool
    {
        return Response::HTTP_BAD_REQUEST === $throwable->getStatusCode()
            && $request->isMethod(Request::METHOD_POST)
            && $this->loginRoute === $request->attributes->get('_route');
    }

    public function weigh(Request $request, HttpExceptionInterface $throwable): int
    {
        if ($this->isExempt($request)) {
            return 0;
        }

        if ($this->isLoginProbe($request, $throwable)) {
            return $this->probeWeight;
        }

        if (Response::HTTP_NOT_FOUND !== $throwable->getStatusCode()) {
            return 0;
        }

        $path = strtolower($request->getPathInfo());

        if ($this->isProbePath($path)) {
            return $this->probeWeight;
        }

        if ($this->isPageResource($request, $path)) {
            return 0;
        }

        return $this->notFoundWeight;
    }

    private function isProbePath(string $path): bool
    {
        foreach ($this->probePaths as $prefix) {
            if (str_starts_with($path, $prefix)) {
                return true;
            }
        }

        return false;
    }

    private function isPageResource(Request $request, string $path): bool
    {
        foreach ($this->assetPrefixes as $prefix) {
            if (str_starts_with($path, $prefix)) {
                return true;
            }
        }

        $extension = pathinfo($path, \PATHINFO_EXTENSION);

        if ('' !== $extension && \in_array($extension, $this->assetExtensions, true)) {
            return true;
        }

        $destination = $request->headers->get('Sec-Fetch-Dest');

        return null !== $destination
            && \in_array(strtolower($destination), self::SUBRESOURCE_DESTINATIONS, true);
    }
}
