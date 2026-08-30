<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan\EventSubscriber;

use MulerTech\ScannerBan\Ban\BanRegistry;
use MulerTech\ScannerBan\Detection\ClientFingerprint;
use MulerTech\ScannerBan\Detection\CrawlerVerifier;
use MulerTech\ScannerBan\Detection\RequestScorer;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Symfony\Component\HttpKernel\KernelEvents;

final readonly class ScannerBanSubscriber implements EventSubscriberInterface
{
    /** @var list<string> */
    private array $allowedIps;

    /**
     * @param string       $allowedIps  comma separated addresses or ranges, split here because the
     *                                  value usually reaches the container as an unresolved env
     *                                  placeholder and only becomes a list at instantiation
     * @param list<string> $uaBlocklist User-Agent fragments that admit to being a tool
     */
    public function __construct(
        private RequestScorer $scorer,
        private BanRegistry $registry,
        private CrawlerVerifier $verifier,
        private ClientFingerprint $fingerprint,
        private LoggerInterface $logger,
        string $allowedIps,
        private array $uaBlocklist,
        private int $uaMinLength,
    ) {
        $this->allowedIps = array_values(array_filter(
            array_map(trim(...), explode(',', $allowedIps)),
            static fn (string $value): bool => '' !== $value,
        ));
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['onKernelRequest', 4096],
            // Ahead of the error listener: setting a response stops propagation, which is what keeps
            // a rejected probe from being logged as an application error and paging a human.
            KernelEvents::EXCEPTION => ['onKernelException', 20],
        ];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();

        if ($this->scorer->isExempt($request)) {
            return;
        }

        $ip = $request->getClientIp();

        if (null === $ip || $this->isAllowedIp($ip)) {
            return;
        }

        $userAgent = (string) $request->headers->get('User-Agent', '');

        if ($this->declaresTooling($userAgent)) {
            $event->setResponse(new Response('', Response::HTTP_FORBIDDEN));

            return;
        }

        // The ban is checked before any exemption is granted: a client that is banned claimed
        // something the address did not confirm, and a fresh header must not undo that.
        if ($this->registry->isBanned(md5($ip), $this->fingerprint->of($request))) {
            $event->setResponse(new Response('', Response::HTTP_FORBIDDEN));
        }
    }

    public function onKernelException(ExceptionEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $throwable = $event->getThrowable();

        if (!$throwable instanceof HttpExceptionInterface) {
            return;
        }

        $request = $event->getRequest();
        $weight = $this->scorer->weigh($request, $throwable);

        if (0 === $weight) {
            return;
        }

        $ip = $request->getClientIp();

        // An allowed address stays loud: a malformed request coming from us is a client bug worth an
        // alert, and silencing it here would hide the only signal there is.
        if (null === $ip || $this->isAllowedIp($ip)) {
            return;
        }

        $userAgent = (string) $request->headers->get('User-Agent', '');

        if ($this->verifier->isVerified($ip, $userAgent)) {
            return;
        }

        $path = $request->getPathInfo();
        $banned = $this->registry->record($ip, $this->fingerprint->of($request), $userAgent, $path, $weight);

        if ($banned) {
            $event->setResponse(new Response('', Response::HTTP_FORBIDDEN));

            return;
        }

        if ($this->scorer->isLoginProbe($request, $throwable)) {
            $this->logger->warning('Malformed login request rejected.', [
                'ip' => $ip,
                'user_agent' => $userAgent,
            ]);

            $event->setResponse(new Response('', Response::HTTP_BAD_REQUEST));
        }
    }

    private function isAllowedIp(string $ip): bool
    {
        return [] !== $this->allowedIps && IpUtils::checkIp($ip, $this->allowedIps);
    }

    private function declaresTooling(string $userAgent): bool
    {
        if (mb_strlen($userAgent) < $this->uaMinLength) {
            return true;
        }

        $lower = strtolower($userAgent);

        foreach ($this->uaBlocklist as $fragment) {
            if (str_contains($lower, $fragment)) {
                return true;
            }
        }

        return false;
    }
}
