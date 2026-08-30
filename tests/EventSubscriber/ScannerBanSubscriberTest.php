<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan\Tests\EventSubscriber;

use MulerTech\ScannerBan\Ban\BanRegistry;
use MulerTech\ScannerBan\Detection\ClientFingerprint;
use MulerTech\ScannerBan\Detection\CrawlerVerifier;
use MulerTech\ScannerBan\Detection\RequestScorer;
use MulerTech\ScannerBan\EventSubscriber\ScannerBanSubscriber;
use MulerTech\ScannerBan\Tests\Double\FakeDnsResolver;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;

final class ScannerBanSubscriberTest extends TestCase
{
    private const string BROWSER_UA = 'Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/141.0 Safari/537.36';
    private const string GOOGLEBOT_UA = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
    private const string GOOGLE_IP = '66.249.66.1';
    private const string SCANNER_IP = '203.0.113.30';

    public function testItRunsAheadOfTheErrorListener(): void
    {
        $events = ScannerBanSubscriber::getSubscribedEvents();

        self::assertSame(['onKernelRequest', 4096], $events[KernelEvents::REQUEST]);
        self::assertSame(['onKernelException', 20], $events[KernelEvents::EXCEPTION]);
    }

    public function testProbePathBansOnTheFirstRequest(): void
    {
        $cache = new ArrayAdapter();
        $subscriber = $this->subscriber($cache);

        $event = $this->exceptionEvent('/.env', self::SCANNER_IP, self::BROWSER_UA);
        $subscriber->onKernelException($event);

        self::assertSame(Response::HTTP_FORBIDDEN, $this->statusOf($event));

        $blocked = $this->requestEvent('/', self::SCANNER_IP, self::BROWSER_UA);
        $subscriber->onKernelRequest($blocked);

        self::assertSame(Response::HTTP_FORBIDDEN, $this->statusOf($blocked));
    }

    public function testOrdinaryMissDoesNotBanOnItsOwn(): void
    {
        $event = $this->exceptionEvent('/blog/moved', self::SCANNER_IP, self::BROWSER_UA);
        $this->subscriber(new ArrayAdapter())->onKernelException($event);

        self::assertNull($event->getResponse());
    }

    public function testPageResourceIsNeverCounted(): void
    {
        $cache = new ArrayAdapter();
        $subscriber = $this->subscriber($cache);

        for ($i = 0; $i < 20; ++$i) {
            $subscriber->onKernelException($this->exceptionEvent('/assets/app.js', self::SCANNER_IP, self::BROWSER_UA));
        }

        $blocked = $this->requestEvent('/', self::SCANNER_IP, self::BROWSER_UA);
        $subscriber->onKernelRequest($blocked);

        self::assertNull($blocked->getResponse());
    }

    public function testDeclaredToolingIsRefusedWithoutBeingCounted(): void
    {
        $event = $this->requestEvent('/', self::SCANNER_IP, 'curl/8.4.0');
        $this->subscriber(new ArrayAdapter())->onKernelRequest($event);

        self::assertSame(Response::HTTP_FORBIDDEN, $this->statusOf($event));
    }

    public function testEmptyUserAgentIsRefused(): void
    {
        $event = $this->requestEvent('/', self::SCANNER_IP, '');
        $this->subscriber(new ArrayAdapter())->onKernelRequest($event);

        self::assertSame(Response::HTTP_FORBIDDEN, $this->statusOf($event));
    }

    public function testExemptPathIsNeverBlocked(): void
    {
        $cache = new ArrayAdapter();
        $subscriber = $this->subscriber($cache);
        $subscriber->onKernelException($this->exceptionEvent('/.env', self::SCANNER_IP, self::BROWSER_UA));

        $event = $this->requestEvent('/robots.txt', self::SCANNER_IP, self::BROWSER_UA);
        $subscriber->onKernelRequest($event);

        self::assertNull($event->getResponse());
    }

    public function testClaimingGooglebotDoesNotLiftAnExistingBan(): void
    {
        $cache = new ArrayAdapter();
        $subscriber = $this->subscriber($cache);
        $subscriber->onKernelException($this->exceptionEvent('/.env', self::SCANNER_IP, self::BROWSER_UA));

        $event = $this->requestEvent('/', self::SCANNER_IP, self::GOOGLEBOT_UA);
        $subscriber->onKernelRequest($event);

        self::assertSame(Response::HTTP_FORBIDDEN, $this->statusOf($event));
    }

    public function testUnverifiableGooglebotClaimIsCounted(): void
    {
        $event = $this->exceptionEvent('/.env', self::SCANNER_IP, self::GOOGLEBOT_UA);
        $this->subscriber(new ArrayAdapter())->onKernelException($event);

        self::assertSame(Response::HTTP_FORBIDDEN, $this->statusOf($event));
    }

    public function testVerifiedCrawlerIsNeverCounted(): void
    {
        $event = $this->exceptionEvent('/.env', self::GOOGLE_IP, self::GOOGLEBOT_UA);
        $this->subscriber(new ArrayAdapter())->onKernelException($event);

        self::assertNull($event->getResponse());
    }

    public function testAllowedAddressStaysLoud(): void
    {
        $event = $this->exceptionEvent('/.env', '10.0.0.5', self::BROWSER_UA);
        $this->subscriber(new ArrayAdapter())->onKernelException($event);

        self::assertNull($event->getResponse());
    }

    public function testAllowedAddressIsNeverBlocked(): void
    {
        $event = $this->requestEvent('/', '10.0.0.5', 'curl/8.4.0');
        $this->subscriber(new ArrayAdapter())->onKernelRequest($event);

        self::assertNull($event->getResponse());
    }

    public function testMalformedLoginPostAnswersQuietlyWhenItCannotBeBanned(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with('Malformed login request rejected.', self::anything());

        $subscriber = $this->subscriber(new ArrayAdapter(), $logger, probeWeight: 1, maxScore: 10);

        $request = Request::create('/login', 'POST', server: ['REMOTE_ADDR' => self::SCANNER_IP]);
        $request->headers->set('User-Agent', self::BROWSER_UA);
        $request->attributes->set('_route', 'app_login');

        $event = new ExceptionEvent(
            $this->createStub(HttpKernelInterface::class),
            $request,
            HttpKernelInterface::MAIN_REQUEST,
            new BadRequestHttpException('The key "_username" must be a string, "NULL" given.'),
        );

        $subscriber->onKernelException($event);

        self::assertSame(Response::HTTP_BAD_REQUEST, $this->statusOf($event));
    }

    public function testSubRequestsAreIgnored(): void
    {
        $subscriber = $this->subscriber(new ArrayAdapter());

        $request = Request::create('/.env', 'GET', server: ['REMOTE_ADDR' => self::SCANNER_IP]);
        $request->headers->set('User-Agent', self::BROWSER_UA);

        $exception = new ExceptionEvent(
            $this->createStub(HttpKernelInterface::class),
            $request,
            HttpKernelInterface::SUB_REQUEST,
            new NotFoundHttpException(),
        );
        $subscriber->onKernelException($exception);

        $sub = new RequestEvent(
            $this->createStub(HttpKernelInterface::class),
            $request,
            HttpKernelInterface::SUB_REQUEST,
        );
        $subscriber->onKernelRequest($sub);

        self::assertNull($exception->getResponse());
        self::assertNull($sub->getResponse());
    }

    public function testNonHttpExceptionsAreIgnored(): void
    {
        $request = Request::create('/.env', 'GET', server: ['REMOTE_ADDR' => self::SCANNER_IP]);
        $request->headers->set('User-Agent', self::BROWSER_UA);

        $event = new ExceptionEvent(
            $this->createStub(HttpKernelInterface::class),
            $request,
            HttpKernelInterface::MAIN_REQUEST,
            new \RuntimeException('boom'),
        );

        $this->subscriber(new ArrayAdapter())->onKernelException($event);

        self::assertNull($event->getResponse());
    }

    private function statusOf(RequestEvent $event): ?int
    {
        return $event->getResponse()?->getStatusCode();
    }

    private function requestEvent(string $path, string $ip, string $userAgent): RequestEvent
    {
        return new RequestEvent(
            $this->createStub(HttpKernelInterface::class),
            $this->request($path, $ip, $userAgent),
            HttpKernelInterface::MAIN_REQUEST,
        );
    }

    private function exceptionEvent(string $path, string $ip, string $userAgent): ExceptionEvent
    {
        return new ExceptionEvent(
            $this->createStub(HttpKernelInterface::class),
            $this->request($path, $ip, $userAgent),
            HttpKernelInterface::MAIN_REQUEST,
            new NotFoundHttpException(),
        );
    }

    private function request(string $path, string $ip, string $userAgent): Request
    {
        $request = Request::create($path, 'GET', server: ['REMOTE_ADDR' => $ip]);
        $request->headers->set('User-Agent', $userAgent);

        return $request;
    }

    private function subscriber(
        ArrayAdapter $cache,
        ?LoggerInterface $logger = null,
        int $probeWeight = 10,
        int $maxScore = 10,
    ): ScannerBanSubscriber {
        $resolver = new FakeDnsResolver(
            [self::GOOGLE_IP => 'crawl-66-249-66-1.googlebot.com'],
            ['crawl-66-249-66-1.googlebot.com' => [self::GOOGLE_IP]],
        );

        return new ScannerBanSubscriber(
            new RequestScorer(
                ['/.env', '/wp-login.php'],
                ['/assets'],
                ['css', 'js', 'png'],
                ['/robots.txt'],
                'app_login',
                $probeWeight,
                1,
            ),
            new BanRegistry($cache, new NullLogger(), $maxScore, 300, 86400, 172800, 500),
            new CrawlerVerifier($resolver, $cache, new NullLogger(), ['googlebot' => ['googlebot.com']], 86400),
            new ClientFingerprint(),
            $logger ?? new NullLogger(),
            '10.0.0.0/8',
            ['curl/', 'sqlmap'],
            10,
        );
    }
}
