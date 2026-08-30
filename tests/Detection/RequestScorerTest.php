<?php

declare(strict_types=1);

namespace MulerTech\ScannerBan\Tests\Detection;

use MulerTech\ScannerBan\Detection\RequestScorer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

final class RequestScorerTest extends TestCase
{
    private const int PROBE_WEIGHT = 10;
    private const int NOT_FOUND_WEIGHT = 1;

    public function testProbePathIsWorthTheWholeThreshold(): void
    {
        $event = Request::create('/.env');

        self::assertSame(self::PROBE_WEIGHT, $this->scorer()->weigh($event, new NotFoundHttpException()));
    }

    public function testProbePathMatchesOnPrefix(): void
    {
        $request = Request::create('/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php');

        self::assertSame(self::PROBE_WEIGHT, $this->scorer()->weigh($request, new NotFoundHttpException()));
    }

    public function testProbePathMatchesWhateverTheCase(): void
    {
        $request = Request::create('/WP-Login.php');

        self::assertSame(self::PROBE_WEIGHT, $this->scorer()->weigh($request, new NotFoundHttpException()));
    }

    public function testOrdinaryMissWeighsLittle(): void
    {
        $request = Request::create('/blog/an-article-that-moved');

        self::assertSame(self::NOT_FOUND_WEIGHT, $this->scorer()->weigh($request, new NotFoundHttpException()));
    }

    #[DataProvider('pageResources')]
    public function testPageResourceNeverCounts(string $path): void
    {
        $request = Request::create($path);

        self::assertSame(0, $this->scorer()->weigh($request, new NotFoundHttpException()));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function pageResources(): iterable
    {
        yield 'asset prefix' => ['/assets/app-1a2b3c.js'];
        yield 'image extension' => ['/uploads/photo.png'];
        yield 'font extension' => ['/fonts/inter.woff2'];
        yield 'stylesheet extension' => ['/css/main.css'];
    }

    public function testSubresourceHeaderCancelsAnOrdinaryMiss(): void
    {
        $request = Request::create('/blog/missing-cover');
        $request->headers->set('Sec-Fetch-Dest', 'image');

        self::assertSame(0, $this->scorer()->weigh($request, new NotFoundHttpException()));
    }

    public function testSubresourceHeaderNeverExcusesAProbePath(): void
    {
        $request = Request::create('/.env');
        $request->headers->set('Sec-Fetch-Dest', 'image');

        self::assertSame(self::PROBE_WEIGHT, $this->scorer()->weigh($request, new NotFoundHttpException()));
    }

    public function testDocumentDestinationStaysCounted(): void
    {
        $request = Request::create('/blog/an-article-that-moved');
        $request->headers->set('Sec-Fetch-Dest', 'document');

        self::assertSame(self::NOT_FOUND_WEIGHT, $this->scorer()->weigh($request, new NotFoundHttpException()));
    }

    public function testExemptPathNeverCounts(): void
    {
        $request = Request::create('/robots.txt');

        self::assertSame(0, $this->scorer()->weigh($request, new NotFoundHttpException()));
        self::assertTrue($this->scorer()->isExempt($request));
    }

    public function testOtherStatusCodesAreIgnored(): void
    {
        $request = Request::create('/anything');

        self::assertSame(0, $this->scorer()->weigh($request, new HttpException(500, 'boom')));
    }

    public function testMalformedLoginPostIsAProbe(): void
    {
        $request = $this->loginRequest();

        self::assertTrue($this->scorer()->isLoginProbe($request, new BadRequestHttpException()));
        self::assertSame(self::PROBE_WEIGHT, $this->scorer()->weigh($request, new BadRequestHttpException()));
    }

    public function testBadRequestOutsideTheLoginRouteIsNotAProbe(): void
    {
        $request = $this->loginRequest(route: 'api_import');

        self::assertFalse($this->scorer()->isLoginProbe($request, new BadRequestHttpException()));
        self::assertSame(0, $this->scorer()->weigh($request, new BadRequestHttpException()));
    }

    public function testGetOnTheLoginRouteIsNotAProbe(): void
    {
        $request = $this->loginRequest(method: 'GET');

        self::assertFalse($this->scorer()->isLoginProbe($request, new BadRequestHttpException()));
    }

    private function loginRequest(string $route = 'app_login', string $method = 'POST'): Request
    {
        $request = Request::create('/login', $method);
        $request->attributes->set('_route', $route);

        return $request;
    }

    private function scorer(): RequestScorer
    {
        return new RequestScorer(
            ['/.env', '/wp-login.php', '/vendor/phpunit'],
            ['/assets'],
            ['css', 'js', 'png', 'woff2'],
            ['/robots.txt'],
            'app_login',
            self::PROBE_WEIGHT,
            self::NOT_FOUND_WEIGHT,
        );
    }
}
