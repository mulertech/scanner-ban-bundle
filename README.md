# ScannerBanBundle

___
[![Latest Version on Packagist](https://img.shields.io/packagist/v/mulertech/scanner-ban-bundle.svg?style=flat-square)](https://packagist.org/packages/mulertech/scanner-ban-bundle)
[![GitHub Tests Action Status](https://img.shields.io/github/actions/workflow/status/mulertech/scanner-ban-bundle/tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/mulertech/scanner-ban-bundle/actions/workflows/tests.yml)
[![GitHub PHPStan Action Status](https://img.shields.io/github/actions/workflow/status/mulertech/scanner-ban-bundle/phpstan.yml?branch=main&label=phpstan&style=flat-square)](https://github.com/mulertech/scanner-ban-bundle/actions/workflows/phpstan.yml)
[![Total Downloads](https://img.shields.io/packagist/dt/mulertech/scanner-ban-bundle.svg?style=flat-square)](https://packagist.org/packages/mulertech/scanner-ban-bundle)
[![Test Coverage](https://raw.githubusercontent.com/mulertech/scanner-ban-bundle/badge/badge-coverage.svg)](https://packagist.org/packages/mulertech/scanner-ban-bundle)
___

Bans scanners on **what they request**, never on what they claim to be.

## The rule

A User-Agent is a string the client writes about itself. It can cost its sender something, never earn
them anything. A requested path is different: asking for `/.env` or `/wp-login.php` is the scan
itself, and giving it up means giving up the scan. So the weight of a rejected request comes from
the path, and identity only ever gets in the way of an exemption.

| Rejected request | Weight |
|---|---|
| A path from an attack list (`/.env`, `/.git/config`, `/wp-login.php`) | `probe_weight`, enough to ban on its own |
| A plausible path of the site | `not_found_weight`: a broken link elsewhere, a stale bookmark, a retired article |
| A resource of a page (asset prefix, asset extension, subresource fetch) | nothing |
| A `POST` on the login route rejected as a bad request | `probe_weight` |

That last line covers credential probing: a login form always sends its username field, so a bad
request on that route came from a client posting foreign field names. The rule keys on the route,
not on the field name, so renaming `_username` changes nothing.

Two consequences worth knowing:

- **A page resource never counts.** One page asking for five missing images produces five rejections
  the visitor never asked for, and that is the likeliest false positive there is.
- **A crawler is exempt only once its address confirms its claim**, through the reverse then forward
  lookup its operator documents. An unverified `Googlebot` header is measured like any other client,
  and it never lifts a ban that is already in place.

The bundle also answers a rejected probe itself, with an empty `400`, which keeps it off the error
channel. An anonymous client error is not an application failure and must not page a human; the
`warning` it logs instead is the trace it leaves.

## Requirements

- PHP 8.4 or later
- Symfony 7.0 or 8.0
- A PSR-6 cache pool shared between requests (`cache.app` by default)
- **`framework.trusted_proxies` set correctly if the application sits behind a reverse proxy.**
  Without it `Request::getClientIp()` returns the proxy address on every request, and the first ban
  locks out every visitor at once.

## Installation

```bash
composer require mulertech/scanner-ban-bundle
```

Register the bundle if Flex did not:

```php
// config/bundles.php
return [
    // ...
    MulerTech\ScannerBan\MulerTechScannerBanBundle::class => ['prod' => true],
];
```

Enabling it in `prod` alone is the usual choice: a development session produces missing paths all
day long, and a test suite has no reason to be counted.

## Usage

The bundle works with no configuration beyond the login route. Everything below shows its defaults.

```yaml
# config/packages/mulertech_scanner_ban.yaml
mulertech_scanner_ban:
    login_route: app_login          # route name of the firewall check_path
    allowed_ips: '%env(default::SCANNER_BAN_ALLOWED_IPS)%'

    max_score: 10                   # score reached within the window bans the client
    probe_weight: 10
    not_found_weight: 1
    window: 300                     # seconds the running score survives
    ban_duration: 86400             # seconds a ban lasts

    cache_service: cache.app
    logger_service: logger
```

`allowed_ips` takes a comma separated list of addresses or CIDR ranges. They are never counted and
never blocked, and a malformed request coming from one of them **stays loud**: from an address you
own, it is a client bug worth an alert, and silencing it would hide the only signal there is.

The loopback is always allowed, whatever `allowed_ips` holds. A request whose client address is the
loopback came from inside the container: a health check, a post-deployment probe, the application
calling itself. Such a caller arrives with the User-Agent of the tool that made the call, `curl` or
none at all, which is exactly what the blocklist refuses.

Keep the operational values in the project, not in a shared example. The thresholds published here
are defaults, so a site that leaves them untouched is a site whose thresholds are public.

### Lists

```yaml
mulertech_scanner_ban:
    # Paths worth the full weight on the first request. Add what your stack invites: a Laravel
    # site draws /telescope, a WordPress-shaped domain draws /wp-admin whether or not it runs it.
    probe_paths: ['/.env', '/.git', '/wp-login.php', '…']

    # Never counted: the resources of a page.
    asset_prefixes: ['/assets', '/bundles', '/build', '/media']
    asset_extensions: ['css', 'js', 'png', 'woff2', '…']

    # Never counted and never blocked, whatever the client.
    exempt_paths: ['/robots.txt', '/sitemap.xml', '/llms.txt']

    # Naming a tool is an admission, and refusing it costs nothing. Nothing important rests on it:
    # anyone who thinks to send a browser string walks straight past.
    user_agent_blocklist: ['curl/', 'sqlmap', '…']
    user_agent_min_length: 10
```

A project serving CSP reports should add its report endpoint to `exempt_paths`: browsers post there
on their own, with no session and no referrer, and a burst must never read as a sweep.

### Verified crawlers

```yaml
mulertech_scanner_ban:
    verified_crawlers:
        googlebot: ['googlebot.com', 'google.com']
        bingbot: ['search.msn.com']
    crawler_cache_ttl: 86400
```

Only crawlers whose operator documents a reverse lookup can appear here, because the entry grants an
exemption and an unverifiable entry is a hole. A crawler that publishes address ranges instead of
reverse records does not need one: it does not request `/.env`, so the path rule already leaves it
alone.

### Digest

The bundle ships a notifier that writes the digest to the log. A project with a channel of its own
implements the interface and aliases it. The alias target must implement
`ScannerBanNotifierInterface`, so an existing messaging service is reached through a small adapter
rather than aliased directly:

```php
// src/Notifier/ScannerBanNotifier.php
final readonly class ScannerBanNotifier implements ScannerBanNotifierInterface
{
    public function __construct(private NotificationService $notificationService)
    {
    }

    public function notify(string $message): void
    {
        $this->notificationService->send($message);
    }
}
```

```yaml
# config/services.yaml
services:
    MulerTech\ScannerBan\Notifier\ScannerBanNotifierInterface:
        alias: App\Notifier\ScannerBanNotifier
```

The bundle carries no schedule of its own, so run the digest from yours. It empties as it sends:

```bash
php bin/console scanner-ban:digest
```

```bash
php bin/console scanner-ban:unban 203.0.113.42
```

### Observability

The bundle answers a probe before Symfony's error listener runs, so nothing it handles reaches the
error channel. Its own records are a `warning` for a rejected login probe and an `info` for a ban.
Behind a `fingers_crossed` handler both are buffered and dropped, so give them a channel that writes
unconditionally:

```yaml
# config/packages/monolog.yaml
monolog:
    channels: ['scanner']
    handlers:
        scanner:
            type: stream
            channels: [scanner]
            path: php://stderr
            level: info
            formatter: monolog.formatter.json
```

Monolog registers a `monolog.logger.<channel>` service for every declared channel, so pointing the
bundle at it is all that is left:

```yaml
mulertech_scanner_ban:
    logger_service: monolog.logger.scanner
```

## Testing

```bash
./vendor/bin/mtdocker test-ai
```
