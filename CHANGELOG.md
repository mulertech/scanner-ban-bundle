# Release notes for scanner-ban-bundle

## v1.0.1 - 2026-08-31

### The loopback is always allowed

A request whose client address is the loopback comes from inside the container: a health check, a post-deployment probe, the application calling itself. It arrives with the User-Agent of whatever tool made the call, `curl` or none at all, which is exactly what the blocklist refuses.

That address is now allowed whatever `allowed_ips` holds, because it is an invariant rather than a setting. Without it, a post-deployment check calling `http://localhost` is answered with a `403` and the deployment reports a failure while the site itself is perfectly healthy.

This exempts no external traffic: a visitor arriving through a reverse proxy carries their own address, provided `framework.trusted_proxies` is set, which the bundle already requires.

### Housekeeping

`phpstan-baseline.neon` no longer ships in the distribution archive. It joins the tooling files already excluded, and its only referent, `phpstan.neon.dist`, was excluded already.

## v1.0.0 - 2026-08-30

Bans scanners on **what they request**, never on what they claim to be.

### The rule

A User-Agent is a string the client writes about itself, so it can cost its sender something but never earn them an exemption. A requested path is different: asking for `/.env` or `/wp-login.php` is the scan itself, and giving it up means giving up the scan.

| Rejected request | Weight |
|---|---|
| A path from an attack list | `probe_weight`, enough to ban on its own |
| A plausible path of the site | `not_found_weight`: a broken link elsewhere, a stale bookmark |
| A resource of a page | nothing |
| A `POST` on the login route rejected as a bad request | `probe_weight` |

### What comes with it

- **A ban reaches one client, not a browser cohort.** The fingerprint pairs the User-Agent with the subnet, never the User-Agent alone.
- **A crawler is exempt only once its address confirms its claim**, through the reverse then forward lookup its operator documents. An unverified `Googlebot` header is measured like any other client and never lifts a ban already in place.
- **A page resource never counts**, recognised by its path, and refined by `Sec-Fetch-Dest` where the browser sends it. Nothing excuses an attack-list path.
- **A rejected probe is answered with an empty `400` ahead of the error listener**, so it leaves a `warning` on its own channel instead of paging a human.
- `scanner-ban:digest` and `scanner-ban:unban`, with a notifier interface that writes to the log until a project points it at its own channel.
- Everything configurable: thresholds, window, ban duration, attack paths, asset prefixes and extensions, exempt paths, allowed addresses, verified crawlers.

### Requirements

PHP 8.4, Symfony 7.0 or 8.0, and a PSR-6 cache pool shared between requests.

Behind a reverse proxy, `framework.trusted_proxies` must be set. Without it `getClientIp()` returns the proxy address on every request and the first ban locks out every visitor at once.

### Getting started

```bash
composer require mulertech/scanner-ban-bundle

Register it for production, where it has something to judge, and set the route of your firewall check_path:

when@prod:
    mulertech_scanner_ban:
        login_route: app_login


```